"""PicoRV32 native ready/valid memory x real PULP APB3 GPIO campaign fixtures.

This is the P6 row-5 counterpart of
``myfuzz.integration.axil_scenario_campaign``: three search strategies over one
real CPU and one real IP, a two-sided fixture whose declared sources come from
the admitted artifacts, and an independently assessed two-round closed chain
per direction.

Why this CPU / IP pair
----------------------
``configs/cpus/picorv32`` declares exactly one ``processor.memory`` endpoint
using ``ready-valid-memory/1`` -- the "native completion" protocol form of the
row -- and ``configs/peripherals/pulp_gpio`` is the real PULP APB3 GPIO that
the checklist names first for this row.  The CPU has no MMIO window of its own,
so the fixture declares one and routes it with a
:class:`~myfuzz.scenario.router.DataflowRouter` to the real device session.  The
directed chain test
``tests/integration/test_native_cpu_pulp_gpio_chain_real.py`` proves one round
of that link; this campaign module supplies the multi-case search that row 5
still lacked.

What the two directions mean here
---------------------------------
Both directions run the same pinned two-round program and declare **both**
sides' sources; the direction decides who *initiated*:

* ``cpu.padout_byte`` -- the 8-bit immediate of one ``addi`` in the CPU program
  image, i.e. the byte the CPU stores to PADOUT in round 1;
* ``gpio0.pin_byte`` -- the byte the external world drives on ``gpio_in``.

The program stores ``A`` to PADOUT, reads the external pin byte ``B`` from
PADIN, commits ``A ^ B`` to RAM, stores ``A ^ B`` to PADOUT again, reads PADIN
again (must still be ``B``: the device has no output-to-input loopback) and
commits ``(A ^ B) + B``.  Both committed values and both real pin words are
joint functions of the two declared sources.

* ``CPU_TO_IP_TO_CPU`` -- the CPU's first PADOUT store is accepted before the
  external pin byte is driven; the checker requires exactly that order of the
  real acceptance, the injection and the delivery.
* ``IP_TO_CPU_TO_IP`` -- the external pin byte is driven at case start, before
  any CPU device access; the CPU then reads, commits and drives the joint value
  back out on the real pins.

Honesty notes
-------------
* The routed beats are **queued**, not inline.  ``DeferredNativeMemorySession``
  delivers inside the declared window with ``DataflowRouter.enqueue``; the
  device beat only runs on the device harness's own step and its completion
  callback releases the CPU answer afterwards.  The checker joins each delivery
  to its acceptance by source-transaction identity and requires the delivery's
  producer event to be a real ``gpio0`` step.
* A credited wire byte is only the device's own observation: ``gpio_out``,
  ``gpio_dir`` and ``gpio_in_sync`` are real physical outputs of the pinned RTL,
  and a PADIN answer is the device's own APB read-back.
* The checker never derives a DUT output from a schedule: every stage is an
  observation copied out of the runner's event stream.
* The CPU profile has no interrupt endpoint.  No IRQ is synthesised, declared or
  claimed by this module.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Mapping

from myfuzz.scenario.dependency import (DependencyGraph, DependencyRule,
                                        FuzzableSource, SourceBinding,
                                        SourceBindings)
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder

from .scenario_campaign import (CampaignBlocked, IbexTwoGpioBoundProvider,
                                _require_pinned_bound_seed)

from myfuzz.scenario import picorv32_native_cpu_example as fixture
from myfuzz.scenario.picorv32_native_cpu_example import (
    CPU_COMPONENT, CPU_SOURCE_ID, GPIO_BASE, GPIO_COMPONENT, GPIO_DEVICE,
    GPIO_INPUT, GPIO_INPUT_SEED, GPIO_WINDOW, GPIOEN, IP_SOURCE_ID,
    MARKER_ADDRESS, MARKER_VALUE, PADIN, PADOUT, PADOUT_BYTE_BIT_OFFSET,
    PADOUT_BYTE_SEED, PADDIR, PADOUT_IMMEDIATE_INSTRUCTION, PROGRAM_IMAGE,
    RESULT_ADDRESS, RESULT2_ADDRESS, SOURCE_WIDTH, joint_value,
    native_gpio_artifacts, round_two_value)

ROOT = Path(__file__).resolve().parents[3]

#: One search target per bit of the two bytes the checker observes on each
#: side: the device's real output pins (the CPU byte and the joint byte reach
#: them) and the CPU's device read answer (the external pin byte).  A single
#: trivially satisfied target would leave the RFuzz corpus at the seed forever,
#: because the client only saves an input that produces coverage the run has
#: not seen; one target per bit lets a mutated genome newly satisfy a target.
TARGET_BITS = 8


def _transaction_identity(event: Mapping) -> tuple:
    transaction = event.get('source_transaction', event.get('transaction', {}))
    if not isinstance(transaction, Mapping):
        return ()
    return tuple(transaction.get(key) for key in (
        'execution_id', 'testcase_id', 'source_component', 'source_epoch',
        'channel_id', 'source_sequence'))


def _device_delivery(event: Mapping) -> bool:
    return (event.get('kind') == 'mmio_delivery'
            and event.get('device_id') == GPIO_DEVICE)


def _device_acceptance(event: Mapping) -> bool:
    return (event.get('kind') == 'mmio_acceptance'
            and event.get('device_id') == GPIO_DEVICE)


def _step_output(event: Mapping, port: str):
    outputs = event.get('outputs')
    if not isinstance(outputs, Mapping):
        return None
    value = outputs.get(port)
    return value if type(value) is int and not isinstance(value, bool) else None


def _find(stream, after: int, predicate):
    return next((event for event in stream
                 if type(event.get('event_id')) is int
                 and event['event_id'] > after and predicate(event)), None)


def _pin_word(event: Mapping, port: str):
    """The low byte of a real GPIO physical output on a gpio0 step event."""
    value = _step_output(event, port)
    return None if value is None else value & 0xff


def assess_native_gpio_closed_chain(direction: str, events,
                                    final_state: Mapping) -> dict | None:
    """Two ordered rounds over the real native port and the real GPIO pins.

    Every stage is copied out of the runner's event stream; nothing is derived
    from a schedule.  The direction decides *who initiated*, and the walk
    enforces exactly that ordering.

    The chain demands, for each of two rounds:

    * the CPU's real device beat accepted by the router (``mmio_acceptance``),
      queued and only then executed by the device on the device's own step
      (``mmio_delivery`` whose producer is a ``gpio0`` step), joined by source
      transaction identity;
    * the device's own APB read-back value, and, for the write, the device's own
      ``gpio_out`` physical pin word after the access;
    * the CPU consuming that exact transaction's answer
      (``data_rsp_consumed`` with the delivery's epoch/sequence);
    * the joint value committed to CPU RAM;
    * the device's synchronized external pin word equal to the injected byte,
      which the PADIN answer must equal too (the device does not loop the output
      pins back onto the inputs).

    ``rounds`` is therefore 0 or 2; a credited round means every stage above
    was observed with its own event identity.
    """
    if direction not in ('CPU_TO_IP_TO_CPU', 'IP_TO_CPU_TO_IP'):
        return None
    stream = tuple(events)
    findings: list[str] = []
    identifiers = [event.get('event_id') for event in stream]
    if any(type(item) is not int for item in identifiers) \
            or identifiers != sorted(set(identifiers)):
        findings.append('event_ids_not_strictly_ordered')
    if any(event.get('kind') == 'reset_barrier' for event in stream):
        findings.append('unexpected_reset')
    if any(event.get('kind') in ('harness_failure', 'budget_exhausted')
           for event in stream):
        findings.append('harness_failure_present')

    injections = [event for event in stream
                  if event.get('kind') == 'source_injection'
                  and event.get('component') == GPIO_COMPONENT
                  and event.get('port') == GPIO_INPUT]
    acceptances = [event for event in stream if _device_acceptance(event)]
    deliveries = [event for event in stream if _device_delivery(event)]
    if len(injections) != 1:
        findings.append('gpio_pin_injection_not_unique')
    if not acceptances:
        findings.append('cpu_device_acceptance_missing')
    if not deliveries:
        findings.append('cpu_device_delivery_missing')
    if findings:
        return {'complete': False, 'rounds': 0, 'findings': findings}

    injection = injections[0]
    pin_byte = injection.get('value')
    if type(pin_byte) is not int or not 0 <= pin_byte < 1 << SOURCE_WIDTH:
        findings.append('gpio_pin_byte_invalid')
        return {'complete': False, 'rounds': 0, 'findings': findings}

    by_id = {event['event_id']: event for event in stream
             if type(event.get('event_id')) is int}
    pinned_words = [event for event in deliveries
                    if event.get('offset') == PADOUT and event.get('write') is True
                    and type(event.get('write_value')) is int]
    padin_reads = [event for event in deliveries
                   if event.get('offset') == PADIN and event.get('write') is False]
    if len(pinned_words) != 2:
        findings.append('padout_write_rounds_not_two')
    if len(padin_reads) != 2:
        findings.append('padin_read_rounds_not_two')
    if findings:
        return {'complete': False, 'rounds': 0, 'findings': findings}

    # The two configuration writes must be real device beats too: the fixture
    # never assumes that a direction/GPIOEN write happened.
    for offset in (PADDIR, GPIOEN):
        if not any(event.get('offset') == offset and event.get('write') is True
                   and event.get('write_value') == 0xffffffff
                   for event in deliveries):
            findings.append(f'gpio_configuration_write_missing_{offset:x}')

    def accepted_before(delivery: Mapping) -> Mapping | None:
        identity = _transaction_identity(delivery)
        if not identity or any(item is None for item in identity):
            return None
        return next((event for event in acceptances
                     if _transaction_identity(event) == identity
                     and event['event_id'] < delivery['event_id']), None)

    # Every device delivery must be one queued request that was accepted
    # earlier by the CPU and executed on the device harness's own step.
    queued = 0
    for delivery in deliveries:
        acceptance = accepted_before(delivery)
        if acceptance is None:
            findings.append('device_delivery_without_earlier_acceptance')
            continue
        producer = by_id.get(delivery.get('producer_event_id'))
        if producer is None or producer.get('component') != GPIO_COMPONENT:
            findings.append('device_delivery_not_executed_on_device_step')
            continue
        if producer['event_id'] <= acceptance['event_id']:
            findings.append('device_delivery_not_after_acceptance')
            continue
        queued += 1

    write_one, write_two = pinned_words
    read_one, read_two = padin_reads
    if not read_one['event_id'] < write_two['event_id']:
        findings.append('round_two_write_preceded_round_one_read')
    if not write_two['event_id'] < read_two['event_id']:
        findings.append('round_two_read_preceded_round_two_write')

    padout_byte = write_one.get('write_value')
    joint = write_two.get('write_value')
    if type(padout_byte) is not int or not 0 <= padout_byte < 1 << SOURCE_WIDTH:
        findings.append('padout_byte_invalid')
        return {'complete': False, 'rounds': 0, 'findings': findings}
    committed_joint = joint_value(padout_byte, pin_byte)
    committed_second = round_two_value(padout_byte, pin_byte)
    if joint != committed_joint:
        findings.append('second_padout_write_is_not_the_joint_value')
    if read_one.get('read_value') != pin_byte:
        findings.append('round_one_padin_answer_mismatch')
    if read_two.get('read_value') != pin_byte:
        findings.append('round_two_padin_answer_mismatch')

    # Direction claim: who initiated the round.
    if direction == 'CPU_TO_IP_TO_CPU':
        cpu_write_acceptance = accepted_before(write_one)
        if (cpu_write_acceptance is None
                or cpu_write_acceptance['event_id'] > injection['event_id']):
            findings.append('cpu_did_not_initiate')
    else:
        first_access = min(acceptances, key=lambda event: event['event_id'])
        if injection['event_id'] > first_access['event_id']:
            findings.append('ip_did_not_initiate')

    # The device's own physical output pins must carry the CPU's words, and its
    # own synchronized input word must carry the external pin byte.
    def pin_after(after: int, port: str, value: int, *, label: str) -> None:
        if _find(stream, after, lambda event:
                 event.get('component') == GPIO_COMPONENT
                 and _pin_word(event, port) == (value & 0xff)) is None:
            findings.append(label)

    pin_after(write_one['event_id'], 'gpio_out', padout_byte,
              label='gpio_out_round_one_missing')
    pin_after(write_two['event_id'], 'gpio_out', committed_joint,
              label='gpio_out_round_two_missing')
    pin_after(injection['event_id'], 'gpio_in_sync', pin_byte,
              label='gpio_in_sync_missing')

    # The CPU consumes exactly each read's answer, then commits both joint
    # values to RAM.  The transaction identity of a read is what makes the join.
    def consume_after(read: Mapping):
        transaction = read.get('source_transaction', {})
        if not isinstance(transaction, Mapping):
            return None
        return _find(stream, read['event_id'], lambda event:
                     event.get('component') == CPU_COMPONENT
                     and _step_output(event, 'data_rsp_consumed') == 1
                     and _step_output(event, 'data_rsp_rdata') == pin_byte
                     and _step_output(event, 'data_rsp_source_epoch')
                     == transaction.get('source_epoch')
                     and _step_output(event, 'data_rsp_source_sequence')
                     == transaction.get('source_sequence'))

    consume_one = consume_after(read_one)
    consume_two = consume_after(read_two)
    if consume_one is None:
        findings.append('cpu_consume_round_one_missing')
    if consume_two is None:
        findings.append('cpu_consume_round_two_missing')

    def ram_commit(after: int, address: int, value: int, *, label: str) -> None:
        if _find(stream, after, lambda event:
                 event.get('kind') == 'memory_write'
                 and event.get('component') == CPU_COMPONENT
                 and event.get('address') == address
                 and event.get('value') == value) is None:
            findings.append(label)

    if consume_one is not None:
        ram_commit(consume_one['event_id'], RESULT_ADDRESS, committed_joint,
                   label='cpu_ram_commit_round_one_missing')
    if consume_two is not None:
        ram_commit(consume_two['event_id'], RESULT2_ADDRESS, committed_second,
                   label='cpu_ram_commit_round_two_missing')
    # The completion marker proves the program ran to its declared end, so a
    # missing later stage is a missing observation rather than a cut budget.
    marker = _find(stream, read_two['event_id'], lambda event:
                   event.get('kind') == 'memory_write'
                   and event.get('component') == CPU_COMPONENT
                   and event.get('address') == MARKER_ADDRESS
                   and event.get('value') == MARKER_VALUE)
    if marker is None:
        findings.append('program_completion_marker_missing')

    # Every credited device beat must be one real, distinct transaction.
    used: set[tuple] = set()
    for event, label in ((write_one, 'padout_write_round_one'),
                         (read_one, 'padin_read_round_one'),
                         (write_two, 'padout_write_round_two'),
                         (read_two, 'padin_read_round_two')):
        identity = _transaction_identity(event)
        if not identity or any(item is None for item in identity):
            findings.append(label + '_transaction_identity_missing')
        elif identity in used:
            findings.append(label + '_transaction_reused')
        used.add(identity)

    inputs = final_state.get('inputs', {})
    if not isinstance(inputs, Mapping) \
            or inputs.get(GPIO_COMPONENT, {}).get(GPIO_INPUT) != pin_byte:
        findings.append('gpio_pin_input_state_mismatch')
    pending = final_state.get('pending_responses', {})
    if not isinstance(pending, Mapping) \
            or any(value != 0 for value in pending.values()):
        findings.append('pending_responses_at_end')

    complete = not findings
    return {'complete': complete, 'rounds': 2 if complete else 0,
            'findings': findings, 'padout_byte': padout_byte,
            'pin_byte': pin_byte, 'joint_value': committed_joint,
            'second_commit': committed_second,
            'queued_device_deliveries': queued}


def _corpus_input_hashes(live: Path) -> frozenset[str]:
    """The raw-input identity of every saved corpus entry, as RFuzz wrote it."""
    hashes = set()
    for path in sorted((Path(live) / 'corpus').glob('entry_*.json')):
        document = json.loads(path.read_text(encoding='utf-8'))
        raw = document.get('entry', {}).get('inputs')
        if (not isinstance(raw, list) or not raw or len(raw) % 8
                or any(type(value) is not int or not 0 <= value <= 255
                       for value in raw)):
            raise CampaignBlocked(f'invalid saved corpus entry: {path.name}')
        hashes.add(hashlib.sha256(bytes(raw)).hexdigest())
    return frozenset(hashes)


def corpus_failure_accounting(corpus_hashes, replayed):
    """Split replayed failure traces into corpus-covered and extra ones.

    ``live/failures`` keeps every case that ended in a violation or an
    unresolved effect, while ``live/corpus`` keeps the inputs whose coverage
    the run had not seen before; the first set is not a subset of the second.
    The framework's replay invariants bound the reported failure count by the
    number of replayed corpus entries, so the counts reported to the gate are
    taken over the corpus-covered subset.  The caller re-executes *every* saved
    failure trace and reports a mismatch for any of them that does not replay
    identically, so the extra ones are verified rather than dropped.
    """
    covered = covered_matched = total = 0
    for raw_sha256, matched in replayed:
        total += 1
        if raw_sha256 in corpus_hashes:
            covered += 1
            covered_matched += int(bool(matched))
    return {'covered_failure_entries': covered,
            'covered_matched_failure_entries': covered_matched,
            'replayed_failure_entries': total}


class PicoNativeGpioBoundProvider(IbexTwoGpioBoundProvider):
    """Three strategies over one real native CPU and one real PULP GPIO."""

    BOUND_REVERSE_SEED = 'pico_native_gpio_reverse_seed.json'

    #: Pinned shape of this provider's CPU-direction seed genome.
    BOUND_SEED_SHAPE = fixture.BOUND_SEED_SHAPE

    #: Both directions execute the same pinned program image.
    PROGRAM_SHA256 = {direction: fixture.program_digest(direction)
                      for direction in ('CPU_TO_IP_TO_CPU', 'IP_TO_CPU_TO_IP')}

    def __init__(self, client_binary: Path | None = None) -> None:
        super().__init__(client_binary)
        #: One Verilator build cache for every cell of one campaign: the local
        #: harness is admitted once and then reused by identity.
        self._build_cache = Path(tempfile.mkdtemp(prefix='myfuzz-pico-native-campaign-'))
        self._bound_pair: fixture.PicoNativeGpioPair | None = None
        self._independent_pair: fixture.PicoNativeGpioPair | None = None

    def _pair(self) -> fixture.PicoNativeGpioPair:
        """The one admitted CPU+IP pair every bound cell of this provider reuses."""
        if self._bound_pair is None:
            cpu_artifact, gpio_artifact = native_gpio_artifacts(ROOT)
            self._bound_pair = fixture.PicoNativeGpioPair(
                cpu_artifact, gpio_artifact, base_dir=ROOT,
                cache_dir=self._build_cache)
        return self._bound_pair

    def _factory(self):
        pair = self._pair()
        return pair.runner

    def search(self, cell, output, manifest):
        """Reuse the code-owned host closure across every cell of the campaign."""
        from myfuzz.local_harness.build import host_source_discovery_scope

        with host_source_discovery_scope():
            return super().search(cell, output, manifest)

    def replay(self, cell, output, manifest):
        """Replay the whole saved corpus and every saved failure trace."""
        from myfuzz.local_harness.build import host_source_discovery_scope

        with host_source_discovery_scope():
            return self._replay(cell, output, manifest)

    def _replay(self, cell, output, manifest):
        from myfuzz.integration.scenario_rfuzz_replay import (
            replay_scenario_rfuzz_corpus)
        from myfuzz.scenario.genome import GenomeCodec
        from .scenario_campaign import (_campaign_budgeted_factory,
                                        _replay_saved_failure_trace)

        factory, _, _, _ = (
            self._independent_fixture(cell.direction, manifest)
            if cell.strategy == 'independent_drive' else
            self._fixture(cell.direction, manifest))
        budgeted_factory = _campaign_budgeted_factory(factory)
        result = replay_scenario_rfuzz_corpus(
            output / 'live', budgeted_factory,
            checker_config=self._checker_config(cell),
            checker_identity_target=self._assess_trace_chain)
        failure_dir = output / 'live' / 'failures'
        failures = sorted(failure_dir.glob('*.json')) if failure_dir.exists() else []
        mismatches = list(result.mismatches)
        replayed = []
        for path in failures:
            matched = False
            try:
                document = json.loads(path.read_text(encoding='utf-8'))
                genome = GenomeCodec.decode(json.dumps(
                    document['genome'], sort_keys=True,
                    separators=(',', ':')).encode('utf-8'))
                matched = _replay_saved_failure_trace(
                    genome, budgeted_factory, document['trace'])
                raw_sha256 = document.get('raw_sha256')
            except (OSError, ValueError, TypeError, KeyError) as exc:
                mismatches.append(f'{path.name}: {type(exc).__name__}: {exc}')
                raw_sha256 = None
            if not matched:
                mismatches.append(f'{path.name}: full trace differs')
            replayed.append((raw_sha256, matched))
        accounting = corpus_failure_accounting(
            _corpus_input_hashes(output / 'live'), replayed)
        from .scenario_campaign import ReplayEvidence

        return ReplayEvidence(
            total_entries=result.total_entries,
            matched_entries=result.matched_entries,
            failure_entries=accounting['covered_failure_entries'],
            matched_failure_entries=accounting['covered_matched_failure_entries'],
            error='; '.join(mismatches) if mismatches else None)

    @staticmethod
    def _assess_trace_chain(direction, events, final_state):
        return assess_native_gpio_closed_chain(direction, events, final_state)

    def _sources(self, direction):
        """Both sides' declared sources, on the profile's own facts."""
        return (
            FuzzableSource(CPU_SOURCE_ID, CPU_COMPONENT, PROGRAM_IMAGE,
                           PADOUT_BYTE_BIT_OFFSET, SOURCE_WIDTH,
                           (direction,), 'memory_image'),
            FuzzableSource(IP_SOURCE_ID, GPIO_COMPONENT, GPIO_INPUT, 0,
                           SOURCE_WIDTH, (direction,), 'source'),
        )

    @staticmethod
    def _source_bindings():
        return SourceBindings((
            SourceBinding(CPU_SOURCE_ID, 'memory_image', CPU_COMPONENT,
                          PROGRAM_IMAGE, PADOUT_BYTE_BIT_OFFSET, SOURCE_WIDTH,
                          f'initial_image:{CPU_COMPONENT}:{PROGRAM_IMAGE}', 0),
            SourceBinding(IP_SOURCE_ID, 'source', GPIO_COMPONENT, GPIO_INPUT,
                          0, SOURCE_WIDTH, fixture.GPIO_SOURCE_ID),
        ))

    @staticmethod
    def _anchor_target(direction):
        if direction == 'CPU_TO_IP_TO_CPU':
            # The CPU consuming a real device answer is the closing observation
            # of the CPU-initiated round.
            return CoverageTarget('cpu.native_device_read_consumed',
                                  CPU_COMPONENT, 'data_rsp_consumed', 1, 1)
        # The device's own synchronized external pin word is the first real
        # downstream observation of the IP-injected byte.
        return CoverageTarget('gpio0.pin_sync_nonzero', GPIO_COMPONENT,
                              'gpio_in_sync', 0xff, 1)

    @classmethod
    def _targets(cls, direction):
        """The direction's search targets, each with an honest upstream source set.

        The three per-bit families are not interchangeable decoration: every
        observation is a function of exactly one declared side, and the
        dependency graph below declares that, so the guided hint really can
        choose between the CPU program byte and the external pin byte instead
        of driving one side forever.

        * ``gpio0.pin_sync_bit_*`` - the device's synchronized external pin
          word, a function of the external byte only;
        * ``gpio0.padout_pin_bit_*`` - the pin word after round 1, a function of
          the CPU's program byte only (round 1 always stores ``A``);
        * ``cpu.device_answer_bit_*`` - the PADIN read answer, a function of the
          external byte only.
        """
        return ((cls._anchor_target(direction),)
                + tuple(CoverageTarget(f'gpio0.pin_sync_bit_{bit}',
                                       GPIO_COMPONENT, 'gpio_in_sync',
                                       1 << bit, 1 << bit)
                        for bit in range(TARGET_BITS))
                + tuple(CoverageTarget(f'gpio0.padout_pin_bit_{bit}',
                                       GPIO_COMPONENT, 'gpio_out',
                                       1 << bit, 1 << bit)
                        for bit in range(TARGET_BITS))
                + tuple(CoverageTarget(f'cpu.device_answer_bit_{bit}',
                                       CPU_COMPONENT, 'data_rsp_rdata',
                                       1 << bit, 1 << bit)
                        for bit in range(TARGET_BITS)))

    @classmethod
    def _rules(cls, direction):
        """One dependency rule per target, naming that target's real producers."""
        rules = [DependencyRule(cls._anchor_target(direction).target_id,
                                (CPU_SOURCE_ID, IP_SOURCE_ID), 'DATA_BINDING')]
        rules.extend(DependencyRule(f'gpio0.pin_sync_bit_{bit}',
                                    (IP_SOURCE_ID,), 'DATA_BINDING')
                     for bit in range(TARGET_BITS))
        rules.extend(DependencyRule(f'gpio0.padout_pin_bit_{bit}',
                                    (CPU_SOURCE_ID,), 'DATA_BINDING')
                     for bit in range(TARGET_BITS))
        rules.extend(DependencyRule(f'cpu.device_answer_bit_{bit}',
                                    (IP_SOURCE_ID,), 'DATA_BINDING')
                     for bit in range(TARGET_BITS))
        return tuple(rules)

    @staticmethod
    def _program_image(seed):
        image = next((item for item in seed.initial_images
                      if item.image_id == PROGRAM_IMAGE
                      and item.component == CPU_COMPONENT), None)
        if image is None or image.address != 0:
            raise CampaignBlocked('native campaign program image differs')
        data = image.data
        if len(data) * 8 < PADOUT_BYTE_BIT_OFFSET + SOURCE_WIDTH:
            raise CampaignBlocked('native campaign program image is too short')
        return image, data

    @classmethod
    def _require_pinned_seed(cls, seed, direction, genome_path):
        """Pin the seed's own declared facts instead of trusting its name."""
        if seed.direction != direction:
            raise CampaignBlocked('native campaign seed direction mismatch')
        if (seed.max_steps, seed.quiesce_steps) != tuple(
                fixture.DIRECTION_SHAPES[direction]):
            raise CampaignBlocked('native campaign needs the pinned Genome shape')
        if seed.schedule_order != (CPU_COMPONENT, GPIO_COMPONENT):
            raise CampaignBlocked('native campaign schedule differs')
        image, data = cls._program_image(seed)
        if hashlib.sha256(data).hexdigest() != cls.PROGRAM_SHA256[direction]:
            raise CampaignBlocked('native campaign program image differs')
        word = int.from_bytes(
            data[4 * PADOUT_IMMEDIATE_INSTRUCTION:
                 4 * PADOUT_IMMEDIATE_INSTRUCTION + 4], 'little')
        immediate = (word >> 20) & 0xfff
        if (((word >> 15) & 0x1f) != 0 or ((word >> 7) & 0x1f) != 3
                or (word & 0x7f) != 0x13 or immediate != PADOUT_BYTE_SEED):
            raise CampaignBlocked('native campaign program seed instruction differs')
        if PADOUT_BYTE_BIT_OFFSET != 32 * PADOUT_IMMEDIATE_INSTRUCTION + 20:
            raise CampaignBlocked('native campaign CPU source offset differs')
        if len(seed.actions) != 1:
            raise CampaignBlocked('native campaign needs one pin action')
        action = seed.actions[0]
        if (action.component != GPIO_COMPONENT or action.port != GPIO_INPUT
                or action.bit_offset != 0 or action.width != SOURCE_WIDTH
                or action.value != GPIO_INPUT_SEED
                or action.direction != direction
                or action.delay_component != GPIO_COMPONENT
                or action.delay_ticks != 0):
            raise CampaignBlocked('native campaign pin action differs')
        if direction == 'CPU_TO_IP_TO_CPU':
            trigger = action.trigger
            if (trigger.kind != 'AFTER_OUTPUT'
                    or trigger.source_component != CPU_COMPONENT
                    or trigger.source_port != 'data_addr'
                    or trigger.mask != 0xffffffff
                    or trigger.value != GPIO_BASE + PADOUT
                    or trigger.occurrence != 1):
                raise CampaignBlocked('native campaign CPU-direction trigger differs')
        elif action.trigger.kind != 'START':
            raise CampaignBlocked('native campaign IP-direction trigger differs')
        return image

    def _fixture(self, direction: str, bound_manifest: Path | None = None):
        if direction not in ('CPU_TO_IP_TO_CPU', 'IP_TO_CPU_TO_IP'):
            raise CampaignBlocked(f'unsupported direction: {direction}')
        if bound_manifest is None:
            bound_manifest = ROOT / 'configs/scenario/pico_native_gpio_campaign_seed.json'
        bound_manifest = Path(bound_manifest)
        _require_pinned_bound_seed(bound_manifest, self.BOUND_SEED_SHAPE)
        genome_path = (bound_manifest if direction == 'CPU_TO_IP_TO_CPU' else
                       bound_manifest.parent / self.BOUND_REVERSE_SEED)
        if not genome_path.is_file():
            raise CampaignBlocked(f'seed genome is missing: {genome_path}')
        seed = GenomeCodec.decode(genome_path.read_bytes())
        self._require_pinned_seed(seed, direction, genome_path)
        targets = self._targets(direction)
        factory = self._factory()
        runner = factory()
        graph = DependencyGraph(sources=self._sources(direction),
                                rules=self._rules(direction))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=tuple(DecoderTemplate(target.target_id, seed)
                            for target in targets),
            source_bindings=self._source_bindings())
        return factory, decoder, targets, seed

    def _independent_fixture(self, direction: str, manifest: Path):
        """Two real RTL instances, no cross-component route, local CPU shadow.

        The CPU is the same real pinned PicoRV32 and the GPIO is the same real
        pinned PULP APB3 device, but the CPU's device window is answered by a
        declared local shadow register file, so no CPU observation can depend
        on the IP's RTL.  The gate requires this arm to claim zero causal
        chains.  The CPU is stepped in its stock inline mode here (the queued
        form is only claimed for the bound arm).
        """
        manifest = Path(manifest)
        if not manifest.is_file():
            raise CampaignBlocked('native independent baseline manifest is missing')
        try:
            document = json.loads(manifest.read_text(encoding='utf-8'))
        except (ValueError, UnicodeError) as exc:
            raise CampaignBlocked('native independent baseline is not JSON') from exc
        if (document.get('schema_version') != 'scenario_independent_baseline.v1'
                or document.get('local_response_model') != 'persistent_shadow_registers'
                or document.get('cross_component_bindings') != []
                or document.get('cpu_irq') != 'constant_zero'):
            raise CampaignBlocked('native independent baseline manifest is invalid')
        window = document.get('gpio_local_window', {})
        if (window.get('base') != GPIO_BASE or window.get('size') != GPIO_WINDOW):
            raise CampaignBlocked('native independent local window differs')
        if direction == 'CPU_TO_IP_TO_CPU':
            seed_name = document.get('cpu_seed')
            source = FuzzableSource(CPU_SOURCE_ID, CPU_COMPONENT, PROGRAM_IMAGE,
                                    PADOUT_BYTE_BIT_OFFSET, SOURCE_WIDTH,
                                    (direction,), 'memory_image')
            binding = SourceBinding(CPU_SOURCE_ID, 'memory_image', CPU_COMPONENT,
                                    PROGRAM_IMAGE, PADOUT_BYTE_BIT_OFFSET,
                                    SOURCE_WIDTH,
                                    f'initial_image:{CPU_COMPONENT}:{PROGRAM_IMAGE}', 0)
            targets = (CoverageTarget('cpu.local_device_read_consumed',
                                      CPU_COMPONENT, 'data_rsp_consumed', 1, 1),)
        elif direction == 'IP_TO_CPU_TO_IP':
            seed_name = document.get('reverse_seed')
            source = FuzzableSource(IP_SOURCE_ID, GPIO_COMPONENT, GPIO_INPUT, 0,
                                    SOURCE_WIDTH, (direction,), 'source')
            binding = SourceBinding(IP_SOURCE_ID, 'source', GPIO_COMPONENT,
                                    GPIO_INPUT, 0, SOURCE_WIDTH,
                                    fixture.GPIO_SOURCE_ID)
            targets = (CoverageTarget('gpio0.pin_sync_nonzero', GPIO_COMPONENT,
                                      'gpio_in_sync', 0xff, 1),)
        else:
            raise CampaignBlocked(f'unsupported direction: {direction}')
        target = targets[0]
        if (not isinstance(seed_name, str) or not seed_name
                or Path(seed_name).name != seed_name or seed_name in ('.', '..')):
            raise CampaignBlocked('native independent baseline seed path is invalid')
        genome_path = manifest.parent / seed_name
        if not genome_path.is_file():
            raise CampaignBlocked(f'independent seed genome is missing: {genome_path}')
        seed = GenomeCodec.decode(genome_path.read_bytes())
        self._require_pinned_seed(seed, direction, genome_path)

        class LocalRegisterModel:
            """Persistent per-testcase CPU response model, never an IP RTL view."""

            def __init__(self):
                self.words: dict[int, int] = {}

            def write_register(self, offset: int, value: int, *, be: int = 15):
                old = self.words.get(offset, 0)
                mask = sum(0xff << (8 * byte) for byte in range(4)
                           if be & (1 << byte))
                self.words[offset] = ((old & ~mask) | (value & mask)) & 0xffffffff

            def read_register(self, offset: int) -> int:
                return self.words.get(offset, 0)

        if self._independent_pair is None:
            cpu_artifact, gpio_artifact = native_gpio_artifacts(ROOT)
            shadow = LocalRegisterModel()
            self._independent_pair = fixture.PicoNativeGpioPair(
                cpu_artifact, gpio_artifact, base_dir=ROOT,
                cache_dir=self._build_cache,
                window_device='gpio0_local', window_target=lambda: shadow,
                reset_window_target=shadow.words.clear, defer_mmio=False,
                independent_baseline=True)
        pair = self._independent_pair
        factory = pair.runner
        runner = factory()
        graph = DependencyGraph(
            sources=(source,),
            rules=(DependencyRule(target.target_id, (source.source_id,),
                                  'BASELINE_GROUPING'),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=(DecoderTemplate(target.target_id, seed),),
            source_bindings=SourceBindings((binding,)))
        return factory, decoder, targets, seed

#: Files whose bytes must still be the bytes that produced a saved campaign.
#: The framework files are also covered by the campaign's own source identity;
#: the provider, the fixture, the frozen inputs, the local session transport and
#: the Rust client are recorded beside the run because the campaign framework
#: does not know about them.
CAMPAIGN_SOURCE_IDENTITY_SCHEMA = 'pico_native_campaign_source_identity.v1'
CAMPAIGN_SOURCES = (
    'src/myfuzz/integration/picorv32_native_scenario_campaign.py',
    'src/myfuzz/scenario/picorv32_native_cpu_example.py',
    'src/myfuzz/local_harness/native_session.py',
    'src/myfuzz/local_harness/gpio_session.py',
    'src/myfuzz/local_harness/pulp_gpio_probe_contract.py',
    'src/myfuzz/local_harness/session.py',
    'src/myfuzz/integration/scenario_campaign.py',
    'src/myfuzz/integration/scenario_rfuzz.py',
    'src/myfuzz/integration/scenario_rfuzz_live.py',
    'src/myfuzz/integration/scenario_rfuzz_replay.py',
    'scripts/run_scenario_campaign.py',
    'third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz',
    'configs/scenario/pico_native_gpio_campaign_seed.json',
    'configs/scenario/pico_native_gpio_reverse_seed.json',
    'configs/scenario/pico_native_gpio_independent_ip_seed.json',
    'configs/scenario/pico_native_gpio_campaign_baseline.json',
)


def record_campaign_source_identity(run_dir: Path, *, base_dir: Path = ROOT):
    """Record the provider/fixture/input/client bytes a saved run must still match.

    The campaign framework's own source identity does not include this row's
    provider or fixture, so the audit test re-hashes the values written here.
    This is a *record of what produced the run*, not a claim that the run
    passed: ``gate_status`` is copied verbatim from the saved report.
    """
    run_dir = Path(run_dir)
    report = json.loads((run_dir / 'campaign_report.json').read_text(encoding='utf-8'))
    if report.get('schema_version') != 'scenario_campaign.v1':
        raise CampaignBlocked('saved directory is not a scenario campaign')
    sources = {}
    for relative in CAMPAIGN_SOURCES:
        path = Path(base_dir) / relative
        if not path.is_file():
            raise CampaignBlocked(f'campaign source is missing: {relative}')
        sources[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    document = {
        'schema_version': CAMPAIGN_SOURCE_IDENTITY_SCHEMA,
        'campaign_run_identity_sha256': report.get('campaign_run_identity_sha256'),
        'gate_status': report.get('gate_status'),
        'sources': sources,
    }
    (run_dir / 'pico_native_campaign_source_identity.json').write_text(
        json.dumps(document, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    return document


def _write_campaign_evidence(run_dir: Path, document) -> None:
    """Write a self-describing run record with only recomputable counts."""
    run_dir = Path(run_dir)
    report = json.loads((run_dir / 'campaign_report.json').read_text(encoding='utf-8'))
    cells = report.get('cells', [])
    complete = sum(cell.get('status') == 'complete' for cell in cells)
    requested = sorted({cell.get('requested_seconds') for cell in cells})
    seeds = sorted({cell.get('seed') for cell in cells})
    seconds = requested[0] if len(requested) == 1 else requested
    first_seed = seeds[0] if seeds else 0
    lines = [
        '# P6 row 5 (PicoRV32 native x PULP APB3 GPIO) campaign run record',
        '',
        'This file is written from the saved `campaign_report.json`; it repeats',
        'only fields that file contains. The independent audit recomputes every',
        'count, verdict and identity from the per-cell artifacts:',
        '',
        '```',
        'PYTHONPATH=src python3 -m pytest \\',
        '    tests/integration/test_picorv32_native_campaign_saved_run_audit.py -q',
        '```',
        '',
        '## Status',
        '',
        f"* `gate_status`: `{report.get('gate_status')}`",
        f"* cells complete: {complete}/{len(cells)}",
        f"* `effective_search_seconds`: {report.get('effective_search_seconds')}",
        f"* `campaign_run_identity_sha256`: `{report.get('campaign_run_identity_sha256')}`",
        '* provider/fixture/input/client identity: `pico_native_campaign_source_identity.json`',
        '',
        '## What it is',
        '',
        '18 G4 cells (3 strategies x 2 directions x 3 seeds) over the pinned',
        'PicoRV32 native ready/valid memory CPU and the pinned PULP APB3 GPIO.',
        'Bound cells route the CPU device window to the real GPIO with queued',
        '`DataflowRouter.enqueue` delivery on the device\'s own step; independent',
        'cells answer the same window from a declared local shadow and claim no',
        'cross-component chain. Both directions declare the CPU program immediate',
        'and the external GPIO pin byte. Each direction runs two ordered rounds',
        'and commits `A ^ B` and `(A ^ B) + B` to RAM.',
        '',
        '## What it does not prove',
        '',
        '* No IRQ/handler path: the pinned native profile has no interrupt',
        '  endpoint and `ENABLE_IRQ=0`; nothing is synthesised.',
        '* No cross-case persistent RTL or RAM state: the campaign uses fresh',
        '  genomes, so each case starts both harnesses and rebuilds RAM from the',
        '  genome images. Cases share the search, decoder, corpus and feedback.',
        '* No controlled-error inspection: this bundle injects no fault.',
        '* The dependency-guided hint is not a proof that every source was',
        '  *known* to be productive in advance; the receipts record selection and',
        '  trace-proven consumption, which is what the audit checks.',
        '',
        '## How it was produced',
        '',
        '```',
        'PYTHONPATH=src python3 scripts/run_scenario_campaign.py \\',
        '    --manifest configs/scenario/pico_native_gpio_campaign_seed.json \\',
        '    --baseline-manifest configs/scenario/pico_native_gpio_campaign_baseline.json \\',
        f'    --seconds {seconds} --seed {first_seed} \\',
        f"    --output {run_dir} \\",
        '    --provider myfuzz.integration.picorv32_native_scenario_campaign:PicoNativeGpioBoundProvider',
        'PYTHONPATH=src python3 -m myfuzz.integration.picorv32_native_scenario_campaign \\',
        f'    {run_dir}',
        '```',
        '',
    ]
    (run_dir / 'CAMPAIGN_EVIDENCE.md').write_text('\n'.join(lines), encoding='utf-8')


def _main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description='Record a saved PicoRV32 native campaign source identity')
    parser.add_argument('run_dir', type=Path)
    parser.add_argument('--base-dir', type=Path, default=ROOT)
    args = parser.parse_args(argv)
    document = record_campaign_source_identity(args.run_dir, base_dir=args.base_dir)
    _write_campaign_evidence(args.run_dir, document)
    print(json.dumps({'gate_status': document['gate_status'],
                      'sources': len(document['sources']),
                      'run_dir': str(args.run_dir)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(_main())
