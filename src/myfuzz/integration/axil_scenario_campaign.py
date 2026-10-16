"""PicoRV32 AXI4-Lite CPU x ZipCPU AXI4-Lite UART campaign fixtures and checker.

This is the P6 row-3 (AXI4-Lite) counterpart of
``myfuzz.integration.cva6_scenario_campaign``: three search strategies over one
real CPU + one real IP, a two-sided fixture whose declared sources come from
the admitted artifacts, and one independently assessed closed chain per
direction.

Why this IP target
------------------
The row's accepted pair is the pinned ``picorv32_axi`` AXI4-Lite CPU and the
pinned ZipCPU ``axiluart`` AXI4-Lite slave, and
``tests/integration/test_axil_cpu_generic_ip_chain_real.py`` already shows both
halves running together through the component-neutral register member.  The
UART is the only AXI4-Lite target in this repository whose profile also
declares a *serial* peer contract, which is what makes a genuine two-sided
closed loop possible: the CPU's MMIO write to TXREG can be observed as a byte
decoded off a real output pin, and a declared frame source can put a byte into
the device's RX FIFO for the CPU to read back.  Nothing in this module names a
register, a pin or a baud rate that the profiles do not declare; the fixture's
constants are re-exported from ``myfuzz.scenario.axil_uart_cpu_example``, which
derives them from ``configs/peripherals/zipcpu_axiluart/component_profile.json``
and ``configs/cpus/picorv32_axi/component_profile.json``.

What the two directions mean here
---------------------------------
* ``CPU_TO_IP_TO_CPU`` - the CPU initiates: the fuzzer's program immediate is
  written to TXREG, the declared 8N1 peer decodes that byte off the real TX
  pin, the declared frame source answers on the real RX pin, the CPU reads the
  device's own RXREG answer, consumes it and commits ``tx_byte ^ rx_byte`` to
  RAM.  The mutation sources are the CPU program image bit range and the frame
  byte: both are genuine joint prerequisites of the committed value.
* ``IP_TO_CPU_TO_IP`` - the IP initiates: the declared frame source drives the
  RX pin at case start (a ``START`` trigger, so the injection precedes every
  CPU access), the CPU reads and commits ``tx_byte ^ rx_byte``, and finally
  pushes that value back into TXREG where the declared peer decodes it off the
  real pin again.

Both directions declare both sides' sources, and the assessment's ordering
constraint is exactly the direction's claim: who observed first.

Honesty notes
-------------
* One round per case.  The peer member accepts one frame per case and refuses a
  byte change while a frame is in flight, so this fixture drives exactly one
  ordered round per case.  ``rounds`` is therefore 0 or 1, and a credited
  round means every stage below was observed with its own event identity.
* A credited wire byte is only credited when the peer's own ``serial_tx_count``
  advanced by exactly one since the previous observation, so a byte that cannot
  be attributed to one decode is never used as evidence.
* The checker never derives a DUT output from a schedule: every stage is an
  observation copied out of the runner's event stream.
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
from myfuzz.scenario.genome import GenomeCodec, Trigger
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder

from .scenario_campaign import (CampaignBlocked, IbexTwoGpioBoundProvider,
                                ReplayEvidence, _campaign_budgeted_factory,
                                _replay_saved_failure_trace,
                                _require_pinned_bound_seed)

from myfuzz.scenario import axil_uart_cpu_example as fixture
from myfuzz.scenario.axil_uart_cpu_example import (
    CPU_COMPONENT, PROGRAM_IMAGE, RAM_BASE, RAM_SIZE, RESULT_ADDRESS,
    RX_FRAME_SEED, TX_IMMEDIATE_BIT_OFFSET, TX_IMMEDIATE_SEED,
    TX_IMMEDIATE_WIDTH, UART_BASE, UART_COMPONENT, UART_DEVICE,
    UART_RX_INPUT, UART_RX_INTERRUPT_PORT, UART_RX_OFFSET, UART_RX_SOURCE_ID,
    UART_TX_OFFSET, UART_WINDOW, axil_artifacts, axil_uart_ownership,
    make_axil_uart_cpu_runner)

ROOT = Path(__file__).resolve().parents[3]

#: The CPU's own view of the byte it transmitted, as the generated memory
#: session reports it: the address presented on the beat that accepts the store.
TX_BEAT_OUTPUT = 'data_addr'
#: What the CPU presents as store data on that beat, and what it consumes as a
#: read answer.  Both are declared physical observations of the generated
#: memory session, so a search target may key on them.
TX_STORE_DATA_PORT = 'data_wdata'
RX_ANSWER_PORT = 'data_rsp_rdata'
#: One search target per bit of the byte the CPU presents to its memory
#: system: the byte it stores to the device's TX register and the round-trip
#: byte it commits to RAM, which is a function of both declared sources.  A
#: single target that the seed case already satisfies would leave the RFuzz
#: corpus at the seed forever, because the client only saves an input that
#: produces coverage the run has not seen; one target per bit lets a mutated
#: genome newly satisfy a target, so those inputs enter the corpus the campaign
#: claims to replay.
TARGET_BITS = 8
#: The two declared fuzzable sources of this fixture, named once.
CPU_SOURCE_ID = 'cpu.tx_byte'
IP_SOURCE_ID = 'uart0.rx_frame'


def _transaction_identity(event: Mapping) -> tuple:
    transaction = event.get('source_transaction', event.get('transaction', {}))
    if not isinstance(transaction, Mapping):
        return ()
    return tuple(transaction.get(key) for key in (
        'execution_id', 'testcase_id', 'source_component', 'source_epoch',
        'channel_id', 'source_sequence'))


def _is_mmio(event: Mapping, *, offset: int, write: bool) -> bool:
    return (event.get('kind') == 'mmio_delivery'
            and event.get('device_id') == UART_DEVICE
            and event.get('offset') == offset
            and event.get('write') is write)


def _attributed_tx_decodes(stream) -> tuple[tuple[int, int], ...]:
    """(event_id, byte) for every TX byte attributed to exactly one decode.

    The declared peer reports ``serial_tx_count``/``serial_tx_last`` on every
    session step.  A byte is credited only when the count advanced by exactly
    one since the previous observation and the reported last byte is a byte, so
    a burst that cannot be attributed to one decode never becomes evidence.
    """
    credited: list[tuple[int, int]] = []
    previous = 0
    for event in stream:
        outputs = event.get('outputs')
        if not isinstance(outputs, Mapping):
            continue
        count = outputs.get('serial_tx_count')
        last = outputs.get('serial_tx_last')
        if type(count) is not int or type(last) is not int:
            continue
        if count == previous + 1 and 0 <= last < 256:
            credited.append((event.get('event_id'), last))
        previous = max(previous, count)
    return tuple(credited)


def _find(stream, after: int, predicate):
    return next((event for event in stream
                 if type(event.get('event_id')) is int
                 and event['event_id'] > after and predicate(event)), None)


def _rx_interrupt(event: Mapping, value: int) -> bool:
    return (event.get('kind') == 'local_tick_sample'
            and event.get('component') == UART_COMPONENT
            and event.get('outputs', {}).get(UART_RX_INTERRUPT_PORT) == value)


def assess_axil_closed_chain(direction: str, events, final_state: Mapping) -> dict | None:
    """One ordered round over the real AXI4-Lite port and the real serial pins.

    Every stage is copied out of the runner's event stream; nothing is derived
    from a schedule.  The direction decides *who initiated*, and the walk
    enforces exactly that ordering:

    * ``CPU_TO_IP_TO_CPU`` - the CPU's real MMIO store to TXREG is observed
      first, then the declared frame source answers.
    * ``IP_TO_CPU_TO_IP`` - the declared frame source drives the RX pin before
      any CPU MMIO access, and the CPU's own byte follows it.

    Both directions then demand the same closing evidence: the device's own
    RX-ready output asserted, the CPU's RXREG read equal to the frame byte, the
    CPU consuming exactly that answer, the joint value ``tx_byte ^ rx_byte``
    committed to RAM, the RX-ready output returning low, and the CPU's own
    transmitted byte decoded off the real TX pin by the declared peer.  The
    committed value is therefore an observed joint function of both declared
    upstream sources, and each of them is a genuine prerequisite of an observed
    effect.

    What this deliberately does not claim: a second round trip carrying the
    committed value back into the device's TX register.  The pinned device
    transmits one byte per ten bit times and a case's step budget is bounded,
    so this fixture drives exactly one ordered round per case.
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

    decodes = _attributed_tx_decodes(stream)
    injections = [event for event in stream
                  if event.get('kind') == 'source_injection'
                  and event.get('component') == UART_COMPONENT
                  and event.get('port') == UART_RX_INPUT]
    writes = [event for event in stream
              if _is_mmio(event, offset=UART_TX_OFFSET, write=True)
              and type(event.get('write_value')) is int
              and 0 < event['write_value'] < 256]
    reads = [event for event in stream
             if _is_mmio(event, offset=UART_RX_OFFSET, write=False)]
    if len(injections) != 1:
        findings.append('rx_frame_injection_not_unique')
    if not writes:
        findings.append('cpu_tx_write_missing')
    if not reads:
        findings.append('cpu_rx_read_missing')
    if findings:
        return {'complete': False, 'rounds': 0, 'findings': findings}

    injection = injections[0]
    frame_byte = injection.get('value')
    if type(frame_byte) is not int or not 0 <= frame_byte < 256:
        findings.append('rx_frame_byte_invalid')
        return {'complete': False, 'rounds': 0, 'findings': findings}

    def decoded(after: int, byte: int, *, label: str) -> None:
        if not any(value == byte and event_id > after
                   for event_id, value in decodes):
            findings.append(label)

    def step(after: int, predicate, *, label: str):
        event = _find(stream, after, predicate)
        if event is None:
            findings.append(label)
        return event

    # --- ordered stages: exactly the direction's own causal claim ----------
    if direction == 'CPU_TO_IP_TO_CPU':
        tx_write = writes[0]
        cursor = tx_write['event_id']
        if injection['event_id'] < cursor:
            findings.append('cpu_did_not_initiate')
    else:
        cursor = injection['event_id']
        tx_write = next((event for event in writes
                         if event['event_id'] > cursor), None)
        if tx_write is None:
            # A write exists but it preceded the frame the IP drove, so the CPU
            # did not answer this round's frame: that is the direction's own
            # claim failing, not a missing observation.
            findings.append('ip_did_not_initiate' if writes
                            else 'cpu_tx_write_missing')
            return {'complete': False, 'rounds': 0, 'findings': findings}

    ready = step(cursor, lambda candidate: _rx_interrupt(candidate, 1),
                 label='ip_rx_ready_missing')
    if ready is None:
        return {'complete': False, 'rounds': 0, 'findings': findings}
    tx_byte = tx_write['write_value']
    decoded(tx_write['event_id'], tx_byte, label='cpu_tx_wire_decode_missing')

    read = step(max(ready['event_id'], tx_write['event_id']),
                lambda candidate: _is_mmio(candidate, offset=UART_RX_OFFSET,
                                           write=False)
                and candidate.get('read_value') == frame_byte,
                label='cpu_rx_read_value_mismatch')
    if read is None:
        return {'complete': False, 'rounds': 0, 'findings': findings}

    transaction = read.get('source_transaction', {})
    consume = step(read['event_id'], lambda candidate:
                   candidate.get('component') == CPU_COMPONENT
                   and candidate.get('outputs', {}).get('data_rsp_consumed') == 1
                   and candidate['outputs'].get('data_rsp_rdata') == frame_byte
                   and candidate['outputs'].get('data_rsp_source_epoch')
                   == transaction.get('source_epoch')
                   and candidate['outputs'].get('data_rsp_source_sequence')
                   == transaction.get('source_sequence'),
                   label='cpu_consume_rdata_missing')
    if consume is None:
        return {'complete': False, 'rounds': 0, 'findings': findings}

    committed = tx_byte ^ frame_byte
    ram = step(consume['event_id'], lambda candidate:
               candidate.get('kind') == 'memory_write'
               and candidate.get('component') == CPU_COMPONENT
               and candidate.get('address') == RESULT_ADDRESS
               and candidate.get('value') == committed,
               label='cpu_ram_commit_missing')
    if ram is None:
        return {'complete': False, 'rounds': 0, 'findings': findings}
    if _find(stream, read['event_id'],
             lambda candidate: _rx_interrupt(candidate, 0)) is None:
        findings.append('ip_rx_fifo_not_drained')

    # A replayed transaction identity would mean the router reused a cached
    # delivery instead of performing a second real access.
    used: set[tuple] = set()
    for event, label in ((tx_write, 'cpu_tx_write'), (read, 'cpu_rx_read'),
                         (ram, 'cpu_ram_commit')):
        identity = _transaction_identity(event)
        if not identity or any(item is None for item in identity):
            findings.append(label + '_transaction_identity_missing')
        elif identity in used:
            findings.append(label + '_transaction_reused')
        used.add(identity)

    inputs = final_state.get('inputs', {})
    if not isinstance(inputs, Mapping) \
            or inputs.get(UART_COMPONENT, {}).get(UART_RX_INPUT) != frame_byte:
        findings.append('rx_frame_input_state_mismatch')
    pending = final_state.get('pending_responses', {})
    if not isinstance(pending, Mapping) \
            or any(value != 0 for value in pending.values()):
        findings.append('pending_responses_at_end')

    return {'complete': not findings, 'rounds': 0 if findings else 1,
            'findings': findings, 'cpu_tx_byte': tx_byte,
            'rx_frame_byte': frame_byte, 'committed_value': committed}


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
    The framework's replay invariants (``scenario_campaign._validated_replay``)
    bound the reported failure count by the number of replayed corpus entries,
    so the counts reported to the gate are taken over the corpus-covered
    subset.  The caller re-executes *every* saved failure trace and reports a
    mismatch for any of them that does not replay identically, so the extra
    ones are verified rather than dropped.

    ``replayed`` is a sequence of ``(raw_sha256, matched)`` pairs.
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


class AxilUartCpuBoundProvider(IbexTwoGpioBoundProvider):
    """Three strategies over one real AXI4-Lite CPU and one real AXI4-Lite IP."""

    BOUND_REVERSE_SEED = 'axil_picorv32_uart_reverse_seed.json'

    #: Pinned shape of this provider's CPU-direction seed genome.
    BOUND_SEED_SHAPE = fixture.BOUND_SEED_SHAPE

    #: Every direction pins the sha256 of the program image its seed declares.
    PROGRAM_SHA256 = {direction: fixture.program_digest(direction)
                      for direction in ('CPU_TO_IP_TO_CPU', 'IP_TO_CPU_TO_IP')}

    def __init__(self, client_binary: Path | None = None) -> None:
        super().__init__(client_binary)
        #: One Verilator build cache for every cell of one campaign: the local
        #: harness is admitted once and then reused by identity.
        self._build_cache = Path(tempfile.mkdtemp(prefix='myfuzz-axil-campaign-'))
        self._bound_pair: fixture.AxilUartCpuPair | None = None
        self._independent_pair: fixture.AxilUartCpuPair | None = None

    def _pair(self) -> fixture.AxilUartCpuPair:
        """The one admitted CPU+IP pair every cell of this provider reuses."""
        if self._bound_pair is None:
            cpu_artifact, uart_artifact = axil_artifacts(ROOT)
            self._bound_pair = fixture.AxilUartCpuPair(
                cpu_artifact, uart_artifact, base_dir=ROOT,
                cache_dir=self._build_cache)
        return self._bound_pair

    def _factory(self):
        pair = self._pair()
        return pair.runner

    def search(self, cell, output, manifest):
        """Reuse the code-owned host closure across every cell of the campaign.

        Discovering the Python import closure is a full AST walk; rewriting it
        for every testcase would put a multi-second build-admission cost inside
        the campaign's per-testcase wall budget.  The scope reuses the
        discovered *paths* only: every byte is re-read and compared, so a
        changed host source still refuses admission.
        """
        from myfuzz.local_harness.build import host_source_discovery_scope

        with host_source_discovery_scope():
            return super().search(cell, output, manifest)

    def replay(self, cell, output, manifest):
        """Replay the whole saved corpus and every saved failure trace.

        Two accounting facts differ from the inherited implementation:

        * the corpus is what the framework replays, so the failure counts the
          gate checks are reported over the failure traces *inside* it;
        * every other saved failure trace is still re-executed and compared,
          and a difference in any of them is reported as the replay error.
        """
        from myfuzz.local_harness.build import host_source_discovery_scope

        with host_source_discovery_scope():
            return self._replay(cell, output, manifest)

    def _replay(self, cell, output, manifest) -> ReplayEvidence:
        from myfuzz.integration.scenario_rfuzz_replay import (
            replay_scenario_rfuzz_corpus)
        from myfuzz.scenario.genome import GenomeCodec
        from .scenario_campaign import _replay_saved_failure_trace

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
        return ReplayEvidence(
            total_entries=result.total_entries,
            matched_entries=result.matched_entries,
            failure_entries=accounting['covered_failure_entries'],
            matched_failure_entries=accounting['covered_matched_failure_entries'],
            error='; '.join(mismatches) if mismatches else None)

    @staticmethod
    def _assess_trace_chain(direction, events, final_state):
        return assess_axil_closed_chain(direction, events, final_state)

    def _sources(self, direction):
        """Both sides' declared sources, on the profile's own facts."""
        return (
            FuzzableSource(CPU_SOURCE_ID, CPU_COMPONENT, PROGRAM_IMAGE,
                           TX_IMMEDIATE_BIT_OFFSET, TX_IMMEDIATE_WIDTH,
                           (direction,), 'memory_image'),
            FuzzableSource(IP_SOURCE_ID, UART_COMPONENT, UART_RX_INPUT, 0, 8,
                           (direction,), 'source'),
        )

    @staticmethod
    def _source_bindings():
        return SourceBindings((
            SourceBinding(CPU_SOURCE_ID, 'memory_image', CPU_COMPONENT,
                          PROGRAM_IMAGE, TX_IMMEDIATE_BIT_OFFSET,
                          TX_IMMEDIATE_WIDTH,
                          f'initial_image:{CPU_COMPONENT}:{PROGRAM_IMAGE}', 0),
            SourceBinding(IP_SOURCE_ID, 'source', UART_COMPONENT, UART_RX_INPUT,
                          0, 8, UART_RX_SOURCE_ID),
        ))

    @staticmethod
    def _anchor_target(direction):
        if direction == 'CPU_TO_IP_TO_CPU':
            # The device's own RX-ready interrupt: it asserts only after the
            # real RTL sampled a complete frame off the RX pin.
            return CoverageTarget('uart0.rx_fifo_nonempty', UART_COMPONENT,
                                  UART_RX_INTERRUPT_PORT, 1, 1)
        # The CPU consuming a device response is the closing observation of the
        # IP-initiated round.
        return CoverageTarget('cpu.axil_roundtrip_consumed', CPU_COMPONENT,
                              'data_rsp_consumed', 1, 1)

    @classmethod
    def _targets(cls, direction):
        """The direction's search targets: its anchor plus one per source bit.

        The first target anchors the dependency graph and the decoder template;
        the bit targets are the ones a mutated genome can newly satisfy, so the
        RFuzz client admits the mutated inputs to its corpus instead of keeping
        only the seed.
        """
        return (cls._anchor_target(direction),) + tuple(
            CoverageTarget(f'cpu.store_byte_bit_{bit}', CPU_COMPONENT,
                           TX_STORE_DATA_PORT, 1 << bit, 1 << bit)
            for bit in range(TARGET_BITS))

    @staticmethod
    def _program_image(seed):
        image = next((item for item in seed.initial_images
                      if item.image_id == PROGRAM_IMAGE
                      and item.component == CPU_COMPONENT), None)
        if image is None or image.address != 0:
            raise CampaignBlocked('AXI4-Lite campaign program image differs')
        data = image.data
        if len(data) * 8 < TX_IMMEDIATE_BIT_OFFSET + TX_IMMEDIATE_WIDTH:
            raise CampaignBlocked('AXI4-Lite campaign program image is too short')
        return image, data

    @classmethod
    def _require_pinned_seed(cls, seed, direction, genome_path):
        """Pin the seed's own declared facts instead of trusting its name."""
        if seed.direction != direction:
            raise CampaignBlocked('AXI4-Lite campaign seed direction mismatch')
        if (seed.max_steps, seed.quiesce_steps) != tuple(
                fixture.DIRECTION_SHAPES[direction]):
            raise CampaignBlocked('AXI4-Lite campaign needs the pinned Genome shape')
        if seed.schedule_order != (CPU_COMPONENT, UART_COMPONENT):
            raise CampaignBlocked('AXI4-Lite campaign schedule differs')
        image, data = cls._program_image(seed)
        if hashlib.sha256(data).hexdigest() != cls.PROGRAM_SHA256[direction]:
            raise CampaignBlocked('AXI4-Lite campaign program image differs')
        word = int.from_bytes(
            data[4 * fixture.TX_IMMEDIATE_INSTRUCTION:
                 4 * fixture.TX_IMMEDIATE_INSTRUCTION + 4], 'little')
        immediate = (word >> 20) & 0xfff
        if ((word >> 15) & 0x1f) != 0 or ((word >> 7) & 0x1f) != 2 \
                or (word & 0x7f) != 0x13 or immediate != TX_IMMEDIATE_SEED:
            raise CampaignBlocked('AXI4-Lite campaign program seed instruction differs')
        divisor = int.from_bytes(data[4:8], 'little')
        if ((divisor >> 20) & 0xfff) != fixture.SETUP_DIVISOR:
            raise CampaignBlocked('AXI4-Lite campaign setup divisor differs')
        if len(seed.actions) != 1:
            raise CampaignBlocked('AXI4-Lite campaign needs one frame action')
        action = seed.actions[0]
        if (action.component != UART_COMPONENT or action.port != UART_RX_INPUT
                or action.bit_offset != 0 or action.width != 8
                or action.value != RX_FRAME_SEED
                or action.direction != direction
                or action.delay_component != UART_COMPONENT
                or action.delay_ticks != 0):
            raise CampaignBlocked('AXI4-Lite campaign frame action differs')
        if direction == 'CPU_TO_IP_TO_CPU':
            trigger = action.trigger
            if (trigger.kind != 'AFTER_OUTPUT'
                    or trigger.source_component != CPU_COMPONENT
                    or trigger.source_port != TX_BEAT_OUTPUT
                    or trigger.mask != 0xffffffff
                    or trigger.value != UART_BASE + UART_TX_OFFSET
                    or trigger.occurrence != 1):
                raise CampaignBlocked('AXI4-Lite campaign CPU-direction trigger differs')
        elif action.trigger.kind != 'START':
            raise CampaignBlocked('AXI4-Lite campaign IP-direction trigger differs')
        return image

    def _fixture(self, direction: str, bound_manifest: Path | None = None):
        if direction not in ('CPU_TO_IP_TO_CPU', 'IP_TO_CPU_TO_IP'):
            raise CampaignBlocked(f'unsupported direction: {direction}')
        if bound_manifest is None:
            bound_manifest = ROOT / 'configs/scenario/axil_picorv32_uart_campaign_seed.json'
        bound_manifest = Path(bound_manifest)
        _require_pinned_bound_seed(bound_manifest, self.BOUND_SEED_SHAPE)
        genome_path = (bound_manifest if direction == 'CPU_TO_IP_TO_CPU' else
                       bound_manifest.parent / self.BOUND_REVERSE_SEED)
        if not genome_path.is_file():
            raise CampaignBlocked(f'seed genome is missing: {genome_path}')
        seed = GenomeCodec.decode(genome_path.read_bytes())
        self._require_pinned_seed(seed, direction, genome_path)
        targets = self._targets(direction)
        target = targets[0]
        factory = self._factory()
        runner = factory()
        graph = DependencyGraph(
            sources=self._sources(direction),
            rules=(DependencyRule(target.target_id,
                                  (CPU_SOURCE_ID, IP_SOURCE_ID), 'DATA_BINDING'),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=(DecoderTemplate(target.target_id, seed),),
            source_bindings=self._source_bindings())
        return factory, decoder, targets, seed

    def _independent_fixture(self, direction: str, manifest: Path):
        """Two real RTL instances, no cross-component route, local CPU shadow.

        The CPU is the same real pinned PicoRV32 and the UART is the same real
        pinned axiluart, but the CPU's MMIO window is answered by a declared
        local shadow register file, so no CPU observation can depend on the
        IP's RTL.  The gate requires this arm to claim zero causal chains.
        """
        manifest = Path(manifest)
        if not manifest.is_file():
            raise CampaignBlocked('AXI4-Lite independent baseline manifest is missing')
        try:
            document = json.loads(manifest.read_text(encoding='utf-8'))
        except (ValueError, UnicodeError) as exc:
            raise CampaignBlocked('AXI4-Lite independent baseline is not JSON') from exc
        if (document.get('schema_version') != 'scenario_independent_baseline.v1'
                or document.get('local_response_model') != 'persistent_shadow_registers'
                or document.get('cross_component_bindings') != []
                or document.get('cpu_irq') != 'constant_zero'):
            raise CampaignBlocked('AXI4-Lite independent baseline manifest is invalid')
        window = document.get('uart_local_window', {})
        if (window.get('base') != UART_BASE or window.get('size') != UART_WINDOW):
            raise CampaignBlocked('AXI4-Lite independent local window differs')
        if direction == 'CPU_TO_IP_TO_CPU':
            seed_name = document.get('cpu_seed')
            source = FuzzableSource(CPU_SOURCE_ID, CPU_COMPONENT, PROGRAM_IMAGE,
                                    TX_IMMEDIATE_BIT_OFFSET, TX_IMMEDIATE_WIDTH,
                                    (direction,), 'memory_image')
            binding = SourceBinding(CPU_SOURCE_ID, 'memory_image', CPU_COMPONENT,
                                    PROGRAM_IMAGE, TX_IMMEDIATE_BIT_OFFSET,
                                    TX_IMMEDIATE_WIDTH,
                                    f'initial_image:{CPU_COMPONENT}:{PROGRAM_IMAGE}', 0)
            targets = (CoverageTarget('cpu.axil_local_response', CPU_COMPONENT,
                                      'data_rsp_consumed', 1, 1),) + tuple(
                CoverageTarget(f'cpu.store_byte_bit_{bit}', CPU_COMPONENT,
                               TX_STORE_DATA_PORT, 1 << bit, 1 << bit)
                for bit in range(TARGET_BITS))
        elif direction == 'IP_TO_CPU_TO_IP':
            seed_name = document.get('reverse_seed')
            source = FuzzableSource(IP_SOURCE_ID, UART_COMPONENT, UART_RX_INPUT,
                                    0, 8, (direction,), 'source')
            binding = SourceBinding(IP_SOURCE_ID, 'source', UART_COMPONENT,
                                    UART_RX_INPUT, 0, 8, UART_RX_SOURCE_ID)
            targets = (CoverageTarget('uart0.rx_fifo_nonempty', UART_COMPONENT,
                                      UART_RX_INTERRUPT_PORT, 1, 1),) + tuple(
                CoverageTarget(f'cpu.store_byte_bit_{bit}', CPU_COMPONENT,
                               TX_STORE_DATA_PORT, 1 << bit, 1 << bit)
                for bit in range(TARGET_BITS))
        else:
            raise CampaignBlocked(f'unsupported direction: {direction}')
        target = targets[0]
        if (not isinstance(seed_name, str) or not seed_name
                or Path(seed_name).name != seed_name or seed_name in ('.', '..')):
            raise CampaignBlocked('AXI4-Lite independent baseline seed path is invalid')
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
            cpu_artifact, uart_artifact = axil_artifacts(ROOT)
            shadow = LocalRegisterModel()
            self._independent_pair = fixture.AxilUartCpuPair(
                cpu_artifact, uart_artifact, base_dir=ROOT,
                cache_dir=self._build_cache,
                window_device='uart0_local', window_target=lambda: shadow,
                reset_window_target=shadow.words.clear,
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
