"""The P6 row-3 (AXI4-Lite) campaign fixture, provider guards and chain checker.

``docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md`` row 3
records two gaps for the PicoRV32 AXI4-Lite CPU plus ZipCPU AXI4-Lite UART row.
The first - "no combination of a real AXI4-Lite CPU adapter and a real
AXI4-Lite IP target" - is already closed by
``tests/integration/test_axil_cpu_generic_ip_chain_real.py``; the second is the
continuous multi-case campaign.  This file pins the pieces that make the
campaign honest, at three levels.

**The checker.**  ``assess_axil_closed_chain`` is exercised against synthetic
event streams: one canonical complete round per direction, and one tampered
copy per required stage.  A checker that cannot fail is not a checker, so
every tamper asserts the *specific* finding it must produce.

**The program.**  The image the fuzzer mutates is assembled here from an
explicit RV32I encoder rather than copied from a blob, and the mutable bit
range is asserted to be exactly the low byte of one ``addi`` immediate, so a
mutation can change the transmitted byte and nothing else.

**The peer member's drained-sample defect.**  The declared 8N1 peer keeps a
monotonic cursor into its own sample deque and ``ScenarioRunner`` drains that
deque after every step.  Under a runner the stock member therefore never feeds
the transmitted byte to its decoder, and - once reply sizes vary - feeds it
ticks with holes and raises ``invalid observed UART 8N1 frame``.  The first
test below pins that behaviour as a *defect* (it fails, loudly, if someone
fixes the stock member and forgets to remove the fixture's workaround), and
the second pins the fixture's behaviour under the same drain.

Real-RTL tests build the pinned harnesses through Verilator; they are the same
two artifacts the campaign uses.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from myfuzz.integration import axil_scenario_campaign
from myfuzz.integration.axil_scenario_campaign import (
    AxilUartCpuBoundProvider, assess_axil_closed_chain,
    corpus_failure_accounting)
from myfuzz.integration.scenario_campaign import (CampaignBlocked,
                                                  _validated_replay)
from myfuzz.integration.scenario_campaign import ReplayEvidence
from myfuzz.scenario import axil_uart_cpu_example as fixture
from myfuzz.scenario import axil_uart_cpu_example
from myfuzz.scenario.genome import GenomeCodec, MemoryImage
from myfuzz.scenario.replay import record_scenario

ROOT = Path(__file__).resolve().parents[2]
BOUND_MANIFEST = ROOT / 'configs/scenario/axil_picorv32_uart_campaign_seed.json'
BASELINE_MANIFEST = ROOT / 'configs/scenario/axil_picorv32_uart_campaign_baseline.json'
CVA6_SEED = ROOT / 'configs/scenario/cva6_cpu_two_gpio_campaign_seed.json'

CPU = 'CPU_TO_IP_TO_CPU'
IP = 'IP_TO_CPU_TO_IP'

_PAIR: dict = {}


def pair():
    """One admitted CPU+IP pair, shared by this module's real-RTL tests."""
    if 'pair' not in _PAIR:
        directory = tempfile.mkdtemp(prefix='myfuzz-axil-campaign-tests-')
        _PAIR['directory'] = directory
        _PAIR['pair'] = fixture.AxilUartCpuPair(
            base_dir=ROOT, cache_dir=Path(directory) / 'cache')
    return _PAIR['pair']


def tearDownModule():
    directory = _PAIR.pop('directory', None)
    _PAIR.clear()
    if directory is not None:
        shutil.rmtree(directory, ignore_errors=True)


# --------------------------------------------------------------------------
# the program image and its mutation source
# --------------------------------------------------------------------------
class ProgramImageTests(unittest.TestCase):
    def test_the_mutable_source_is_the_tx_immediate_field(self):
        for direction in (CPU, IP):
            program = fixture.direction_program(direction)
            index = fixture.TX_IMMEDIATE_INSTRUCTION
            word = int.from_bytes(program[4 * index:4 * index + 4], 'little')
            self.assertEqual(0x13, word & 0x7f, 'opcode must be addi')
            self.assertEqual(0, (word >> 15) & 0x1f, 'rs1 must be x0')
            self.assertEqual(2, (word >> 7) & 0x1f, 'rd must be the TX register')
            self.assertEqual(fixture.TX_IMMEDIATE_SEED, (word >> 20) & 0xfff)
            self.assertEqual(32 * index + 20, fixture.TX_IMMEDIATE_BIT_OFFSET)
            self.assertEqual(8, fixture.TX_IMMEDIATE_WIDTH)
            # Bits 20..27 are the low byte of the 12-bit immediate: every bit
            # of the declared source belongs to the transmitted byte and no
            # bit of the source reaches the opcode, the registers or the
            # immediate's sign bits.
            self.assertLess(fixture.TX_IMMEDIATE_BIT_OFFSET + fixture.TX_IMMEDIATE_WIDTH,
                            32 * index + 32)

    def test_mutating_the_source_changes_only_the_transmitted_byte(self):
        for direction in (CPU, IP):
            program = bytearray(fixture.direction_program(direction))
            for bit in range(fixture.TX_IMMEDIATE_WIDTH):
                absolute = fixture.TX_IMMEDIATE_BIT_OFFSET + bit
                mutated = bytearray(program)
                mutated[absolute // 8] ^= 1 << (absolute % 8)
                index = fixture.TX_IMMEDIATE_INSTRUCTION
                word = int.from_bytes(mutated[4 * index:4 * index + 4], 'little')
                self.assertEqual(0x13, word & 0x7f)
                self.assertEqual(2, (word >> 7) & 0x1f)
                self.assertEqual(fixture.TX_IMMEDIATE_SEED ^ (1 << bit),
                                 (word >> 20) & 0xfff)
                # Nothing outside the immediate field may move.
                mask = ~(((1 << fixture.TX_IMMEDIATE_WIDTH) - 1)
                         << 20) & 0xffffffff
                original = int.from_bytes(program[4 * index:4 * index + 4], 'little')
                self.assertEqual(original & mask, word & mask)

    def test_the_setup_divisor_is_written_before_the_frame_is_armed(self):
        for direction in (CPU, IP):
            program = fixture.direction_program(direction)
            load = int.from_bytes(program[4:8], 'little')
            store = int.from_bytes(program[8:12], 'little')
            self.assertEqual(0x13, load & 0x7f)
            self.assertEqual(fixture.SETUP_DIVISOR, (load >> 20) & 0xfff)
            self.assertEqual(0x23, store & 0x7f, 'the SETUP write must be a store')
            self.assertEqual(fixture.UART_SETUP_OFFSET, (store >> 7) & 0x1f)
            self.assertLess(fixture.TX_IMMEDIATE_INSTRUCTION, 4)

    def test_each_direction_declares_the_wait_it_needs(self):
        self.assertEqual((0, fixture.SLED_ITERATIONS), fixture.DIRECTION_SLEDS[CPU])
        self.assertEqual((fixture.SLED_ITERATIONS, 0), fixture.DIRECTION_SLEDS[IP])
        self.assertNotEqual(fixture.program_digest(CPU), fixture.program_digest(IP))
        for direction, shape in fixture.DIRECTION_SHAPES.items():
            self.assertEqual(2, len(shape))
            self.assertGreater(shape[0], 0)
            self.assertEqual(0, shape[1])


# --------------------------------------------------------------------------
# the closed-chain checker, against synthetic but exactly shaped streams
# --------------------------------------------------------------------------
def _canonical_stream(direction, *, tx_byte=0x41, frame_byte=0x5A):
    """One complete round, stage by stage, in the direction's own order."""
    committed = tx_byte ^ frame_byte
    identity = lambda sequence: {  # noqa: E731
        'execution_id': 'e', 'testcase_id': 't', 'source_component': 'cpu',
        'source_epoch': 0, 'channel_id': 'memory', 'source_sequence': sequence}
    write = {'event_id': 0, 'kind': 'mmio_delivery', 'device_id': 'uart0',
             'offset': fixture.UART_TX_OFFSET, 'write': True,
             'write_value': tx_byte, 'source_transaction': identity(1)}
    injection = {'event_id': 0, 'kind': 'source_injection', 'component': 'uart0',
                 'port': fixture.UART_RX_INPUT, 'value': frame_byte}
    ready = {'event_id': 0, 'kind': 'local_tick_sample', 'component': 'uart0',
             'local_tick': 300,
             'outputs': {fixture.UART_RX_INTERRUPT_PORT: 1}}
    read = {'event_id': 0, 'kind': 'mmio_delivery', 'device_id': 'uart0',
            'offset': fixture.UART_RX_OFFSET, 'write': False,
            'read_value': frame_byte, 'source_transaction': identity(2)}
    consume = {'event_id': 0, 'component': 'cpu',
               'outputs': {'data_rsp_consumed': 1, 'data_rsp_rdata': frame_byte,
                           'data_rsp_source_epoch': 0, 'data_rsp_source_sequence': 2}}
    commit = {'event_id': 0, 'kind': 'memory_write', 'component': 'cpu',
              'address': fixture.RESULT_ADDRESS, 'value': committed,
              'transaction': identity(3)}
    drained = {'event_id': 0, 'kind': 'local_tick_sample', 'component': 'uart0',
               'local_tick': 700,
               'outputs': {fixture.UART_RX_INTERRUPT_PORT: 0}}
    decode_tx = {'event_id': 0, 'component': 'uart0',
                 'outputs': {'serial_tx_count': 1, 'serial_tx_last': tx_byte}}
    if direction == CPU:
        ordered = [write, injection, ready, read, consume, commit, drained]
        decode_tx['event_id'] = 0
        ordered.insert(1, decode_tx)
    else:
        ordered = [injection, ready, write, decode_tx, read, consume, commit, drained]
    for index, event in enumerate(ordered, start=1):
        event['event_id'] = index
    return ordered


def _state(frame_byte=0x5A):
    return {'inputs': {'uart0': {fixture.UART_RX_INPUT: frame_byte}},
            'pending_responses': {'cpu': 0, 'uart0': 0}}


def _findings(stream, direction=CPU, state=None):
    assessment = assess_axil_closed_chain(direction, stream, state or _state())
    return assessment, tuple(assessment['findings'])


class ClosedChainCheckerTests(unittest.TestCase):
    def test_a_complete_round_is_credited_in_both_directions(self):
        for direction in (CPU, IP):
            stream = _canonical_stream(direction)
            assessment, findings = _findings(stream, direction)
            self.assertEqual((), findings, direction)
            self.assertTrue(assessment['complete'], direction)
            self.assertEqual(1, assessment['rounds'], direction)
            self.assertEqual(0x41, assessment['cpu_tx_byte'], direction)
            self.assertEqual(0x5A, assessment['rx_frame_byte'], direction)
            self.assertEqual(0x41 ^ 0x5A, assessment['committed_value'], direction)

    def test_an_initiating_side_that_did_not_initiate_is_refused(self):
        # The CPU direction with the frame injected before the CPU's own store:
        # the same observations, only the causal order swapped.
        stream = _canonical_stream(CPU)
        stream[0], stream[2] = stream[2], stream[0]
        for index, event in enumerate(stream, start=1):
            event['event_id'] = index
        _, findings = _findings(stream, CPU)
        self.assertIn('cpu_did_not_initiate', findings)
        # The IP direction with the CPU writing first is refused symmetrically.
        stream = _canonical_stream(IP)
        stream[0], stream[2] = stream[2], stream[0]
        for index, event in enumerate(stream, start=1):
            event['event_id'] = index
        _, findings = _findings(stream, IP)
        self.assertIn('ip_did_not_initiate', findings)

    def test_every_required_stage_is_individually_required(self):
        tampering = {
            'cpu_tx_wire_decode_missing':
                lambda stream: stream.remove(next(e for e in stream
                                                 if 'serial_tx_last' in e.get('outputs', {}))),
            'ip_rx_ready_missing':
                lambda stream: stream.remove(next(e for e in stream if e.get('kind') == 'local_tick_sample'
                                                  and e['outputs'][fixture.UART_RX_INTERRUPT_PORT] == 1)),
            'ip_rx_fifo_not_drained':
                lambda stream: stream.remove(next(e for e in stream if e.get('kind') == 'local_tick_sample'
                                                  and e['outputs'][fixture.UART_RX_INTERRUPT_PORT] == 0)),
            'cpu_rx_read_value_mismatch':
                lambda stream: next(e for e in stream if e.get('kind') == 'mmio_delivery'
                                    and e.get('offset') == fixture.UART_RX_OFFSET
                                    ).update(read_value=0x11),
            'cpu_consume_rdata_missing':
                lambda stream: stream.remove(next(e for e in stream
                                                  if e.get('component') == 'cpu'
                                                  and 'data_rsp_consumed' in e.get('outputs', {}))),
            'cpu_ram_commit_missing':
                lambda stream: stream.remove(next(e for e in stream
                                                  if e.get('kind') == 'memory_write')),
            'rx_frame_input_state_mismatch':
                lambda stream: None,
        }
        for expected, tamper in tampering.items():
            if expected == 'rx_frame_input_state_mismatch':
                _, findings = _findings(_canonical_stream(CPU), CPU,
                                        _state(frame_byte=0x00))
                self.assertEqual(('rx_frame_input_state_mismatch',), findings)
                continue
            stream = _canonical_stream(CPU)
            tamper(stream)
            _, findings = _findings(stream, CPU)
            self.assertIn(expected, findings, expected)

    def test_a_replayed_transaction_identity_is_refused(self):
        stream = _canonical_stream(CPU)
        read = next(e for e in stream if e.get('kind') == 'mmio_delivery'
                    and e.get('offset') == fixture.UART_RX_OFFSET)
        write = next(e for e in stream if e.get('kind') == 'mmio_delivery'
                     and e.get('write') is True)
        read['source_transaction'] = dict(write['source_transaction'])
        next(e for e in stream if e.get('component') == 'cpu'
             and 'data_rsp_consumed' in e.get('outputs', {})
             )['outputs']['data_rsp_source_sequence'] = 1
        _, findings = _findings(stream, CPU)
        self.assertIn('cpu_rx_read_transaction_reused', findings)

    def test_pending_responses_and_failures_are_refused(self):
        stream = _canonical_stream(CPU)
        state = _state()
        state['pending_responses'] = {'cpu': 1}
        _, findings = _findings(stream, CPU, state)
        self.assertIn('pending_responses_at_end', findings)
        stream = _canonical_stream(IP)
        stream.append({'event_id': 99, 'kind': 'harness_failure', 'component': 'cpu'})
        _, findings = _findings(stream, IP)
        self.assertIn('harness_failure_present', findings)

    def test_an_unattributable_decode_is_never_credited(self):
        """A count that jumps by two cannot be attributed to one byte."""
        stream = _canonical_stream(CPU)
        decode = next(e for e in stream if 'serial_tx_last' in e.get('outputs', {}))
        decode['outputs']['serial_tx_count'] = 2
        _, findings = _findings(stream, CPU)
        self.assertIn('cpu_tx_wire_decode_missing', findings)

    def test_an_unknown_direction_is_not_assessed(self):
        self.assertIsNone(assess_axil_closed_chain('CPU_TO_IP', [], {}))


# --------------------------------------------------------------------------
# replay accounting: corpus-covered failures versus every saved failure trace
# --------------------------------------------------------------------------
#: The run the coordinating agent executed before the fixture's routed-access
#: tick bound was fixed: every bound cell died at its first device access, so
#: each saved 73 failure traces against a one-entry corpus.  Those saved bytes
#: are the RED evidence for the accounting below and are used read-only.
PRE_FIX_RUN = (ROOT / 'runs' / 'scenario' /
               'campaign-axil-18cell-p6-row3-20261014-v1')
PRE_FIX_CELL = PRE_FIX_RUN / 'dependency_guided__CPU_TO_IP_TO_CPU__seed_20260927'


def _saved_shapes(cell):
    live = cell / 'live'
    entries = sorted((live / 'corpus').glob('entry_*.json'))
    failures = sorted((live / 'failures').glob('*.json'))
    return live, entries, failures


class ReplayAccountingTests(unittest.TestCase):
    def test_the_inherited_accounting_is_inconsistent_on_the_real_cells(self):
        """RED: the framework refuses a failure count above the corpus size."""
        if not PRE_FIX_CELL.is_dir():
            self.skipTest('the pre-fix run is not present in this checkout')
        live, entries, failures = _saved_shapes(PRE_FIX_CELL)
        self.assertGreater(len(failures), len(entries))
        with self.assertRaisesRegex(ValueError, 'replay counts are inconsistent'):
            _validated_replay(ReplayEvidence(
                total_entries=len(entries), matched_entries=len(entries),
                failure_entries=len(failures),
                matched_failure_entries=len(failures), error=None))

    def test_the_provider_accounting_is_consistent_and_replays_every_failure(self):
        """GREEN: the reported counts fit the corpus; every trace is verified."""
        if not PRE_FIX_CELL.is_dir():
            self.skipTest('the pre-fix run is not present in this checkout')
        live, entries, failures = _saved_shapes(PRE_FIX_CELL)
        documents = [json.loads(path.read_text(encoding='utf-8'))
                     for path in failures]
        # Every saved failure trace replays identically (this run's failures
        # are deterministic harness failures), so the caller's replayed list is
        # one matched pair per saved trace.
        replayed = [(document['raw_sha256'], True) for document in documents]
        accounting = corpus_failure_accounting(
            __import__('myfuzz.integration.axil_scenario_campaign',
                       fromlist=['_corpus_input_hashes'])._corpus_input_hashes(live),
            replayed)
        self.assertEqual(len(failures), accounting['replayed_failure_entries'])
        self.assertEqual(len(entries), accounting['covered_failure_entries'])
        self.assertEqual(accounting['covered_failure_entries'],
                         accounting['covered_matched_failure_entries'])
        _validated_replay(ReplayEvidence(
            total_entries=len(entries), matched_entries=len(entries),
            failure_entries=accounting['covered_failure_entries'],
            matched_failure_entries=accounting['covered_matched_failure_entries'],
            error=None))

    def test_a_mismatching_saved_failure_still_fails_the_replay(self):
        """A trace that does not replay identically is an error, not a count."""
        accounting = corpus_failure_accounting(frozenset({'aa' * 32}),
                                               [('aa' * 32, False), ('bb' * 32, True)])
        self.assertEqual({'covered_failure_entries': 1,
                          'covered_matched_failure_entries': 0,
                          'replayed_failure_entries': 2}, accounting)
        _validated_replay(ReplayEvidence(
            total_entries=1, matched_entries=1,
            failure_entries=accounting['covered_failure_entries'],
            matched_failure_entries=accounting['covered_matched_failure_entries'],
            error='x.json: full trace differs'))


# --------------------------------------------------------------------------
# the provider's declared guards
# --------------------------------------------------------------------------
class ProviderGuardTests(unittest.TestCase):
    def provider(self):
        return AxilUartCpuBoundProvider()

    def test_a_foreign_bound_manifest_is_refused(self):
        provider = self.provider()
        with self.assertRaises(CampaignBlocked):
            provider._fixture(CPU, CVA6_SEED)

    def test_a_seed_with_another_shape_is_refused(self):
        provider = self.provider()
        seed = GenomeCodec.decode(BOUND_MANIFEST.read_bytes())
        tampered = ScenarioGenomeWith(seed, max_steps=seed.max_steps + 2)
        path = Path(tempfile.mkdtemp(prefix='myfuzz-axil-guard-')) / BOUND_MANIFEST.name
        path.write_bytes(GenomeCodec.encode(tampered))
        try:
            with self.assertRaises(CampaignBlocked):
                provider._fixture(CPU, path)
        finally:
            shutil.rmtree(path.parent, ignore_errors=True)

    def test_a_seed_with_another_program_is_refused(self):
        provider = self.provider()
        seed = GenomeCodec.decode(BOUND_MANIFEST.read_bytes())
        image = seed.initial_images[0]
        changed = image.data[:4] + b'\x00' + image.data[5:]
        tampered = ScenarioGenomeWith(
            seed, initial_images=(MemoryImage(
                image.image_id, image.component, image.address, changed.hex()),))
        path = Path(tempfile.mkdtemp(prefix='myfuzz-axil-guard-')) / BOUND_MANIFEST.name
        path.write_bytes(GenomeCodec.encode(tampered))
        try:
            with self.assertRaises(CampaignBlocked):
                provider._fixture(CPU, path)
        finally:
            shutil.rmtree(path.parent, ignore_errors=True)

    def test_a_tampered_independent_baseline_is_refused(self):
        provider = self.provider()
        directory = Path(tempfile.mkdtemp(prefix='myfuzz-axil-baseline-'))
        try:
            for name in ('axil_picorv32_uart_campaign_seed.json',
                         'axil_picorv32_uart_independent_ip_seed.json'):
                shutil.copy(BASELINE_MANIFEST.parent / name, directory / name)
            document = json.loads(BASELINE_MANIFEST.read_text())
            document['uart_local_window'] = {'base': fixture.UART_BASE,
                                             'size': fixture.UART_WINDOW * 2}
            tampered = directory / BASELINE_MANIFEST.name
            tampered.write_text(json.dumps(document, sort_keys=True))
            with self.assertRaises(CampaignBlocked):
                provider._independent_fixture(CPU, tampered)
            document['uart_local_window'] = {'base': fixture.UART_BASE,
                                             'size': fixture.UART_WINDOW}
            document['cpu_irq'] = 'bound'
            tampered.write_text(json.dumps(document, sort_keys=True))
            with self.assertRaises(CampaignBlocked):
                provider._independent_fixture(CPU, tampered)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_the_bound_fixture_declares_both_sides_and_the_pinned_program(self):
        provider = self.provider()
        for direction in (CPU, IP):
            factory, decoder, targets, seed = provider._fixture(direction, BOUND_MANIFEST)
            self.assertEqual(direction, seed.direction)
            self.assertEqual(('cpu', 'uart0'), seed.schedule_order)
            self.assertEqual(fixture.DIRECTION_SHAPES[direction],
                             (seed.max_steps, seed.quiesce_steps))
            self.assertEqual(fixture.PROGRAM_IMAGE, seed.initial_images[0].image_id)
            self.assertEqual(
                fixture.program_digest(direction),
                __import__('hashlib').sha256(seed.initial_images[0].data).hexdigest())
            sources = {item.source_id for item in decoder.graph.sources.values()}
            self.assertEqual({'cpu.tx_byte', 'uart0.rx_frame'}, sources)
            bindings = {item.source_id for item in decoder.source_bindings.entries}
            self.assertEqual(sources, bindings)
            # One anchor target plus one per bit of the byte the CPU presents
            # to memory, so a mutated genome can newly satisfy a target and the
            # RFuzz client admits the mutated input to its corpus.
            self.assertEqual(1 + axil_scenario_campaign.TARGET_BITS, len(targets))
            self.assertEqual({'uart0.rx_fifo_nonempty'} if direction == CPU
                             else {'cpu.axil_roundtrip_consumed'},
                             {targets[0].target_id})
            for bit, target in enumerate(targets[1:]):
                self.assertEqual((target.mask, target.value), (1 << bit, 1 << bit))
                self.assertEqual('data_wdata', target.port)
                self.assertEqual('cpu', target.component)

    def test_the_independent_fixture_claims_one_source_and_no_binding(self):
        provider = self.provider()
        for direction, expected in ((CPU, 'cpu.tx_byte'), (IP, 'uart0.rx_frame')):
            factory, decoder, targets, seed = provider._independent_fixture(
                direction, BASELINE_MANIFEST)
            self.assertEqual({expected},
                             {item.source_id for item in decoder.graph.sources.values()})
            runner = factory()
            self.assertTrue(runner.independent_baseline)
            self.assertEqual((), runner.bindings)
            self.assertEqual(['uart0_local'],
                             [window.device_id for window in runner.sessions['cpu'].router.windows])
            self.assertNotIn('uart0_local', runner.sessions)


def ScenarioGenomeWith(seed, **changes):
    """A copy of ``seed`` with the named dataclass fields replaced."""
    from dataclasses import replace

    return replace(seed, **changes)


# --------------------------------------------------------------------------
# the peer member's drained-sample defect, and the fixture's behaviour
# --------------------------------------------------------------------------
def _transmit_and_step(session, *, drain, steps=600):
    """Configure, write one byte to TXREG and clock the device, runner-style."""
    session.begin_case('peer-decode')
    if drain:
        session.drain_tick_samples()
    failure = None
    try:
        # The declared peer decodes at the divisor the program configures, so
        # the SETUP register must be written first, exactly as the program does.
        session.write_register(fixture.UART_SETUP_OFFSET, fixture.SETUP_DIVISOR,
                               be=15)
        session.write_register(fixture.UART_TX_OFFSET, 0x41, be=15)
        for _ in range(steps):
            session.step_local({})
            if drain:
                session.drain_tick_samples()
    except Exception as exc:                      # noqa: BLE001 - the failure is the fact
        failure = f'{type(exc).__name__}: {exc}'
    captured = list(session.peer.captured)
    session.end_case()
    return captured, failure


class PeerDrainDefectTests(unittest.TestCase):
    def test_the_stock_peer_member_loses_the_decode_under_a_runner_drain(self):
        """Pinned defect of the stock member; see the module docstring.

        If this starts failing, the stock member's cursor was fixed: delete
        ``AxilUartPeerSession.drain_tick_samples`` and this test together.
        """
        from myfuzz.local_harness.generated_register_factory import (
            create_generated_register_session)

        def factory():
            return create_generated_register_session(
                axil_uart_cpu_example.axil_artifacts(ROOT)[1], base_dir=ROOT,
                cache_dir=pair().cache_dir)

        captured, failure = _transmit_and_step(factory(), drain=True)
        self.assertEqual([], captured,
                         'the stock member decoded a byte despite the drain')

    def test_the_fixture_peer_decodes_the_transmitted_byte_under_a_drain(self):
        captured, failure = _transmit_and_step(pair().uart, drain=True)
        self.assertIsNone(failure)
        self.assertEqual([0x41], captured,
                         'the fixture member must decode what the pin carried')

    def test_the_fixture_peer_also_decodes_without_any_drain(self):
        captured, failure = _transmit_and_step(pair().uart, drain=False)
        self.assertIsNone(failure)
        self.assertEqual([0x41], captured)


# --------------------------------------------------------------------------
# one real case per direction, closed by the checker
# --------------------------------------------------------------------------
class RealCaseTests(unittest.TestCase):
    def run_case(self, direction):
        provider = AxilUartCpuBoundProvider()
        factory, decoder, targets, seed = provider._fixture(direction, BOUND_MANIFEST)
        holder = {}

        def runner():
            r = pair().runner()
            holder['runner'] = r
            return r

        from myfuzz.local_harness.build import host_source_discovery_scope

        with host_source_discovery_scope():
            trace = record_scenario(seed, runner)
        self.assertEqual('complete', trace.status, trace.events[-3:])
        assessment = assess_axil_closed_chain(
            direction, trace.events, holder['runner'].final_state_document())
        self.assertTrue(assessment['complete'], assessment['findings'])
        self.assertEqual(1, assessment['rounds'])
        self.assertEqual(fixture.TX_IMMEDIATE_SEED, assessment['cpu_tx_byte'])
        self.assertEqual(fixture.RX_FRAME_SEED, assessment['rx_frame_byte'])
        self.assertEqual(fixture.TX_IMMEDIATE_SEED ^ fixture.RX_FRAME_SEED,
                         assessment['committed_value'])
        return trace, assessment

    def test_a_real_cpu_initiated_case_closes_the_chain(self):
        self.run_case(CPU)

    def test_a_real_ip_initiated_case_closes_the_chain(self):
        self.run_case(IP)

    def test_a_mutated_genome_changes_what_the_assessment_credits(self):
        """Both declared sources really move the observables the checker reads.

        This is the experiment that distinguishes "the assessment is wrong"
        from "the mutation does nothing": the seed and two mutated genomes are
        run through the same fixture and the credited bytes must differ.
        """
        from myfuzz.local_harness.build import host_source_discovery_scope
        from myfuzz.scenario.feedback import observed_targets

        seen = {}
        for direction in (CPU, IP):
            provider = AxilUartCpuBoundProvider()
            factory, decoder, targets, seed = provider._fixture(direction, BOUND_MANIFEST)
            holder = {}

            def runner():
                r = pair().runner()
                holder['runner'] = r
                return r

            cases = (('seed', seed),
                     ('cpu-bit3', decoder.decode((bytes((0, 0, 0, 0, 0, 1, 3, 0)),))),
                     ('frame-bit0', decoder.decode((bytes((0, 0, 1, 0, 0, 1, 0, 0)),))))
            for label, genome in cases:
                with host_source_discovery_scope():
                    trace = record_scenario(genome, runner)
                assessment = assess_axil_closed_chain(
                    direction, trace.events, holder['runner'].final_state_document())
                self.assertTrue(assessment['complete'],
                                (direction, label, assessment['findings']))
                seen[(direction, label)] = (
                    assessment['cpu_tx_byte'], assessment['rx_frame_byte'],
                    tuple(sorted(observed_targets(trace.events, targets))),
                    genome.effective_sha256 if hasattr(genome, 'effective_sha256')
                    else genome.genome_sha256 if hasattr(genome, 'genome_sha256') else '')
            self.assertEqual(0x41, seen[(direction, 'seed')][0])
            self.assertEqual(0x40, seen[(direction, 'cpu-bit3')][0])
            self.assertEqual(0x5A, seen[(direction, 'seed')][1])
            self.assertEqual(0x5B, seen[(direction, 'frame-bit0')][1])
            # The mutated CPU byte newly satisfies a target the seed did not,
            # so the RFuzz client has a reason to save the mutated input.
            self.assertNotEqual(seen[(direction, 'seed')][2],
                                seen[(direction, 'cpu-bit3')][2])


if __name__ == '__main__':
    unittest.main()
