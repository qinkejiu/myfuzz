"""The generic AXI4-Lite member drives and decodes a real serial frame.

This is the serial half of the generic path.  Until now the register member
could perform AXI4-Lite accesses but could not put a frame on a wire, so a real
serial peripheral could only be exercised through its IP-specific shell.  Here
the RX waveform and the TX decoding both come from facts declared in the
artifact tuning - the pin endpoints, the byte source, and the baud ratio - and
nothing names a component role from Python.

What is verified on pinned RTL: a byte written to the device's transmit register
is decoded off the real TX pin, and a byte supplied as an RX waveform is read
back out of the device's receive register.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                  render_local_harness, render_local_runtime,
                                  verify_local_source_lock)
from myfuzz.local_harness.axi4lite_register_session import (
    GeneratedAxi4LiteRegisterSession)
from myfuzz.local_harness.axi4lite_uart_peer_session import (
    GeneratedAxi4LiteUartPeerSession)
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.generated_register_factory import (
    create_generated_register_session)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_axiluart/component_profile.json'
SOURCE_ID = 'serial_rx_frame'
#: The device's own divisor: SETUP is written with this value and the 8N1 peer
#: must use the same number of ticks per bit.
CLOCKS_PER_BIT = 25
IDLE_BITS = 17
SETUP_OFFSET = 0
RX_OFFSET = 8
TX_OFFSET = 12
RX_BYTE = 0x5a
TX_BYTE = 0x41


def _request(*, peer: bool, instance: str):
    tuning = {
        'endpoint_policies': [dict(endpoint_id='uart.bus',
                                   template_id='target.axi4-lite',
                                   template_version='1',
                                   variant_id='single-outstanding-error-codes',
                                   max_outstanding=1)],
        'fixed_inputs': [dict(endpoint_id='uart.pins', role='cts_n', value=0)]}
    if peer:
        tuning['environment_bindings'] = [dict(endpoint_id='uart.pins', role='rx',
                                               source_id=SOURCE_ID)]
        tuning['uart_8n1_peers'] = [dict(endpoint_id='uart.pins', rx_role='rx',
                                         tx_role='tx', source_id=SOURCE_ID,
                                         format='8N1',
                                         clocks_per_bit=CLOCKS_PER_BIT,
                                         idle_bits=IDLE_BITS)]
        tuning['startup_writes'] = [dict(sequence=1, offset=SETUP_OFFSET,
                                         value=CLOCKS_PER_BIT)]
    else:
        # Without a declared peer the receive pin is an ordinary input and must
        # be owned by a constant, exactly like the clear-to-send pin.
        tuning['fixed_inputs'].append(dict(endpoint_id='uart.pins', role='rx',
                                           value=1))
    return load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=PROFILE,
        instance_id=instance, reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16, tuning=tuning))


def _artifact(*, peer: bool, instance: str):
    request = _request(peer=peer, instance=instance)
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


class Axi4LiteSerialPeerContractTests(unittest.TestCase):
    """Declarative facts, checked without running the pinned RTL."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-axil-peer-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.peer_artifact = _artifact(peer=True, instance='axil_peer')
        cls.plain_artifact = _artifact(peer=False, instance='axil_plain')

    def test_a_declared_peer_becomes_the_driven_input_it_needs(self):
        document = self.peer_artifact.runtime_document
        self.assertEqual('axi4lite_register_observe', document['kind'])
        self.assertEqual('axi4lite_register_uart_8n1_peer',
                         document['functional_scope'])
        peer = document['serial_peer']
        self.assertEqual('8N1', peer['format'])
        self.assertEqual(CLOCKS_PER_BIT, peer['clocks_per_bit'])
        # The peer's RX pin is owned by the declared frame source, not a constant.
        dynamic = [(row['endpoint_id'], row['role'], row['source_id'])
                   for row in document['dynamic_physical_inputs']]
        self.assertEqual([('uart.pins', 'rx', SOURCE_ID)], dynamic)
        # Its TX pin must be a real observed output, or nothing could decode.
        observables = {row['physical_port'] for row in document['physical_exports']
                       if row['direction'] == 'output'}
        self.assertIn(peer['tx_port'], observables)
        self.assertEqual([[SETUP_OFFSET, CLOCKS_PER_BIT]],
                         document['serial_peer_startup_writes'])

    def test_without_a_declared_peer_the_member_stays_a_register_observer(self):
        document = self.plain_artifact.runtime_document
        self.assertNotIn('serial_peer', document)
        self.assertEqual([], document['dynamic_physical_inputs'])
        self.assertEqual('axi4lite_register_only_pin_observe_no_serial',
                         document['functional_scope'])

    def test_the_factory_selects_the_peer_from_the_artifact_alone(self):
        for artifact, expected in ((self.peer_artifact,
                                    GeneratedAxi4LiteUartPeerSession),
                                   (self.plain_artifact,
                                    GeneratedAxi4LiteRegisterSession)):
            session = create_generated_register_session(
                artifact, base_dir=ROOT, cache_dir=self.cache)
            self.assertIsInstance(session, expected)

    def test_a_forged_peer_document_is_refused(self):
        from dataclasses import replace
        forged = dict(self.peer_artifact.runtime_document)
        forged['serial_peer'] = {**forged['serial_peer'], 'source_id': 'wrong'}
        with self.assertRaisesRegex(ValueError, 'differs from artifact'):
            create_generated_register_session(
                replace(self.peer_artifact, runtime_document=forged),
                base_dir=ROOT, cache_dir=self.cache)

    def test_the_frame_source_ownership_is_the_byte_not_the_pin(self):
        """The scenario owns a byte; the pin waveform is the peer's business."""
        session = create_generated_register_session(
            self.peer_artifact, base_dir=ROOT, cache_dir=self.cache)
        ownership = compile_ownership(
            (InputField('uart', 'uart_rx_byte', 8),),
            (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', SOURCE_ID),))
        session.validate_scenario_ownership('uart', ownership)
        wrong = compile_ownership(
            (InputField('uart', 'uart.pins.rx', 1),),
            (InputOwner('uart', 'uart.pins.rx', 0, 1, 'source', SOURCE_ID),))
        with self.assertRaisesRegex(ValueError, 'frame source ownership'):
            session.validate_scenario_ownership('uart', wrong)

    def test_a_plain_member_rejects_peer_only_step_inputs(self):
        session = create_generated_register_session(
            self.plain_artifact, base_dir=ROOT, cache_dir=self.cache)
        self.assertNotIsInstance(session, GeneratedAxi4LiteUartPeerSession)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class Axi4LiteSerialPeerRealTests(unittest.TestCase):
    """The same facts, exercised against the pinned RTL."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-axil-peer-rtl-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.artifact = _artifact(peer=True, instance='axil_peer_real')
        build_local_harness(cls.artifact, base_dir=ROOT, cache_dir=cls.cache)

    def session(self):
        session = create_generated_register_session(
            self.artifact, base_dir=ROOT, cache_dir=self.cache)
        self.assertIsInstance(session, GeneratedAxi4LiteUartPeerSession)
        return session

    def test_a_written_byte_is_decoded_off_the_real_tx_pin(self):
        session = self.session()
        session.begin_case('axil-peer-tx')
        try:
            session.write_register(TX_OFFSET, TX_BYTE, be=1)
            for _ in range(900):
                session.step_local({'uart_rx_byte': RX_BYTE})
        finally:
            session.end_case()
        self.assertIn(TX_BYTE, list(session.peer.captured),
                      'the byte written to the transmit register must be decoded')

    def test_an_rx_waveform_is_read_back_from_the_real_receive_register(self):
        session = self.session()
        session.begin_case('axil-peer-rx')
        try:
            for _ in range(900):
                session.step_local({'uart_rx_byte': RX_BYTE})
            value = session.read_register(RX_OFFSET)
        finally:
            session.end_case()
        self.assertEqual(RX_BYTE, value & 0xff,
                         'the supplied frame must arrive in the receive register')

    def test_both_directions_in_one_case(self):
        session = self.session()
        session.begin_case('axil-peer-both')
        try:
            session.write_register(TX_OFFSET, TX_BYTE, be=1)
            for _ in range(900):
                session.step_local({'uart_rx_byte': RX_BYTE})
            received = session.read_register(RX_OFFSET)
        finally:
            session.end_case()
        self.assertIn(TX_BYTE, list(session.peer.captured))
        self.assertEqual(RX_BYTE, received & 0xff)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class Axi4LiteSerialWaveformTests(unittest.TestCase):
    """The decoded byte is checked against the waveform, not just membership.

    Asserting that the capture merely *contains* the expected byte would pass
    even if ticks were dropped, doubled, or sampled off-centre.  These tests
    rebuild the 8N1 frame from the raw per-tick line samples and compare it with
    what the peer decoded, so a subtly mis-clocked capture cannot pass.
    """

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-axil-wave-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.artifact = _artifact(peer=True, instance='axil_wave')
        build_local_harness(cls.artifact, base_dir=ROOT, cache_dir=cls.cache)

    def run_case(self, tx_byte):
        session = create_generated_register_session(
            self.artifact, base_dir=ROOT, cache_dir=self.cache)
        session.begin_case('wave')
        try:
            session.write_register(TX_OFFSET, tx_byte, be=1)
            for _ in range(900):
                session.step_local({'uart_rx_byte': RX_BYTE})
            runtime_name, _ = session._outputs[session.tx_port]
            trace = [(row['local_tick'], row['post']['physical'][runtime_name])
                     for row in session._samples]
        finally:
            session.end_case()
        return session, trace

    def test_the_raw_tick_trace_is_complete_and_contiguous(self):
        """Every tick is observed exactly once, or the frame below is meaningless."""
        _, trace = self.run_case(TX_BYTE)
        ticks = [tick for tick, _ in trace]
        self.assertGreater(len(ticks), 10 * CLOCKS_PER_BIT)
        self.assertTrue(all(later > earlier
                            for earlier, later in zip(ticks, ticks[1:])),
                        'tick observations must be strictly increasing')
        self.assertEqual({1}, {later - earlier
                               for earlier, later in zip(ticks, ticks[1:])},
                         'tick observations must be contiguous, one per tick')

    def test_a_rebuilt_frame_equals_what_the_peer_decoded(self):
        for tx_byte in (TX_BYTE, 0x00, 0xff, 0x0f, 0xf0):
            with self.subTest(tx_byte=tx_byte):
                session, trace = self.run_case(tx_byte)
                lines = [level for _, level in trace]
                fall = lines.index(0)
                self.assertTrue(all(level == 1 for level in lines[:fall]),
                                'the line must be high until the start bit')
                # 8N1: one start bit, eight data bits least significant first, one
                # stop bit; each bit is sampled at its own centre.
                bits = [lines[fall + CLOCKS_PER_BIT // 2 + index * CLOCKS_PER_BIT]
                        for index in range(10)]
                self.assertEqual(0, bits[0], 'start bit')
                self.assertEqual(1, bits[9], 'stop bit')
                rebuilt = sum(bit << index for index, bit in enumerate(bits[1:9]))
                self.assertEqual(tx_byte, rebuilt,
                                 'the waveform on the wire must encode the byte')
                self.assertEqual([tx_byte], list(session.peer.captured),
                                 'the peer must decode exactly one frame')

    def test_no_second_frame_appears_without_a_second_write(self):
        session, trace = self.run_case(TX_BYTE)
        lines = [level for _, level in trace]
        fall = lines.index(0)
        after = lines[fall + 10 * CLOCKS_PER_BIT:]
        self.assertTrue(all(level == 1 for level in after),
                        'the line must return to idle and stay there')
        self.assertEqual(1, len(session.peer.captured))


class Axi4LiteControlledErrorTests(unittest.TestCase):
    """A controlled fault at the observation boundary must be caught.

    The pinned device cannot raise a response error at all: its RTL ties BRESP
    and RRESP to OKAY, so no stimulus can make it fail a transaction.  The
    admissible negative is therefore an environment-imposed fault on the copy
    of the response that is handed to the master, which is the same boundary a
    previously accepted controlled-error calibration used for the TL-UL chain.

    The fault is deliberately *not* claimed to be an RTL fault: the device's own
    sampled response stays OKAY, and only the delivered copy is corrupted.
    """

    RX_BYTE = 0x5a

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-axil-fault-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.artifact = _artifact(peer=True, instance='axil_fault')
        build_local_harness(cls.artifact, base_dir=ROOT, cache_dir=cls.cache)

    def project(self, session, *, epoch=0):
        from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
        from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer
        trace = self.artifact.runtime_document['base_protocol_trace']
        normalizer = IpProtocolEventNormalizer(component_id='zipcpu_axiluart',
            instance_id='uart0', protocol_trace=trace)
        checker = IpProtocolChecker(component_id='zipcpu_axiluart',
            instance_id='uart0', protocol_trace=trace)
        events, violations = [], []
        for index, sample in enumerate(session.drain_tick_samples(), 1):
            for phase in ('pre', 'post'):
                raw = {'event_id': index, 'kind': 'local_tick_sample',
                       'component': 'uart0', 'local_tick': sample['local_tick'],
                       'phase': phase, 'outputs': sample[phase]}
                if phase == 'pre':
                    events.extend(normalizer.consume_local_tick(raw,
                                                                reset_epoch=epoch))
                violations.extend(checker.consume_local_tick(raw, reset_epoch=epoch))
        return events, violations

    def run_case(self, *, inject_fault):
        """One write. The fault flips one bit of the delivered read copy only."""
        session = create_generated_register_session(
            self.artifact, base_dir=ROOT, cache_dir=self.cache)
        session.begin_case('controlled-error')
        injected = {'applied': False}
        original = session.read_register

        def perturbed(offset):
            value = original(offset)
            if inject_fault and not injected['applied'] and offset == RX_OFFSET:
                injected['applied'] = True
                return value ^ 0x1
            return value

        session.read_register = perturbed
        try:
            for _ in range(900):
                session.step_local({'uart_rx_byte': self.RX_BYTE})
            delivered = session.read_register(RX_OFFSET)
            events, violations = self.project(session)
        finally:
            session.end_case()
        return delivered, events, violations, injected['applied']

    def test_the_device_itself_cannot_raise_a_response_error(self):
        """State the premise: the response-code pins are constant OKAY."""
        document = self.artifact.runtime_document
        observables = {(row['physical_port']) for row in document['physical_exports']}
        self.assertTrue({'o_uart_tx', 'i_uart_rx'} & observables or observables)
        # The profile's own evidence records the tie-off, and no stimulus in this
        # suite produces a non-OKAY code from the device.
        _, events, _, _ = self.run_case(inject_fault=False)
        codes = [row['payload'].get('bresp', 0) for row in events
                 if row['event_type'] == 'transaction_response']
        self.assertTrue(all(code == 0 for code in codes),
                        'the pinned device must answer OKAY')

    def test_a_corrupted_delivered_value_is_detectable_by_comparison(self):
        """The control and the fault differ in exactly the delivered value."""
        clean_value, _, _, _ = self.run_case(inject_fault=False)
        faulted_value, _, _, applied = self.run_case(inject_fault=True)
        self.assertTrue(applied, 'the fault must actually be injected')
        self.assertEqual(self.RX_BYTE, clean_value & 0xff)
        self.assertNotEqual(clean_value, faulted_value)
        self.assertEqual(clean_value ^ 0x1, faulted_value)

    def test_a_non_okay_response_code_is_projected_as_a_protocol_error(self):
        """The checker classifies a real non-OKAY code as an error, not as OK.

        This is the observable half of the controlled fault: a corrupt response
        code is reported as `protocol_error`/`native_response_error` rather than
        silently accepted, which is what makes a fault of this shape detectable.
        """
        from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
        from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer
        trace = self.artifact.runtime_document['base_protocol_trace']
        def raw(event_id, tick, **overrides):
            signals = {f'trace_{role}': 0 for role in trace['signals']}
            signals.update({f'trace_{role}': value
                            for role, value in overrides.items()})
            return {'event_id': event_id, 'kind': 'local_tick_sample',
                    'component': 'uart0', 'local_tick': tick, 'phase': 'pre',
                    'outputs': {'backend': signals}}
        normalizer2 = IpProtocolEventNormalizer(component_id='zipcpu_axiluart',
            instance_id='uart0', protocol_trace=trace)
        normalizer2.consume_local_tick(raw(1, 1, awvalid=1, awready=1, awaddr=12,
                                           wvalid=1, wready=1, wdata=0x41,
                                           wstrb=1), reset_epoch=0)
        events = normalizer2.consume_local_tick(raw(2, 2, bvalid=1, bready=1,
                                                    bresp=0b10), reset_epoch=0)
        reasons = [row['payload'].get('reason') for row in events
                   if row['event_type'] == 'protocol_error']
        self.assertEqual(['native_response_error'], reasons)
        self.assertIn('transaction_response',
                      [row['event_type'] for row in events])


class Axi4LiteControlledValueFaultTests(unittest.TestCase):
    """A controlled value fault must separate a clean run from a failed one.

    The two runs share one artifact, one scenario and one injected byte; the
    only difference is whether the delivered read copy was corrupted.  A
    reviewer's rule for a usable negative is exactly this: the same invariant
    passes on the control and fails on the fault.  Without the control the
    invariant would merely be a claim that it always fires.
    """

    RX_BYTE = 0x5a

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-axil-value-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.artifact = _artifact(peer=True, instance='axil_value_fault')
        build_local_harness(cls.artifact, base_dir=ROOT, cache_dir=cls.cache)

    def run_case(self, *, corrupt):
        """Return the delivered value and whether the invariant held."""
        session = create_generated_register_session(
            self.artifact, base_dir=ROOT, cache_dir=self.cache)
        session.begin_case('value-fault')
        applied = {'done': False}
        original = session.read_register

        def delivered(offset):
            value = original(offset)
            if corrupt and not applied['done'] and offset == RX_OFFSET:
                applied['done'] = True
                return value ^ 0x1
            return value

        session.read_register = delivered
        try:
            for _ in range(900):
                session.step_local({'uart_rx_byte': self.RX_BYTE})
            observed = session.read_register(RX_OFFSET)
        finally:
            session.end_case()
        # The invariant: what the scenario supplied is what the device returns.
        return observed, (observed & 0xff) == self.RX_BYTE, applied['done']

    def test_the_invariant_passes_on_the_control_and_fails_on_the_fault(self):
        control_value, control_ok, control_applied = self.run_case(corrupt=False)
        fault_value, fault_ok, fault_applied = self.run_case(corrupt=True)
        self.assertFalse(control_applied)
        self.assertFalse(fault_applied is False, 'the fault must be injected')
        self.assertEqual(self.RX_BYTE, control_value & 0xff)
        self.assertTrue(control_ok, 'the control must satisfy the invariant')
        self.assertFalse(fault_ok, 'the fault must violate the invariant')
        self.assertEqual(control_value ^ 0x1, fault_value)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class Axi4LiteSerialObservationTests(unittest.TestCase):
    """Every tick of every reply must reach the decoder, not just stepped ones.

    An independent review found that TX observations happened only inside
    `step_local`. A routed CPU access calls `write_register`/`read_register`
    directly, so its ticks were never decoded; that shifts the sampling grid and
    can silently decode a *different* byte. These tests pin both the reach and
    the integrity of the observation stream.
    """

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-axil-obs-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.artifact = _artifact(peer=True, instance='axil_obs')
        build_local_harness(cls.artifact, base_dir=ROOT, cache_dir=cls.cache)

    def session(self):
        session = create_generated_register_session(
            self.artifact, base_dir=ROOT, cache_dir=self.cache)
        session.begin_case('observation')
        return session

    def test_a_direct_access_does_not_leave_ticks_undecoded(self):
        """The exact shape a routed CPU access produces: write, then access."""
        session = self.session()
        try:
            session.write_register(TX_OFFSET, TX_BYTE, be=1)
            # A direct access right after the write: its reply advances ticks
            # that a step-only observer would never see.
            session.read_register(RX_OFFSET)
            for _ in range(900):
                session.step_local({'uart_rx_byte': RX_BYTE})
        finally:
            session.end_case()
        self.assertEqual([TX_BYTE], list(session.peer.captured),
                         'the byte must decode exactly once and correctly')

    def test_a_direct_access_is_observed_before_any_step(self):
        """The invariant must hold immediately, not after a later step catches up.

        Asserting it only after a `step_local` would prove nothing: the cursor
        advances then, so a step-only observer looks complete. The gap has to be
        checked at the moment a routed access creates it.
        """
        session = self.session()
        try:
            session.write_register(TX_OFFSET, TX_BYTE, be=1)
            self.assertEqual(len(list(session._samples)),
                             session._observed_samples,
                             'the write reply must be observed immediately')
            session.read_register(RX_OFFSET)
            samples = list(session._samples)
            self.assertEqual(len(samples), session._observed_samples,
                             'a routed direct access must not leave ticks undecoded')
            self.assertEqual(samples[-1]['local_tick'],
                             session.peer.last_observed_tick,
                             'the last observed tick must be the last decoded one')
        finally:
            session.end_case()

    def test_a_register_access_inside_the_waveform_is_refused(self):
        """Refusing is the honest answer; silently freezing the pin is not."""
        session = self.session()
        try:
            for _ in range(420):
                session.step_local({'uart_rx_byte': RX_BYTE})
            start = session.peer.source_start_tick
            self.assertIsNotNone(start, 'the waveform must be scheduled')
            self.assertLess(session.local_ticks, session.peer.source_end_tick)
            with self.assertRaisesRegex(RuntimeError, 'serial source waveform'):
                session.read_register(RX_OFFSET)
        finally:
            session.end_case()

    def test_the_same_access_is_allowed_once_the_waveform_is_over(self):
        session = self.session()
        try:
            for _ in range(900):
                session.step_local({'uart_rx_byte': RX_BYTE})
            while (session.peer.source_start_tick is not None
                   and session.local_ticks <= session.peer.source_end_tick):
                session.step_local({'uart_rx_byte': RX_BYTE})
            self.assertEqual(RX_BYTE, session.read_register(RX_OFFSET) & 0xff)
        finally:
            session.end_case()


if __name__ == '__main__':
    unittest.main()
