"""Generic IP events projected from a real AXI4-Lite peripheral's own RTL.

This is the point of the generic-protocol work: the same component-neutral
normalizer and checker that already cover ``tl-ul``, ``apb3`` and ``wishbone``
now cover a real AXI4-Lite slave, with no IP-specific shell in the loop.  The
events below are decoded from RTL tick samples of the pinned ``zipcpu_axiluart``
harness, not from any Python-side record of what was requested.

The two writes are chosen to be independently checkable against the RTL's own
register map: offset 0 is SETUP and offset 12 is TX.  A projection that merely
echoed commands back could not also produce the measured AXI addresses and
padded data widths.
"""
from __future__ import annotations

import collections
import tempfile
import unittest
from pathlib import Path

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                  render_local_harness, render_local_runtime,
                                  verify_local_source_lock)
from myfuzz.local_harness.axi4lite_register_session import (
    GeneratedAxi4LiteRegisterSession)
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_axiluart/component_profile.json'
SETUP_OFFSET = 0
RX_OFFSET = 8
SETUP_VALUE = 25
TX_OFFSET = 12
TX_BYTE = 0x41
#: Long enough for the 8N1 frame driven by the TX register to leave the wire.
FRAME_TICKS = 780


def _artifact():
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=PROFILE,
        instance_id='generic_axil_uart', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(endpoint_id='uart.bus',
                    template_id='target.axi4-lite', template_version='1',
                    variant_id='single-outstanding-error-codes',
                    max_outstanding=1)],
                # Both serial inputs are physically real pins, so the
                # generic register member must be told what drives them
                # instead of leaving an unowned input.
                'fixed_inputs': [dict(endpoint_id='uart.pins', role='cts_n',
                                      value=0),
                                 dict(endpoint_id='uart.pins', role='rx',
                                      value=1)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


class RealAxiLiteGenericEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-axil-events-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.artifact = _artifact()
        build_local_harness(cls.artifact, base_dir=ROOT, cache_dir=cls.cache)
        cls.trace = cls.artifact.runtime_document['base_protocol_trace']
        cls.samples = cls._run_case()

    @classmethod
    def _run_case(cls):
        session = GeneratedAxi4LiteRegisterSession(cls.artifact, base_dir=ROOT,
            cache_dir=cls.cache)
        session.begin_case('axil-generic-events')
        try:
            # Three real accesses, all through the generic register member:
            # two writes with measured addresses, and one read whose value is
            # the RTL's own answer rather than anything the test supplied.
            session.write_register(SETUP_OFFSET, SETUP_VALUE, be=15)
            session.write_register(TX_OFFSET, TX_BYTE, be=1)
            cls.read_back = session.read_register(RX_OFFSET)
            for _ in range(FRAME_TICKS):
                session.step_local({})
            samples = session.drain_tick_samples()
        finally:
            session.end_case()
        return samples

    def project(self):
        normalizer = IpProtocolEventNormalizer(component_id='zipcpu_axiluart',
            instance_id='uart0', protocol_trace=self.trace)
        checker = IpProtocolChecker(component_id='zipcpu_axiluart',
            instance_id='uart0', protocol_trace=self.trace)
        events, violations = [], []
        for index, sample in enumerate(self.samples, 1):
            for phase in ('pre', 'post'):
                raw = {'event_id': index, 'kind': 'local_tick_sample',
                       'component': 'uart0', 'local_tick': sample['local_tick'],
                       'phase': phase, 'outputs': sample[phase]}
                if phase == 'pre':
                    events.extend(normalizer.consume_local_tick(raw, reset_epoch=0))
                violations.extend(checker.consume_local_tick(raw, reset_epoch=0))
        return events, violations

    # -- the artifact really is an AXI4-Lite endpoint ----------------------
    def test_artifact_carries_the_declared_slave_role_set(self):
        self.assertEqual('axi4-lite', self.trace['protocol'])
        self.assertEqual('uart.bus', self.trace['endpoint_id'])
        self.assertEqual(19, len(self.trace['signals']))
        # Widths are the RTL's own declared port widths, not a default.
        self.assertEqual(4, self.trace['signal_widths']['awaddr'])
        self.assertEqual(4, self.trace['signal_widths']['araddr'])
        self.assertEqual(32, self.trace['signal_widths']['wdata'])
        self.assertEqual(2, self.trace['signal_widths']['bresp'])

    def test_the_harness_snapshots_the_trace_signals_from_rtl(self):
        """Without these the normalizer has nothing real to read."""
        backend = self.samples[0]['pre']['backend']
        for role in ('awvalid', 'awready', 'wvalid', 'bresp', 'rvalid'):
            self.assertIn('trace_' + role, backend)

    # -- the projection -----------------------------------------------
    def test_real_register_writes_become_generic_transactions(self):
        events, _ = self.project()
        kinds = collections.Counter(event['event_type'] for event in events)
        self.assertEqual(3, kinds['transaction_request'])
        self.assertEqual(3, kinds['transaction_accept'])
        self.assertEqual(3, kinds['transaction_response'])
        self.assertEqual(0, kinds['transaction_timeout'])
        self.assertEqual(0, kinds['protocol_error'])

    def test_completions_carry_the_measured_address_and_data(self):
        events, _ = self.project()
        responses = [event for event in events
                     if event['event_type'] == 'transaction_response']
        writes = [(row['payload']['awaddr'], row['payload']['wdata'],
                   row['payload']['bresp']) for row in responses
                  if row['payload']['direction'] == 'write']
        self.assertEqual([(SETUP_OFFSET, SETUP_VALUE, 0),
                          (TX_OFFSET, TX_BYTE, 0)], writes)
        reads = [row['payload'] for row in responses
                 if row['payload']['direction'] == 'read']
        self.assertEqual(1, len(reads))
        self.assertEqual(RX_OFFSET, reads[0]['araddr'])

    def test_the_projected_read_carries_the_value_the_rtl_returned(self):
        """Cross-check the projection against the session's own real read.

        The value decoded from the trace must be the value the register member
        received from the RTL, so the projection is not reading back anything
        the test wrote into a Python-side record.
        """
        events, _ = self.project()
        reads = [row['payload'] for row in events
                 if row['event_type'] == 'transaction_response'
                 and row['payload']['direction'] == 'read']
        self.assertEqual(1, len(reads))
        self.assertEqual(self.read_back, reads[0]['rdata'],
                         'the tapped read data must equal the real RTL answer')

    def test_a_compliant_real_slave_produces_no_violation(self):
        _, violations = self.project()
        self.assertEqual([], [row['payload']['violation_code']
                              for row in violations])

    def test_projected_events_trace_back_to_real_raw_sample_indices(self):
        """Every projection names the raw sample index it was decoded from."""
        events, _ = self.project()
        sample_count = len(self.samples)
        self.assertGreater(sample_count, 0)
        for event in events:
            self.assertTrue(event['raw_event_refs'],
                            'a projection must name the sample it came from')
            for ref in event['raw_event_refs']:
                self.assertTrue(1 <= ref <= sample_count,
                                f'raw reference {ref} is outside the real samples')
                self.assertTrue(event['local_event_id'].endswith(str(ref)) or
                                f'|{event["tick"]}|' in event['local_event_id'])
            self.assertEqual(event['tick'],
                             self.samples[event['raw_event_refs'][0] - 1]['local_tick'])


if __name__ == '__main__':
    unittest.main()
