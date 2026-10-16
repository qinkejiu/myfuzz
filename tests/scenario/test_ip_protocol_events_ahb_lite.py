"""AHB-Lite target address and data phases from passive physical taps."""
import unittest

from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer


WIDTHS = {'haddr': 32, 'hwdata': 32, 'hsel': 1, 'hwrite': 1,
          'hreadyin': 1, 'htrans': 2, 'hsize': 3, 'hresp': 1,
          'hreadyout': 1, 'hrdata': 32}


def trace():
    return {'schema_version': 'ip_protocol_trace.v1', 'protocol': 'ahb-lite',
            'endpoint_id': 'sha256.bus', 'clock_domain': 'core',
            'max_wait_cycles': 3,
            'signals': {role: 'trace_' + role for role in WIDTHS},
            'signal_widths': dict(WIDTHS)}


def sample(tick, **signals):
    values = {role: 0 for role in WIDTHS}
    values.update(hsize=2, hreadyin=1, hreadyout=1)
    values.update(signals)
    return {'event_id': tick, 'kind': 'local_tick_sample',
            'local_tick': tick, 'phase': 'pre',
            'outputs': {'backend': {'trace_' + role: value
                                    for role, value in values.items()}}}


class AhbLiteEventTests(unittest.TestCase):
    def setUp(self):
        self.projection = IpProtocolEventNormalizer(
            component_id='caliptra_sha256', instance_id='sha256',
            protocol_trace=trace())
        self.checker = IpProtocolChecker(
            component_id='caliptra_sha256', instance_id='sha256',
            protocol_trace=trace())

    def feed(self, tick, *, epoch=0, **signals):
        raw = sample(tick, **signals)
        return (self.projection.consume_local_tick(raw, reset_epoch=epoch),
                self.checker.consume_local_tick(raw, reset_epoch=epoch))

    def test_write_and_read_keep_address_and_data_phases_separate(self):
        offered, violations = self.feed(1, hsel=1, htrans=2, hwrite=1,
                                         haddr=0x80, hwdata=0xDEAD)
        self.assertEqual([], list(violations))
        self.assertEqual(['transaction_request', 'transaction_accept'],
                         [e['event_type'] for e in offered])
        completed, violations = self.feed(2, hwdata=0x12345678)
        self.assertEqual([], list(violations))
        self.assertEqual(['transaction_response'],
                         [e['event_type'] for e in completed])
        self.assertEqual(0x12345678, completed[0]['payload']['value'])
        self.assertEqual([1], completed[0]['related_request_event_refs'])
        offered, violations = self.feed(3, hsel=1, htrans=2, haddr=0x00)
        self.assertEqual([], list(violations))
        self.assertEqual(['transaction_request', 'transaction_accept'],
                         [e['event_type'] for e in offered])
        completed, violations = self.feed(4, hrdata=0x43414c49)
        self.assertEqual([], list(violations))
        self.assertEqual(0x43414c49, completed[0]['payload']['value'])
        self.assertEqual('read', completed[0]['payload']['direction'])

    def test_wait_observation_and_reset_cancel(self):
        events, violations = self.feed(1, hsel=1, htrans=2, haddr=4,
                                        hreadyin=0, hreadyout=0)
        self.assertEqual(['transaction_request', 'wait_observation'],
                         [e['event_type'] for e in events])
        self.assertEqual([], list(violations))
        events, violations = self.feed(2, epoch=1)
        self.assertEqual(['transaction_cancel'], [e['event_type'] for e in events])
        self.assertEqual(0, events[0]['reset_epoch'])
        self.assertEqual([], list(violations))

    def test_ready_inputs_have_distinct_address_and_data_roles(self):
        events, violations = self.feed(1, hsel=1, htrans=2, haddr=8,
                                        hreadyin=1, hreadyout=0)
        self.assertEqual(['transaction_request', 'transaction_accept'],
                         [e['event_type'] for e in events])
        self.assertEqual([], list(violations))
        events, violations = self.feed(2, hreadyin=1, hreadyout=0)
        self.assertEqual(['wait_observation'],
                         [e['event_type'] for e in events])
        self.assertEqual([], list(violations))
        events, violations = self.feed(3, hreadyin=0, hreadyout=1, hrdata=9)
        self.assertEqual(['transaction_response'],
                         [e['event_type'] for e in events])
        self.assertEqual([], list(violations))

    def test_checker_rejects_changed_stalled_address_and_nonword(self):
        self.feed(1, hsel=1, htrans=2, haddr=0x80,
                  hreadyin=0, hreadyout=0)
        _, violations = self.feed(2, hsel=1, htrans=2, haddr=0x84,
                                  hreadyin=0, hreadyout=0)
        self.assertIn('ahb_address_changed_while_waiting',
                      [v['payload']['violation_code'] for v in violations])
        self.feed(3, epoch=1)
        _, violations = self.feed(4, epoch=1, hsel=1, htrans=2,
                                  haddr=0x83, hsize=0)
        self.assertIn('ahb_unaligned_or_nonword_transfer',
                      [v['payload']['violation_code'] for v in violations])

    def test_checker_requires_exact_physical_widths(self):
        wrong = trace()
        wrong['signal_widths']['htrans'] = 1
        with self.assertRaisesRegex(ValueError, 'trace-signals-invalid'):
            IpProtocolChecker(component_id='caliptra_sha256',
                instance_id='sha256', protocol_trace=wrong)


if __name__ == '__main__':
    unittest.main()
