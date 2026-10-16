"""Protocol-contract checks for a real AXI4-Lite slave endpoint.

The normalizer tests in ``test_ip_protocol_events_axi4_lite`` pin what the
generic layer *reports*.  These tests pin what the checker *refuses*: the rules
that hold for any AXI4-Lite endpoint regardless of what registers it contains,
and only those.  A rule the protocol does not state is never reported, so a
slave that merely takes a long time is distinguished from a slave that breaks a
channel invariant.
"""
from __future__ import annotations

import importlib
import unittest


AXI4_LITE_ROLES = (
    'awvalid', 'awready', 'awaddr', 'awprot',
    'wvalid', 'wready', 'wdata', 'wstrb',
    'bvalid', 'bready', 'bresp',
    'arvalid', 'arready', 'araddr', 'arprot',
    'rvalid', 'rready', 'rdata', 'rresp',
)
WIDTHS = {
    'awvalid': 1, 'awready': 1, 'awaddr': 32, 'awprot': 3,
    'wvalid': 1, 'wready': 1, 'wdata': 32, 'wstrb': 4,
    'bvalid': 1, 'bready': 1, 'bresp': 2,
    'arvalid': 1, 'arready': 1, 'araddr': 32, 'arprot': 3,
    'rvalid': 1, 'rready': 1, 'rdata': 32, 'rresp': 2,
}


def checker_type():
    module = importlib.import_module('myfuzz.scenario.ip_protocol_checker')
    checker = getattr(module, 'IpProtocolChecker', None)
    if checker is None:
        raise AssertionError('component-neutral IP protocol checker is missing')
    return checker


def trace(*, max_wait=2, widths=None):
    return {
        'schema_version': 'ip_protocol_trace.v1',
        'protocol': 'axi4-lite',
        'endpoint_id': 'uart.bus',
        'clock_domain': 'sys_clk',
        'max_wait_cycles': max_wait,
        'signals': {role: 'trace_' + role for role in AXI4_LITE_ROLES},
        'signal_widths': dict(widths or WIDTHS),
    }


class Axi4LiteCheckerTests(unittest.TestCase):
    def checker(self, **kwargs):
        return checker_type()(component_id='zipcpu_axiluart', instance_id='uart0',
                              protocol_trace=trace(**kwargs))

    @staticmethod
    def raw(checker, tick, **drive):
        signals = {role: 0 for role in AXI4_LITE_ROLES}
        signals.update(drive)
        return {
            'event_id': tick, 'kind': 'local_tick_sample',
            'component': 'uart0', 'local_tick': tick, 'phase': 'pre',
            'outputs': {'backend': {checker._signals[role]: value
                                    for role, value in signals.items()}},
        }

    def codes(self, events):
        return [event['payload']['violation_code'] for event in events]

    def feed(self, checker, tick, *, epoch=0, **drive):
        return checker.consume_local_tick(self.raw(checker, tick, **drive),
                                          reset_epoch=epoch)

    # -- contract ---------------------------------------------------------
    def test_signal_contract_requires_consistent_data_and_strobe_widths(self):
        broken = dict(WIDTHS)
        broken['wstrb'] = 2  # 32-bit data needs four strobe bits
        with self.assertRaisesRegex(ValueError, 'trace-signals-invalid'):
            self.checker(widths=broken)
        mismatched = dict(WIDTHS)
        mismatched['rdata'] = 64  # both data channels are one width
        with self.assertRaisesRegex(ValueError, 'trace-signals-invalid'):
            self.checker(widths=mismatched)
        bad_code = dict(WIDTHS)
        bad_code['bresp'] = 1  # AXI4-Lite response codes are two bits
        with self.assertRaisesRegex(ValueError, 'trace-signals-invalid'):
            self.checker(widths=bad_code)

    # -- a compliant sequence reports nothing -----------------------------
    def test_compliant_write_and_read_sequence_reports_no_violation(self):
        checker = self.checker(max_wait=8)
        self.assertEqual((), self.feed(checker, 1, awvalid=1, awready=1,
                                       awaddr=0x4000c))
        self.assertEqual((), self.feed(checker, 2, wvalid=1, wready=1, wdata=0x41,
                                       wstrb=0b0001))
        self.assertEqual((), self.feed(checker, 3, bvalid=1, bready=1))
        self.assertEqual((), self.feed(checker, 4, arvalid=1, arready=1,
                                       araddr=0x40008))
        self.assertEqual((), self.feed(checker, 5, rvalid=1, rready=1, rdata=0x5a))

    def test_slow_but_progressing_channels_within_budget_are_not_violations(self):
        checker = self.checker(max_wait=8)
        self.assertEqual((), self.feed(checker, 1, arvalid=1, araddr=0x40008))
        self.assertEqual((), self.feed(checker, 2, arvalid=1, araddr=0x40008))
        self.assertEqual((), self.feed(checker, 3, arvalid=1, araddr=0x40008,
                                       arready=1))
        self.assertEqual((), self.feed(checker, 4, rvalid=1, rready=1, rdata=1))

    # -- payload stability -------------------------------------------------
    def test_address_payload_changing_while_stalled_is_reported(self):
        checker = self.checker(max_wait=8)
        self.feed(checker, 1, awvalid=1, awaddr=0x4000c)
        events = self.feed(checker, 2, awvalid=1, awaddr=0x40008)
        self.assertEqual(['axi4lite_payload_changed_while_stalled'],
                         self.codes(events))
        self.assertEqual({'awaddr': 0x4000c, 'awprot': 0},
                         events[0]['payload']['expected'])

    def test_write_data_changing_while_stalled_is_reported(self):
        checker = self.checker(max_wait=8)
        self.feed(checker, 1, wvalid=1, wdata=0x41, wstrb=0b0001)
        events = self.feed(checker, 2, wvalid=1, wdata=0x42, wstrb=0b0001)
        self.assertEqual(['axi4lite_payload_changed_while_stalled'],
                         self.codes(events))

    def test_read_address_changing_while_stalled_is_reported(self):
        checker = self.checker(max_wait=8)
        self.feed(checker, 1, arvalid=1, araddr=0x40008)
        events = self.feed(checker, 2, arvalid=1, araddr=0x4000c)
        self.assertEqual(['axi4lite_payload_changed_while_stalled'],
                         self.codes(events))

    # -- VALID must be held until READY -----------------------------------
    def test_valid_withdrawn_before_ready_is_reported_per_channel(self):
        checker = self.checker(max_wait=8)
        self.feed(checker, 1, awvalid=1, awaddr=0x4000c)
        self.assertEqual(['axi4lite_awvalid_withdrawn_before_ready'],
                         self.codes(self.feed(checker, 2)))
        self.feed(checker, 3, arvalid=1, araddr=0x40008)
        self.assertEqual(['axi4lite_arvalid_withdrawn_before_ready'],
                         self.codes(self.feed(checker, 4)))
        self.feed(checker, 5, wvalid=1, wdata=1, wstrb=1)
        self.assertEqual(['axi4lite_wvalid_withdrawn_before_ready'],
                         self.codes(self.feed(checker, 6)))

    # -- responses require their request ----------------------------------
    def test_response_without_a_request_is_reported(self):
        checker = self.checker()
        self.assertEqual(['axi4lite_write_response_without_request'],
                         self.codes(self.feed(checker, 1, bvalid=1, bready=1)))
        self.assertEqual(['axi4lite_read_response_without_request'],
                         self.codes(self.feed(checker, 2, rvalid=1, rready=1,
                                              rdata=7)))

    def test_second_write_accepted_while_a_response_is_outstanding_is_reported(self):
        checker = self.checker()
        self.feed(checker, 1, awvalid=1, awready=1, awaddr=0x4000c,
                  wvalid=1, wready=1, wdata=0x41, wstrb=1)
        events = self.feed(checker, 2, awvalid=1, awready=1, awaddr=0x40000,
                           wvalid=1, wready=1, wdata=0x42, wstrb=1)
        self.assertEqual(['axi4lite_write_accepted_with_response_outstanding'],
                         self.codes(events))

    def test_second_read_accepted_while_a_response_is_outstanding_is_reported(self):
        checker = self.checker()
        self.feed(checker, 1, arvalid=1, arready=1, araddr=0x40008)
        events = self.feed(checker, 2, arvalid=1, arready=1, araddr=0x4000c)
        self.assertEqual(['axi4lite_read_accepted_with_response_outstanding'],
                         self.codes(events))

    # -- wait budget -------------------------------------------------------
    def test_held_request_channel_beyond_budget_is_reported_once(self):
        checker = self.checker(max_wait=2)
        self.feed(checker, 1, arvalid=1, araddr=0x40008)
        self.assertEqual(['axi4lite_request_wait_budget_exceeded'],
                         self.codes(self.feed(checker, 2, arvalid=1,
                                              araddr=0x40008)))
        # A timeout is reported once per held request, not once per edge.
        self.assertEqual([], self.codes(self.feed(checker, 3, arvalid=1,
                                                  araddr=0x40008)))

    def test_held_response_is_not_a_request_budget_violation(self):
        """A pending B is slow, not illegal: the protocol states no such limit."""
        checker = self.checker(max_wait=2)
        self.feed(checker, 1, awvalid=1, awready=1, awaddr=0x4000c,
                  wvalid=1, wready=1, wdata=0x41, wstrb=1)
        self.assertEqual([], self.codes(self.feed(checker, 2, bvalid=1)))
        self.assertEqual([], self.codes(self.feed(checker, 3, bvalid=1)))
        self.assertEqual([], self.codes(self.feed(checker, 4, bvalid=1)))
        self.assertEqual([], self.codes(self.feed(checker, 5, bvalid=1, bready=1)))

    # -- reset -------------------------------------------------------------
    def test_reset_reopens_every_channel_group(self):
        checker = self.checker()
        self.feed(checker, 1, awvalid=1, awaddr=0x4000c)
        self.feed(checker, 2, arvalid=1, araddr=0x40008)
        self.assertEqual((), self.feed(checker, 3, epoch=1))
        # The stale request is gone: its own response is now unmatched.
        self.assertEqual(['axi4lite_write_response_without_request'],
                         self.codes(self.feed(checker, 4, epoch=1, bvalid=1,
                                              bready=1)))

    # -- same-edge handoff (independently reviewed defect) ------------------
    def test_back_to_back_handoff_on_one_edge_is_not_a_second_outstanding(self):
        """A response completing while the next request is accepted is legal.

        Processing requests before responses made the checker see the *new*
        write as a second outstanding transaction, even though the previous
        response had completed on the very same edge.
        """
        checker = self.checker(max_wait=8)
        self.feed(checker, 1, awvalid=1, awready=1, awaddr=0x4000c,
                  wvalid=1, wready=1, wdata=0x41, wstrb=1)
        # B of write #1 completes on the same edge that AW/W of write #2 arrive.
        events = self.feed(checker, 2, bvalid=1, bready=1,
                           awvalid=1, awready=1, awaddr=0x40000,
                           wvalid=1, wready=1, wdata=0x42, wstrb=1)
        self.assertEqual([], self.codes(events))

    def test_back_to_back_read_handoff_on_one_edge_is_not_a_second_outstanding(self):
        checker = self.checker(max_wait=8)
        self.feed(checker, 1, arvalid=1, arready=1, araddr=0x40008)
        events = self.feed(checker, 2, rvalid=1, rready=1, rdata=1,
                           arvalid=1, arready=1, araddr=0x4000c)
        self.assertEqual([], self.codes(events))

    def test_a_genuinely_second_outstanding_write_is_still_reported(self):
        """The single-outstanding rule must survive the reordering."""
        checker = self.checker(max_wait=8)
        self.feed(checker, 1, awvalid=1, awready=1, awaddr=0x4000c,
                  wvalid=1, wready=1, wdata=0x41, wstrb=1)
        # No response has completed, so a second accepted write is a violation.
        events = self.feed(checker, 2, awvalid=1, awready=1, awaddr=0x40000,
                           wvalid=1, wready=1, wdata=0x42, wstrb=1)
        self.assertEqual(['axi4lite_write_accepted_with_response_outstanding'],
                         self.codes(events))
    # -- re-accepted address (second independently reviewed defect) ---------
    def test_a_second_accepted_address_before_completion_is_reported(self):
        """A silent address overwrite would make the answered write unidentifiable."""
        checker = self.checker(max_wait=8)
        self.assertEqual((), self.feed(checker, 1, awvalid=1, awready=1,
                                       awaddr=0x4000c))
        events = self.feed(checker, 2, awvalid=1, awready=1, awaddr=0x40000)
        self.assertEqual(['axi4lite_address_reaccepted_before_completion'],
                         self.codes(events))
        self.assertEqual(0x4000c, events[0]['payload']['accepted_address'])
        self.assertEqual(0x40000, events[0]['payload']['observed_address'])

    def test_repeating_an_address_while_it_is_merely_stalled_is_not_a_violation(self):
        """VALID is held until READY, so re-presenting the same address is normal."""
        checker = self.checker(max_wait=8)
        self.feed(checker, 1, awvalid=1, awaddr=0x4000c)
        self.assertEqual([], self.codes(self.feed(checker, 2, awvalid=1,
                                                  awaddr=0x4000c)))


if __name__ == '__main__':
    unittest.main()
