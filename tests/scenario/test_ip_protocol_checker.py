from __future__ import annotations

import importlib
from types import SimpleNamespace
import unittest


def checker_type():
    module = importlib.import_module('myfuzz.scenario.ip_protocol_checker')
    checker = getattr(module, 'IpProtocolChecker', None)
    if checker is None:
        raise AssertionError('component-neutral IP protocol checker is missing')
    return checker


def trace(protocol, roles, widths, *, max_wait=2):
    return {
        'schema_version': 'ip_protocol_trace.v1',
        'protocol': protocol,
        'endpoint_id': 'opaque.bus',
        'clock_domain': 'bus_clk',
        'max_wait_cycles': max_wait,
        'signals': {role: 'trace_' + role for role in roles},
        'signal_widths': dict(widths),
    }


class IpProtocolCheckerTests(unittest.TestCase):
    def checker(self, protocol, roles, widths, *, max_wait=2):
        return checker_type()(
            component_id='anonymous_ip', instance_id='dut0',
            protocol_trace=trace(protocol, roles, widths, max_wait=max_wait))

    @staticmethod
    def raw(event_id, tick, backend):
        return {
            'event_id': event_id, 'kind': 'local_tick_sample',
            'component': 'dut0', 'local_tick': tick, 'phase': 'pre',
            'outputs': {'backend': {'trace_' + key: value
                                    for key, value in backend.items()}},
        }

    @staticmethod
    def tlul(**updates):
        values = {
            'a_valid': 0, 'a_ready': 1, 'a_source': 0, 'a_opcode': 4,
            'a_size': 0, 'a_address': 0x20, 'a_mask': 1, 'a_data': 0,
            'd_valid': 0, 'd_ready': 1, 'd_opcode': 1, 'd_size': 0,
            'd_source': 0, 'd_data': 0,
            'd_error': 0,
        }
        values.update(updates)
        return values

    def tl_checker(self, *, max_wait=2):
        roles = ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_size',
                 'a_address', 'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_source',
                 'd_opcode', 'd_size', 'd_data', 'd_error')
        widths = {'a_valid': 1, 'a_ready': 1, 'a_source': 8, 'a_opcode': 3,
                  'a_size': 2, 'a_address': 32, 'a_mask': 4, 'a_data': 32,
                  'd_valid': 1, 'd_ready': 1, 'd_opcode': 3, 'd_size': 2,
                  'd_source': 8, 'd_data': 32, 'd_error': 1}
        return self.checker('tl-ul', roles, widths, max_wait=max_wait)

    def test_tlul_allows_zero_get_and_partial_masks_and_checks_stalled_payload(self):
        for opcode in (1, 4):
            checker = self.tl_checker()
            zero_mask = checker.consume_local_tick(
                self.raw(1, 1, self.tlul(a_valid=1, a_ready=1,
                                         a_opcode=opcode, a_mask=0)),
                reset_epoch=0)
            self.assertFalse(zero_mask)

        full_write = self.tl_checker().consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=1, a_opcode=0, a_mask=0)),
            reset_epoch=0)
        self.assertEqual(['tlul_mask_mismatch'],
                         [row['payload']['violation_code'] for row in full_write])

        checker = self.tl_checker()
        checker.consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=1, a_ready=0)), reset_epoch=0)
        changed = checker.consume_local_tick(
            self.raw(2, 2, self.tlul(a_valid=1, a_ready=0, a_address=0x24)),
            reset_epoch=0)
        self.assertIn('tlul_a_payload_changed_while_stalled',
                      [row['payload']['violation_code'] for row in changed])

    def test_tlul_rejects_duplicate_delivery_and_unmatched_or_duplicate_response(self):
        checker = self.tl_checker()
        checker.consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=1, a_source=3)), reset_epoch=0)
        duplicate_request = checker.consume_local_tick(
            self.raw(2, 2, self.tlul(a_valid=1, a_source=3)), reset_epoch=0)
        self.assertEqual(['tlul_source_already_outstanding'],
                         [row['payload']['violation_code']
                          for row in duplicate_request])

        unmatched = checker.consume_local_tick(
            self.raw(3, 3, self.tlul(d_valid=1, d_source=7)), reset_epoch=0)
        self.assertIn('tlul_response_without_outstanding_request',
                      [row['payload']['violation_code'] for row in unmatched])
        checker.consume_local_tick(
            self.raw(4, 4, self.tlul(d_valid=1, d_source=3)), reset_epoch=0)
        duplicate_response = checker.consume_local_tick(
            self.raw(5, 5, self.tlul(d_valid=1, d_source=3)), reset_epoch=0)
        self.assertEqual(['tlul_response_without_outstanding_request'],
                         [row['payload']['violation_code']
                          for row in duplicate_response])

    def test_tlul_wait_budget_reports_once_and_allows_late_correlated_response(self):
        checker = self.tl_checker(max_wait=2)
        checker.consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=1, a_source=9)), reset_epoch=0)
        first_wait = checker.consume_local_tick(
            self.raw(2, 2, self.tlul()), reset_epoch=0)
        second_wait = checker.consume_local_tick(
            self.raw(3, 3, self.tlul()), reset_epoch=0)
        later_wait = checker.consume_local_tick(
            self.raw(4, 4, self.tlul()), reset_epoch=0)
        self.assertFalse(first_wait)
        self.assertEqual(['tlul_response_wait_budget_exceeded'],
                         [row['payload']['violation_code'] for row in second_wait])
        self.assertFalse(later_wait)
        self.assertFalse(checker.consume_local_tick(
            self.raw(5, 5, self.tlul(d_valid=1, d_source=9)), reset_epoch=0))

    def test_tlul_response_payload_stays_stable_while_backpressured(self):
        checker = self.tl_checker()
        checker.consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=1, a_source=4, d_ready=0)),
            reset_epoch=0)
        self.assertFalse(checker.consume_local_tick(
            self.raw(2, 2, self.tlul(d_valid=1, d_ready=0,
                                     d_source=4, d_data=0x55)), reset_epoch=0))
        changed = checker.consume_local_tick(
            self.raw(3, 3, self.tlul(d_valid=1, d_ready=0,
                                     d_source=4, d_data=0x56)), reset_epoch=0)
        self.assertEqual(['tlul_d_payload_changed_while_stalled'],
                         [row['payload']['violation_code'] for row in changed])

    def test_tlul_signal_width_contract_rejects_out_of_range_handshake(self):
        checker = self.tl_checker()
        out_of_range = checker.consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=2)), reset_epoch=0)
        self.assertEqual(['tlul_signal_out_of_range'],
                         [row['payload']['violation_code'] for row in out_of_range])

    def test_tlul_mask_must_stay_within_size_and_address_byte_lanes(self):
        checker = self.tl_checker()
        valid = checker.consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=1, a_size=1,
                                     a_address=0x22, a_mask=0b1100)),
            reset_epoch=0)
        self.assertFalse(valid)
        checker = self.tl_checker()
        outside = checker.consume_local_tick(
            self.raw(2, 2, self.tlul(a_valid=1, a_size=1,
                                     a_address=0x22, a_mask=0b0011,
                                     a_opcode=1)),
            reset_epoch=0)
        self.assertEqual(['tlul_mask_outside_transfer'],
                         [row['payload']['violation_code'] for row in outside])

        checker = self.tl_checker()
        narrow_get = checker.consume_local_tick(
            self.raw(3, 3, self.tlul(a_valid=1, a_size=2,
                                     a_address=0x20, a_mask=0b0011)),
            reset_epoch=0)
        self.assertFalse(narrow_get)
        checker = self.tl_checker()
        oversized_get = checker.consume_local_tick(
            self.raw(4, 4, self.tlul(a_valid=1, a_size=0,
                                     a_address=0x20, a_mask=0b0011)),
            reset_epoch=0)
        self.assertEqual(['tlul_mask_exceeds_size'],
                         [row['payload']['violation_code']
                          for row in oversized_get])
        checker = self.tl_checker()
        noncontiguous_get = checker.consume_local_tick(
            self.raw(5, 5, self.tlul(a_valid=1, a_size=2,
                                     a_address=0x20, a_mask=0b0101)),
            reset_epoch=0)
        self.assertEqual(['tlul_noncontiguous_mask'],
                         [row['payload']['violation_code']
                          for row in noncontiguous_get])
        incomplete_put_full = self.tl_checker().consume_local_tick(
            self.raw(6, 6, self.tlul(a_valid=1, a_opcode=0, a_size=2,
                                     a_address=0x20, a_mask=0b0001)),
            reset_epoch=0)
        self.assertEqual(['tlul_mask_mismatch'],
                         [row['payload']['violation_code']
                          for row in incomplete_put_full])
        valid_partial = self.tl_checker().consume_local_tick(
            self.raw(7, 7, self.tlul(a_valid=1, a_opcode=1, a_size=2,
                                     a_address=0x20, a_mask=0b0101)),
            reset_epoch=0)
        self.assertFalse(valid_partial)
        unsupported = self.tl_checker().consume_local_tick(
            self.raw(8, 8, self.tlul(a_valid=1, a_opcode=2)), reset_epoch=0)
        self.assertEqual(['tlul_unsupported_opcode'],
                         [row['payload']['violation_code'] for row in unsupported])

    def test_tlul_unmatched_stalled_response_cannot_bind_to_later_request(self):
        checker = self.tl_checker()
        unmatched_offer = checker.consume_local_tick(
            self.raw(1, 1, self.tlul(d_valid=1, d_ready=0, d_source=5)),
            reset_epoch=0)
        self.assertEqual(['tlul_response_without_outstanding_request'],
                         [row['payload']['violation_code']
                          for row in unmatched_offer])

        checker.consume_local_tick(
            self.raw(2, 2, self.tlul(a_valid=1, a_source=5,
                                     d_valid=1, d_ready=0, d_source=5)),
            reset_epoch=0)
        checker.consume_local_tick(
            self.raw(3, 3, self.tlul(d_valid=1, d_ready=1, d_source=5)),
            reset_epoch=0)
        duplicate = checker.consume_local_tick(
            self.raw(4, 4, self.tlul(a_valid=1, a_source=5, d_ready=0)),
            reset_epoch=0)
        self.assertEqual(['tlul_source_already_outstanding'],
                         [row['payload']['violation_code'] for row in duplicate])

    def test_tlul_allows_same_cycle_request_acceptance_and_response_offer(self):
        checker = self.tl_checker()
        same_cycle = checker.consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=1, a_source=4,
                                     d_valid=1, d_source=4)),
            reset_epoch=0)
        self.assertFalse(same_cycle)

        checker = self.tl_checker()
        stalled_offer = checker.consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=1, a_source=4,
                                     d_valid=1, d_ready=0, d_source=4)),
            reset_epoch=0)
        self.assertFalse(stalled_offer)
        accepted_offer = checker.consume_local_tick(
            self.raw(2, 2, self.tlul(d_valid=1, d_source=4)), reset_epoch=0)
        self.assertFalse(accepted_offer)

    def test_tlul_response_opcode_and_size_match_the_request(self):
        checker = self.tl_checker()
        checker.consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=1, a_opcode=4, a_size=1,
                                     a_address=0x20, a_mask=0b0011,
                                     a_source=4)), reset_epoch=0)
        mismatch = checker.consume_local_tick(
            self.raw(2, 2, self.tlul(d_valid=1, d_source=4,
                                     d_opcode=0, d_size=0)), reset_epoch=0)
        codes = [row['payload']['violation_code'] for row in mismatch]
        self.assertIn('tlul_response_opcode_mismatch', codes)
        self.assertIn('tlul_response_size_mismatch', codes)

    def test_tlul_all_outstanding_sources_age_during_another_response_handshake(self):
        checker = self.tl_checker(max_wait=2)
        checker.consume_local_tick(
            self.raw(1, 1, self.tlul(a_valid=1, a_source=1)), reset_epoch=0)
        checker.consume_local_tick(
            self.raw(2, 2, self.tlul(a_valid=1, a_source=2)), reset_epoch=0)
        first_response = checker.consume_local_tick(
            self.raw(3, 3, self.tlul(d_valid=1, d_source=1)), reset_epoch=0)
        self.assertFalse(first_response)
        second_source_wait = checker.consume_local_tick(
            self.raw(4, 4, self.tlul()), reset_epoch=0)
        self.assertEqual(['tlul_response_wait_budget_exceeded'],
                         [row['payload']['violation_code']
                          for row in second_source_wait])

    def test_apb_requires_setup_and_stable_payload_until_completion(self):
        roles = ('psel', 'penable', 'pwrite', 'paddr', 'pwdata', 'pready',
                 'prdata', 'pslverr')
        widths = {'psel': 1, 'penable': 1, 'pwrite': 1, 'paddr': 12,
                  'pwdata': 32, 'pready': 1, 'prdata': 32, 'pslverr': 1}
        checker = self.checker('apb3', roles, widths)
        no_setup = checker.consume_local_tick(self.raw(1, 1, {
            'psel': 1, 'penable': 1, 'pwrite': 0, 'paddr': 0x20,
            'pwdata': 0, 'pready': 0, 'prdata': 0, 'pslverr': 0,
        }), reset_epoch=0)
        self.assertEqual(['apb_access_without_setup'],
                         [row['payload']['violation_code'] for row in no_setup])

        checker = self.checker('apb3', roles, widths)
        checker.consume_local_tick(self.raw(1, 1, {
            'psel': 1, 'penable': 0, 'pwrite': 1, 'paddr': 0x20,
            'pwdata': 0x55, 'pready': 0, 'prdata': 0, 'pslverr': 0,
        }), reset_epoch=0)
        changed = checker.consume_local_tick(self.raw(2, 2, {
            'psel': 1, 'penable': 1, 'pwrite': 1, 'paddr': 0x24,
            'pwdata': 0x55, 'pready': 0, 'prdata': 0, 'pslverr': 0,
        }), reset_epoch=0)
        self.assertEqual(['apb_payload_changed_during_access'],
                         [row['payload']['violation_code'] for row in changed])

    def test_apb_wait_budget_is_bounded_and_reset_clears_pending_transaction(self):
        roles = ('psel', 'penable', 'pwrite', 'paddr', 'pwdata', 'pready',
                 'prdata', 'pslverr')
        widths = {'psel': 1, 'penable': 1, 'pwrite': 1, 'paddr': 12,
                  'pwdata': 32, 'pready': 1, 'prdata': 32, 'pslverr': 1}
        checker = self.checker('apb3', roles, widths, max_wait=1)
        checker.consume_local_tick(self.raw(1, 1, {
            'psel': 1, 'penable': 0, 'pwrite': 0, 'paddr': 0x10,
            'pwdata': 0, 'pready': 0, 'prdata': 0, 'pslverr': 0,
        }), reset_epoch=0)
        wait = checker.consume_local_tick(self.raw(2, 2, {
            'psel': 1, 'penable': 1, 'pwrite': 0, 'paddr': 0x10,
            'pwdata': 0, 'pready': 0, 'prdata': 0, 'pslverr': 0,
        }), reset_epoch=0)
        self.assertEqual(['apb_wait_budget_exceeded'],
                         [row['payload']['violation_code'] for row in wait])
        after_reset = checker.consume_local_tick(self.raw(3, 3, {
            'psel': 1, 'penable': 1, 'pwrite': 0, 'paddr': 0x10,
            'pwdata': 0, 'pready': 0, 'prdata': 0, 'pslverr': 0,
        }), reset_epoch=1)
        self.assertEqual(['apb_access_without_setup'],
                         [row['payload']['violation_code'] for row in after_reset])

    def test_wishbone_checks_select_width_stall_stability_and_response_once(self):
        roles = ('cyc', 'stb', 'we', 'adr', 'dat_w', 'sel', 'ack', 'stall',
                 'dat_r')
        widths = {'cyc': 1, 'stb': 1, 'we': 1, 'adr': 16, 'dat_w': 32,
                  'sel': 4, 'ack': 1, 'stall': 1, 'dat_r': 32}
        checker = self.checker('wishbone', roles, widths)
        out_of_range = checker.consume_local_tick(self.raw(1, 1, {
            'cyc': 1, 'stb': 1, 'we': 1, 'adr': 4, 'dat_w': 5,
            'sel': 16, 'ack': 0, 'stall': 0, 'dat_r': 0,
        }), reset_epoch=0)
        self.assertEqual(['wishbone_signal_out_of_range'],
                         [row['payload']['violation_code'] for row in out_of_range])

        checker = self.checker('wishbone', roles, widths)
        checker.consume_local_tick(self.raw(1, 1, {
            'cyc': 1, 'stb': 1, 'we': 1, 'adr': 4, 'dat_w': 5,
            'sel': 1, 'ack': 0, 'stall': 1, 'dat_r': 0,
        }), reset_epoch=0)
        changed = checker.consume_local_tick(self.raw(2, 2, {
            'cyc': 1, 'stb': 1, 'we': 1, 'adr': 8, 'dat_w': 5,
            'sel': 1, 'ack': 0, 'stall': 1, 'dat_r': 0,
        }), reset_epoch=0)
        self.assertIn('wishbone_request_changed_while_stalled',
                      [row['payload']['violation_code'] for row in changed])

        checker = self.checker('wishbone', roles, widths)
        checker.consume_local_tick(self.raw(1, 1, {
            'cyc': 1, 'stb': 1, 'we': 0, 'adr': 4, 'dat_w': 0,
            'sel': 0, 'ack': 0, 'stall': 0, 'dat_r': 0,
        }), reset_epoch=0)
        self.assertFalse(checker.consume_local_tick(self.raw(2, 2, {
            'cyc': 1, 'stb': 0, 'we': 0, 'adr': 4, 'dat_w': 0,
            'sel': 0, 'ack': 1, 'stall': 0, 'dat_r': 0x55,
        }), reset_epoch=0))
        repeated = checker.consume_local_tick(self.raw(3, 3, {
            'cyc': 1, 'stb': 0, 'we': 0, 'adr': 4, 'dat_w': 0,
            'sel': 0, 'ack': 1, 'stall': 0, 'dat_r': 0x55,
        }), reset_epoch=0)
        self.assertEqual(['wishbone_response_without_request'],
                         [row['payload']['violation_code'] for row in repeated])

    def test_wishbone_wait_budget_is_bounded(self):
        roles = ('cyc', 'stb', 'we', 'adr', 'dat_w', 'sel', 'ack', 'stall',
                 'dat_r')
        widths = {'cyc': 1, 'stb': 1, 'we': 1, 'adr': 16, 'dat_w': 32,
                  'sel': 4, 'ack': 1, 'stall': 1, 'dat_r': 32}
        checker = self.checker('wishbone', roles, widths, max_wait=1)
        stalled = checker.consume_local_tick(self.raw(1, 1, {
            'cyc': 1, 'stb': 1, 'we': 1, 'adr': 4, 'dat_w': 5,
            'sel': 1, 'ack': 0, 'stall': 1, 'dat_r': 0,
        }), reset_epoch=0)
        self.assertEqual(['wishbone_request_wait_budget_exceeded'],
                         [row['payload']['violation_code'] for row in stalled])

        checker = self.checker('wishbone', roles, widths)
        self.assertFalse(checker.consume_local_tick(self.raw(1, 1, {
            'cyc': 1, 'stb': 1, 'we': 1, 'adr': 4, 'dat_w': 5,
            'sel': 1, 'ack': 0, 'stall': 0, 'dat_r': 0,
        }), reset_epoch=0))
        self.assertFalse(checker.consume_local_tick(self.raw(2, 2, {
            'cyc': 1, 'stb': 0, 'we': 1, 'adr': 4, 'dat_w': 5,
            'sel': 1, 'ack': 0, 'stall': 0, 'dat_r': 0,
        }), reset_epoch=0))
        late = checker.consume_local_tick(self.raw(3, 3, {
            'cyc': 1, 'stb': 0, 'we': 1, 'adr': 4, 'dat_w': 5,
            'sel': 1, 'ack': 0, 'stall': 0, 'dat_r': 0,
        }), reset_epoch=0)
        self.assertEqual(['wishbone_response_wait_budget_exceeded'],
                         [row['payload']['violation_code'] for row in late])

    def test_runner_records_protocol_violation_and_fails_the_run(self):
        from myfuzz.local_harness.request import load_local_harness_request
        from myfuzz.scenario.ownership import compile_ownership
        from myfuzz.scenario.runner import ScenarioRunner

        request = load_local_harness_request({
            'schema_version': 'local_harness.v2',
            'profile_path': 'configs/peripherals/opentitan_uart_local/component_profile.json',
            'instance_id': 'dut0', 'reset_assert_ticks': 1,
            'reset_release_ticks': 0, 'max_wait_cycles': 2, 'tuning': {},
        })
        profile = SimpleNamespace(component_id='anonymous_ip', endpoints=(
            SimpleNamespace(endpoint_id='opaque.bus', clock='bus_clk'),))
        roles = ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_size',
                 'a_address', 'a_mask', 'a_data', 'd_valid', 'd_ready',
                 'd_opcode', 'd_size', 'd_source', 'd_data', 'd_error')
        widths = {'a_valid': 1, 'a_ready': 1, 'a_source': 8, 'a_opcode': 3,
                  'a_size': 2, 'a_address': 32, 'a_mask': 4, 'a_data': 32,
                  'd_valid': 1, 'd_ready': 1, 'd_opcode': 3, 'd_size': 2,
                  'd_source': 8, 'd_data': 32, 'd_error': 1}
        artifact = SimpleNamespace(runtime_document={
            'kind': 'tlul_register_observe',
            'base_event_schema_version': 'ip_base_event.v1',
            'base_protocol_trace': trace('tl-ul', roles, widths),
            'clock_schedule': {'primary_clock_domain': 'bus_clk'},
            'effective_max_wait_cycles': 2, 'physical_exports': [],
        }, plan=SimpleNamespace(request=request, profile=profile))

        class Session:
            reset_epoch = 0

            def __init__(self):
                self.artifact = artifact

            def drain_tick_samples(self):
                return [{'local_tick': 1,
                         'pre': {'backend': {
                             'trace_a_valid': 1, 'trace_a_ready': 1,
                             'trace_a_source': 6, 'trace_a_opcode': 2,
                             'trace_a_size': 2,
                             'trace_a_address': 0x20, 'trace_a_mask': 1,
                             'trace_a_data': 0, 'trace_d_valid': 0,
                             'trace_d_opcode': 1, 'trace_d_size': 2,
                             'trace_d_ready': 1, 'trace_d_source': 0,
                             'trace_d_data': 0, 'trace_d_error': 0}},
                         'post': {'backend': {}}}]

        runner = ScenarioRunner(sessions={'dut0': Session()},
                                ownership=compile_ownership((), ()), bindings=())
        runner._status = 'running'
        runner.local_ticks['dut0'] = 1
        runner._drain_tick_samples(producer_event_id=1)
        violation = next(row for row in runner._events
                         if row.get('kind') == 'protocol_violation')
        self.assertEqual('tlul_unsupported_opcode',
                         violation['payload']['violation_code'])
        self.assertEqual('protocol_violation', runner.failure_status)
        self.assertEqual('failed', runner._status)


if __name__ == '__main__':
    unittest.main()
