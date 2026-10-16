from __future__ import annotations

import importlib
from types import SimpleNamespace
import unittest


def normalizer_type():
    module = importlib.import_module('myfuzz.scenario.ip_protocol_events')
    normalizer = getattr(module, 'IpProtocolEventNormalizer', None)
    if normalizer is None:
        raise AssertionError('component-neutral IP protocol event normalizer is missing')
    return normalizer


def trace(protocol, roles, *, endpoint='opaque.bus', max_wait=2):
    widths = {
        'a_valid': 1, 'a_ready': 1, 'a_source': 8, 'a_opcode': 3,
        'a_size': 2,
        'a_address': 32, 'a_mask': 4, 'a_data': 32,
        'd_valid': 1, 'd_ready': 1, 'd_opcode': 3, 'd_size': 2,
        'd_source': 8, 'd_data': 32,
        'd_error': 1, 'psel': 1, 'penable': 1, 'pwrite': 1,
        'paddr': 12, 'pwdata': 32, 'pready': 1, 'prdata': 32,
        'pslverr': 1, 'cyc': 1, 'stb': 1, 'we': 1, 'adr': 32,
        'dat_w': 32, 'sel': 4, 'ack': 1, 'stall': 1, 'dat_r': 32,
    }
    return {
        'schema_version': 'ip_protocol_trace.v1',
        'protocol': protocol,
        'endpoint_id': endpoint,
        'clock_domain': 'bus_clk',
        'max_wait_cycles': max_wait,
        'signals': {role: 'trace_' + role for role in roles},
        'signal_widths': {role: widths[role] for role in roles},
    }


class IpProtocolEventNormalizerTests(unittest.TestCase):
    def normalizer(self, protocol, roles, *, max_wait=2):
        return normalizer_type()(
            component_id='anonymous_ip', instance_id='dut0',
            protocol_trace=trace(protocol, roles, max_wait=max_wait))

    def test_rejects_malformed_protocol_and_aliased_backend_signal_contracts(self):
        roles = ('psel', 'penable', 'pwrite', 'paddr', 'pwdata', 'pready',
                 'prdata', 'pslverr')
        malformed_protocol = trace('apb3', roles)
        malformed_protocol['protocol'] = []
        with self.assertRaisesRegex(ValueError, 'trace-contract-invalid'):
            normalizer_type()(component_id='anonymous_ip', instance_id='dut0',
                              protocol_trace=malformed_protocol)

        aliased_signals = trace('apb3', roles)
        aliased_signals['signals']['penable'] = aliased_signals['signals']['psel']
        with self.assertRaisesRegex(ValueError, 'trace-signals-invalid'):
            normalizer_type()(component_id='anonymous_ip', instance_id='dut0',
                              protocol_trace=aliased_signals)

    @staticmethod
    def raw(event_id, tick, backend):
        return {
            'event_id': event_id, 'kind': 'local_tick_sample',
            'component': 'dut0', 'local_tick': tick, 'phase': 'pre',
            'outputs': {'backend': {'trace_' + key: value
                                    for key, value in backend.items()}},
        }

    def test_tlul_request_wait_accept_response_and_error_keep_native_source(self):
        roles = ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_address',
                 'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_source',
                 'd_data', 'd_error')
        normalizer = self.normalizer('tl-ul', roles)
        rows = []
        rows += normalizer.consume_local_tick(self.raw(1, 1, {
            'a_valid': 1, 'a_ready': 0, 'a_source': 7, 'a_opcode': 4,
            'a_address': 0x24, 'a_mask': 15, 'a_data': 0,
            'd_valid': 0, 'd_ready': 1, 'd_source': 0, 'd_data': 0,
            'd_error': 0,
        }), reset_epoch=3)
        rows += normalizer.consume_local_tick(self.raw(2, 2, {
            'a_valid': 1, 'a_ready': 1, 'a_source': 7, 'a_opcode': 4,
            'a_address': 0x24, 'a_mask': 15, 'a_data': 0,
            'd_valid': 0, 'd_ready': 0, 'd_source': 0, 'd_data': 0,
            'd_error': 0,
        }), reset_epoch=3)
        rows += normalizer.consume_local_tick(self.raw(3, 3, {
            'a_valid': 0, 'a_ready': 1, 'a_source': 7, 'a_opcode': 0,
            'a_address': 0, 'a_mask': 0, 'a_data': 0,
            'd_valid': 1, 'd_ready': 1, 'd_source': 7, 'd_data': 0xdeadbeef,
            'd_error': 1,
        }), reset_epoch=3)

        event_types = [row['event_type'] for row in rows]
        self.assertEqual(['transaction_request', 'wait_observation',
                          'transaction_accept', 'transaction_response',
                          'protocol_error'], event_types)
        key = {'protocol': 'tl-ul', 'endpoint_id': 'opaque.bus',
               'reset_epoch': 3, 'source': 7}
        self.assertTrue(all(row['transaction_key'] == key for row in rows))
        self.assertEqual({'channel': 'A', 'source': 7},
                         rows[0]['native_identity'])
        self.assertEqual({'channel': 'D', 'source': 7},
                         rows[-2]['native_identity'])
        self.assertEqual([1], rows[0]['raw_event_refs'])
        self.assertEqual([3], rows[-1]['raw_event_refs'])

    def test_tlul_duplicate_outstanding_source_and_reset_cancellation_keep_id(self):
        roles = ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_address',
                 'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_source',
                 'd_data', 'd_error')
        normalizer = self.normalizer('tl-ul', roles)

        def sample(event_id, tick, *, epoch, source, a_valid, a_ready,
                   d_valid=0, d_ready=1, d_source=0):
            return normalizer.consume_local_tick(self.raw(event_id, tick, {
                'a_valid': a_valid, 'a_ready': a_ready, 'a_source': source,
                'a_opcode': 4, 'a_address': 0x20, 'a_mask': 15, 'a_data': 0,
                'd_valid': d_valid, 'd_ready': d_ready, 'd_source': d_source,
                'd_data': 0, 'd_error': 0,
            }), reset_epoch=epoch)

        first = sample(1, 1, epoch=0, source=5, a_valid=1, a_ready=1,
                       d_ready=0)
        duplicate = sample(2, 2, epoch=0, source=5, a_valid=1, a_ready=1)
        cancelled = sample(3, 1, epoch=1, source=0, a_valid=0, a_ready=0,
                           d_ready=0)

        dup = next(row for row in duplicate
                   if row['event_type'] == 'transaction_duplicate')
        cancel = next(row for row in cancelled
                      if row['event_type'] == 'transaction_cancel')
        key = {'protocol': 'tl-ul', 'endpoint_id': 'opaque.bus',
               'reset_epoch': 0, 'source': 5}
        self.assertEqual(key, first[-1]['transaction_key'])
        self.assertEqual(key, dup['transaction_key'])
        self.assertEqual(key, cancel['transaction_key'])
        self.assertEqual('reset_epoch_changed', cancel['payload']['reason'])

    def test_tlul_timeout_reports_native_source(self):
        roles = ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_address',
                 'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_source',
                 'd_data', 'd_error')
        normalizer = self.normalizer('tl-ul', roles, max_wait=2)

        def sample(event_id, tick, *, a_valid, a_ready, d_valid=0, d_ready=1):
            return normalizer.consume_local_tick(self.raw(event_id, tick, {
                'a_valid': a_valid, 'a_ready': a_ready, 'a_source': 9,
                'a_opcode': 4, 'a_address': 0x20, 'a_mask': 15, 'a_data': 0,
                'd_valid': d_valid, 'd_ready': d_ready, 'd_source': 9,
                'd_data': 0, 'd_error': 0,
            }), reset_epoch=0)

        accepted = sample(1, 1, a_valid=1, a_ready=1, d_ready=0)
        first_wait = sample(2, 2, a_valid=0, a_ready=1)
        second_wait = sample(3, 3, a_valid=0, a_ready=1)

        self.assertFalse(any(row['event_type'] == 'transaction_timeout'
                             for row in first_wait))
        timeout = next(row for row in second_wait
                       if row['event_type'] == 'transaction_timeout')
        self.assertEqual(accepted[-1]['transaction_key'], timeout['transaction_key'])
        self.assertEqual('D', timeout['payload']['channel'])

    def test_tlul_a_wait_budget_resets_when_a_request_is_accepted(self):
        roles = ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_address',
                 'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_source',
                 'd_data', 'd_error')
        normalizer = self.normalizer('tl-ul', roles, max_wait=2)

        def sample(event_id, tick, *, a_valid, a_ready, d_ready):
            return normalizer.consume_local_tick(self.raw(event_id, tick, {
                'a_valid': a_valid, 'a_ready': a_ready, 'a_source': 13,
                'a_opcode': 4, 'a_address': 0x20, 'a_mask': 15, 'a_data': 0,
                'd_valid': 0, 'd_ready': d_ready, 'd_source': 13,
                'd_data': 0, 'd_error': 0,
            }), reset_epoch=0)

        sample(1, 1, a_valid=1, a_ready=0, d_ready=0)
        sample(2, 2, a_valid=1, a_ready=1, d_ready=0)
        first_d_wait = sample(3, 3, a_valid=0, a_ready=1, d_ready=1)
        second_d_wait = sample(4, 4, a_valid=0, a_ready=1, d_ready=1)

        self.assertFalse(any(row['event_type'] == 'transaction_timeout'
                            for row in first_d_wait))
        timeout = next(row for row in second_d_wait
                       if row['event_type'] == 'transaction_timeout')
        self.assertEqual(2, timeout['payload']['wait_cycles'])

    def test_tlul_source_stays_reserved_after_timeout_until_late_response(self):
        roles = ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_address',
                 'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_source',
                 'd_data', 'd_error')
        normalizer = self.normalizer('tl-ul', roles, max_wait=1)

        def sample(event_id, tick, *, a_valid=0, a_ready=1,
                   d_valid=0, d_ready=0):
            return normalizer.consume_local_tick(self.raw(event_id, tick, {
                'a_valid': a_valid, 'a_ready': a_ready, 'a_source': 7,
                'a_opcode': 4, 'a_address': 0x20, 'a_mask': 15, 'a_data': 0,
                'd_valid': d_valid, 'd_ready': d_ready, 'd_source': 7,
                'd_data': 0x55, 'd_error': 0,
            }), reset_epoch=0)

        accepted = sample(1, 1, a_valid=1, a_ready=1)
        timed_out = sample(2, 2, d_ready=1)
        reused = sample(3, 3, a_valid=1, a_ready=1)
        late_response = sample(4, 4, d_valid=1, d_ready=1)

        self.assertTrue(any(row['event_type'] == 'transaction_timeout'
                            for row in timed_out))
        self.assertFalse(any(row['event_type'] == 'transaction_accept'
                             for row in reused))
        duplicate = next(row for row in reused
                         if row['event_type'] == 'transaction_duplicate')
        self.assertEqual('source_id_not_released_after_timeout',
                         duplicate['payload']['reason'])
        response = next(row for row in late_response
                        if row['event_type'] == 'transaction_response')
        self.assertFalse(response['payload']['signals']['matched_outstanding'])
        self.assertTrue(response['payload']['signals']['matched_timed_out'])
        self.assertEqual([accepted[0]['raw_event_refs'][0]],
                         response['related_request_event_refs'])

    def test_tlul_reset_cancels_pending_duplicate_offer_separately(self):
        roles = ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_address',
                 'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_source',
                 'd_data', 'd_error')
        normalizer = self.normalizer('tl-ul', roles)

        def sample(event_id, tick, *, epoch, a_valid, a_ready):
            return normalizer.consume_local_tick(self.raw(event_id, tick, {
                'a_valid': a_valid, 'a_ready': a_ready, 'a_source': 5,
                'a_opcode': 4, 'a_address': 0x20, 'a_mask': 15, 'a_data': 0,
                'd_valid': 0, 'd_ready': 0, 'd_source': 0,
                'd_data': 0, 'd_error': 0,
            }), reset_epoch=epoch)

        sample(1, 1, epoch=0, a_valid=1, a_ready=1)
        sample(2, 2, epoch=0, a_valid=1, a_ready=0)
        cancelled = sample(3, 3, epoch=1, a_valid=0, a_ready=0)

        cancellations = [row for row in cancelled
                         if row['event_type'] == 'transaction_cancel']
        self.assertEqual([[1], [2]], [row['related_request_event_refs']
                                      for row in cancellations])

    def test_tlul_request_timeout_keeps_source_and_clears_unaccepted_offer(self):
        roles = ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_address',
                 'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_source',
                 'd_data', 'd_error')
        normalizer = self.normalizer('tl-ul', roles, max_wait=2)

        def sample(event_id, tick):
            return normalizer.consume_local_tick(self.raw(event_id, tick, {
                'a_valid': 1, 'a_ready': 0, 'a_source': 11, 'a_opcode': 4,
                'a_address': 0x30, 'a_mask': 15, 'a_data': 0,
                'd_valid': 0, 'd_ready': 0, 'd_source': 0,
                'd_data': 0, 'd_error': 0,
            }), reset_epoch=0)

        first = sample(1, 1)
        timed_out = sample(2, 2)
        timeout = next(row for row in timed_out
                       if row['event_type'] == 'transaction_timeout')
        self.assertFalse(any(row['event_type'] == 'transaction_timeout'
                             for row in first))
        self.assertEqual(11, timeout['transaction_key']['source'])
        self.assertEqual('A', timeout['payload']['channel'])

    def test_wishbone_events_link_raw_request_without_fabricating_native_key(self):
        roles = ('cyc', 'stb', 'we', 'adr', 'dat_w', 'sel', 'ack',
                 'stall', 'dat_r')
        normalizer = self.normalizer('wishbone', roles)
        rows = []
        rows += normalizer.consume_local_tick(self.raw(20, 1, {
            'cyc': 1, 'stb': 1, 'we': 1, 'adr': 4, 'dat_w': 0xa5,
            'sel': 15, 'ack': 0, 'stall': 0, 'dat_r': 0,
        }), reset_epoch=1)
        rows += normalizer.consume_local_tick(self.raw(21, 2, {
            'cyc': 1, 'stb': 0, 'we': 1, 'adr': 4, 'dat_w': 0xa5,
            'sel': 15, 'ack': 0, 'stall': 0, 'dat_r': 0,
        }), reset_epoch=1)
        rows += normalizer.consume_local_tick(self.raw(22, 3, {
            'cyc': 1, 'stb': 0, 'we': 1, 'adr': 4, 'dat_w': 0xa5,
            'sel': 15, 'ack': 1, 'stall': 0, 'dat_r': 0x55,
        }), reset_epoch=1)

        self.assertEqual(['transaction_request', 'transaction_accept',
                          'wait_observation', 'transaction_response'],
                         [row['event_type'] for row in rows])
        self.assertTrue(all(row['transaction_key'] is None for row in rows))
        self.assertTrue(all(row['native_identity'] is None for row in rows))
        self.assertEqual([20], rows[-1]['related_request_event_refs'])
        self.assertEqual('protocol_has_no_transaction_id', rows[-1]['identity_gap'])

    def test_apb_wait_response_and_error_preserve_missing_native_identity(self):
        roles = ('psel', 'penable', 'pwrite', 'paddr', 'pwdata', 'pready',
                 'prdata', 'pslverr')
        normalizer = self.normalizer('apb3', roles)
        rows = []
        rows += normalizer.consume_local_tick(self.raw(10, 1, {
            'psel': 1, 'penable': 0, 'pwrite': 0, 'paddr': 0x18,
            'pwdata': 0, 'pready': 0, 'prdata': 0, 'pslverr': 0,
        }), reset_epoch=2)
        rows += normalizer.consume_local_tick(self.raw(11, 2, {
            'psel': 1, 'penable': 1, 'pwrite': 0, 'paddr': 0x18,
            'pwdata': 0, 'pready': 0, 'prdata': 0, 'pslverr': 0,
        }), reset_epoch=2)
        rows += normalizer.consume_local_tick(self.raw(12, 3, {
            'psel': 1, 'penable': 1, 'pwrite': 0, 'paddr': 0x18,
            'pwdata': 0, 'pready': 1, 'prdata': 0x55, 'pslverr': 1,
        }), reset_epoch=2)

        self.assertEqual(['transaction_request', 'wait_observation',
                          'transaction_accept', 'transaction_response',
                          'protocol_error'],
                         [row['event_type'] for row in rows])
        self.assertTrue(all(row['transaction_key'] is None for row in rows))
        self.assertTrue(all(row['native_identity'] is None for row in rows))
        response = next(row for row in rows
                        if row['event_type'] == 'transaction_response')
        self.assertEqual([10], response['related_request_event_refs'])
        self.assertEqual('protocol_has_no_transaction_id',
                         response['identity_gap'])

    def test_runner_appends_protocol_events_from_opted_in_raw_backend_samples(self):
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
        roles = ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_size', 'a_address',
                 'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_opcode', 'd_size',
                 'd_source', 'd_data', 'd_error')
        artifact = SimpleNamespace(runtime_document={
            'kind': 'tlul_register_observe',
            'base_event_schema_version': 'ip_base_event.v1',
            'base_protocol_trace': trace('tl-ul', roles),
            'clock_schedule': {'primary_clock_domain': 'bus_clk'},
            'effective_max_wait_cycles': 2,
            'physical_exports': [],
        }, plan=SimpleNamespace(request=request, profile=profile))

        class Session:
            reset_epoch = 4

            def __init__(self):
                self.artifact = artifact

            def drain_tick_samples(self):
                return [{'local_tick': 1,
                         'pre': {'backend': {
                             'trace_a_valid': 1, 'trace_a_ready': 1,
                             'trace_a_source': 6, 'trace_a_opcode': 4,
                             'trace_a_size': 2,
                             'trace_a_address': 0x20, 'trace_a_mask': 15,
                             'trace_a_data': 0, 'trace_d_valid': 0,
                             'trace_d_opcode': 1, 'trace_d_size': 2,
                             'trace_d_ready': 1, 'trace_d_source': 0,
                             'trace_d_data': 0, 'trace_d_error': 0}},
                         'post': {'backend': {}}}]

        runner = ScenarioRunner(sessions={'dut0': Session()},
                                ownership=compile_ownership((), ()), bindings=())
        runner.local_ticks['dut0'] = 1
        runner._drain_tick_samples(producer_event_id=1)
        rows = list(runner._events)
        raw = next(row for row in rows if row['kind'] == 'local_tick_sample')
        projected = [row for row in rows
                     if row.get('event_type') == 'transaction_accept']
        self.assertEqual(1, len(projected))
        self.assertEqual([raw['event_id']], projected[0]['raw_event_refs'])
        self.assertEqual(6, projected[0]['transaction_key']['source'])


if __name__ == '__main__':
    unittest.main()
