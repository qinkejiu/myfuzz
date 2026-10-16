from copy import deepcopy
import json
import unittest

from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.ip_base_coverage import IpBaseCoverageConsumer


def event(kind, cursor, tick, *, epoch=0, endpoint='bus', payload=None, refs=(), raw_refs=None):
    return {'schema_version': 'ip_base_event.v1', 'event_type': kind,
            'component_id': 'opaque', 'instance_id': 'dut',
            'endpoint_id': endpoint, 'reset_epoch': epoch, 'tick': tick,
            'raw_event_refs': [cursor] if raw_refs is None else list(raw_refs),
            'related_request_event_refs': list(refs),
            'payload': payload or {}, 'local_event_id': f'event-{cursor}-{kind}'}


class BaseCoverageTests(unittest.TestCase):
    def consumer(self, **kw):
        return IpBaseCoverageConsumer(
            component_id='opaque', instance_id='dut',
            endpoint_protocols={'bus': 'apb3'},
            physical_exports=({'endpoint_id': 'pins', 'role': 'ready',
                               'physical_port': 'status', 'direction': 'output',
                               'bit_lo': 2, 'width': 1},),
            targets=(CoverageTarget('seen_status', 'dut', 'status', 4, 4),), **kw)

    def test_counts_protocol_response_latency_port_change_and_raw_target(self):
        c = self.consumer()
        rows = [
            {'kind': 'local_tick_sample', 'event_id': 5, 'component': 'dut',
             'local_tick': 1, 'phase': 'pre',
             'outputs': {'status': 4}},
            event('transaction_request', 6, 1, payload={'channel': 'APB',
                  'signals': {'pwrite': 1}}),
            event('transaction_accept', 7, 2, refs=(6,)),
            {**event('signal_change', 8, 2, endpoint='pins',
                     payload={'previous_value': 0, 'value': 1, 'width': 1}),
             'role': 'ready', 'direction': 'output',
             'physical_port': 'status', 'bit_lo': 2},
            event('transaction_response', 9, 4, refs=(6,),
                  payload={'channel': 'APB', 'error': False}),
        ]
        before = deepcopy(rows)
        consumed = c.consume(rows, start_cursor=0)
        self.assertEqual(rows, before)
        self.assertEqual(list(range(5)), [r.cursor for r in consumed])
        self.assertTrue(all(r.event is rows[i] for i, r in enumerate(consumed)))
        self.assertEqual(5, c.cursor)
        self.assertEqual(1, c.counts['transaction:bus:write'])
        self.assertEqual(1, c.counts['response:bus:ok'])
        self.assertEqual(1, c.counts['latency:bus:2-3'])
        self.assertEqual(1, c.counts['port_change:pins:ready:output:status:2:1'])
        self.assertEqual(1, c.counts['target:seen_status'])
        self.assertEqual({}, c.diagnostics)

    def test_overlapping_prefix_and_incremental_suffix_count_once(self):
        c = self.consumer()
        rows = [event('transaction_request', i, i, payload={'channel': 'APB',
                 'signals': {'pwrite': 0}}) for i in range(1, 4)]
        c.consume(rows[:2], start_cursor=0)
        self.assertEqual(1, len(c.consume(rows, start_cursor=0)))
        self.assertEqual(0, len(c.consume(rows[1:], start_cursor=1)))
        self.assertEqual(3, c.counts['transaction:bus:read'])
        with self.assertRaisesRegex(ValueError, 'cursor-gap'):
            c.consume(rows, start_cursor=5)

    def test_saturation_and_finite_features_and_pending_bound(self):
        c = self.consumer(counter_cap=2, max_pending=1)
        rows = [event('transaction_request', i, i, payload={'channel': 'APB',
                 'signals': {'pwrite': 0}, 'untrusted': 'x' * i})
                for i in range(1, 30)]
        rows.append(event('signal_change', 30, 30, endpoint='untrusted',
                          payload={'value': 2**4096}))
        c.consume(rows, start_cursor=0)
        self.assertEqual(2, c.counts['transaction:bus:read'])
        self.assertLessEqual(len(c.counts), c.feature_capacity)
        self.assertLessEqual(c.pending_count, 1)
        self.assertEqual(2, c.diagnostics['pending_evicted'])
        self.assertFalse(any('untrusted' in key for key in c.counts))

    def test_unmatched_late_and_epoch_separated_responses(self):
        c = self.consumer()
        rows = [event('transaction_response', 1, 1, refs=(999,)),
                event('transaction_request', 2, 2, payload={'channel': 'APB',
                       'signals': {'pwrite': 0}}),
                event('transaction_accept', 3, 2, refs=(2,)),
                event('transaction_response', 4, 5, refs=(2,),
                      payload={'channel': 'APB', 'error': True}),
                event('transaction_response', 5, 6, refs=(2,)),
                event('transaction_request', 6, 7, payload={'channel': 'APB',
                       'signals': {'pwrite': 1}}),
                event('transaction_accept', 7, 7, refs=(6,)),
                event('transaction_response', 8, 8, epoch=1, refs=(6,))]
        c.consume(rows, start_cursor=0)
        self.assertEqual(1, c.counts['latency:bus:2-3'])
        self.assertEqual(1, c.counts['response:bus:error'])
        self.assertEqual(3, c.diagnostics['latency_uncorrelated'])
        self.assertEqual(0, c.pending_count)

    def test_change_must_match_declared_physical_slice(self):
        c = self.consumer()
        rows = [{**event('signal_change', 1, 1, endpoint='pins',
                         payload={'previous_value': 0, 'value': 1, 'width': 1}),
                 'role': 'ready', 'direction': 'output',
                 'physical_port': 'other', 'bit_lo': 2},
                {**event('signal_change', 2, 2, endpoint='pins',
                         payload={'previous_value': 0, 'value': 1, 'width': 2}),
                 'role': 'ready', 'direction': 'output',
                 'physical_port': 'status', 'bit_lo': 2},
                {**event('signal_change', 3, 3, endpoint='pins',
                         payload={'previous_value': 0, 'value': 1, 'width': 1}),
                 'role': 'ready', 'direction': 'output',
                 'physical_port': 'status', 'bit_lo': 2}]
        c.consume(rows, start_cursor=0)
        self.assertEqual(1, c.counts['port_change:pins:ready:output:status:2:1'])

    def test_distinct_declared_offsets_have_distinct_change_bins(self):
        exports = [dict(endpoint_id='pins', role='ready', direction='output',
                        physical_port='status', bit_lo=offset, width=1)
                   for offset in (2, 3)]
        c = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                   endpoint_protocols={}, physical_exports=exports)
        rows = [{**event('signal_change', i, i, endpoint='pins',
                         payload={'previous_value': 0, 'value': 1, 'width': 1}),
                 'role': 'ready', 'direction': 'output',
                 'physical_port': 'status', 'bit_lo': offset}
                for i, offset in enumerate((2, 3, 4), start=1)]
        c.consume(rows, start_cursor=0)
        self.assertEqual({'port_change:pins:ready:output:status:2:1': 1,
                          'port_change:pins:ready:output:status:3:1': 1}, c.counts)

    def test_invalid_signal_change_envelope_is_ignored(self):
        c = self.consumer()
        valid = {**event('signal_change', 1, 1, endpoint='pins',
                        payload={'previous_value': 0, 'value': 1, 'width': 1}),
                 'role': 'ready', 'direction': 'output',
                 'physical_port': 'status', 'bit_lo': 2}
        rows = [{**valid, key: invalid} for key in ('reset_epoch', 'tick')
                for invalid in (None, -1, True, '1')]
        c.consume(rows, start_cursor=0)
        self.assertEqual({}, c.counts)
        self.assertEqual(len(rows), c.cursor)

    def test_latency_starts_at_acceptance_instead_of_request(self):
        c = self.consumer()
        rows = [event('transaction_request', 1, 1),
                event('transaction_accept', 2, 8, refs=(1,)),
                event('transaction_response', 3, 9, refs=(1,))]
        c.consume(rows, start_cursor=0)
        self.assertEqual(1, c.counts.get('latency:bus:1'))
        self.assertFalse('latency:bus:8-15' in c.counts)

    def test_response_before_acceptance_tick_is_uncorrelated(self):
        c = self.consumer()
        rows = [event('transaction_request', 1, 1),
                event('transaction_accept', 2, 8, refs=(1,)),
                event('transaction_response', 3, 7, refs=(1,))]
        c.consume(rows, start_cursor=0)
        self.assertEqual(1, c.diagnostics.get('latency_uncorrelated'))
        self.assertFalse(any(k.startswith('latency:') for k in c.counts))

    def test_target_can_name_actual_selected_runtime_output(self):
        c = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                   endpoint_protocols={}, physical_exports=(
                                       dict(endpoint_id='pins', role='ready', direction='output',
                                            physical_port='status', runtime_name='rt_status',
                                            encoding='integer', bit_lo=2, width=1),), targets=(
                                       CoverageTarget('seen_bit', 'dut', 'rt_status', 1, 1),))
        c.consume([{'kind': 'local_tick_sample', 'component': 'dut',
                    'event_id': 1, 'local_tick': 1, 'phase': 'pre',
                    'outputs': {'physical': {'rt_status': 1}}}], start_cursor=0)
        self.assertEqual({'target:seen_bit': 1}, c.counts)

    def test_wide_target_uses_declared_runtime_encoding_and_selected_bits(self):
        export = dict(endpoint_id='pins', role='wide', direction='output',
                      physical_port='status_bus', runtime_name='rt_wide',
                      encoding='fixed_width_hex', bit_lo=9, width=65)
        for port in ('status_bus', 'rt_wide'):
            with self.subTest(port=port):
                c = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                           endpoint_protocols={}, physical_exports=(export,),
                                           targets=(CoverageTarget('wide_bit', 'dut', port,
                                                                   1 << 64, 1 << 64),))
                c.consume([{'kind': 'local_tick_sample', 'component': 'dut',
                    'event_id': 1, 'local_tick': 1, 'phase': 'pre',
                            'outputs': {'physical': {'rt_wide': '10000000000000000'}}}],
                          start_cursor=0)
                self.assertEqual({'target:wide_bit': 1}, c.counts)

    def test_malformed_or_overwidth_declared_hex_cannot_hit_target(self):
        export = dict(endpoint_id='pins', role='wide', direction='output',
                      physical_port='status_bus', runtime_name='rt_wide',
                      encoding='fixed_width_hex', bit_lo=9, width=65)
        # Direct alias would hit if a malformed canonical snapshot fell back.
        for value in ('10000000000000001', 'g0000000000000001',
                      ' 0000000000000001', '+0000000000000001',
                      '0x000000000000001', '00000000000000_1',
                      '0000000000000001', '30000000000000000',
                      '010000000000000000', 1, None):
            with self.subTest(value=value):
                c = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                           endpoint_protocols={}, physical_exports=(export,),
                                           targets=(CoverageTarget('low_zero', 'dut',
                                                                   'status_bus', 1, 0),))
                c.consume([{'kind': 'local_tick_sample', 'component': 'dut',
                    'event_id': 1, 'local_tick': 1, 'phase': 'pre',
                            'outputs': {'status_bus': 0,
                                        'physical': {'rt_wide': value}}}], start_cursor=0)
                self.assertEqual({}, c.counts)

    def test_nested_physical_target_requires_export_declaration(self):
        c = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                   endpoint_protocols={}, targets=(
                                       CoverageTarget('undeclared', 'dut', 'rt_unknown', 1, 1),))
        c.consume([{'kind': 'local_tick_sample', 'component': 'dut',
                    'event_id': 1, 'local_tick': 1, 'phase': 'pre',
                    'outputs': {'physical': {'rt_unknown': value}}}
                   for value in (1, '1')], start_cursor=0)
        self.assertEqual({}, c.counts)

    def test_ambiguous_target_physical_port_mapping_is_rejected(self):
        exports = [dict(endpoint_id='pins', role=f'part_{offset}', direction='output',
                        physical_port='status', runtime_name=f'rt_status_{offset}',
                        bit_lo=offset, width=1) for offset in (2, 3)]
        with self.assertRaisesRegex(ValueError, 'target-ambiguous'):
            IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                   endpoint_protocols={}, physical_exports=exports,
                                   targets=(CoverageTarget('ambiguous', 'dut', 'status', 1, 1),))

    def test_target_mask_cannot_select_bits_outside_declared_slice(self):
        export = dict(endpoint_id='pins', role='ready', direction='output',
                      physical_port='status', runtime_name='rt_status', bit_lo=2, width=1)
        with self.assertRaisesRegex(ValueError, 'target-width'):
            IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                   endpoint_protocols={}, physical_exports=(export,),
                                   targets=(CoverageTarget('missing_bit', 'dut', 'rt_status', 2, 0),))

    def test_incomplete_declared_snapshot_cannot_use_conflicting_alias(self):
        export = dict(endpoint_id='pins', role='ready', direction='output',
                      physical_port='status', runtime_name='rt_status', bit_lo=2, width=1)
        c = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                   endpoint_protocols={}, physical_exports=(export,),
                                   targets=(CoverageTarget('seen_bit', 'dut', 'status', 1, 1),))
        c.consume([{'kind': 'local_tick_sample', 'component': 'dut',
                    'event_id': 1, 'local_tick': 1, 'phase': 'pre',
                    'outputs': {'status': 1, 'physical': {}}}], start_cursor=0)
        self.assertEqual({}, c.counts)

    def test_invalid_raw_envelope_cannot_hit_direct_or_physical_target(self):
        export = dict(endpoint_id='pins', role='ready', direction='output',
                      physical_port='status', runtime_name='rt_status', bit_lo=2, width=1)
        for physical in (False, True):
            def consumer():
                return (IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                               endpoint_protocols={}, physical_exports=(export,),
                                               targets=(CoverageTarget('seen_bit', 'dut',
                                                                       'rt_status', 1, 1),))
                        if physical else self.consumer())
            valid = {'kind': 'local_tick_sample', 'component': 'dut',
                     'event_id': 1, 'local_tick': 1, 'phase': 'pre',
                     'outputs': {'physical': {'rt_status': 1}} if physical
                     else {'status': 4}}
            malformed = [{k: v for k, v in valid.items() if k != missing}
                         for missing in ('event_id', 'local_tick', 'phase')]
            malformed += [{**valid, key: value} for key in ('event_id', 'local_tick')
                          for value in (None, 0, -1, True, '1', 1.0, [])]
            malformed += [{**valid, 'phase': phase}
                          for phase in (None, 'middle', 'PRE', 0, [], True)]
            for row in malformed:
                with self.subTest(physical=physical, row=row):
                    c = consumer()
                    c.consume([row], start_cursor=0)
                    self.assertEqual({}, c.counts)
                    self.assertEqual(1, c.cursor)
            c = consumer()
            c.consume([valid, {**valid, 'event_id': 2, 'phase': 'post'}], start_cursor=0)
            self.assertEqual(2, sum(c.counts.values()))

    def test_float_operation_bits_do_not_count_as_transactions(self):
        for protocol, bit in (('apb3', 'pwrite'), ('wishbone', 'we')):
            with self.subTest(protocol=protocol):
                c = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                           endpoint_protocols={'bus': protocol})
                c.consume([event('transaction_request', i, i,
                                 payload={'signals': {bit: value}})
                           for i, value in enumerate((0.0, 1.0), start=1)], start_cursor=0)
                self.assertFalse(any(k.startswith('transaction:') for k in c.counts))

    def test_float_response_error_does_not_count_as_valid_outcome(self):
        for protocol, bit in (('apb3', 'error'), ('wishbone', 'err'), ('tl-ul', 'd_error')):
            with self.subTest(protocol=protocol):
                c = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                           endpoint_protocols={'bus': protocol})
                payloads = [({'signals': {bit: value}} if protocol == 'tl-ul'
                             else {bit: value}) for value in (0.0, 1.0)]
                c.consume([event('transaction_response', i, i, payload=payload)
                           for i, payload in enumerate(payloads, start=1)], start_cursor=0)
                self.assertFalse(any(k.startswith('response:') for k in c.counts))

    def test_ambiguous_raw_or_related_refs_cannot_correlate_latency(self):
        for ambiguous in ('request', 'accept', 'response'):
            with self.subTest(ambiguous=ambiguous):
                c = self.consumer()
                rows = [event('transaction_request', 1, 1,
                              raw_refs=(1, 99) if ambiguous == 'request' else (1,)),
                        event('transaction_accept', 2, 2,
                              refs=(1, 99) if ambiguous == 'accept' else (1,)),
                        event('transaction_response', 3, 3,
                              refs=(1, 99) if ambiguous == 'response' else (1,))]
                c.consume(rows, start_cursor=0)
                self.assertFalse(any(k.startswith('latency:') for k in c.counts))
                self.assertEqual(1, c.diagnostics.get('latency_uncorrelated'))

    def test_snapshot_is_detached_json_base_coverage_with_cursor(self):
        c = self.consumer()
        c.consume([event('transaction_request', 1, 1)], start_cursor=0)
        snapshot = c.snapshot()
        self.assertEqual('ip_base_coverage.v1', snapshot['schema_version'])
        self.assertEqual('base_coverage', snapshot['category'])
        self.assertEqual(1, snapshot['cursor'])
        self.assertEqual(c.counts, snapshot['counts'])
        self.assertEqual(snapshot, json.loads(json.dumps(snapshot)))
        snapshot['counts'].clear()
        snapshot['diagnostics']['latency_uncorrelated'] = 9
        self.assertTrue(c.counts)
        self.assertEqual({}, c.diagnostics)

    def test_tlul_opcode_and_late_response_use_explicit_request_ref(self):
        c = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                   endpoint_protocols={'bus': 'tl-ul'})
        rows = [event('transaction_request', 1, 1,
                      payload={'channel': 'A', 'signals': {'a_opcode': 4}}),
                event('transaction_accept', 2, 2, refs=(1,)),
                event('transaction_timeout', 3, 3, refs=(1,)),
                event('transaction_response', 4, 5, refs=(1,),
                      payload={'channel': 'D', 'signals': {
                          'd_error': 1, 'matched_timed_out': True}})]
        c.consume(rows, start_cursor=0)
        self.assertEqual(1, c.counts['transaction:bus:opcode-4'])
        self.assertEqual(1, c.counts['response:bus:error'])
        self.assertEqual(1, c.counts['latency:bus:2-3'])
        self.assertEqual(1, c.diagnostics['late_response'])
        self.assertEqual(0, c.pending_count)

    def test_wishbone_no_native_key_correlates_only_by_request_ref(self):
        c = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                   endpoint_protocols={'bus': 'wishbone'})
        rows = [event('transaction_request', 1, 1,
                      payload={'channel': 'Wishbone', 'signals': {'we': 1}}),
                event('transaction_accept', 2, 2, refs=(1,)),
                event('transaction_response', 3, 18, refs=(1,),
                      payload={'channel': 'Wishbone', 'ack': 1, 'err': 0})]
        c.consume(rows, start_cursor=0)
        self.assertEqual(1, c.counts['transaction:bus:write'])
        self.assertEqual(1, c.counts['response:bus:ok'])
        self.assertEqual(1, c.counts['latency:bus:16+'])

    def test_no_native_key_is_fabricated_and_acceptance_is_required(self):
        c = self.consumer()
        rows = [event('transaction_request', 1, 1),
                event('transaction_response', 2, 2, refs=(1,))]
        c.consume(rows, start_cursor=0)
        self.assertEqual(1, c.diagnostics['latency_uncorrelated'])
        self.assertFalse(any(k.startswith('latency:') for k in c.counts))


class Axi4LiteBaseCoverageTests(unittest.TestCase):
    """The AXI4-Lite feature families must actually be reachable.

    An independent review found that this consumer read a write-enable bit and
    an ``error`` key that AXI4-Lite does not define, so ``transaction:*:read``,
    ``transaction:*:write``, ``response:*:ok`` and ``response:*:error`` were
    declared but could never be counted: the capacity was inflated and the
    coverage signal was blind on these dimensions.
    """

    def consumer(self):
        return IpBaseCoverageConsumer(
            component_id='opaque', instance_id='dut',
            endpoint_protocols={'uart.bus': 'axi4-lite'},
            physical_exports=(), targets=())

    @staticmethod
    def write_pair(first, *, bresp=0):
        return [
            event('transaction_request', first, 1, endpoint='uart.bus',
                  payload={'channel_protocol': 'axi4-lite', 'direction': 'write',
                           'signals': {'awaddr': 12, 'wdata': 65, 'wstrb': 1}}),
            event('transaction_accept', first + 1, 2, endpoint='uart.bus',
                  refs=(first,)),
            event('transaction_response', first + 2, 4, endpoint='uart.bus',
                  refs=(first,),
                  payload={'channel_protocol': 'axi4-lite', 'direction': 'write',
                           'channel': 'b', 'bresp': bresp, 'awaddr': 12}),
        ]

    @staticmethod
    def read_pair(first, *, rresp=0):
        return [
            event('transaction_request', first, 5, endpoint='uart.bus',
                  payload={'channel_protocol': 'axi4-lite', 'direction': 'read',
                           'signals': {'araddr': 8}}),
            event('transaction_accept', first + 1, 6, endpoint='uart.bus',
                  refs=(first,)),
            event('transaction_response', first + 2, 8, endpoint='uart.bus',
                  refs=(first,),
                  payload={'channel_protocol': 'axi4-lite', 'direction': 'read',
                           'channel': 'r', 'rresp': rresp, 'araddr': 8}),
        ]

    def test_write_and_read_directions_and_both_response_codes_are_counted(self):
        consumer = self.consumer()
        consumer.consume(self.write_pair(1) + self.read_pair(4), start_cursor=0)
        counts = consumer.snapshot()['counts']
        self.assertEqual(1, counts.get('transaction:uart.bus:write'))
        self.assertEqual(1, counts.get('transaction:uart.bus:read'))
        # Both accesses were answered OKAY; the non-OKAY case is the other test.
        self.assertEqual(2, counts.get('response:uart.bus:ok'))
        self.assertNotIn('response:uart.bus:error', counts)
        # Latency is derived from the request/accept/response chain, so a
        # counted direction with no latency would mean only half the path works.
        self.assertEqual(2, sum(value for key, value in counts.items()
                                if key.startswith('latency:uart.bus:')))

    def test_a_response_code_is_read_as_the_measured_code_not_a_missing_key(self):
        """A non-OKAY code must classify as an error without inventing a key."""
        consumer = self.consumer()
        consumer.consume(self.read_pair(1, rresp=0b10), start_cursor=0)
        counts = consumer.snapshot()['counts']
        self.assertEqual(1, counts.get('response:uart.bus:error'))
        self.assertNotIn('response:uart.bus:ok', counts)


if __name__ == '__main__':
    unittest.main()
