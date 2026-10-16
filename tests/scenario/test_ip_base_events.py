from __future__ import annotations

from copy import deepcopy
import importlib
from types import SimpleNamespace
import unittest


def normalizer_type():
    module = importlib.import_module('myfuzz.scenario.ip_base_events')
    normalizer = getattr(module, 'IpBaseEventNormalizer', None)
    if normalizer is None:
        raise AssertionError('component-neutral IP base event normalizer is missing')
    return normalizer


class IpBaseEventNormalizerTests(unittest.TestCase):
    def setUp(self):
        self.export = {
            'endpoint_id': 'opaque.pins', 'role': 'status',
            'physical_port': 'status_bus', 'runtime_name': 'rt_status',
            'bit_lo': 2, 'bit_hi': 4, 'width': 3,
            'direction': 'output', 'encoding': 'integer',
        }
        self.normalizer = normalizer_type()(
            component_id='anonymous_ip', instance_id='dut0',
            endpoint_clock_domains={'opaque.pins': 'peripheral'},
            physical_exports=(self.export,),
        )

    def raw_sample(self, event_id, tick, phase, value):
        selected = (value >> self.export['bit_lo']) & ((1 << self.export['width']) - 1)
        return {
            'event_id': event_id, 'kind': 'local_tick_sample',
            'component': 'dut0', 'local_tick': tick, 'phase': phase,
            'outputs': {'status_bus': selected,
                        'physical': {'rt_status': selected}},
        }

    def test_projects_declared_slice_with_raw_reference_without_mutation(self):
        raw = self.raw_sample(7, 3, 'post', 0b101101)
        before = deepcopy(raw)

        projected = self.normalizer.consume_local_tick(raw, reset_epoch=4)

        samples = [event for event in projected
                   if event['event_type'] == 'port_sample']
        self.assertEqual(1, len(samples))
        event = samples[0]
        self.assertEqual('ip_base_event.v1', event['schema_version'])
        self.assertEqual('anonymous_ip', event['component_id'])
        self.assertEqual('dut0', event['instance_id'])
        self.assertEqual(('opaque.pins', 'status', 'peripheral', 3, 4),
                         (event['endpoint_id'], event['role'], event['clock_domain'],
                          event['tick'], event['reset_epoch']))
        self.assertEqual(('status_bus', 2, 3),
                         (event['physical_port'], event['bit_lo'],
                          event['payload']['width']))
        self.assertEqual([7], event['raw_event_refs'])
        self.assertIsNone(event['transaction_key'])
        self.assertEqual({'value': 0b011, 'width': 3, 'phase': 'post'},
                         event['payload'])
        self.assertEqual(before, raw)

    def test_signal_change_uses_observed_values_and_resets_epoch_history(self):
        first = self.normalizer.consume_local_tick(
            self.raw_sample(10, 8, 'pre', 0b001100), reset_epoch=1)
        same = self.normalizer.consume_local_tick(
            self.raw_sample(11, 8, 'post', 0b001100), reset_epoch=1)
        changed = self.normalizer.consume_local_tick(
            self.raw_sample(12, 9, 'pre', 0b011100), reset_epoch=1)
        new_epoch = self.normalizer.consume_local_tick(
            self.raw_sample(13, 1, 'pre', 0b011100), reset_epoch=2)

        changes = lambda rows: [row for row in rows
                                if row['event_type'] == 'signal_change']
        self.assertEqual([], changes(first))
        self.assertEqual([], changes(same))
        self.assertEqual(1, len(changes(changed)))
        self.assertEqual({'previous_value': 3, 'value': 7, 'width': 3,
                          'phase': 'pre'}, changes(changed)[0]['payload'])
        self.assertEqual(2, changes(changed)[0]['bit_lo'])
        self.assertEqual([], changes(new_epoch))

    def test_missing_physical_sample_fails_closed(self):
        raw = self.raw_sample(20, 10, 'post', 1)
        raw['outputs'] = {}
        with self.assertRaisesRegex(ValueError, 'base-event-output-missing'):
            self.normalizer.consume_local_tick(raw, reset_epoch=2)

    def test_incomplete_physical_snapshot_cannot_fall_back_to_conflicting_alias(self):
        raw = self.raw_sample(21, 11, 'pre', 0b101101)
        raw['outputs']['physical'] = {}
        raw['outputs']['status_bus'] = 7
        with self.assertRaisesRegex(ValueError, 'base-event-output-missing'):
            self.normalizer.consume_local_tick(raw, reset_epoch=2)

    def test_projects_arbitrary_profile_input_sample_changes_and_reset_epoch(self):
        input_export = {
            'endpoint_id': 'opaque.pins', 'role': 'wake_hint',
            'physical_port': 'pin_with_unrelated_name',
            'runtime_name': 'rt_pin_17', 'bit_lo': 1, 'bit_hi': 3,
            'width': 3, 'direction': 'input', 'encoding': 'integer',
        }
        normalizer = normalizer_type()(
            component_id='anonymous_ip', instance_id='dut0',
            endpoint_clock_domains={'opaque.pins': 'peripheral'},
            physical_exports=(self.export, input_export),
        )

        def raw(event_id, tick, value):
            return {'event_id': event_id, 'kind': 'local_tick_sample',
                    'component': 'dut0', 'local_tick': tick, 'phase': 'pre',
                    'outputs': {'status_bus': 0,
                                'physical': {'rt_status': 0,
                                             'rt_pin_17': value}}}

        first = normalizer.consume_local_tick(raw(31, 1, 2), reset_epoch=4)
        changed = normalizer.consume_local_tick(raw(32, 2, 5), reset_epoch=4)
        reset = normalizer.consume_local_tick(raw(33, 1, 5), reset_epoch=5)

        input_samples = [row for row in first + changed + reset
                         if row['event_type'] == 'port_sample'
                         and row['role'] == 'wake_hint']
        changes = [row for row in first + changed + reset
                   if row['event_type'] == 'signal_change'
                   and row['role'] == 'wake_hint']
        self.assertEqual([2, 5, 5], [row['payload']['value']
                                     for row in input_samples])
        self.assertEqual([31, 32, 33], [row['raw_event_refs'][0]
                                       for row in input_samples])
        self.assertEqual(1, len(changes))
        self.assertEqual({'previous_value': 2, 'value': 5, 'width': 3,
                          'phase': 'pre'}, changes[0]['payload'])
        self.assertEqual([4, 4, 5], [row['reset_epoch']
                                     for row in input_samples])

    def test_runner_appends_versioned_events_and_preserves_raw_tick_sample(self):
        from myfuzz.local_harness.request import load_local_harness_request
        from myfuzz.scenario.ownership import compile_ownership
        from myfuzz.scenario.runner import ScenarioRunner

        request = load_local_harness_request({
            'schema_version': 'local_harness.v2',
            'profile_path': 'configs/peripherals/novauart/component_profile.json',
            'instance_id': 'dut0', 'reset_assert_ticks': 1,
            'reset_release_ticks': 0, 'max_wait_cycles': 1, 'tuning': {},
        })
        profile = SimpleNamespace(component_id='anonymous_ip', endpoints=(
            SimpleNamespace(endpoint_id='opaque.pins', clock=None),))
        artifact = SimpleNamespace(
            runtime_document={
                'kind': 'tlul_register_observe',
                'base_event_schema_version': 'ip_base_event.v1',
                'clock_schedule': {'primary_clock_domain': 'peripheral'},
                'physical_exports': [self.export],
            },
            plan=SimpleNamespace(request=request, profile=profile),
        )

        class Session:
            def __init__(self):
                self.reset_epoch = 4
                self.artifact = artifact

            def drain_tick_samples(self):
                return [{'local_tick': 3,
                         'pre': {'status_bus': 0b011,
                                 'physical': {'rt_status': 0b011}},
                         'post': {'status_bus': 0b011,
                                  'physical': {'rt_status': 0b011}}}]

        runner = ScenarioRunner(sessions={'dut0': Session()},
                                ownership=compile_ownership((), ()), bindings=())
        runner.local_ticks['dut0'] = 3
        runner._drain_tick_samples(producer_event_id=1)
        rows = list(runner._events)

        raw = next(row for row in rows if row['kind'] == 'local_tick_sample')
        normalized = [row for row in rows if row.get('schema_version') == 'ip_base_event.v1']
        self.assertEqual(2, len(normalized))
        self.assertEqual(0b011, normalized[0]['payload']['value'])
        self.assertEqual([raw['event_id']], normalized[0]['raw_event_refs'])
        self.assertEqual({'status_bus': 0b011,
                          'physical': {'rt_status': 0b011}}, raw['outputs'])

        old_document = dict(artifact.runtime_document)
        old_document.pop('base_event_schema_version')
        old_artifact = SimpleNamespace(
            runtime_document=old_document,
            plan=SimpleNamespace(request=request, profile=profile),
        )
        old_session = SimpleNamespace(artifact=old_artifact)
        self.assertIsNone(runner._ip_base_event_normalizer('legacy', old_session))

    def test_runner_links_profile_binding_delivery_to_matching_target_input_sample(self):
        from myfuzz.local_harness.request import load_local_harness_request
        from myfuzz.scenario.ownership import (InputField, InputOwner,
                                               compile_ownership)
        from myfuzz.scenario.runner import Binding, ScenarioRunner

        def artifact(component_id, instance_id, endpoint_id, clock, exports,
                     *, protocol_trace=None, bound_inputs=()):
            request = load_local_harness_request({
                'schema_version': 'local_harness.v2',
                'profile_path': 'configs/peripherals/novauart/component_profile.json',
                'instance_id': instance_id, 'reset_assert_ticks': 1,
                'reset_release_ticks': 0, 'max_wait_cycles': 2, 'tuning': {},
            })
            profile = SimpleNamespace(component_id=component_id, endpoints=(
                SimpleNamespace(endpoint_id=endpoint_id, clock=clock),))
            document = {
                'kind': 'apb3_register_observe',
                'base_event_schema_version': 'ip_base_event.v1',
                'clock_schedule': {'primary_clock_domain': clock},
                'effective_max_wait_cycles': 2,
                'physical_exports': list(exports),
            }
            if protocol_trace is not None:
                document['base_protocol_trace'] = protocol_trace
            if bound_inputs:
                document['bound_physical_inputs'] = list(bound_inputs)
            return SimpleNamespace(runtime_document=document,
                                   plan=SimpleNamespace(request=request, profile=profile))

        source_export = {
            'endpoint_id': 'opaque.source', 'role': 'sampled_state',
            'physical_port': 'unusual_output_name',
            'runtime_name': 'rt_unusual_output', 'bit_lo': 0, 'bit_hi': 0,
            'width': 1, 'direction': 'output', 'encoding': 'integer',
        }
        target_export = {
            'endpoint_id': 'opaque.pins', 'role': 'wake_hint',
            'physical_port': 'pin_with_unrelated_name',
            'runtime_name': 'rt_pin_17', 'bit_lo': 0, 'bit_hi': 0,
            'width': 1, 'direction': 'input', 'encoding': 'integer',
        }
        trace_roles = ('psel', 'penable', 'pwrite', 'paddr', 'pwdata',
                       'pready', 'prdata', 'pslverr')
        protocol_trace = {
            'schema_version': 'ip_protocol_trace.v1', 'protocol': 'apb3',
            'endpoint_id': 'opaque.pins', 'clock_domain': 'target_clk',
            'max_wait_cycles': 2,
            'signals': {role: 'trace_' + role for role in trace_roles},
            'signal_widths': {'psel': 1, 'penable': 1, 'pwrite': 1,
                              'paddr': 12, 'pwdata': 32, 'pready': 1,
                              'prdata': 32, 'pslverr': 1},
        }
        bound = {'endpoint_id': 'opaque.pins', 'role': 'wake_hint',
                 'input_name': 'opaque.pins.wake_hint',
                 'runtime_name': 'rt_pin_17', 'width': 1,
                 'producer_ref': 'source.unusual_output_name'}

        class Session:
            def __init__(self, artifact, *, epoch=0, samples=()):
                self.artifact = artifact
                self.reset_epoch = epoch
                self._samples = list(samples)

            def drain_tick_samples(self):
                samples, self._samples = self._samples, []
                return samples

        source_session = Session(artifact(
            'source_ip', 'src0', 'opaque.source', 'source_clk', (source_export,)))
        backend = {'trace_' + role: 0 for role in trace_roles}
        target_session = Session(artifact(
            'target_ip', 'dst0', 'opaque.pins', 'target_clk', (target_export,),
            protocol_trace=protocol_trace, bound_inputs=(bound,)), epoch=4,
            samples=({'local_tick': 1,
                      'pre': {'backend': backend,
                              'physical': {'rt_pin_17': 0}},
                      'post': {'backend': backend,
                               'physical': {'rt_pin_17': 0}}},
                     {'local_tick': 2,
                      'pre': {'backend': backend,
                              'physical': {'rt_pin_17': 1}},
                      'post': {'backend': backend,
                               'physical': {'rt_pin_17': 1}}}))
        ownership = compile_ownership(
            (InputField('target', 'opaque.pins.wake_hint', 1),),
            (InputOwner('target', 'opaque.pins.wake_hint', 0, 1,
                        'bound', 'source.unusual_output_name'),))
        runner = ScenarioRunner(
            sessions={'source': source_session, 'target': target_session},
            ownership=ownership,
            bindings=(Binding('source', 'unusual_output_name', 'target',
                              'opaque.pins.wake_hint', 1),))
        runner.local_ticks['target'] = 2
        source_raw = {'event_id': 1, 'kind': 'local_tick_sample',
                      'component': 'source', 'local_tick': 1,
                      'phase': 'post', 'outputs': {'unusual_output_name': 1}}
        runner._events.append_unchecked(source_raw)
        runner._route_observed_outputs('source', {'unusual_output_name': 1},
                                       event_id=1, source_tick=1,
                                       source_phase='post')
        runner._drain_tick_samples(producer_event_id=1)
        target_session.reset_epoch = 5
        target_session._samples = [{'local_tick': 3,
                                    'pre': {'backend': backend,
                                            'physical': {'rt_pin_17': 1}},
                                    'post': {'backend': backend,
                                             'physical': {'rt_pin_17': 1}}}]
        runner.local_ticks['target'] = 3
        runner._drain_tick_samples(producer_event_id=1)

        rows = list(runner._events)
        deliveries = [row for row in rows
                      if row.get('event_type') == 'binding_delivery']
        input_samples = [row for row in rows
                         if row.get('event_type') == 'input_sample']
        self.assertEqual(1, len(deliveries))
        self.assertEqual(1, len(input_samples))
        self.assertEqual([1], deliveries[0]['raw_event_refs'])
        self.assertEqual(4, deliveries[0]['payload']['target_reset_epoch'])
        self.assertEqual(4, input_samples[0]['reset_epoch'])
        self.assertEqual(deliveries[0]['event_id'],
                         input_samples[0]['binding_delivery_event_id'])
        target_raw = next(row for row in rows
                          if row['kind'] == 'local_tick_sample'
                          and row['component'] == 'target'
                          and row['local_tick'] == 2 and row['phase'] == 'pre')
        self.assertEqual([target_raw['event_id']],
                         input_samples[0]['raw_event_refs'])
        self.assertEqual(1, input_samples[0]['payload']['value'])


if __name__ == '__main__':
    unittest.main()
