"""V2 is typed configuration, not an executable or accepted harness."""
from dataclasses import FrozenInstanceError, replace
import importlib
import unittest

from myfuzz.local_harness.request import LocalHarnessRequest, load_local_harness_request
from tests.local_harness.test_request import GOOD


def tuning_module():
    return importlib.import_module('myfuzz.local_harness.tuning')


def request_v2(tuning):
    return load_local_harness_request({**GOOD, 'schema_version': 'local_harness.v2', 'tuning': tuning})


class LocalTuningParsingTests(unittest.TestCase):
    def test_v2_is_separate_and_roundtrips(self):
        request = request_v2({})
        self.assertNotIsInstance(request, LocalHarnessRequest)
        self.assertEqual(load_local_harness_request(request.document()), request)
        with self.assertRaises(FrozenInstanceError):
            request.instance_id = 'other'

    def test_v1_rejects_tuning_and_v2_requires_it(self):
        self.assertEqual(load_local_harness_request(GOOD).document(), GOOD)
        with self.assertRaises(ValueError):
            load_local_harness_request({**GOOD, 'tuning': {}})
        with self.assertRaises(ValueError):
            load_local_harness_request({**GOOD, 'schema_version': 'local_harness.v2'})

    def test_normalized_order_fresh_documents_and_identity(self):
        rows = [{'domain': 'b', 'assert_ticks': 3, 'release_ticks': 2},
                {'domain': 'a', 'assert_ticks': 1, 'release_ticks': 0}]
        a = request_v2({'reset_policies': rows})
        b = request_v2({'reset_policies': list(reversed(rows))})
        self.assertEqual(a.document(), b.document())
        self.assertEqual(a.tuning.identity_sha256, b.tuning.identity_sha256)
        doc = a.document()
        doc['tuning']['reset_policies'][0]['assert_ticks'] = 9
        self.assertEqual(a.document(), b.document())
        c = request_v2({'reset_policies': [{'domain': 'a', 'assert_ticks': 2, 'release_ticks': 0}]})
        self.assertNotEqual(a.tuning.identity_sha256, c.tuning.identity_sha256)

    def test_strict_keys_at_every_depth(self):
        bad = [{'raw_sv': 'assign x=1;'}, {'reset_policies': [{'domain': 'a', 'assert_ticks': 1,
                'release_ticks': 0, 'raw_python': 'run()'}]},
               {'optional_signals': [{'endpoint_id': 'cfg', 'role': 'mode', 'policy': 'drive_constant'}]},
               {'optional_signals': [{'endpoint_id': 'cfg', 'role': 'mode', 'policy': 'template_default', 'value': 0}]},
               {'boot': {'endpoint_id': 'cpu', 'entry_address': 0, 'code': 'main()'}}]
        for tuning in bad:
            with self.subTest(tuning=tuning), self.assertRaises(ValueError):
                request_v2(tuning)
        with self.assertRaises(ValueError):
            load_local_harness_request({**GOOD, 'schema_version': 'local_harness.v2', 'tuning': {}, 'extra': 1})

    def test_duplicate_rows_and_types_rejected(self):
        row = {'endpoint_id': 'pins', 'role': 'in', 'source_id': 'src'}
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            request_v2({'environment_bindings': [row, row]})
        bound = {'endpoint_id': 'pins', 'role': 'in', 'producer_ref': 'gpio.out'}
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            request_v2({'bound_bindings': [bound, bound]})
        for value in (True, -1, 1025, '2', 2.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                request_v2({'reset_policies': [{'domain': 'a', 'assert_ticks': value, 'release_ticks': 0}]})
        for value in (None, [], 'raw'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                request_v2(value)
        with self.assertRaises(ValueError):
            request_v2({'irq_delivery': [{'endpoint_id': 'irq', 'role': 'irq', 'delivery': 'invent_irq'}]})

    def test_v2_request_identity_includes_common_fields(self):
        a = request_v2({})
        document = a.document()
        document['max_wait_cycles'] += 1
        b = load_local_harness_request(document)
        self.assertNotEqual(a.identity_sha256, b.identity_sha256)
        self.assertEqual(a.identity_sha256, load_local_harness_request(a.document()).identity_sha256)

    def test_supported_shapes_parse_without_claiming_capability(self):
        tuning = {'endpoint_policies': [{'endpoint_id': 'cpu.mem', 'template_id': 'obi',
            'template_version': '1', 'variant_id': 'base', 'max_outstanding': 1}],
            'optional_signals': [{'endpoint_id': 'cpu.mem', 'role': 'error', 'policy': 'template_default'}],
            'boot': {'endpoint_id': 'cpu.mem', 'entry_address': 0},
            'peer_bindings': [{'endpoint_id': 'pins', 'peer_id': 'peer'}]}
        self.assertEqual(request_v2(tuning).document()['tuning']['boot'], tuning['boot'])


def bound_fixture():
    from myfuzz.composition.component_profile import (
        ComponentProfile, EndpointSpec, ProfileField, ClockBinding, ResetBinding,
        InterruptSource, PortAction, PhysicalFacts, bind_profile)
    from myfuzz.composition.interface_description import SourceLocator
    from myfuzz.composition.source_crawler import ElaboratedPortFact
    source = SourceLocator('fixture', 'git:' + '1' * 40, 'top', files=('top.sv',))
    fields = lambda role, port, direction, width: ProfileField(role, direction=direction, width=width, aliases=(port,))
    profile = ComponentProfile(
        'fixture', 'memory', source,
        (EndpointSpec('pins', 'external_pins', fields=(fields('in', 'pin', 'input', 4),)),
         EndpointSpec('irq', 'interrupt_source', fields=(fields('irq', 'irq', 'output', 1),))),
        (ClockBinding('clk', 'core', 100),),
        (ResetBinding('rst_n', 'reset', 'active_low', True),), {},
        (PortAction('cfg', 'constant', value=3, reason='legal fixed mode'),),
        interrupts=(InterruptSource('irq', 'irq', 'active_high', 'core', 'level', 'none'),))
    ports = tuple(ElaboratedPortFact(name, direction, width, False, 'top.sv', 1, 1)
                  for name, direction, width in [('clk', 'input', 1), ('rst_n', 'input', 1),
                    ('pin', 'input', 4), ('cfg', 'input', 4), ('irq', 'output', 1)])
    facts = PhysicalFacts('top', ports, 'sha256:' + '2' * 64, source.revision)
    return profile, bind_profile(profile, facts)


class LocalTuningValidationTests(unittest.TestCase):
    def setUp(self):
        self.profile, self.binding = bound_fixture()

    def validate(self, tuning, **kwargs):
        module = tuning_module()
        return module.validate_local_harness_tuning(request_v2(tuning).tuning,
            profile=kwargs.pop('profile', self.profile), binding=kwargs.pop('binding', self.binding), **kwargs)

    def test_reset_irq_and_unbound_environment_are_only_validated(self):
        tuning = {'reset_policies': [{'domain': 'reset', 'assert_ticks': 8, 'release_ticks': 4}],
            'irq_delivery': [{'endpoint_id': 'irq', 'role': 'irq', 'delivery': 'follow_level'}],
            'environment_bindings': [{'endpoint_id': 'pins', 'role': 'in', 'source_id': 'gpio_input'}]}
        result = self.validate(tuning, registered_source_ids={'gpio_input'}, bound_inputs=set())
        self.assertEqual(result.document()['status'], 'validated_configuration_only')
        self.assertFalse(result.document()['runtime_effective'])
        result.document()['tuning']['reset_policies'][0]['assert_ticks'] = 77
        self.assertEqual(result.document()['tuning']['reset_policies'][0]['assert_ticks'], 8)
        self.assertEqual(result.identity_sha256, self.validate(tuning,
            registered_source_ids={'gpio_input'}, bound_inputs=set()).identity_sha256)

    def test_environment_requires_complete_context_and_refuses_bound_input(self):
        tuning = {'environment_bindings': [{'endpoint_id': 'pins', 'role': 'in', 'source_id': 'src'}]}
        for kwargs in ({}, {'registered_source_ids': {'src'}}, {'bound_inputs': set()},
                       {'registered_source_ids': set(), 'bound_inputs': set()},
                       {'registered_source_ids': {'src'}, 'bound_inputs': {('pins', 'in')}}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.validate(tuning, **kwargs)

    def test_bound_binding_requires_declared_upstream_owned_field(self):
        tuning = {'bound_bindings': [{'endpoint_id': 'pins', 'role': 'in',
                                      'producer_ref': 'gpio.out'}]}
        for context in (None, set()):
            with self.subTest(context=context), self.assertRaisesRegex(
                    ValueError, 'bound-input-context-required'):
                self.validate(tuning, bound_inputs=context)
        result = self.validate(tuning, bound_inputs={('pins', 'in')})
        self.assertEqual('gpio.out', result.document()['tuning']
                         ['bound_bindings'][0]['producer_ref'])

    def test_environment_cannot_override_constant_or_output(self):
        for endpoint, role in [('cfg', 'mode'), ('irq', 'irq')]:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                self.validate({'environment_bindings': [{'endpoint_id': endpoint, 'role': role, 'source_id': 'src'}]},
                              registered_source_ids={'src'}, bound_inputs=set())

    def test_optional_signals_without_verified_contract_are_rejected(self):
        for endpoint, role, value in [('cfg', 'mode', 16), ('cfg', 'mode', 4),
                                      ('pins', 'in', 0), ('irq', 'irq', 0), ('cfg', 'missing', 0)]:
            with self.subTest(endpoint=endpoint, value=value), self.assertRaises(ValueError):
                self.validate({'optional_signals': [{'endpoint_id': endpoint, 'role': role,
                               'policy': 'drive_constant', 'value': value}]})

    def test_constant_cannot_override_bound_input(self):
        with self.assertRaises(ValueError):
            self.validate({'optional_signals': [{'endpoint_id': 'cfg', 'role': 'mode',
                          'policy': 'drive_constant', 'value': 3}]}, bound_inputs={('pins', 'in')})

    def test_reset_irq_and_unavailable_template_contracts_refuse(self):
        bad = [{'reset_policies': [{'domain': 'unknown', 'assert_ticks': 1, 'release_ticks': 0}]},
               {'irq_delivery': [{'endpoint_id': 'irq', 'role': 'irq', 'delivery': 'capture_pulse_event'}]},
               {'endpoint_policies': [{'endpoint_id': 'pins', 'template_id': 'obi',
                  'template_version': '1', 'variant_id': 'base', 'max_outstanding': 1}]},
               {'optional_signals': [{'endpoint_id': 'cfg', 'role': 'mode', 'policy': 'template_default'}]},
               {'boot': {'endpoint_id': 'cpu', 'entry_address': 0}},
               {'peer_bindings': [{'endpoint_id': 'pins', 'peer_id': 'spi'}]}]
        for tuning in bad:
            with self.subTest(tuning=tuning), self.assertRaises(ValueError):
                self.validate(tuning)

    def test_stale_binding_and_non_full_top_refuse(self):
        from myfuzz.composition.component_profile import bind_profile
        for binding in (replace(self.binding, binding_hash='wrong'),
                        replace(self.binding, component_id='other'),
                        bind_profile(self.profile, replace(self.binding.facts, selection='declared'))):
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                self.validate({}, binding=binding)

    def test_pulse_requires_width_and_matching_delivery(self):
        from myfuzz.composition.component_profile import bind_profile
        interrupt = replace(self.profile.interrupts[0], trigger='pulse', pulse_width_cycles=2)
        profile = replace(self.profile, interrupts=(interrupt,))
        binding = bind_profile(profile, self.binding.facts)
        tuning = {'irq_delivery': [{'endpoint_id': 'irq', 'role': 'irq', 'delivery': 'capture_pulse_event'}]}
        result = self.validate(tuning, profile=profile, binding=binding)
        self.assertFalse(result.document()['runtime_effective'])
        invalid = replace(profile, interrupts=(replace(interrupt, pulse_width_cycles=None),))
        with self.assertRaises(ValueError):
            self.validate(tuning, profile=invalid, binding=bind_profile(invalid, binding.facts))

    def test_identity_includes_policy_profile_and_ownership_context(self):
        a = self.validate({})
        b = self.validate({'reset_policies': [{'domain': 'reset', 'assert_ticks': 9, 'release_ticks': 0}]})
        c = self.validate({}, bound_inputs={('pins', 'in')})
        profile = replace(self.profile, interrupts=(replace(self.profile.interrupts[0], polarity='active_low'),))
        d = self.validate({}, profile=profile)
        self.assertEqual(len({a.identity_sha256, b.identity_sha256, c.identity_sha256, d.identity_sha256}), 4)

    def test_existing_planner_refuses_v2(self):
        from myfuzz.local_harness.plan import plan_local_harness
        from pathlib import Path
        with self.assertRaisesRegex(ValueError, 'local-harness-request-required'):
            plan_local_harness(request_v2({}), base_dir=Path('.'))

    def test_irq_bit_outside_real_width_is_rejected(self):
        profile = replace(self.profile, interrupts=(replace(self.profile.interrupts[0], bit=1),))
        with self.assertRaisesRegex(ValueError, 'irq-bit-outside-field'):
            self.validate({'irq_delivery': [{'endpoint_id': 'irq', 'role': 'irq', 'delivery': 'follow_level'}]},
                          profile=profile)

    def test_changed_actual_profile_source_is_rejected(self):
        profile = replace(self.profile, source=replace(self.profile.source, revision='git:' + '3' * 40))
        with self.assertRaisesRegex(ValueError, 'source-facts-mismatch'):
            self.validate({}, profile=profile)

    def test_optional_signal_policy_has_no_verified_execution_contract(self):
        for policy in ('drive_constant', 'template_default'):
            row = {'endpoint_id': 'pins', 'role': 'in', 'policy': policy}
            if policy == 'drive_constant':
                row['value'] = 0
            with self.assertRaisesRegex(ValueError, 'capability-unverified:optional_signals'):
                self.validate({'optional_signals': [row]})

    def test_invalid_ownership_context_is_rejected(self):
        for context in ([('pins', 'in')], {('irq', 'irq')}, {('pins', 'unknown')}, {'pins.in'}):
            with self.subTest(context=context), self.assertRaises(ValueError):
                self.validate({}, bound_inputs=context)
        with self.assertRaises(ValueError):
            self.validate({}, registered_source_ids={'raw code()'})

    def test_irq_with_unknown_clock_domain_is_rejected(self):
        profile = replace(self.profile, interrupts=(replace(self.profile.interrupts[0], clock_domain='unknown'),))
        with self.assertRaisesRegex(ValueError, 'irq-clock-domain'):
            self.validate({'irq_delivery': [{'endpoint_id': 'irq', 'role': 'irq', 'delivery': 'follow_level'}]},
                          profile=profile)

    def test_unowned_physical_input_is_rejected(self):
        profile = replace(self.profile, port_actions=())
        with self.assertRaisesRegex(ValueError, 'undisposed-port-bits'):
            self.validate({}, profile=profile)
