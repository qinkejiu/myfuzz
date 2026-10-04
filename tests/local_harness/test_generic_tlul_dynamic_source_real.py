"""Declarative GPIO environment ownership and real pin-to-IRQ propagation."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import GeneratedTlulRegisterSession, load_local_harness_request
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from tests.local_harness.test_generic_tlul_register_real import ROOT, artifact, request


def dynamic_request(*, source_id='gpio_external', fixed_pin=False,
                    dynamic_role='in', include_environment=True):
    constants = [('gpio.pins', 'strap_en', 0)]
    if fixed_pin:
        constants.append(('gpio.pins', 'in', 0))
    document = request('gpio', constants=tuple(constants)).document()
    if include_environment:
        document['tuning']['environment_bindings'] = [
            dict(endpoint_id='gpio.pins', role=dynamic_role, source_id=source_id)]
    return load_local_harness_request(document)


class GenericTlulDynamicContractTests(unittest.TestCase):
    def test_physical_input_ownership_and_source_identity(self):
        a = artifact(dynamic_request())
        b = artifact(dynamic_request(source_id='another_external_source'))
        self.assertEqual('tlul_register_observe', a.runtime_document['kind'])
        self.assertEqual([dict(endpoint_id='gpio.pins', role='in',
            input_name='gpio.pins.in', runtime_name='rt_lh_p_12_31_0', width=32,
            source_id='gpio_external')], a.runtime_document['dynamic_physical_inputs'])
        self.assertEqual(['strap_en'],
            [row['role'] for row in a.runtime_document['fixed_physical_inputs']])
        self.assertEqual(a.plan.profile_sha256, b.plan.profile_sha256)
        self.assertNotEqual(a.runtime_document['artifact_digest'],
                            b.runtime_document['artifact_digest'])

    def test_overlap_unowned_and_output_binding_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'overlapping-input-owners'):
            artifact(dynamic_request(fixed_pin=True))
        with self.assertRaisesRegex(ValueError, 'unowned-input'):
            artifact(dynamic_request(include_environment=False))
        with self.assertRaisesRegex(ValueError, 'environment-input-required'):
            artifact(dynamic_request(dynamic_role='out'))
        owners = compile_ownership(
            (InputField('gpio', 'gpio.pins.strap_en', 1),
             InputField('gpio', 'gpio.pins.in', 32)),
            (InputOwner('gpio', 'gpio.pins.strap_en', 0, 1, 'fixed', 'profile_constant'),
             InputOwner('gpio', 'gpio.pins.in', 0, 32, 'bound', 'real_upstream')))
        for port, width in (('gpio.pins.strap_en', 1), ('gpio.pins.in', 32)):
            with self.subTest(port=port), self.assertRaisesRegex(ValueError, 'cannot be mutated'):
                owners.mutation_source('gpio', port, 0, width, direction='IP_TO_CPU')

    def test_runner_rejects_wrong_source_identity_and_bound_reclassification(self):
        generated = artifact(dynamic_request())
        with tempfile.TemporaryDirectory() as directory:
            session = GeneratedTlulRegisterSession(generated, base_dir=ROOT,
                cache_dir=Path(directory))
            for kind, reference in (('source', 'wrong_external'),
                                    ('bound', 'real_upstream')):
                ownership = compile_ownership(
                    (InputField('gpio', 'gpio.pins.in', 32),),
                    (InputOwner('gpio', 'gpio.pins.in', 0, 32, kind, reference),))
                with self.subTest(kind=kind), self.assertRaisesRegex(
                        ValueError, 'source identity or fixed ownership mismatch'):
                    ScenarioRunner(sessions={'gpio': session},
                        ownership=ownership, bindings=())
            fixed_as_source = compile_ownership(
                (InputField('gpio', 'gpio.pins.in', 32),
                 InputField('gpio', 'gpio.pins.strap_en', 1)),
                (InputOwner('gpio', 'gpio.pins.in', 0, 32,
                            'source', 'gpio_external'),
                 InputOwner('gpio', 'gpio.pins.strap_en', 0, 1,
                            'source', 'illicit_source')))
            with self.assertRaisesRegex(ValueError, 'source identity or fixed ownership mismatch'):
                ScenarioRunner(sessions={'gpio': session},
                    ownership=fixed_as_source, bindings=())


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class GenericTlulDynamicRealTests(unittest.TestCase):
    def test_real_gpio_pin_state_irq_and_fresh_replay(self):
        generated = artifact(dynamic_request())
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-tlul-source-') as directory:
            cache = Path(directory) / 'cache'
            direct = GeneratedTlulRegisterSession(generated, base_dir=ROOT,
                cache_dir=cache, setup_writes=((0x04, 1), (0x2c, 1)))
            direct.prepare_local()
            direct.begin_case('direct-gpio-source')
            try:
                self.assertEqual(0, direct.step_local({})['intr_gpio_o'])
                self.assertEqual(0, direct.read_register(0x10))
                with self.assertRaisesRegex(ValueError, 'fixed input'):
                    direct.step_local({'gpio.pins.strap_en': 1})
                with self.assertRaisesRegex(ValueError, 'physical width'):
                    direct.step_local({'gpio.pins.in': 1 << 32})
                self.assertEqual(0, direct.step_local({'gpio.pins.in': 1})['intr_gpio_o'])
                levels = [direct.step_local({})['intr_gpio_o'] for _ in range(8)]
                self.assertEqual(1, levels[-1] & 1)
                self.assertEqual(1, direct.read_register(0x10) & 1)
                self.assertEqual(1, direct.read_register(0x00) & 1)
                tick_count = direct.local_ticks
                direct.step_local({'gpio.pins.in': 1})
                self.assertEqual(tick_count + 1, direct.local_ticks,
                                 'unchanged source must not be reinjected')
            finally:
                direct.end_case()

            sessions = []
            ownership = compile_ownership(
                (InputField('gpio', 'gpio.pins.in', 32),),
                (InputOwner('gpio', 'gpio.pins.in', 0, 32,
                            'source', 'gpio_external'),))

            def factory():
                session = GeneratedTlulRegisterSession(generated, base_dir=ROOT,
                    cache_dir=cache, setup_writes=((0x04, 1), (0x2c, 1)))
                sessions.append(session)
                return ScenarioRunner(sessions={'gpio': session},
                    ownership=ownership, bindings=())

            genome = ScenarioGenome(testcase_id='generic-gpio-pin-irq',
                direction='IP_TO_CPU', path_id='gpio-pin-to-real-irq',
                schedule_order=('gpio',), max_steps=12,
                actions=(Action('rise', 'gpio', 'gpio.pins.in', 1,
                                'IP_TO_CPU', Trigger('START')),))
            bundle = Path(directory) / 'gpio-source-evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            self.assertTrue(any(event.get('outputs', {}).get('intr_gpio_o', 0) & 1
                                for event in trace.events))
            self.assertGreater(sessions[0].local_ticks, 12)
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(sessions[0], sessions[1])


if __name__ == '__main__':
    unittest.main()
