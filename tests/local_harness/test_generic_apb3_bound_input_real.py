"""Two generic APB3 GPIOs exchange a real output through a bound input."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedApb3RegisterSession,
    compile_generated_register_bindings, compile_generated_register_ownership,
    create_generated_register_session,
    load_local_harness_request)
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from tests.local_harness.test_generic_apb3_register_real import ROOT, artifact, request


def source_request():
    document = request('gpio', fixed=(('gpio.pins', 'in', 0),)).document()
    document['instance_id'] = 'generic_apb_gpio_a'
    return load_local_harness_request(document)


def target_request(*, producer_ref='a.gpio_out', overlap=False):
    document = request('gpio').document()
    document['instance_id'] = 'generic_apb_gpio_b'
    document['tuning']['bound_bindings'] = [dict(
        endpoint_id='gpio.pins', role='in', producer_ref=producer_ref)]
    if overlap:
        document['tuning']['environment_bindings'] = [dict(
            endpoint_id='gpio.pins', role='in', source_id='illicit_source')]
    return load_local_harness_request(document)


def ownership():
    return compile_ownership((InputField('b', 'gpio.pins.in', 32),),
        (InputOwner('b', 'gpio.pins.in', 0, 32, 'bound', 'a.gpio_out'),))


class GenericApb3BoundContractTests(unittest.TestCase):
    def test_target_binding_identity_and_mutation_rejection(self):
        target = artifact(target_request())
        alternate = artifact(target_request(producer_ref='other.real_output'))
        self.assertEqual('apb3_register_observe', target.runtime_document['kind'])
        self.assertEqual('a.gpio_out',
                         target.runtime_document['bound_physical_inputs'][0]['producer_ref'])
        self.assertNotEqual(target.runtime_document['artifact_digest'],
                            alternate.runtime_document['artifact_digest'])
        with self.assertRaisesRegex(ValueError, 'overlapping-input-owners'):
            artifact(target_request(overlap=True))
        with self.assertRaisesRegex(ValueError, 'cannot be mutated'):
            ownership().mutation_source('b', 'gpio.pins.in', 0, 32,
                                        direction='IP_TO_IP')
        with tempfile.TemporaryDirectory() as directory:
            session = GeneratedApb3RegisterSession(target, base_dir=ROOT,
                cache_dir=Path(directory))
            with self.assertRaisesRegex(ValueError, 'exact real output route'):
                ScenarioRunner(sessions={'b': session}, ownership=ownership(),
                               bindings=())
            with self.assertRaisesRegex(ValueError, 'fixed input'):
                session.step_local({'gpio.pins.in': 1})


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class GenericApb3BoundRealTests(unittest.TestCase):
    def test_gpio_a_real_output_persists_at_gpio_b_input_until_real_irq_and_replay(self):
        source = artifact(source_request())
        target = artifact(target_request())
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-apb3-bound-') as directory:
            work = Path(directory)
            sessions = []

            def factory():
                a = create_generated_register_session(source, base_dir=ROOT,
                    cache_dir=work / 'cache',
                    setup_writes=((0x00, 1), (0x04, 1), (0x0c, 1)))
                b = create_generated_register_session(target, base_dir=ROOT,
                    cache_dir=work / 'cache',
                    setup_writes=((0x04, 1), (0x18, 1), (0x1c, 1)))
                self.assertIsInstance(a, GeneratedApb3RegisterSession)
                self.assertIsInstance(b, GeneratedApb3RegisterSession)
                sessions.append((a, b))
                return ScenarioRunner(sessions={'a': a, 'b': b},
                    ownership=compile_generated_register_ownership(
                        {'a': source, 'b': target}),
                    bindings=compile_generated_register_bindings(
                        {'a': source, 'b': target}))

            genome = ScenarioGenome(testcase_id='generic-apb3-gpio-bound',
                direction='IP_TO_IP', path_id='real-a-out-b-in-b-irq',
                schedule_order=('b', 'a'), max_steps=24, actions=())
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            deliveries = [e for e in trace.events
                          if e.get('kind') == 'dataflow_delivery'
                          and e.get('source') == ('a', 'gpio_out')
                          and e.get('value', 0) & 1]
            irq_events = [e for e in trace.events
                          if e.get('component') == 'b'
                          and e.get('outputs', {}).get('interrupt', 0)]
            self.assertTrue(deliveries, 'A real GPIO output must be delivered')
            self.assertTrue(irq_events, 'B RTL must assert its own interrupt')
            self.assertLess(deliveries[0]['event_id'], irq_events[0]['event_id'],
                            'B IRQ must follow the bound A output')
            held = [e for e in trace.events if e.get('component') == 'b'
                    and e.get('inputs', {}).get('gpio.pins.in') == 1]
            self.assertGreaterEqual(len(held), 2,
                'one real A output must remain bound across B local ticks')
            self.assertTrue(replay_evidence_bundle(bundle, factory).matches)
            self.assertIsNot(sessions[0][0], sessions[1][0])


if __name__ == '__main__':
    unittest.main()
