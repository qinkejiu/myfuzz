"""A real GPIO output drives a second generated GPIO's declared bound pin."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import GeneratedTlulRegisterSession, load_local_harness_request
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner
from tests.local_harness.test_generic_tlul_register_real import ROOT, artifact, request


def bound_request(*, producer_ref='a.cio_gpio_o', overlap=False):
    document = request('gpio', constants=(('gpio.pins', 'strap_en', 0),)).document()
    document['tuning']['bound_bindings'] = [
        dict(endpoint_id='gpio.pins', role='in', producer_ref=producer_ref)]
    if overlap:
        document['tuning']['environment_bindings'] = [
            dict(endpoint_id='gpio.pins', role='in', source_id='illegal_source')]
    return load_local_harness_request(document)


class GenericTlulBoundContractTests(unittest.TestCase):
    def test_profile_only_bound_identity_and_source_override_rejection(self):
        a = artifact(bound_request())
        b = artifact(bound_request(producer_ref='other.real_output'))
        self.assertEqual([dict(endpoint_id='gpio.pins', role='in',
            input_name='gpio.pins.in', runtime_name='rt_lh_p_12_31_0',
            width=32, producer_ref='a.cio_gpio_o')],
            a.runtime_document['bound_physical_inputs'])
        self.assertNotEqual(a.runtime_document['artifact_digest'],
                            b.runtime_document['artifact_digest'])
        with self.assertRaisesRegex(ValueError, 'overlapping-input-owners'):
            artifact(bound_request(overlap=True))

    def test_runner_requires_exact_whole_field_real_route(self):
        generated = artifact(bound_request())
        ownership = compile_ownership(
            (InputField('b', 'gpio.pins.in', 32),),
            (InputOwner('b', 'gpio.pins.in', 0, 32, 'bound', 'a.cio_gpio_o'),))
        with tempfile.TemporaryDirectory() as directory:
            session = GeneratedTlulRegisterSession(generated, base_dir=ROOT,
                cache_dir=Path(directory))
            with self.assertRaisesRegex(ValueError, 'exact real output route'):
                ScenarioRunner(sessions={'b': session}, ownership=ownership,
                               bindings=())
            with self.assertRaisesRegex(ValueError, 'cannot be mutated'):
                ownership.mutation_source('b', 'gpio.pins.in', 0, 32,
                                          direction='IP_TO_IP')
            with self.assertRaisesRegex(ValueError, 'fixed input'):
                session.step_local({'gpio.pins.in': 1})


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class GenericTlulBoundRealTests(unittest.TestCase):
    def test_gpio_a_real_output_to_gpio_b_input_irq_and_fresh_replay(self):
        source = artifact(request('gpio', constants=(
            ('gpio.pins', 'in', 0), ('gpio.pins', 'strap_en', 0))))
        target = artifact(bound_request())
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-tlul-bound-') as directory:
            work = Path(directory)
            sessions = []

            def factory():
                a = GeneratedTlulRegisterSession(source, base_dir=ROOT,
                    cache_dir=work / 'cache', setup_writes=((0x14, 1), (0x20, 1)))
                b = GeneratedTlulRegisterSession(target, base_dir=ROOT,
                    cache_dir=work / 'cache', setup_writes=((0x04, 1), (0x2c, 1)))
                sessions.append((a, b))
                ownership = compile_ownership(
                    (InputField('b', 'gpio.pins.in', 32),),
                    (InputOwner('b', 'gpio.pins.in', 0, 32,
                                'bound', 'a.cio_gpio_o'),))
                return ScenarioRunner(sessions={'a': a, 'b': b},
                    ownership=ownership,
                    bindings=(Binding('a', 'cio_gpio_o', 'b', 'gpio.pins.in', 32),))

            genome = ScenarioGenome(testcase_id='real-gpio-bound-input',
                direction='IP_TO_IP', path_id='gpio-a-out-to-gpio-b-in-irq',
                schedule_order=('b', 'a'), max_steps=24, actions=())
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            self.assertTrue(any(event.get('kind') == 'dataflow_delivery'
                                and event.get('source') == ('a', 'cio_gpio_o')
                                and event.get('value', 0) & 1
                                for event in trace.events))
            self.assertTrue(any(event.get('outputs', {}).get('intr_gpio_o', 0) & 1
                                and event.get('component') == 'b'
                                for event in trace.events))
            held = [event for event in trace.events
                    if event.get('component') == 'b' and
                    event.get('inputs', {}).get('gpio.pins.in') == 1]
            self.assertGreaterEqual(len(held), 2,
                'one real output must persist across multiple target steps')
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(sessions[0][0], sessions[1][0])


if __name__ == '__main__':
    unittest.main()
