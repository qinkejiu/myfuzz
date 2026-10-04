"""One APB3 register template accepts two pinned PULP RTL components."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedApb3RegisterSession, load_local_harness_request,
    plan_local_harness, render_local_driver, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]


def request(kind, *, fixed=(), environment=()):
    return load_local_harness_request(dict(
        schema_version='local_harness.v2',
        profile_path=f'configs/peripherals/pulp_{kind}/component_profile.json',
        instance_id='generic_apb_' + kind, reset_assert_ticks=2,
        reset_release_ticks=2, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(
            endpoint_id=f'{kind}.bus', template_id='target.apb3',
            template_version='1', variant_id='full-word', max_outstanding=1)],
            'fixed_inputs': [dict(endpoint_id=endpoint, role=role, value=value)
                             for endpoint, role, value in fixed],
            'environment_bindings': [dict(endpoint_id=endpoint, role=role,
                                           source_id=source_id)
                                     for endpoint, role, source_id in environment]},
    ))


def artifact(req):
    plan = plan_local_harness(req, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


class GenericApb3RegisterTests(unittest.TestCase):
    def test_two_profiles_share_one_generic_kind_and_fail_closed_input_ownership(self):
        gpio = artifact(request('gpio', fixed=(('gpio.pins', 'in', 0),)))
        timer = artifact(request('timer'))
        self.assertEqual('apb3_register_observe', gpio.runtime_document['kind'])
        self.assertEqual(gpio.runtime_document['kind'], timer.runtime_document['kind'])
        self.assertEqual('apb3_register_only_pin_observe_no_peer',
                         gpio.runtime_document['functional_scope'])
        self.assertEqual({'in'}, {row['role'] for row in
                                  gpio.runtime_document['fixed_physical_inputs']})
        self.assertEqual([], timer.runtime_document['fixed_physical_inputs'])
        with self.assertRaisesRegex(ValueError, 'unowned-input'):
            artifact(request('gpio'))
        with self.assertRaisesRegex(ValueError, 'constant-width'):
            artifact(request('gpio', fixed=(('gpio.pins', 'in', 1 << 32),)))

    def test_dynamic_gpio_source_is_declarative_and_cannot_overlap_fixed_owner(self):
        gpio = artifact(request('gpio', environment=(('gpio.pins', 'in', 'pins'),)))
        self.assertEqual([('gpio.pins.in', 'pins')], [(row['input_name'], row['source_id'])
            for row in gpio.runtime_document['dynamic_physical_inputs']])
        with self.assertRaisesRegex(ValueError, 'overlapping-input-owners'):
            artifact(request('gpio', fixed=(('gpio.pins', 'in', 0),),
                environment=(('gpio.pins', 'in', 'pins'),)))
        session = GeneratedApb3RegisterSession(gpio, base_dir=ROOT,
            cache_dir=Path(tempfile.gettempdir()) / 'myfuzz-apb3-contract-cache')
        wrong = compile_ownership((InputField('dut', 'gpio.pins.in', 32),),
            (InputOwner('dut', 'gpio.pins.in', 0, 32, 'bound', 'wrong'),))
        with self.assertRaisesRegex(ValueError, 'source identity'):
            ScenarioRunner(sessions={'dut': session}, ownership=wrong, bindings=())


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class GenericApb3RealTests(unittest.TestCase):
    def test_gpio_and_timer_real_registers_outputs_and_fresh_replay(self):
        cases = (
            ('gpio', (('gpio.pins', 'in', 0),),
             ((0x00, 0xffffffff), (0x0c, 0xa5)), (0x0c,), 'gpio_out', 0xa5),
            ('timer', (), ((0x08, 8), (0x04, 1)),
             (0x00,), 'irq_o', 0),
        )
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-apb3-') as directory:
            work = Path(directory)
            for kind, fixed, writes, probes, observed, expected in cases:
                with self.subTest(kind=kind):
                    generated = artifact(request(kind, fixed=fixed))
                    sessions = []

                    def factory():
                        session = GeneratedApb3RegisterSession(generated, base_dir=ROOT,
                            cache_dir=work / ('cache-' + kind),
                            setup_writes=writes, probe_offsets=probes)
                        sessions.append(session)
                        return ScenarioRunner(sessions={'dut': session},
                            ownership=compile_ownership((), ()), bindings=())

                    genome = ScenarioGenome(testcase_id='generic-apb3-' + kind,
                        direction='IP_TO_IP', path_id='apb3-register-observe',
                        schedule_order=('dut',), max_steps=12, actions=())
                    bundle = work / ('evidence-' + kind)
                    trace = save_evidence_bundle(genome, factory, bundle, budget=None)
                    self.assertEqual('complete', trace.status, trace.events[-3:])
                    self.assertEqual(expected, next(event['outputs'][observed]
                        for event in trace.events if observed in event.get('outputs', {})))
                    self.assertEqual(len(writes) + len(probes), len(sessions[0].local_transactions))
                    self.assertGreater(sessions[0].local_ticks, 12)
                    if kind == 'gpio':
                        self.assertEqual(0xa5, sessions[0].local_transactions[-1]['read_value'])
                    else:
                        self.assertGreater(sessions[0].local_transactions[-1]['read_value'], 0,
                                           'timer count must advance in real RTL')
                    replay = replay_evidence_bundle(bundle, factory)
                    self.assertTrue(replay.matches, replay.difference_context)
                    self.assertIsNot(sessions[0], sessions[1])

    def test_dynamic_gpio_pin_causes_real_irq_and_replays(self):
        generated = artifact(request('gpio', environment=(('gpio.pins', 'in', 'pins'),)))
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-apb3-source-') as directory:
            work = Path(directory)
            sessions = []
            ownership = compile_ownership((InputField('dut', 'gpio.pins.in', 32),),
                (InputOwner('dut', 'gpio.pins.in', 0, 32, 'source', 'pins'),))

            def factory():
                session = GeneratedApb3RegisterSession(generated, base_dir=ROOT,
                    cache_dir=work / 'cache', setup_writes=((0x04, 1),
                    (0x18, 1), (0x1c, 1)))
                sessions.append(session)
                return ScenarioRunner(sessions={'dut': session},
                    ownership=ownership, bindings=())

            genome = ScenarioGenome(testcase_id='generic-apb3-gpio-irq',
                direction='IP_TO_CPU', path_id='pin-real-irq',
                schedule_order=('dut',), max_steps=12,
                actions=(Action('rise', 'dut', 'gpio.pins.in', 1,
                                'IP_TO_CPU', Trigger('START')),))
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            self.assertTrue(any(event.get('outputs', {}).get('interrupt', 0)
                                for event in trace.events))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
