"""Pinned PULP APB timer: real count, comparator IRQ, reset and replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.timer_session import GeneratedPulpTimerSession
from myfuzz.scenario.contracts import ResourceBudget, ScenarioManifest
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedPulpTimerRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-pulp-timer-')
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/pulp_timer/component_profile.json',
            instance_id='timer_a', reset_assert_ticks=8, reset_release_ticks=8,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        top = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        cls.artifact = render_local_driver(top, base_dir=ROOT)
        cls.cache = Path(cls.temp.name) / 'cache'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, name):
        timer = GeneratedPulpTimerSession(self.artifact, base_dir=ROOT, cache_dir=self.cache)
        timer.prepare_local()
        timer.begin_case(name)
        self.addCleanup(timer.end_case)
        return timer

    def test_two_independent_counters_native_irq_and_reset(self):
        timer = self.session('timer-count-irq')
        self.assertEqual(0, timer.read_register(0))
        timer.write_register(8, 5)
        timer.write_register(4, 1)
        timer.write_register(24, 7)
        timer.write_register(20, 1)
        levels = [timer.step_local({})['irq_o'] for _ in range(36)]
        self.assertTrue(any(level & 2 for level in levels))
        self.assertTrue(any(level & 8 for level in levels))
        self.assertTrue(any(edge['bit'] == 1 and edge['level'] == 1
                            for edge in timer.irq_edges))
        self.assertTrue(any(edge['bit'] == 3 and edge['level'] == 1
                            for edge in timer.irq_edges))
        self.assertLess(timer.read_register(0), 6)
        self.assertLess(timer.read_register(16), 8)
        samples = timer.drain_tick_samples()
        self.assertTrue(any(row['pre']['irq_o'] or row['post']['irq_o']
                            for row in samples))
        with self.assertRaisesRegex(ValueError, 'full-word'):
            timer.write_register(8, 3, be=1)
        with self.assertRaisesRegex(ValueError, 'external input'):
            timer.step_local({'irq_o': 1})
        timer.reset_local()
        self.assertEqual(0, timer.read_register(0))
        self.assertEqual(0, timer.read_register(4))
        self.assertEqual(0, timer.read_register(8))
        self.assertEqual(0, timer.read_register(16))
        self.assertEqual([], timer.irq_edges)

    def test_budgeted_formal_replay(self):
        def factory():
            timer = GeneratedPulpTimerSession(self.artifact, base_dir=ROOT,
                cache_dir=self.cache)
            return ScenarioRunner(sessions={'timer': timer},
                ownership=compile_ownership((), ()), bindings=())

        identity = factory().identity_document()
        doc = self.artifact.runtime_document
        timing = dict(schema_version='generated_local_reset.v1',
            artifact_digest=doc['artifact_digest'], driver_sha256=doc['cpp_sha256'],
            hold_cycles=8, release_cycles=8)
        manifest = ScenarioManifest.from_runner_identity(identity,
            scenario_id='generated-pulp-timer', schedule_order=('timer',),
            scheduler_policy_id='stable-local-v1', budget=ResourceBudget(),
            reset_timings={'timer': timing})
        self.assertEqual('apb_timer',
            manifest.to_document()['runner_identity']['sessions']['timer']['identity']['runtime_artifact']['kind'])

        genome = ScenarioGenome(testcase_id='generated-timer-replay',
            direction='IP_TO_CPU', path_id='timer-native-irq',
            schedule_order=('timer',), max_steps=32, actions=())
        bundle = Path(self.temp.name) / 'formal-timer-evidence'
        trace = save_evidence_bundle(genome, factory, bundle,
            budget=ResourceBudget(max_wall_time_ms=180000))
        self.assertEqual('complete', trace.status)
        self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                            and event.get('component') == 'timer'
                            and 'irq_o' in event.get('outputs', {})
                            for event in trace.events))
        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
