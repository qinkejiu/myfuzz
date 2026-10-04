"""Real generated ZipCPU ziptimer Wishbone register and pulse evidence."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

import jsonschema

from myfuzz.local_harness import (GeneratedZipTimerSession, load_local_harness_request,
    plan_local_harness, render_local_harness, render_local_runtime,
    render_local_driver, verify_local_source_lock)
from myfuzz.scenario.contracts import ResourceBudget, ScenarioManifest
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedZipTimerRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-generated-zip-timer-')
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/zipcpu_timer/component_profile.json',
            instance_id='timer_z', reset_assert_ticks=2, reset_release_ticks=2,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        assert plan.facts.selection == 'all' and len(plan.facts.ports) == 12
        top = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        cls.artifact = render_local_driver(top, base_dir=ROOT)
        cls.cache = Path(cls.temp.name) / 'cache'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, name):
        timer = GeneratedZipTimerSession(self.artifact, base_dir=ROOT, cache_dir=self.cache)
        timer.prepare_local()
        timer.begin_case(name)
        self.addCleanup(timer.end_case)
        return timer

    def test_real_register_registered_ack_and_single_cycle_irq(self):
        timer = self.session('timer-register')
        self.assertEqual(0, timer.read_register())
        with self.assertRaisesRegex(RuntimeError, 'Wishbone write error'):
            timer.write_register(5, be=1)
        self.assertEqual(0, timer.read_register())
        timer.write_register(20)
        self.assertGreater(timer.read_register(), 0)
        levels = [timer.step_local({})['irq'] for _ in range(24)]
        self.assertEqual(1, sum(levels))
        self.assertEqual(0, timer.read_register())
        self.assertEqual(1, sum(sample['post']['interrupt']
                                for sample in timer.drain_tick_samples()))
        with self.assertRaisesRegex(ValueError, 'one addressless register'):
            timer.read_register(4)

    def test_budgeted_manifest_saved_evidence_and_fresh_replay(self):
        ownership = compile_ownership((InputField('timer', 'load_count', 32),),
            (InputOwner('timer', 'load_count', 0, 32, 'source', 'external'),))
        def factory():
            timer = GeneratedZipTimerSession(self.artifact, base_dir=ROOT, cache_dir=self.cache)
            return ScenarioRunner(sessions={'timer': timer}, ownership=ownership, bindings=())

        budget = ResourceBudget(max_local_cycles_per_component=512,
            max_scheduler_steps=512, max_transactions=32,
            max_semantic_records=50_000, max_evidence_bytes=16 * 1024 * 1024,
            evidence_termination_reserve_bytes=1024 * 1024)
        identity = factory().identity_document()
        doc = self.artifact.runtime_document
        timing = dict(schema_version='generated_local_reset.v1',
            artifact_digest=doc['artifact_digest'], driver_sha256=doc['cpp_sha256'],
            hold_cycles=2, release_cycles=2)
        manifest = ScenarioManifest.from_runner_identity(identity,
            scenario_id='generated-zipcpu-wishbone-timer', schedule_order=('timer',),
            scheduler_policy_id='stable-local-v1', budget=budget,
            reset_timings={'timer': timing})
        schema = json.loads((ROOT / 'schemas/scenario_runtime_manifest.v1.json').read_text())
        budget_schema = json.loads((ROOT / 'schemas/scenario_manifest.v1.json').read_text())
        schema['properties']['budget'] = budget_schema['properties']['budget']
        schema['$defs'].update(budget_schema.get('$defs', {}))
        jsonschema.Draft202012Validator(schema).validate(manifest.to_document())
        genome = ScenarioGenome(testcase_id='zip-timer-one-shot', direction='IP_TO_IP',
            path_id='standalone-wishbone-timer', schedule_order=('timer',), max_steps=10,
            actions=(Action('load', 'timer', 'load_count', 5,
                            'IP_TO_IP', Trigger('START')),))
        bundle = Path(self.temp.name) / 'formal-wishbone-timer-evidence'
        trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
        self.assertEqual('complete', trace.status, [e for e in trace.events if e.get('kind') == 'budget_exhausted'])
        self.assertTrue(any(event.get('outputs', {}).get('irq', 0) == 1
                            for event in trace.events))
        self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                            and event.get('outputs', {}).get('interrupt', 0) == 1
                            for event in trace.events))
        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
