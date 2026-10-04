"""Pinned OpenTitan RV Timer through generated TL-UL and fresh replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanRvTimerSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
STARTUP = ((0x118, 5), (0x11c, 0), (0x100, 1), (0x004, 1))


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedOpentitanRvTimerRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-generated-ot-rv-timer-')
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/opentitan_rv_timer_local/component_profile.json',
            instance_id='rv_timer_ot', reset_assert_ticks=2, reset_release_ticks=2,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        assert plan.facts.selection == 'all' and len(plan.facts.ports) == 25
        top = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        cls.artifact = render_local_driver(top, base_dir=ROOT)
        cls.cache = Path(cls.temp.name) / 'cache'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, name, *, startup_writes=()):
        session = GeneratedOpentitanRvTimerSession(self.artifact, base_dir=ROOT,
            cache_dir=self.cache, startup_writes=startup_writes)
        session.prepare_local()
        session.begin_case(name)
        self.addCleanup(session.end_case)
        return session

    def test_real_timer_count_irq_and_w1c(self):
        timer = self.session('real-rv-timer')
        timer.write_register(0x118, 5)
        timer.write_register(0x11c, 0)
        timer.write_register(0x100, 1)
        self.assertEqual(1, timer.read_register(0x100))
        timer.write_register(0x004, 1)
        earlier = timer.read_register(0x110)
        levels = [timer.step_local({})['irq'] for _ in range(12)]
        later = timer.read_register(0x110)
        self.assertGreater(later, earlier)
        self.assertEqual(1, levels[-1])
        self.assertEqual(1, timer.read_register(0x104) & 1)
        timer.write_register(0x004, 0)  # Stop the compare event before clearing its sticky state.
        timer.write_register(0x104, 1)
        self.assertEqual(0, timer.step_local({})['irq'])
        self.assertTrue(any(row['post']['irq'] for row in timer.drain_tick_samples()))

    def test_saved_evidence_fresh_replay(self):
        ownership = compile_ownership((), ())
        def factory():
            timer = GeneratedOpentitanRvTimerSession(self.artifact, base_dir=ROOT,
                cache_dir=self.cache, startup_writes=STARTUP)
            return ScenarioRunner(sessions={'timer': timer}, ownership=ownership, bindings=())
        genome = ScenarioGenome(testcase_id='ot-rv-timer-compare', direction='IP_TO_IP',
            path_id='standalone-tlul-rv-timer', schedule_order=('timer',),
            max_steps=12, actions=())
        bundle = Path(self.temp.name) / 'formal-tlul-rv-timer-evidence'
        trace = save_evidence_bundle(genome, factory, bundle, budget=None)
        self.assertEqual('complete', trace.status)
        self.assertTrue(any(event.get('outputs', {}).get('irq') == 1
                            for event in trace.events))
        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
