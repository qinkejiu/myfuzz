"""Generated Ibex OBI and OpenTitan RV Timer close two real IRQ rounds."""
from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_rv_timer_session import GeneratedOpentitanRvTimerSession
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.checker import check_generated_rv_timer_irq_chain
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
GENOME_PATH = ROOT / 'configs/scenario/ibex_timer_two_rounds.json'


def _artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def make_factory(cache_dir: Path):
    cpu_artifact = _artifact('configs/cpus/ibex_obi_local/component_profile.json', 'cpu')
    timer_artifact = _artifact(
        'configs/peripherals/opentitan_rv_timer_local/component_profile.json', 'timer')
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0, 0x30000),),
            initialization_seed=89, max_initialized_bytes=0x30000)
        timer = GeneratedOpentitanRvTimerSession(timer_artifact, base_dir=ROOT,
                                                 cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('timer', 0x40000000, 0x1000, timer),))
        cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                                   cache_dir=cache_dir, memory=memory,
                                   router=router, defer_mmio=True)
        irq = Binding('timer', 'irq', 'cpu', 'irq', 1)
        ownership = compile_ownership(
            (InputField('cpu', 'irq', 1),),
            (InputOwner('cpu', 'irq', 0, 1, 'bound', 'timer.irq'),))
        runner = ScenarioRunner(sessions={'cpu': cpu, 'timer': timer},
                                ownership=ownership, bindings=(irq,))
        instances.append(runner)
        return runner

    return factory, instances


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedIbexOpentitanRvTimerRealTests(unittest.TestCase):
    def test_two_timer_irqs_reach_real_ibex_isr_and_replay(self):
        genome = GenomeCodec.decode(GENOME_PATH.read_bytes())
        with tempfile.TemporaryDirectory(prefix='myfuzz-generated-ibex-timer-') as directory:
            factory, instances = make_factory(Path(directory) / 'cache')
            trace = record_scenario(genome, factory)
            self.assertEqual('complete', trace.status, trace.events[-5:])
            check = check_generated_rv_timer_irq_chain(trace.events)
            self.assertTrue(check['complete'], check)
            self.assertEqual(2, len([e for e in trace.events
                if e.get('kind') == 'memory_write' and e.get('address') in (0x200, 0x204)]))
            self.assertFalse(any(e.get('kind') == 'reset_barrier' for e in trace.events))
            corrupted = deepcopy(trace.events)
            count = next(e for e in corrupted if e.get('kind') == 'mmio_delivery'
                         and e.get('device_id') == 'timer' and e.get('offset') == 0x110
                         and e.get('write') is False)
            count['read_value'] ^= 1
            self.assertIn('round_1_cpu_count_response_mismatch',
                          check_generated_rv_timer_irq_chain(corrupted)['dut_violations'])
            cut = [e for e in trace.events if not (
                e.get('kind') == 'dataflow_delivery'
                and tuple(e.get('source', ())) == ('timer', 'irq')
                and tuple(e.get('target', ())) == ('cpu', 'irq'))]
            self.assertIn('round_1_cpu_irq_vector_missing',
                          check_generated_rv_timer_irq_chain(cut)['path_incomplete'])
            replay = replay_scenario(genome, factory, trace)
            self.assertTrue(replay.matches, replay)
            self.assertIsNot(instances[0].sessions['cpu'], instances[1].sessions['cpu'])
            self.assertIsNot(instances[0].sessions['timer'], instances[1].sessions['timer'])


if __name__ == '__main__':
    unittest.main()
