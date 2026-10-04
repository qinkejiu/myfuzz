"""Real pinned Pico custom IRQ handler fed by the pinned ziptimer RTL."""
from pathlib import Path
import json
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.local_harness.zip_timer_session import GeneratedZipTimerSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/cpus/picorv32_wb_irq/component_profile.json'


def artifact(profile, instance):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def program_hex():
    # Pinned firmware/custom_ops.S defines custom0 f7/getq=0, retirq=2,
    # maskirq=3; it selects f3=4 for getq and f3=6 for maskirq.
    # Default PROGADDR_IRQ=0x10, PROGADDR_RESET=0, no compressed ISA.
    words = [0x0400006f] + [0x00000013] * 3  # jal x0,0x40; padding
    words += [0x0000c28b, 0x20502023, 0x00100313, 0x20602223,
              0x0400000b]  # getq x5,q1; sw x5,0x200; marker; retirq
    words += [0x00000013] * (16-len(words))
    words += [0xff700093, 0x0600e00b, 0x40000137, 0x05000193,
              0x00312023, 0x00100213, 0x20402423, 0xffdff06f]
    # addi x1,x0,-9; maskirq x0,x1 (only irq3 enabled); lui x2,0x40000;
    # addi x3,x0,80; sw x3,0(x2) arms real timer; repeated main RAM marker.
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


class WishboneCpuIrqAcceptance(unittest.TestCase):
    def test_separate_profile_exposes_real_custom_irq_and_preserves_disabled_profile(self):
        self.assertTrue((ROOT/PROFILE).is_file(), 'IRQ-enabled profile is missing')
        old = json.loads((ROOT/'configs/cpus/picorv32_wb/component_profile.json').read_text())
        new = json.loads((ROOT/PROFILE).read_text())
        self.assertEqual('0', next(row['value'] for row in old['source']['elaboration']['parameters']
                                  if row['name'] == 'ENABLE_IRQ'))
        self.assertEqual('1', next(row['value'] for row in new['source']['elaboration']['parameters']
                                  if row['name'] == 'ENABLE_IRQ'))
        cpu = artifact(PROFILE, 'cpu_irq')
        irq = [row for row in cpu.runtime_document['physical_exports']
               if row['physical_port'] == 'irq']
        self.assertEqual(1, len(irq))
        self.assertEqual(('input', 32, 'functional'),
                         (irq[0]['direction'], irq[0]['width'], irq[0]['disposition']))
        self.assertIn('STEP_WISHBONE_IRQ', cpu.cpp_text)
        self.assertEqual('wishbone_cpu', cpu.runtime_document['kind'])

    def test_real_timer_irq_handler_ram_and_fresh_replay(self):
        self.assertTrue((ROOT/PROFILE).is_file(), 'IRQ-enabled profile is missing')
        cpu_art = artifact(PROFILE, 'cpu_irq')
        timer_art = artifact('configs/peripherals/zipcpu_timer/component_profile.json', 'timer')
        binding = Binding('timer', 'irq', 'cpu', 'irq', 1, target_bit_offset=3)
        ownership = compile_ownership((InputField('cpu', 'irq', 32),), (
            InputOwner('cpu', 'irq', 0, 3, 'fixed', 'inactive'),
            InputOwner('cpu', 'irq', 3, 1, 'bound', 'timer.irq'),
            InputOwner('cpu', 'irq', 4, 28, 'fixed', 'inactive')))
        with tempfile.TemporaryDirectory(prefix='myfuzz-pico-irq-') as directory:
            root = Path(directory)
            instances = []
            def factory():
                memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                    initialization_seed=4, max_initialized_bytes=4096)
                timer = GeneratedZipTimerSession(timer_art, base_dir=ROOT, cache_dir=root/'cache')
                router = DataflowRouter((DeviceWindow('timer', 0x40000000, 4, timer),))
                cpu = GeneratedWishboneCpuSession(cpu_art, base_dir=ROOT, cache_dir=root/'cache',
                    memory=memory, router=router)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'timer': timer},
                    ownership=ownership, bindings=(binding,), irq_pulses={binding: 1})
                instances.append((runner, cpu, memory))
                return runner
            case = ScenarioGenome(testcase_id='pico-real-timer-irq', direction='CPU_TO_IP_TO_CPU',
                path_id='wishbone-timer-custom-irq', schedule_order=('timer','cpu'),
                max_steps=800, actions=(),
                initial_images=(MemoryImage('program', 'cpu', 0, program_hex()),
                                MemoryImage('results', 'cpu', 0x200, '00'*12)))
            trace = save_evidence_bundle(case, factory, root/'evidence',
                budget=ResourceBudget(max_wall_time_ms=120000,
                    max_materialized_bytes_per_memory=4096))
            self.assertEqual('complete', trace.status, trace)
            replay = replay_evidence_bundle(root/'evidence', factory)
            self.assertTrue(replay.matches, replay)
            self.assertNotEqual(instances[0][1]._execution, instances[1][1]._execution)
            for runner, cpu, memory in instances:
                self.assertEqual([8, 1, 1], [memory.read(address, 4,
                    transaction_id=f'check-{address}').value for address in (0x200,0x204,0x208)])
                self.assertEqual(1, cpu.mmio_write_count)
                self.assertTrue(any(event.get('kind') == 'source_start' for event in runner.events))
                cpu_steps = [event for event in runner.events if event.get('component') == 'cpu'
                             and 'inputs' in event and 'outputs' in event]
                self.assertTrue(cpu_steps)
                self.assertTrue(any(event['inputs'].get('irq') == 8 for event in cpu_steps))
                self.assertTrue(any(event['outputs']['eoi'] == 8 for event in cpu_steps))
                self.assertEqual(0, cpu_steps[-1]['outputs']['eoi'])
                self.assertTrue(all(event['outputs']['trap'] == 0 for event in cpu_steps))
                handler_end = max(index for index, event in enumerate(cpu_steps)
                                  if event['outputs']['eoi'] == 8)
                self.assertTrue(any(event['outputs']['data_req_accepted']
                    and event['outputs']['data_write']
                    and event['outputs']['data_addr'] == 0x208
                    for event in cpu_steps[handler_end+1:]))
                with self.assertRaisesRegex(ValueError, 'bound input cannot be mutated'):
                    ownership.mutation_source('cpu', 'irq', 3, 1, direction='IP_TO_CPU')


if __name__ == '__main__':
    unittest.main()
