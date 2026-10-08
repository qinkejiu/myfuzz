"""Generated CVA6 native M_TIMER path with a real OpenTitan RV Timer."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock)
from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
from myfuzz.local_harness.opentitan_rv_timer_session import GeneratedOpentitanRvTimerSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
BOOT = ROOT / 'third_party/docs/task-13/cva6-fixed/run/boot/boot.bin'
TIMER_BASE = 0x40000000
TIMER_COMPARE = 128
RESULT = 0x20000
TIMER_VECTOR = 0x10100


def _artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=16,
        reset_release_ticks=20, max_wait_cycles=32))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _sd(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            3 << 12 | (offset & 31) << 7 | 0x23)


def _csr(funct3: int, rd: int, csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | 0x73


def _program() -> bytes:
    # Configure the native machine-timer trap before starting the real Timer.
    main = (
        _lui(1, TIMER_VECTOR >> 12),
        _addi(1, 1, TIMER_VECTOR & 0xfff),
        _csr(1, 0, 0x305, 1),              # mtvec = TIMER_VECTOR
        _addi(1, 0, 1 << 7),
        _csr(1, 0, 0x304, 1),              # mie.MTIE = 1
        _addi(1, 0, 1 << 3),
        _csr(2, 0, 0x300, 1),              # mstatus.MIE = 1
        _lui(1, TIMER_BASE >> 12),
        _addi(2, 0, TIMER_COMPARE),
        _sw(2, 1, 0x118),                  # compare lower
        _sw(0, 1, 0x11c),                  # compare upper
        _addi(2, 0, 1),
        _sw(2, 1, 0x100),                  # interrupt enable
        _sw(2, 1, 0x4),                    # start timer
        0x0000006f,                        # wait for the real IRQ
    )

    # M_TIMER ISR captures real interrupt state, count, and mcause in RAM,
    # disables the source, clears the sticky interrupt, then returns.
    isr = (
        _lui(1, TIMER_BASE >> 12),
        _lui(8, RESULT >> 12),
        _lw(2, 1, 0x104),                  # real INTR_STATE0
        _lw(3, 1, 0x110),                  # real TIMER_V_LOWER0
        _csr(2, 4, 0x342, 0),              # mcause must be M_TIMER (7)
        _sw(2, 8, 0),
        _sw(3, 8, 4),
        _sd(4, 8, 8),                    # preserve full RV64 mcause
        _sw(0, 1, 0x100),                  # disable further IRQ delivery
        _sw(0, 1, 0x4),                    # stop counter
        _addi(5, 0, 1),
        _sw(5, 1, 0x104),                  # W1C INTR_STATE0
        _lw(6, 1, 0x104),
        _sw(6, 8, 16),                    # verify the real clear
        _addi(7, 0, 0x55),
        _sw(7, 8, 20),                    # ISR completion marker
        0x30200073,                        # mret
    )
    boot_prefix = BOOT.read_bytes()[:16]
    return (boot_prefix + b''.join(word.to_bytes(4, 'little') for word in main),
            b''.join(word.to_bytes(4, 'little') for word in isr))


def _make_factory(cpu_artifact, timer_artifact, cache_dir: Path):
    ownership = compile_ownership(
        (InputField('cpu', 'irq_external', 1),
         InputField('cpu', 'irq_timer', 1)),
        (InputOwner('cpu', 'irq_external', 0, 1, 'fixed', 'constant_zero'),
         InputOwner('cpu', 'irq_timer', 0, 1, 'bound', 'timer.irq')))
    binding = Binding('timer', 'irq', 'cpu', 'irq_timer', 1)
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0, 0x40000),),
            initialization_seed=0, max_initialized_bytes=0x40000)
        timer = GeneratedOpentitanRvTimerSession(timer_artifact, base_dir=ROOT,
            cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('timer', TIMER_BASE, 0x1000, timer),))
        cpu = GeneratedCva6Axi4Session(cpu_artifact, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True,
            command_timeout_seconds=60)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'timer': timer},
            ownership=ownership, bindings=(binding,))
        instances.append(runner)
        return runner

    return factory, instances


@unittest.skipUnless(__import__('os').environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCva6OpentitanRvTimerIrqRealTests(unittest.TestCase):
    def test_native_m_timer_isr_routes_real_timer_irq_and_replays(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        with tempfile.TemporaryDirectory(prefix='myfuzz-cva6-generated-ot-timer-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cva6/component_profile.json', 'cpu')
            timer_artifact = _artifact(
                'configs/peripherals/opentitan_rv_timer_local/component_profile.json',
                'timer')
            factory, instances = _make_factory(cpu_artifact, timer_artifact,
                                               work / 'cache')
            program, isr = _program()
            genome = ScenarioGenome(testcase_id='cva6-generated-opentitan-rv-timer',
                direction='CPU_TO_IP_TO_CPU', path_id='cva6-mtimer-tlul-axi4-ram',
                schedule_order=('cpu', 'timer'), max_steps=1400, actions=(),
                initial_images=(
                    MemoryImage('cpu.program', 'cpu', 0x10000, program.hex()),
                    MemoryImage('cpu.timer_isr', 'cpu', TIMER_VECTOR, isr.hex()),
                    MemoryImage('cpu.result', 'cpu', RESULT, bytes(24).hex()),
                ))
            budget = ResourceBudget(max_wall_time_ms=300000,
                                    max_materialized_bytes_per_memory=0x40000)
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
            self.assertEqual('complete', trace.status, trace.events[-8:])

            cpu, timer = instances[0].sessions['cpu'], instances[0].sessions['timer']
            deliveries = [event for event in trace.events
                if event.get('kind') == 'mmio_delivery'
                and event.get('device_id') == 'timer']
            self.assertTrue(any(event.get('offset') == 0x118 and event.get('write')
                                and event.get('write_value') == TIMER_COMPARE
                                for event in deliveries))
            self.assertTrue(any(event.get('offset') == 0x104 and not event.get('write')
                                for event in deliveries))
            irq_deliveries = [event for event in trace.events
                if event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('timer', 'irq')
                and tuple(event.get('target', ())) == ('cpu', 'irq_timer')
                and event.get('value') == 1]
            self.assertTrue(irq_deliveries, 'real Timer IRQ never reached CVA6 time_irq_i')
            cpu_irq_samples = [event for event in trace.events
                if event.get('component') == 'cpu'
                and event.get('inputs', {}).get('irq_timer') == 1]
            self.assertTrue(cpu_irq_samples, 'CVA6 never sampled the bound timer input')

            result_word = lambda offset: cpu.memory.read(
                RESULT + offset, 4,
                transaction_id=f'cva6-mtimer-result-{offset:x}').value
            self.assertEqual(1, result_word(0),
                             'ISR must observe the real sticky Timer interrupt state')
            self.assertGreaterEqual(result_word(4), TIMER_COMPARE,
                                    'ISR must read the real Timer counter')
            mcause = cpu.memory.read(RESULT + 8, 8,
                transaction_id='cva6-mtimer-result-mcause').value
            self.assertEqual(0x8000000000000007, mcause,
                             'CVA6 must take native machine-timer cause 7, not M_EXT')
            self.assertEqual(0, result_word(16),
                             'Timer W1C must clear its real interrupt state')
            self.assertEqual(0x55, result_word(20))
            self.assertGreaterEqual(cpu.mmio_write_count, 6)
            self.assertGreaterEqual(cpu.mmio_read_count, 3)
            self.assertFalse(any(event.get('kind') == 'reset_barrier'
                                 for event in trace.events))

            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(instances[0].sessions['cpu'], instances[1].sessions['cpu'])
            self.assertIsNot(instances[0].sessions['timer'], instances[1].sessions['timer'])


if __name__ == '__main__':
    unittest.main()
