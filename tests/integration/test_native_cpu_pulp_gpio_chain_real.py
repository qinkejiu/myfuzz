"""Row 5: the native ready-valid memory CPU reaches a real PULP APB3 GPIO.

The P6 checklist's row 5 (PicoRV32 native ``ready-valid-memory/1``) records that
the CPU has real RAM/ROM acceptance but *no* MMIO target, no address window and
no consumption chain to a real GPIO: its profile declares exactly one
``memory_master`` endpoint, and ``GeneratedNativeMemorySession`` serves every
accepted beat out of local RAM, so an access outside the RAM regions aborts the
run and an access inside them would be aliased into RAM.

This test runs the real pinned PicoRV32 RTL through the generated native driver
and the real pinned PULP APB3 GPIO RTL in a second generated harness, connected
by a scenario-level :class:`~myfuzz.scenario.router.DataflowRouter` window.  The
program the CPU executes stores PADDIR/GPIOEN/PADOUT and loads PADIN, so the
evidence is a real CPU beat delivered to the device and a real device answer
returned to the CPU -- not a synthesised register value.  No RTL was modified
and no value is computed in Python: every register answer asserted below is the
device's own readback, and every pin value is the device's own output.

What this deliberately does not claim: a continuous multi-case session, an
IRQ/handler path, deferred MMIO, or any byte-enable/partial-write support (the
device declares ``byte_enable: false``, so a partial write fails closed).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from myfuzz.local_harness import (render_local_harness, render_local_runtime,
                                  verify_local_source_lock)
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner

ROOT = Path(__file__).resolve().parents[2]
CPU_PROFILE = 'configs/cpus/picorv32/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/pulp_gpio/component_profile.json'

GPIO_BASE = 0x40000000
GPIO_SIZE = 0x1000
PADDIR = 0x00
GPIOEN = 0x04
PADIN = 0x08
PADOUT = 0x0C
OTHER_BASE = 0x50000000

#: The byte the external world drives on gpio_in, and the byte the CPU stores.
DRIVEN_INPUT = 0x5A
INSTALLED_OUTPUT = 0x5A
RESULT_WORD = 0x100
MARKER_WORD = 0x104
RUN_LIMIT = 600


def program() -> str:
    """RV32I program: configure the GPIO, drive PADOUT, read PADIN into RAM.

    0x40000000 is the declared device window base; every other data address is
    inside the 4 KiB RAM region.  The last store is a completion marker so the
    test can stop without guessing a tick budget.
    """
    words = [
        0x400000b7,  # lui  x1, 0x40000      -> x1 = 0x40000000 (device window)
        0xfff00113,  # addi x2, x0, -1      -> x2 = 0xffffffff
        0x0020a023,  # sw   x2, 0(x1)       -> PADDIR
        0x0020a223,  # sw   x2, 4(x1)       -> GPIOEN
        0x05a00193,  # addi x3, x0, 0x5a
        0x0030a623,  # sw   x3, 12(x1)      -> PADOUT
        0x0080a203,  # lw   x4, 8(x1)       -> PADIN
        0x10402023,  # sw   x4, 256(x0)     -> real device value into RAM
        0x00100293,  # addi x5, x0, 1
        0x10502223,  # sw   x5, 260(x0)     -> completion marker
        0x0000006f,  # jal  x0, 0           -> park
    ]
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _artifact(profile: str, instance: str):
    from myfuzz.local_harness.request import load_local_harness_request
    from myfuzz.local_harness.plan import plan_local_harness

    request = load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=profile,
        instance_id=instance, reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


class NativeCpuPulpGpioChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-native-gpio-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.cpu_artifact = _artifact(CPU_PROFILE, 'cpu')
        cls.gpio_artifact = _artifact(GPIO_PROFILE, 'gpio')
        build_local_harness(cls.cpu_artifact, base_dir=ROOT, cache_dir=cls.cache)
        build_local_harness(cls.gpio_artifact, base_dir=ROOT, cache_dir=cls.cache)

    def chain(self, *, window_base: int = GPIO_BASE):
        """Real CPU harness + real GPIO harness joined by one declared window."""
        gpio = GeneratedPulpGpioSession(self.gpio_artifact, base_dir=ROOT,
                                        cache_dir=self.cache)
        gpio.prepare_local()
        gpio.begin_case('native-gpio-chain')
        self.addCleanup(gpio.end_case)
        router = DataflowRouter((DeviceWindow('gpio', window_base, GPIO_SIZE, gpio),))
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                                  initialization_seed=7, max_initialized_bytes=0x1000)
        memory.preload(0, bytes.fromhex(program()))
        cpu = GeneratedNativeMemorySession(self.cpu_artifact, base_dir=ROOT,
                                           cache_dir=self.cache, memory=memory,
                                           router=router)
        cpu.begin_case('native-gpio-chain')
        self.addCleanup(cpu.end_case)
        return cpu, gpio, router, memory

    def drive_input(self, gpio, value: int = DRIVEN_INPUT) -> None:
        """Drive gpio_in, then let the RTL's input synchronizers settle."""
        gpio.step_local({'gpio_in': value})
        for _ in range(6):
            gpio.step_local({})

    def run_program(self, cpu):
        """Step the real CPU RTL until its completion marker reaches RAM."""
        for _ in range(RUN_LIMIT):
            cpu.step_local({})
            if any(event['kind'] == 'memory_write' and event['address'] == MARKER_WORD
                   and event['value'] == 1 for event in cpu.service.events):
                return True
        return False

    # -- premises ----------------------------------------------------------
    def test_the_cpu_is_the_native_memory_profile_with_no_declared_window(self):
        """The row's premise: one memory_master endpoint and no MMIO window."""
        document = json.loads((ROOT / CPU_PROFILE).read_text())
        self.assertEqual('picorv32', document['component_id'])
        self.assertEqual(['processor.memory'],
                         [row['endpoint_id'] for row in document['endpoints']])
        self.assertEqual(['ready-valid-memory', '1'],
                         document['endpoints'][0]['protocol'])
        self.assertNotIn('address', document, 'the profile declares no MMIO window')
        self.assertEqual('native_memory_cpu',
                         self.cpu_artifact.runtime_document['kind'])

    def test_the_gpio_side_really_is_the_pinned_pulp_apb3_device(self):
        self.assertEqual('apb_gpio', self.gpio_artifact.runtime_document['kind'])
        self.assertEqual('third_party/soc-pulp-apb-gpio',
                         self.gpio_artifact.plan.profile.source.source_root)

    # -- CPU -> IP ---------------------------------------------------------
    def test_cpu_stores_reach_the_real_gpio_and_the_pins_follow(self):
        cpu, gpio, router, memory = self.chain()
        self.drive_input(gpio)
        self.assertTrue(self.run_program(cpu), 'the CPU program never completed')

        self.assertEqual(
            [(PADDIR, True), (GPIOEN, True), (PADOUT, True), (PADIN, False)],
            [(row['offset'], row['write']) for row in router.deliveries],
            'exactly the four MMIO beats, in program order, reach the device')
        self.assertEqual(3, cpu.mmio_write_count)
        self.assertEqual(1, cpu.mmio_read_count)
        self.assertEqual(2, cpu.memory_write_count,
                         'only the two RAM stores are RAM traffic')

        # The device's own readback, then the device's own output pins.
        self.assertEqual(INSTALLED_OUTPUT, gpio.read_register(PADOUT))
        state = gpio.step_local({})
        self.assertEqual(INSTALLED_OUTPUT, state['gpio_out'],
                         'the real GPIO output pins must carry the CPU store')
        self.assertEqual(0xFFFFFFFF, state['gpio_dir'],
                         'the real GPIO direction pins must carry the CPU store')
        self.assertEqual(DRIVEN_INPUT, state['gpio_in_sync'])
        self.assertEqual(DRIVEN_INPUT,
                         memory.read(RESULT_WORD, 4, transaction_id='check').value)

    # -- IP -> CPU ---------------------------------------------------------
    def test_device_input_reaches_the_cpu_through_the_window(self):
        cpu, gpio, router, memory = self.chain()
        # Drive the pin before the CPU starts: PADIN then reads the RTL's own
        # synchronized input register rather than a value Python remembers.
        self.drive_input(gpio)
        self.assertTrue(self.run_program(cpu), 'the CPU program never completed')

        self.assertEqual(DRIVEN_INPUT, gpio.read_register(PADIN),
                         'the device itself must read the driven pin')
        self.assertEqual(DRIVEN_INPUT,
                         memory.read(RESULT_WORD, 4, transaction_id='check').value,
                         'the CPU must store the device value it loaded')
        read = [row for row in router.deliveries if not row['write']]
        self.assertEqual([PADIN], [row['offset'] for row in read])
        self.assertEqual(DRIVEN_INPUT, read[0]['read_value'],
                         'the routed read response is the device answer')

    # -- the window boundary stays fail-closed -----------------------------
    def test_an_address_outside_every_declared_window_never_reaches_the_device(self):
        """A different window base must not capture the program's MMIO beats."""
        cpu, gpio, router, memory = self.chain(window_base=OTHER_BASE)
        with self.assertRaisesRegex(ProtocolEnvironmentError,
                                    'native backend error without completion'):
            for _ in range(RUN_LIMIT):
                cpu.step_local({})
        self.assertEqual([], router.deliveries)
        self.assertEqual(0, cpu.mmio_write_count)
        self.assertEqual(0, gpio.read_register(PADOUT),
                         'the device must never have been written')
        self.assertIsNone(cpu.process, 'the failed run is terminated, not continued')


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class NativeCpuPulpGpioScenarioTests(unittest.TestCase):
    """The same chain through the real scenario runner, with fresh replay.

    The direct chain above drives the two sessions itself.  This one hands the
    same CPU, the same device and the same declared window to
    :class:`~myfuzz.scenario.runner.ScenarioRunner`, so the routed beat is
    budgeted by ``max_mmio_target_accesses_per_step`` and the whole case is
    recorded and replayed from the initial state.  It is one case, not the
    multi-case persistent session the row still needs.
    """

    def make_factory(self, cache_dir: Path):
        cpu_artifact = _artifact(CPU_PROFILE, 'cpu')
        gpio_artifact = _artifact(GPIO_PROFILE, 'gpio')
        instances = []

        def factory():
            memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                                      initialization_seed=37,
                                      max_initialized_bytes=0x1000)
            gpio = GeneratedPulpGpioSession(gpio_artifact, base_dir=ROOT,
                                            cache_dir=cache_dir)
            router = DataflowRouter(
                (DeviceWindow('gpio', GPIO_BASE, GPIO_SIZE, gpio),))
            cpu = GeneratedNativeMemorySession(cpu_artifact, base_dir=ROOT,
                                               cache_dir=cache_dir, memory=memory,
                                               router=router)
            ownership = compile_ownership((InputField('gpio', 'gpio_in', 32),),
                (InputOwner('gpio', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),))
            runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio},
                                    ownership=ownership, bindings=())
            instances.append(runner)
            return runner

        return factory, instances

    @staticmethod
    def genome() -> ScenarioGenome:
        return ScenarioGenome(
            testcase_id='native-pulp-gpio-chain', direction='CPU_TO_IP_TO_CPU',
            path_id='native-gpio-out-in-cpu-read', schedule_order=('cpu', 'gpio'),
            max_steps=390, actions=(),
            initial_images=(MemoryImage('program', 'cpu', 0, program()),
                            MemoryImage('result', 'cpu', RESULT_WORD, 'a5' * 8)))

    def test_the_routed_case_runs_and_replays_under_the_scenario_runner(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-native-gpio-case-') as directory:
            factory, instances = self.make_factory(Path(directory) / 'cache')
            case = self.genome()
            trace = record_scenario(case, factory)
            self.assertEqual('complete', trace.status)

            deliveries = [event for event in trace.events
                          if event.get('kind') == 'mmio_delivery']
            self.assertEqual(
                [('gpio', PADDIR, True, 0xFFFFFFFF), ('gpio', GPIOEN, True, 0xFFFFFFFF),
                 ('gpio', PADOUT, True, INSTALLED_OUTPUT), ('gpio', PADIN, False, 0)],
                [(event['device_id'], event['offset'], event['write'],
                  event['write_value'] if event['write'] else event['read_value'])
                 for event in deliveries])

            write = next(event for event in deliveries if event['offset'] == PADOUT)
            self.assertTrue(any(event.get('component') == 'gpio'
                                and event.get('outputs', {}).get('gpio_out')
                                == INSTALLED_OUTPUT
                                and event['event_id'] > write['event_id']
                                for event in trace.events),
                            'the real GPIO pins must carry the routed CPU store')

            memory = instances[-1].sessions['cpu'].memory
            self.assertEqual(0, memory.read(RESULT_WORD, 4,
                                            transaction_id='padin').value,
                             'the preloaded a5a5a5a5 must be overwritten by the '
                             'device value the CPU loaded')
            self.assertEqual(1, memory.read(MARKER_WORD, 4,
                                            transaction_id='marker').value,
                             'the CPU program completed inside the runner')
            self.assertTrue(replay_scenario(case, factory, trace).matches)


if __name__ == '__main__':
    unittest.main()
