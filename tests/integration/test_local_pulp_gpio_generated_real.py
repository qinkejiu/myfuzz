"""Generated, persistent PULP APB3 GPIO against pinned real RTL."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from tests.local_harness.test_renderer import ROOT, real_plan


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedPulpGpioRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-generated-pulp-gpio-')
        plan = real_plan('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')
        structure = render_local_harness(plan)
        verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
        top = render_local_runtime(plan, structure, verified, base_dir=ROOT)
        cls.artifact = render_local_driver(top, base_dir=ROOT)
        cls.cache = Path(cls.temp.name) / 'cache'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, name):
        session = GeneratedPulpGpioSession(self.artifact, base_dir=ROOT, cache_dir=self.cache)
        session.prepare_local()
        session.begin_case(name)
        self.addCleanup(session.end_case)
        return session

    def test_padout_set_clear_and_actual_apb_readback(self):
        gpio = self.session('padout')
        gpio.write_register(0x0c, 0xa5)
        self.assertEqual(0xa5, gpio.read_register(0x0c))
        gpio.write_register(0x10, 0x02)
        self.assertEqual(0xa7, gpio.read_register(0x0c))
        gpio.write_register(0x14, 0x04)
        self.assertEqual(0xa3, gpio.read_register(0x0c))
        with self.assertRaisesRegex(ValueError, 'full-word'):
            gpio.write_register(0x0c, 0xffff, be=1)
        self.assertEqual(0xa3, gpio.read_register(0x0c))
        self.assertGreater(gpio.local_ticks, 0)

    def test_independent_processes_retained_input_and_pulse_samples(self):
        first = self.session('gpio-a')
        second = self.session('gpio-b')
        first.write_register(0x04, 1)  # GPIOEN
        first.write_register(0x18, 1)  # INTEN
        first.write_register(0x1c, 1)  # rising edge for pin 0
        second.write_register(0x0c, 0x80)
        first.step_local({'gpio_in': 1})
        for _ in range(8):
            first.step_local({})
        samples = first.drain_tick_samples()
        self.assertTrue(any(item['pre']['interrupt'] or item['post']['interrupt']
                            for item in samples), 'real GPIO rising-edge pulse not observed')
        self.assertEqual(1, first.read_register(0x24) & 1)
        self.assertEqual(0, first.read_register(0x24) & 1)
        self.assertEqual(0x80, second.read_register(0x0c))
        self.assertEqual(1, first.step_local({})['gpio_in_sync'] & 1)


if __name__ == '__main__':
    unittest.main()
