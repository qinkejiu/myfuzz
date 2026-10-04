"""Generated session admission follows the audited artifact kind."""
import unittest

from myfuzz.scenario.contracts import _generated_session_class_kind
from myfuzz.local_harness.runtime_renderer import _apb_local_kind


class GeneratedSessionRegistrationTests(unittest.TestCase):
    def test_existing_classes_declare_exact_kinds(self):
        expected = {
            'myfuzz.local_harness.cpu_session.GeneratedCve2Session': 'obi_cpu',
            'myfuzz.local_harness.native_session.GeneratedNativeMemorySession': 'native_memory_cpu',
            'myfuzz.local_harness.axi_lite_session.GeneratedAxiLiteMemorySession': 'axi4_lite_cpu',
            'myfuzz.local_harness.wishbone_cpu_session.GeneratedWishboneCpuSession': 'wishbone_cpu',
            'myfuzz.local_harness.axi4_cpu_session.GeneratedAxi4CpuSession': 'axi4_cpu',
            'myfuzz.local_harness.gpio_session.GeneratedPulpGpioSession': 'apb_gpio',
            'myfuzz.local_harness.spi_session.GeneratedPulpSpiSession': 'apb_spi',
            'myfuzz.local_harness.opentitan_gpio_session.GeneratedOpentitanGpioSession': 'tlul_gpio',
        }
        for name, kind in expected.items():
            with self.subTest(name=name):
                self.assertEqual(kind, _generated_session_class_kind(name))

    def test_arbitrary_or_unregistered_class_is_rejected(self):
        for name in ('os.path.PathLike',
                     'myfuzz.local_harness.session.GeneratedLocalSession',
                     'myfuzz.local_harness.cpu_session.NoSuchClass',
                     'myfuzz.local_harness.cpu_session.GeneratedNativeMemorySession'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                _generated_session_class_kind(name)

    def test_timer_executor_requires_typed_profile_variant(self):
        native_irq = [{'disposition': 'observe', 'direction': 'output',
                       'physical_port': 'irq_o', 'width': 4}]
        with self.assertRaisesRegex(ValueError, 'runtime-external-pin-shape'):
            _apb_local_kind([], native_irq, {})
        self.assertEqual('apb_timer', _apb_local_kind(
            [], native_irq, {'local_runtime_variant': 'apb_timer'}))


if __name__ == '__main__':
    unittest.main()
