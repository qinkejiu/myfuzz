"""Dedicated boot/image contract gate for the profile composition path."""
import unittest

from myfuzz.composition.soc_image import build_image_plan
from tests.composition.soc_generation_fixture import example_plan


class SocBootContractTests(unittest.TestCase):
    def test_entry_and_memory_lifecycle_are_declared(self):
        image = build_image_plan(example_plan())
        self.assertEqual(0x10000, image.entry_address)
        self.assertEqual("frozen_before_cpu_release", image.freeze_policy)
        self.assertIn("test_begin", image.lifecycle)
        self.assertIn("dut_reset", image.lifecycle)
        self.assertIn("driver_reset", image.lifecycle)

    def test_image_layout_contains_code_and_data_segments(self):
        image = build_image_plan(example_plan())
        self.assertLess(image.segment("init_offer").raw_lo,
                        image.segment("data_offer").raw_lo)
        self.assertEqual("ram0", image.data_region_id)


if __name__ == "__main__":
    unittest.main()
