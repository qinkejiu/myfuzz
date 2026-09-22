"""Dedicated regression for the generated special-port ABI."""
import unittest

from .soc_generation_fixture import example_plan


class CustomPortLayoutTests(unittest.TestCase):
    def test_only_declared_fuzz_ports_consume_raw_bits(self):
        plan = example_plan()
        fields = plan.raw_layout["fields"]
        self.assertEqual({"cpu0::event_i:event_i", "gpio0::pin_mode_i:pin_mode_i"},
                         {field["field_id"] for field in fields})
        self.assertEqual(7, plan.raw_layout["raw_width"])
        self.assertNotIn("uart0::uart_rx_i:uart_rx_i",
                         {field["field_id"] for field in fields})

    def test_layout_identity_and_drive_strategy_are_published(self):
        layout = example_plan().raw_layout
        self.assertTrue(layout["layout_hash"])
        self.assertEqual("cycle_value", layout["drive_strategies"]["cpu0__event_i"])

    def test_external_endpoints_are_top_level_links_without_implicit_peers(self):
        links = example_plan().spec["environment_links"]
        ids = {item["link_id"] for item in links}
        self.assertIn("uart0:uart.pins", ids)
        self.assertIn("gpio0:gpio.pins", ids)
        for item in links:
            self.assertEqual("top_level_unbound", item["parameters"]["connection"])
            self.assertIsNone(item["parameters"]["peer"])

    def test_unavailable_bfm_modes_are_recorded_as_gaps(self):
        gaps = " ".join(example_plan().gaps)
        self.assertIn("mmio_only", gaps)
        self.assertIn("mixed", gaps)
        self.assertIn("synthetic beat-master", gaps)


if __name__ == "__main__":
    unittest.main()
