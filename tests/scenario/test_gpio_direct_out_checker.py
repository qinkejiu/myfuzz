"""Independent GPIO output check uses accepted writes and actual observations."""

import unittest

from myfuzz.scenario.checker import check_gpio_direct_out


class GpioDirectOutCheckerTests(unittest.TestCase):
    def test_mismatch_after_full_direct_out_write_is_reported(self):
        events = (
            {"event_id": 1, "component": "gpio_a", "outputs": {"gpio_out": 7}},
            {"event_id": 2, "kind": "mmio_delivery", "device_id": "gpio_a",
             "offset": 0x14, "write": True, "write_value": 5,
             "byte_enable": 15},
            {"event_id": 3, "component": "gpio_a", "outputs": {"gpio_out": 4}},
        )
        findings = check_gpio_direct_out(events, ("gpio_a",))
        self.assertEqual(1, len(findings))
        self.assertEqual("gpio_direct_out_mismatch:gpio_a", findings[0].finding_id)
        self.assertEqual((3, 5, 4), (findings[0].event_id,
                                     findings[0].expected, findings[0].observed))

    def test_partial_write_and_reset_do_not_create_false_expectation(self):
        events = (
            {"event_id": 1, "kind": "mmio_delivery", "device_id": "gpio_a",
             "offset": 0x14, "write": True, "write_value": 5,
             "byte_enable": 1},
            {"event_id": 2, "component": "gpio_a", "outputs": {"gpio_out": 4}},
            {"event_id": 3, "kind": "mmio_delivery", "device_id": "gpio_a",
             "offset": 0x14, "write": True, "write_value": 9,
             "byte_enable": 15},
            {"event_id": 4, "kind": "reset_barrier", "policy": "warm_all"},
            {"event_id": 5, "component": "gpio_a", "outputs": {"gpio_out": 0}},
        )
        self.assertEqual((), check_gpio_direct_out(events, ("gpio_a",)))

    def test_masked_out_write_retires_previous_direct_out_expectation(self):
        events = (
            {"event_id": 1, "kind": "mmio_delivery", "device_id": "gpio_a",
             "offset": 0x14, "write": True, "write_value": 9,
             "byte_enable": 15},
            {"event_id": 2, "kind": "mmio_delivery", "device_id": "gpio_a",
             "offset": 0x18, "write": True, "write_value": 0,
             "byte_enable": 15},
            {"event_id": 3, "component": "gpio_a", "outputs": {"gpio_out": 0}},
        )
        self.assertEqual((), check_gpio_direct_out(events, ("gpio_a",)))


if __name__ == "__main__":
    unittest.main()
