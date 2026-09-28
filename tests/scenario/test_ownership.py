"""Only declared environmental sources may be changed by a mutator."""

import unittest

from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership


class OwnershipTests(unittest.TestCase):
    def fields(self):
        return (InputField("gpio_b", "cio_gpio_i", 16),
                InputField("cpu", "irq_external_i", 1),
                InputField("cpu", "clk_i", 1))

    def owners(self):
        return (
            InputOwner("gpio_b", "cio_gpio_i", 0, 8, "bound", "gpio_a.cio_gpio_o"),
            InputOwner("gpio_b", "cio_gpio_i", 8, 8, "source", "external_gpio_b"),
            InputOwner("cpu", "irq_external_i", 0, 1, "bound", "gpio_b.intr_gpio_o"),
            InputOwner("cpu", "clk_i", 0, 1, "fixed", "clock_driver"),
        )

    def test_bound_segment_cannot_be_mutated_in_any_direction(self):
        ownership = compile_ownership(self.fields(), self.owners())
        self.assertEqual("external_gpio_b", ownership.mutation_source(
            "gpio_b", "cio_gpio_i", 8, 8, direction="IP_TO_CPU"))
        for direction in ("CPU_TO_IP", "IP_TO_CPU", "MULTI_COMPONENT_CHAIN"):
            with self.subTest(direction=direction):
                with self.assertRaisesRegex(ValueError, "bound"):
                    ownership.mutation_source("gpio_b", "cio_gpio_i", 0, 8,
                                              direction=direction)
        with self.assertRaisesRegex(ValueError, "bound"):
            ownership.mutation_source("cpu", "irq_external_i", 0, 1,
                                      direction="IP_TO_CPU")
        with self.assertRaisesRegex(ValueError, "fixed"):
            ownership.mutation_source("cpu", "clk_i", 0, 1,
                                      direction="CPU_TO_IP")

    def test_overlap_or_unclassified_bits_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "overlap"):
            compile_ownership(self.fields(), self.owners() + (
                InputOwner("gpio_b", "cio_gpio_i", 7, 2, "source", "rogue"),))
        with self.assertRaisesRegex(ValueError, "unclassified"):
            compile_ownership(self.fields(), self.owners()[:-1])

    def test_crossing_a_bound_and_source_segment_is_not_mutable(self):
        ownership = compile_ownership(self.fields(), self.owners())
        with self.assertRaisesRegex(ValueError, "bound"):
            ownership.mutation_source("gpio_b", "cio_gpio_i", 7, 2,
                                      direction="IP_TO_CPU")


if __name__ == "__main__":
    unittest.main()
