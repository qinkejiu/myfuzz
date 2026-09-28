"""A scenario keeps independent harnesses alive and routes observed outputs."""

import unittest

from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner


class RecordingSession:
    def __init__(self, outputs=()):
        self.outputs = list(outputs)
        self.begins = 0
        self.steps = []
        self.ends = 0

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        self.steps.append(dict(inputs))
        return self.outputs.pop(0) if self.outputs else {}

    def end_case(self):
        self.ends += 1


class RunnerContinuityTests(unittest.TestCase):
    def setUp(self):
        self.cpu = RecordingSession(outputs=({"mmio_write_data": 0x35}, {}))
        self.gpio = RecordingSession(outputs=({"irq": 1}, {}))
        ownership = compile_ownership(
            (InputField("cpu", "program_word", 32),
             InputField("cpu", "irq", 1),
             InputField("gpio", "mmio_write_data", 32)),
            (InputOwner("cpu", "program_word", 0, 32, "source", "cpu_program"),
             InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq"),
             InputOwner("gpio", "mmio_write_data", 0, 32, "bound",
                        "cpu.mmio_write_data")))
        self.runner = ScenarioRunner(
            sessions={"cpu": self.cpu, "gpio": self.gpio}, ownership=ownership,
            bindings=(Binding("cpu", "mmio_write_data", "gpio", "mmio_write_data", 32),
                      Binding("gpio", "irq", "cpu", "irq", 1)))

    def test_output_routes_to_later_input_without_reset(self):
        self.runner.begin_test("case-1")
        self.runner.inject_source("cpu", "program_word", 0x12345678,
                                  direction="CPU_TO_IP")
        self.runner.step("cpu")
        self.runner.step("gpio")
        self.runner.step("cpu")
        self.assertEqual(1, self.cpu.begins)
        self.assertEqual(1, self.gpio.begins)
        self.assertEqual(0x35, self.gpio.steps[0]["mmio_write_data"])
        self.assertEqual(1, self.cpu.steps[1]["irq"])
        self.assertEqual(0x12345678, self.cpu.steps[0]["program_word"])
        self.assertEqual(0x12345678, self.cpu.steps[1]["program_word"])
        self.assertEqual((2, 1), (self.runner.local_ticks["cpu"],
                                  self.runner.local_ticks["gpio"]))

    def test_bound_input_cannot_be_injected_by_fuzzer(self):
        self.runner.begin_test("case-1")
        with self.assertRaisesRegex(ValueError, "bound"):
            self.runner.inject_source("cpu", "irq", 1, direction="IP_TO_CPU")
        self.assertEqual({}, self.cpu.steps[0] if self.cpu.steps else {})

    def test_bare_step_does_not_fabricate_missing_output(self):
        self.runner.begin_test("case-1")
        self.runner.step("gpio")
        self.assertNotIn("mmio_write_data", self.gpio.steps[0])
        self.runner.finalize()
        self.assertEqual((1, 1), (self.cpu.ends, self.gpio.ends))

    def test_reports_real_local_ticks_advanced_during_other_component_step(self):
        self.runner.begin_test("case-1")
        self.cpu.local_ticks = 1
        self.gpio.local_ticks = 5  # a delivered MMIO transaction advanced GPIO RTL
        self.runner.step("cpu")
        self.assertEqual(5, self.runner.local_ticks["gpio"])


if __name__ == "__main__":
    unittest.main()
