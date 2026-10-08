"""Calibration of one deliberate checker-input IRQ corruption."""

from __future__ import annotations

import unittest

from myfuzz.scenario.session_runtime import OnlineCaseReceipt


def receipt(events):
    return OnlineCaseReceipt("case-4", 0, len(events), tuple(events), {}, {}, "running")


def witnessed_irq_events():
    return (
        {"event_id": 1, "kind": "source_admission", "admission": {
            "admission_id": "admission-4", "case_id": "case-4"}},
        {"event_id": 2, "kind": "gpio_irq_trigger", "component": "gpio_b",
         "local_tick": 12,
         "causes": [{"bit": 8}]},
        {"event_id": 3, "component": "gpio_b", "local_tick": 12,
         "outputs": {"irq": 1, "interrupt": 1}},
        {"event_id": 4, "kind": "source_start", "source_tick": 12,
         "source": ["gpio_b", "irq"],
         "target": ["cpu", "irq"], "provenance": {
             "origin_status": "unknown", "origin_admission_ids": []}},
        {"event_id": 5, "component": "cpu", "inputs": {"irq": 1}},
    )


class ControlledIrqFaultTest(unittest.TestCase):
    def test_fault_exposes_irq_source_contradiction_without_mutating_trace(self):
        from myfuzz.scenario.p5_controlled_irq_fault import ControlledIrqOutputFaultChecker

        events = witnessed_irq_events()
        checker = ControlledIrqOutputFaultChecker()
        self.assertEqual(checker(receipt(events)), ("gpio_b_irq_source_mismatch",))
        self.assertEqual(events[2]["outputs"], {"irq": 1, "interrupt": 1})
        self.assertEqual(checker.fault["observed_event_id"], 3)
        self.assertEqual(checker.fault["source_start_event_id"], 4)
        self.assertEqual(checker.fault["observed_case_id"], "case-4")
        self.assertEqual(checker.fault["source_origin_status"], "unknown")

    def test_missing_trigger_does_not_inject_or_fabricate_finding(self):
        from myfuzz.scenario.p5_controlled_irq_fault import ControlledIrqOutputFaultChecker

        events = tuple(event for event in witnessed_irq_events()
                       if event["event_id"] != 2)
        checker = ControlledIrqOutputFaultChecker()
        self.assertEqual(checker(receipt(events)), ())
        self.assertIsNone(checker.fault)

    def test_config_identity_is_stable_after_checking(self):
        from myfuzz.scenario.p5_controlled_irq_fault import ControlledIrqOutputFaultChecker
        from myfuzz.scenario.session_runtime import _checker_identity

        checker = ControlledIrqOutputFaultChecker()
        before = _checker_identity(checker)
        checker(receipt(witnessed_irq_events()))
        after = _checker_identity(ControlledIrqOutputFaultChecker())
        self.assertEqual(before, after)
        self.assertEqual(before["config"]["fault_mode"], "checker_input_irq_output_zero.v1")


if __name__ == "__main__":
    unittest.main()
