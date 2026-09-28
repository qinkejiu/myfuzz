"""A replay wall cut identifies one operation among same-tick actions."""

import unittest
from unittest.mock import patch

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioBudgetExhausted, ScenarioRunner


class _Session:
    max_final_state_growth_bytes_per_operation = 65536
    max_evidence_record_bytes = 8192

    def identity_document(self):
        return {"fixture": "same-tick-wall-cut"}

    def begin_case(self, testcase_id):
        pass

    def end_case(self):
        pass


def _runner():
    ownership = compile_ownership(
        (InputField("gpio", "pin", 1),),
        (InputOwner("gpio", "pin", 0, 1, "source", "external"),))
    runner = ScenarioRunner(sessions={"gpio": _Session()}, ownership=ownership,
                            bindings=())
    runner.set_resource_budget(ResourceBudget(max_wall_time_ms=5))
    return runner


def _inject(runner, action_id, value):
    runner.inject_source("gpio", "pin", value, direction="IP_TO_CPU",
                         action_id=action_id)


class ReplayWallCutLocatorTests(unittest.TestCase):
    def test_physical_before_source_cut_records_prefix_metadata(self):
        runner = _runner()
        with patch("myfuzz.scenario.runner.time.monotonic", return_value=100.0):
            runner.begin_test("source-cut")
            _inject(runner, "first", 1)
        with patch("myfuzz.scenario.runner.time.monotonic", return_value=100.01):
            with self.assertRaises(ScenarioBudgetExhausted):
                _inject(runner, "second", 0)
        marker = runner.events[-1]
        self.assertEqual("before_source_injection", marker["phase"])
        self.assertEqual(1, marker["prefix_event_count"])
        self.assertEqual({"gpio": 0}, marker["prefix_local_ticks"])

    def test_replay_cut_targets_second_same_tick_source_action(self):
        runner = _runner()
        runner.set_replay_wall_cut(0, "before_source_injection",
                                   prefix_event_count=1)
        runner.begin_test("source-replay")
        _inject(runner, "first", 1)
        with self.assertRaises(ScenarioBudgetExhausted):
            _inject(runner, "second", 0)
        self.assertEqual(["source_injection", "budget_exhausted"],
                         [event["kind"] for event in runner.events])
        self.assertEqual("first", runner.events[0]["action_id"])
        self.assertEqual(1, runner.events[-1]["prefix_event_count"])


if __name__ == "__main__":
    unittest.main()
