"""Wall-clock variation and component registration do not order local steps."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler
import myfuzz.scenario.runner as runner_module


class _LocalSession:
    def __init__(self):
        self.local_ticks = 0

    def begin_case(self, testcase_id):
        self.testcase_id = testcase_id

    def step_local(self, inputs):
        self.local_ticks += 1
        return {"out": inputs.get("pin", 0), "tick": self.local_ticks}

    def end_case(self):
        pass


class _ScriptedClock:
    def __init__(self, origin, interval):
        self.origin = origin
        self.interval = interval
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.origin + self.calls * self.interval


def _run(order, clock):
    genome = ScenarioGenome(
        testcase_id="stable-wall-schedule", direction="IP_TO_IP",
        path_id="a-out-triggers-b", schedule_order=("a", "b"), max_steps=12,
        actions=(
            Action("drive-a", "a", "pin", 1, "IP_TO_IP", Trigger("START")),
            Action("drive-b", "b", "pin", 1, "IP_TO_IP",
                   Trigger("AFTER_OUTPUT", "a", "out", 1, 1),
                   delay_component="b", delay_ticks=2),
        ))
    ownership = compile_ownership(
        (InputField("a", "pin", 1), InputField("b", "pin", 1)),
        (InputOwner("a", "pin", 0, 1, "source", "external-a"),
         InputOwner("b", "pin", 0, 1, "source", "external-b")))
    runner = ScenarioRunner(
        sessions={name: _LocalSession() for name in order},
        ownership=ownership, bindings=())
    runner.set_resource_budget(ResourceBudget(max_wall_time_ms=60_000))
    with patch.object(runner_module, "time",
                      SimpleNamespace(monotonic=clock)):
        result = DependencyScheduler().run(runner, genome)
    events = runner.events
    ticks = dict(runner.local_ticks)
    payload = {"status": result.status, "events": events, "local_ticks": ticks}
    semantic_sha256 = hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
    return (result, events, ticks, runner.final_state_document(), semantic_sha256)


class Run03WallScheduleTests(unittest.TestCase):
    def test_monotonic_variation_and_reverse_registration_preserve_trace(self):
        fast_clock = _ScriptedClock(10.0, 0.001)
        slow_clock = _ScriptedClock(10_000.0, 0.25)
        baseline = _run(("a", "b"), fast_clock)
        varied = _run(("b", "a"), slow_clock)
        self.assertGreater(fast_clock.calls, 12)
        self.assertEqual(fast_clock.calls, slow_clock.calls)
        self.assertEqual("complete", baseline[0].status)
        self.assertEqual(("drive-a", "drive-b"), baseline[0].fired_actions)
        self.assertEqual({"a": 6, "b": 6}, baseline[2])
        self.assertEqual(baseline, varied)


if __name__ == "__main__":
    unittest.main()
