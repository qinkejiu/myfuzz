"""RUN-04: replay a real three-device in-flight reply timeout."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from tests.integration.test_scenario_opentitan_uart_done_real import (
    _three_device_runner,
)


def make_three_device_timeout_runner():
    gpio_a, gpio_b, uart, runner = _three_device_runner()

    def configure(session, writes):
        begin = session.begin_case

        def configured_begin(testcase_id):
            begin(testcase_id)
            for offset, value in writes:
                session.write_register(offset, value)

        session.begin_case = configured_begin

    configure(gpio_a, ((0x14, 1),))
    configure(gpio_b, ((0x04, 1), (0x2c, 1)))
    configure(uart, ((0x10, (0x2000 << 16) | 1),
                     (0x1c, 0xa5), (0x04, 0b100)))
    real_step = gpio_b.step_local
    real_end = gpio_b.end_case
    blocked_streams = []

    def step_with_blocked_reply(inputs):
        if not blocked_streams:
            read_fd, write_fd = os.pipe()
            old_stdout = gpio_b._process.stdout
            gpio_b._process.stdout = os.fdopen(
                read_fd, "r", encoding="ascii", buffering=1)
            blocked_streams.extend((write_fd, old_stdout))
        return real_step(inputs)

    def end_with_cleanup():
        try:
            real_end()
        finally:
            if blocked_streams:
                os.close(blocked_streams[0])
                blocked_streams[1].close()

    gpio_b.step_local = step_with_blocked_reply
    gpio_b.end_case = end_with_cleanup
    return runner


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealThreeDeviceTimeoutReplayTests(unittest.TestCase):
    def test_gpio_reply_timeout_preserves_uart_and_replays_prefix(self):
        genome = ScenarioGenome(
            testcase_id="three-device-gpio-reply-timeout",
            direction="IP_TO_IP", path_id="gpio-a-to-b-with-uart-pending",
            schedule_order=("gpio_a", "gpio_b", "uart"), max_steps=1,
            actions=(), encoding_version=3, quiesce_steps=2)
        budget = ResourceBudget(max_wall_time_ms=2000)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                genome, make_three_device_timeout_runner, bundle,
                budget=budget)
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual("inflight_step", trace.events[-1]["phase"])
            self.assertTrue(trace.events[-1]["effect_may_have_occurred"])
            self.assertTrue(any(event.get("kind") == "harness_failure"
                                and event.get("component") == "gpio_b"
                                for event in trace.events))
            state = json.loads((bundle / "final_state.json").read_text())
            self.assertEqual(1, state["pending_events"]["uart"])
            self.assertGreater(state["pending_events"]["gpio_b"], 0)
            self.assertIn("gpio_b", state["pending_dataflow_targets"])
            comparison = replay_evidence_bundle(
                bundle, make_three_device_timeout_runner)
            self.assertTrue(comparison.matches, comparison.first_difference)
            self.assertEqual("semantic_prefix", comparison.verification_scope)


if __name__ == "__main__":
    unittest.main()
