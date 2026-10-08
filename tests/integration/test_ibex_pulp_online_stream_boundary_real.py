"""A finite online RV32I stream ends in a fixed real Ibex self-loop."""

from __future__ import annotations

import os
from pathlib import Path
import unittest

from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.ibex_pulp_dual_source import (
    make_ibex_pulp_dual_source_factory,
    make_ibex_pulp_dual_source_stream_bootstrap,
)
from myfuzz.scenario.session_runtime import (
    OnlineCase, OnlineInstruction, ScenarioSession, replay_online_session,
)


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for pinned RTL")
class IbexPulpOnlineStreamBoundaryRealTest(unittest.TestCase):
    def test_fixed_tail_is_fetched_after_two_online_words_and_ip_continues(self):
        bootstrap = make_ibex_pulp_dual_source_stream_bootstrap(
            instruction_start=0x11000, instruction_end=0x11008)
        factory = make_ibex_pulp_dual_source_factory(Path(os.environ.get(
            "MYFUZZ_IBEX_GPIO_CACHE", "/tmp/myfuzz-ibex-pulp-boundary-cache")))
        session = ScenarioSession(bootstrap.template, factory())
        session.declare_instruction_slots("cpu", bootstrap.instruction_start,
                                          bootstrap.instruction_count)
        session.begin()
        cpu = session.runner.sessions["cpu"]
        self.assertEqual(0x0000006f, cpu.memory.read(
            bootstrap.instruction_end, 4, transaction_id="tail-before").value)

        for _ in range(1024):
            if cpu.waiting_instruction_address == bootstrap.instruction_start:
                break
            receipt = session.advance_initial(bootstrap.template.schedule_order)
            self.assertEqual("running", receipt.status)
        else:
            self.fail("real Ibex did not reach the first reserved instruction")

        rounds = tuple(BatchAdvance(("cpu", "gpio_a", "gpio_b"))
                       for _ in range(20))
        for index, address in enumerate((0x11000, 0x11004)):
            receipt = session.submit_case(OnlineCase(
                f"cpu-{index}", "CPU_TO_IP_TO_CPU", "tiny-stream-boundary",
                OnlineInstruction(f"nop-{index}", "cpu", address, "13000000"),
                rounds))
            self.assertEqual("running", receipt.status)

        tail_reads = [event for event in session.runner.events
                      if event.get("kind") == "memory_read"
                      and bootstrap.instruction_end <= event.get("address", -1)
                      < 0x20000]
        addresses = {event["address"] for event in tail_reads}
        self.assertIn(bootstrap.instruction_end, addresses)
        self.assertIn(bootstrap.instruction_end + 4, addresses)
        # Ibex may prefetch the next sequential word before its JAL resolves.
        # Every fetched word in the fixed guard must still be deterministic.
        self.assertTrue(all(event["value"] == 0x0000006f
                            for event in tail_reads))
        self.assertEqual({bootstrap.instruction_end,
                          bootstrap.instruction_end + 4}, addresses)
        self.assertEqual(0x0000006f, cpu.memory.read(
            bootstrap.instruction_end, 4, transaction_id="tail-after").value)
        self.assertIsNone(cpu.waiting_instruction_address)

        pin_receipt = session.submit_case(OnlineCase(
            "pin-after-end", "IP_TO_CPU_TO_IP", "tiny-stream-boundary",
            BatchSourceEvent("pin8-rise", "gpio_b", "gpio_in", 1, 8, 1),
            tuple(BatchAdvance(("cpu", "gpio_a", "gpio_b"))
                  for _ in range(24))))
        self.assertEqual("running", pin_receipt.status)
        self.assertTrue(any(event.get("kind") == "source_injection"
                            and event.get("action_id") == "pin8-rise"
                            for event in pin_receipt.events))
        self.assertFalse(any(event.get("kind") in
                             ("harness_failure", "unmapped_access")
                             for event in session.runner.events))

        trace = session.finish()
        self.assertEqual("complete", trace.status)
        replay = replay_online_session(session.encode_plan(), factory, trace)
        self.assertTrue(replay.matches, replay)


if __name__ == "__main__":
    unittest.main()
