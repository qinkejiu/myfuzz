"""Only explicit whole-scenario reset changes RTL epochs and memory policy."""

import unittest

from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


class ResettableSession:
    def __init__(self, memory):
        self.memory = memory
        self.epoch = 0
        self.begins = 0
        self.local_ticks = 0

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        self.local_ticks += 1
        return {"observed": inputs.get("pin", 0), "epoch": self.epoch}

    def reset_local(self):
        self.epoch += 1
        return {"cancelled_responses": 0}

    def end_case(self):
        pass


class ResetPolicyTests(unittest.TestCase):
    def setUp(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0, 0x1000),),
            initialization_seed=7, max_initialized_bytes=0x1000)
        self.memory.preload(0x100, b"\x11\x22\x33\x44")
        self.session = ResettableSession(self.memory)
        ownership = compile_ownership(
            (InputField("cpu", "pin", 1),),
            (InputOwner("cpu", "pin", 0, 1, "source", "external"),))
        self.runner = ScenarioRunner(sessions={"cpu": self.session},
                                     ownership=ownership, bindings=())
        self.runner.begin_test("reset-policy")

    def test_warm_retains_ram_and_cold_restores_initial_image(self):
        self.runner.inject_source("cpu", "pin", 1, direction="CPU_TO_IP")
        self.runner.step("cpu")
        self.memory.write(0x100, 0xAABBCCDD, width_bytes=4,
                          byte_enable=15, writer_event_id="store")
        warm = self.runner.reset_all("warm_all")
        self.assertEqual(0, warm.memory_generations["ram"])
        self.assertEqual(0xAABBCCDD,
                         self.memory.read(0x100, 4, transaction_id="warm").value)
        self.assertEqual(0, self.runner.step("cpu")["observed"])
        self.assertEqual(1, self.session.epoch)
        cold = self.runner.reset_all("cold_all")
        self.assertEqual(1, cold.memory_generations["ram"])
        self.assertEqual(0x44332211,
                         self.memory.read(0x100, 4, transaction_id="cold").value)
        self.assertEqual(2, self.session.epoch)
        self.assertEqual(1, self.session.begins)
        self.assertEqual(["warm_all", "cold_all"],
                         [event["policy"] for event in self.runner.events
                          if event.get("kind") == "reset_barrier"])
        self.runner.finalize()

    def test_partial_or_unknown_reset_is_rejected_without_state_change(self):
        with self.assertRaisesRegex(ValueError, "policy"):
            self.runner.reset_all("cpu_only")
        self.assertEqual(0, self.session.epoch)
        self.assertEqual(0, self.memory.generation)
        self.runner.finalize()

    def test_ip_only_reset_is_rejected_before_any_state_change(self):
        self.runner.step("cpu")
        self.memory.write(0x100, 0xAABBCCDD, width_bytes=4,
                          byte_enable=15, writer_event_id="before-ip-only")
        before = self.runner.final_state_document()
        events = self.runner.events
        ticks = self.session.local_ticks
        begins = self.session.begins
        with self.assertRaisesRegex(ValueError, "unsupported reset policy"):
            self.runner.reset_all("ip_only")
        self.assertEqual(before, self.runner.final_state_document())
        self.assertEqual(events, self.runner.events)
        self.assertEqual(ticks, self.session.local_ticks)
        self.assertEqual(begins, self.session.begins)
        self.assertEqual(0, self.session.epoch)
        self.assertEqual(0, self.memory.generation)
        saved = self.memory.read(0x100, 4, transaction_id="after-ip-only")
        self.assertEqual(0xAABBCCDD, saved.value)
        self.assertEqual(("before-ip-only",) * 4, saved.writer_event_ids)
        self.runner.step("cpu")
        self.assertEqual(ticks + 1, self.session.local_ticks)
        self.runner.finalize()


if __name__ == "__main__":
    unittest.main()
