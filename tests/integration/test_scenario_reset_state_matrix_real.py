"""Warm and cold state policy across real Ibex, GPIO, RAM, and IRQ."""

from __future__ import annotations

import os
import unittest

from tests.integration.test_scenario_reset_quiesce_real import (
    _case, _run_until_store,
)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealResetStateMatrixTests(unittest.TestCase):
    @staticmethod
    def _bound_case():
        memory, cpu, gpio, _ = _case()
        binding = Binding("gpio", "irq", "cpu", "irq", 1)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 2), InputField("gpio", "gpio_in", 32)),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq"),
             InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
             InputOwner("gpio", "gpio_in", 0, 32, "source", "external_pins")))
        runner = ScenarioRunner(
            sessions={"cpu": cpu, "gpio": gpio}, ownership=ownership,
            bindings=(binding,), irq_pulses={binding: 2})
        return memory, cpu, gpio, runner

    @staticmethod
    def _raise_real_gpio_irq(runner, gpio):
        gpio.write_register(0x04, 1)  # INTR_ENABLE
        gpio.write_register(0x2c, 1)  # INTR_CTRL_EN_RISING
        for _ in range(12):
            runner.step("gpio")
        runner.inject_source("gpio", "gpio_in", 1, direction="IP_TO_CPU")
        for _ in range(24):
            if runner.step("gpio")["irq"] == 1:
                return
        raise AssertionError("real GPIO did not raise IRQ")

    def test_warm_and_cold_preserve_or_invalidate_state_in_one_real_case(self):
        memory, cpu, gpio, runner = self._bound_case()
        runner.begin_test("warm-cold-real-state-matrix")
        try:
            _run_until_store(runner, cpu, 1)
            self._raise_real_gpio_irq(runner, gpio)
            self.assertEqual(1, gpio.read_register(0x00) & 1)
            self.assertEqual(0xa5, gpio.read_register(0x14))
            self.assertGreater(cpu.pending_responses, 0)
            self.assertEqual({"cpu": 1}, runner.final_state_document()[
                "pending_irq_pulses"])
            stored = memory.read(0x200, 4, transaction_id="matrix-store-before")
            unknown = memory.read(0x300, 4,
                                  transaction_id="matrix-unknown-before")
            self.assertEqual(0xa5, stored.value)
            self.assertEqual(0, stored.generation)
            self.assertEqual(0, unknown.generation)

            warm = runner.reset_all("warm_all")
            self.assertEqual(0, warm.memory_generations["ram"])
            self.assertGreaterEqual(warm.cancelled_responses["cpu"], 1)
            self.assertEqual(0, cpu.pending_responses)
            self.assertEqual({}, runner.final_state_document()[
                "pending_irq_pulses"])
            self.assertEqual(0, gpio.read_register(0x00) & 1)
            self.assertEqual(0, gpio.read_register(0x14))
            runner.step("cpu")
            post_warm_cpu = [event for event in runner.events
                             if event.get("component") == "cpu"
                             and "inputs" in event][-1]
            self.assertEqual(0, post_warm_cpu["inputs"]["irq"])
            warm_store = memory.read(0x200, 4,
                                     transaction_id="matrix-store-warm")
            warm_unknown = memory.read(0x300, 4,
                                       transaction_id="matrix-unknown-warm")
            self.assertEqual((stored.value, stored.versions,
                              stored.writer_event_ids),
                             (warm_store.value, warm_store.versions,
                              warm_store.writer_event_ids))
            self.assertEqual((unknown.value, unknown.versions,
                              unknown.writer_event_ids),
                             (warm_unknown.value, warm_unknown.versions,
                              warm_unknown.writer_event_ids))

            _run_until_store(runner, cpu, 2)
            self._raise_real_gpio_irq(runner, gpio)
            self.assertEqual(1, gpio.read_register(0x00) & 1)
            self.assertGreater(cpu.pending_responses, 0)
            self.assertEqual({"cpu": 1}, runner.final_state_document()[
                "pending_irq_pulses"])
            cold = runner.reset_all("cold_all")
            self.assertEqual(1, cold.memory_generations["ram"])
            self.assertEqual(0, cpu.pending_responses)
            self.assertEqual({}, runner.final_state_document()[
                "pending_irq_pulses"])
            self.assertEqual(0, gpio.read_register(0x00) & 1)
            self.assertEqual(0, gpio.read_register(0x14))
            self.assertNotIn(("ram", 0x300), memory._bytes)
            cold_store = memory.read(0x200, 4,
                                     transaction_id="matrix-store-cold")
            cold_unknown = memory.read(0x300, 4,
                                       transaction_id="matrix-unknown-cold")
            self.assertEqual((0, 1), (cold_store.value, cold_store.generation))
            self.assertEqual(1, cold_unknown.generation)
            self.assertEqual((0x300, 0x301, 0x302, 0x303),
                             cold_unknown.materialized_offsets)
            self.assertEqual(bytes(memory._initial_byte("ram", offset)
                                   for offset in range(0x300, 0x304)),
                             cold_unknown.data)
            self.assertNotIn(stored.writer_event_ids[0],
                             cold_store.writer_event_ids)
            self.assertNotEqual(unknown.versions, cold_unknown.versions)
            runner.step("cpu")
            post_cold_cpu = [event for event in runner.events
                             if event.get("component") == "cpu"
                             and "inputs" in event][-1]
            self.assertEqual(0, post_cold_cpu["inputs"]["irq"])
            barriers = [event for event in runner.events
                        if event.get("kind") == "reset_barrier"]
            self.assertEqual(["warm_all", "cold_all"],
                             [event["policy"] for event in barriers])
            self.assertEqual([{"cpu": 1}, {"cpu": 1}],
                             [event["cancelled_irq_pulses"]
                              for event in barriers])
            self.assertTrue(any(event.get("edge_kind") == "INVALIDATE"
                                and event.get("memory_id") == "ram"
                                and event.get("byte_offset") == 0x200
                                for event in runner.events))
        finally:
            runner.finalize()


if __name__ == "__main__":
    unittest.main()
