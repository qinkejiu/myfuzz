"""IRQ delivery uses source observations and target local ticks."""

import unittest

from myfuzz.scenario.irq import IrqPulseDelivery
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner


class RecordingSession:
    def __init__(self, outputs=()):
        self.outputs = list(outputs)
        self.inputs = []
        self.local_ticks = 0

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        self.inputs.append(dict(inputs))
        self.local_ticks += 1
        return self.outputs.pop(0) if self.outputs else {}

    def reset_local(self):
        return {"cancelled_responses": 0}

    def begin_quiesce(self):
        pass

    def end_case(self):
        pass


class IrqPulseDeliveryTests(unittest.TestCase):
    def test_pulse_expires_after_exact_cpu_ticks_even_while_source_held(self):
        irq = IrqPulseDelivery(width_ticks=2)
        irq.observe_source(1, source_tick=7, cpu_tick=4)
        self.assertEqual(1, irq.sample_cpu(5))
        self.assertEqual(1, irq.sample_cpu(6))
        self.assertEqual(0, irq.sample_cpu(7))
        irq.observe_source(1, source_tick=8, cpu_tick=7)
        self.assertEqual(0, irq.sample_cpu(8))
        self.assertEqual(["source_start", "pulse_start", "pulse_expired"],
                         [event["kind"] for event in irq.events])

    def test_masked_pulse_expiry_is_recorded_without_retry(self):
        irq = IrqPulseDelivery(width_ticks=2)
        irq.observe_source(1, source_tick=1, cpu_tick=0)
        self.assertEqual(1, irq.sample_cpu(1, masked=True))
        self.assertEqual(1, irq.sample_cpu(2, masked=True))
        self.assertEqual(0, irq.sample_cpu(3, masked=True))
        self.assertEqual("expired_masked", irq.events[-1]["kind"])
        irq.observe_source(0, source_tick=2, cpu_tick=3)
        irq.observe_source(1, source_tick=3, cpu_tick=3)
        self.assertEqual(1, irq.sample_cpu(4, masked=False))
        starts = [e for e in irq.events if e["kind"] == "source_start"]
        self.assertEqual(2, len(starts))
        self.assertNotEqual(starts[0]["source_event_id"], starts[1]["source_event_id"])

    def test_second_source_event_during_slot_is_retained_as_overrun(self):
        irq = IrqPulseDelivery(width_ticks=3)
        irq.observe_source(1, source_tick=10, cpu_tick=0)
        self.assertEqual(1, irq.sample_cpu(1))
        irq.observe_source(0, source_tick=11, cpu_tick=1)
        irq.observe_source(1, source_tick=12, cpu_tick=1)
        self.assertEqual("unsupported_irq_overrun", irq.status)
        self.assertEqual(1, irq.sample_cpu(2))
        self.assertEqual(1, irq.sample_cpu(3))
        self.assertEqual(0, irq.sample_cpu(4))
        starts = [e for e in irq.events if e["kind"] == "source_start"]
        overrun = [e for e in irq.events if e["kind"] == "irq_overrun"]
        self.assertEqual(2, len(starts))
        self.assertEqual(starts[1]["source_event_id"], overrun[0]["source_event_id"])
        self.assertEqual(starts[0]["source_event_id"], overrun[0]["active_source_event_id"])

    def test_host_pause_does_not_advance_local_pulse(self):
        irq = IrqPulseDelivery(width_ticks=2)
        irq.observe_source(1, source_tick=1, cpu_tick=0)
        for _ in range(100):
            self.assertEqual(1, irq.input_at(1))
        self.assertEqual(1, irq.sample_cpu(1))
        self.assertEqual(1, irq.sample_cpu(2))

    def test_unobserved_cpu_ticks_cannot_prove_masked_expiry(self):
        irq = IrqPulseDelivery(width_ticks=2)
        irq.observe_source(1, source_tick=1, cpu_tick=0)
        self.assertEqual(0, irq.sample_cpu(3, masked=True))
        self.assertEqual("pulse_expired", irq.events[-1]["kind"])

    def test_irq_take_is_recorded_only_from_explicit_cpu_observation(self):
        irq = IrqPulseDelivery(width_ticks=2)
        irq.observe_source(1, source_tick=1, cpu_tick=0)
        irq.sample_cpu(1, masked=False, accepted=True)
        self.assertEqual(1, sum(e["kind"] == "cpu_irq_taken" for e in irq.events))
        irq.sample_cpu(2, masked=False)
        self.assertEqual(1, sum(e["kind"] == "cpu_irq_taken" for e in irq.events))


class RunnerIrqPulseTests(unittest.TestCase):
    def _runner(self, gpio_outputs, *, width=2):
        cpu = RecordingSession()
        gpio = RecordingSession({"irq": level} for level in gpio_outputs)
        binding = Binding("gpio", "irq", "cpu", "irq", 1)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 1),),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq"),))
        runner = ScenarioRunner(sessions={"cpu": cpu, "gpio": gpio},
                                ownership=ownership, bindings=(binding,),
                                irq_pulses={binding: width})
        runner.begin_test("irq-pulse")
        return runner, cpu

    def test_runner_uses_cpu_ticks_and_records_actual_input(self):
        runner, cpu = self._runner((1,))
        runner.step("gpio")
        self.assertEqual(1, runner.final_state_document()["irq_delivery"][0]
                         ["active_source_event_id"])
        runner.step("cpu")
        runner.step("cpu")
        runner.step("cpu")
        self.assertEqual([1, 1, 0], [item["irq"] for item in cpu.inputs])
        self.assertEqual([1, 1, 0],
                         [event["inputs"]["irq"] for event in runner.events
                          if event.get("component") == "cpu" and "inputs" in event])
        self.assertTrue(any(e.get("kind") == "pulse_expired" for e in runner.events))

    def test_reset_cancels_old_pulse_with_policy_receipt(self):
        runner, cpu = self._runner((1, 0, 1), width=3)
        runner.step("gpio")
        old_source = runner.final_state_document()["irq_delivery"][0][
            "active_source_event_id"]
        runner.reset_all("warm_all")
        barrier = next(e for e in runner.events if e.get("kind") == "reset_barrier")
        self.assertEqual("warm_all", barrier["policy"])
        self.assertEqual({"cpu": 1}, barrier["cancelled_irq_pulses"])
        self.assertTrue(any(e.get("kind") == "pulse_cancelled_by_reset"
                            and e.get("source_event_id") == old_source
                            for e in runner.events))
        runner.step("cpu")
        self.assertEqual(0, cpu.inputs[-1]["irq"])
        runner.step("gpio")
        runner.step("gpio")
        runner.step("cpu")
        self.assertEqual(1, cpu.inputs[-1]["irq"])
        new_source = runner.final_state_document()["irq_delivery"][0][
            "active_source_event_id"]
        self.assertNotEqual(old_source, new_source)

    def test_quiesce_zero_budget_reports_active_pulse_incomplete(self):
        runner, _cpu = self._runner((1,), width=2)
        runner.step("gpio")
        result = runner.quiesce(0)
        self.assertEqual("incomplete", result.status)
        self.assertEqual(0, result.steps)
        self.assertEqual({"cpu": 1}, runner.events[-1]["pending_irq_pulses"])
        self.assertEqual({"cpu": 1}, runner.final_state_document()[
            "pending_irq_pulses"])

    def test_quiesce_drains_pulse_through_declared_cpu_ticks(self):
        runner, cpu = self._runner((1,), width=2)
        runner.step("gpio")
        result = runner.quiesce(3)
        self.assertEqual("drained", result.status)
        self.assertEqual(3, result.steps)
        self.assertEqual([1, 1, 0], [item["irq"] for item in cpu.inputs])
        self.assertTrue(any(e.get("kind") == "pulse_expired" for e in runner.events))
        self.assertEqual({}, runner.events[-1]["pending_irq_pulses"])

    def test_quiesce_respects_declared_local_async_event_queue(self):
        class AsyncSession(RecordingSession):
            def __init__(self):
                super().__init__()
                self.pending_events = 2

            def step_local(self, inputs):
                self.pending_events -= 1
                return super().step_local(inputs)

        session = AsyncSession()
        runner = ScenarioRunner(sessions={"local": session},
                                ownership=compile_ownership((), ()), bindings=())
        runner.begin_test("async-quiesce")
        result = runner.quiesce(1)
        self.assertEqual("incomplete", result.status)
        self.assertEqual({"local": 1}, runner.events[-1]["pending_events"])
        self.assertEqual({"local": 1}, runner.final_state_document()[
            "pending_events"])

    def test_runner_overrun_preserves_both_rtl_events_and_reports_status(self):
        runner, cpu = self._runner((1, 0, 1), width=3)
        runner.step("gpio")
        runner.step("cpu")
        runner.step("gpio")
        runner.step("gpio")
        self.assertEqual("unsupported_irq_overrun", runner.failure_status)
        self.assertEqual(2, sum(e.get("kind") == "source_start"
                                for e in runner.events))
        self.assertEqual(1, sum(e.get("kind") == "irq_overrun"
                                for e in runner.events))
        self.assertEqual(1, cpu.inputs[0]["irq"])

    def test_runner_uses_real_cpu_mask_and_take_observations(self):
        runner, cpu = self._runner((1, 0))
        cpu.outputs = [{"irq_masked_pre": 1, "irq_taken_pre": 0},
                       {"irq_masked_pre": 1, "irq_taken_pre": 0},
                       {"irq_masked_pre": 1, "irq_taken_pre": 0}]
        runner.step("gpio")
        for _ in range(3):
            runner.step("cpu")
        self.assertTrue(any(e.get("kind") == "expired_masked"
                            for e in runner.events))
        runner.step("gpio")
        runner.step("cpu")
        self.assertEqual(0, cpu.inputs[-1]["irq"])

    def test_failed_cpu_step_does_not_consume_pulse_tick(self):
        runner, cpu = self._runner((1,))
        def fail(_inputs):
            raise RuntimeError("lost CPU reply")
        cpu.step_local = fail
        runner.step("gpio")
        with self.assertRaisesRegex(RuntimeError, "lost CPU reply"):
            runner.step("cpu")
        self.assertEqual(0, runner.final_state_document()["irq_delivery"][0]
                         ["last_cpu_tick"])

    def test_default_level_mapping_has_no_pulse_identity_or_state(self):
        cpu = RecordingSession()
        gpio = RecordingSession(({"irq": 1},))
        binding = Binding("gpio", "irq", "cpu", "irq", 1)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 1),),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq"),))
        runner = ScenarioRunner(sessions={"cpu": cpu, "gpio": gpio},
                                ownership=ownership, bindings=(binding,))
        self.assertNotIn("irq_pulses", runner.identity_document())
        self.assertNotIn("irq_delivery", runner.final_state_document())

    def test_failed_cpu_step_does_not_certify_pulse_tick(self):
        class FailedCpu(RecordingSession):
            def step_local(self, inputs):
                raise RuntimeError("CPU reply lost before observed tick")

        cpu = FailedCpu()
        gpio = RecordingSession(({"irq": 1},))
        binding = Binding("gpio", "irq", "cpu", "irq", 1)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 1),),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq"),))
        runner = ScenarioRunner(sessions={"cpu": cpu, "gpio": gpio},
                                ownership=ownership, bindings=(binding,),
                                irq_pulses={binding: 1})
        runner.begin_test("failed-cpu")
        runner.step("gpio")
        with self.assertRaisesRegex(RuntimeError, "reply lost"):
            runner.step("cpu")
        self.assertEqual(0, runner.final_state_document()["irq_delivery"][0]
                         ["last_cpu_tick"])


if __name__ == "__main__":
    unittest.main()
