"""Host-to-runner STEP retransmission returns the complete original receipt."""

import unittest

from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


class CountingSession:
    def __init__(self):
        self.local_ticks = 0
        self.reset_epoch = 0
        self.fail_after_tick = False

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        self.local_ticks += 1
        if self.fail_after_tick:
            raise RuntimeError("reply lost after possible effect")
        return {"out": inputs.get("pin", 0), "count": self.local_ticks}

    def reset_local(self):
        self.reset_epoch += 1
        return {"cancelled_responses": 0}

    def end_case(self):
        pass


class StepCommandReceiptTests(unittest.TestCase):
    def setUp(self):
        self.session = CountingSession()
        ownership = compile_ownership(
            (InputField("cpu", "pin", 1),),
            (InputOwner("cpu", "pin", 0, 1, "source", "external"),))
        self.runner = ScenarioRunner(sessions={"cpu": self.session},
                                     ownership=ownership, bindings=())
        self.runner.begin_test("commands")

    def tearDown(self):
        self.runner.finalize()

    def command(self, sequence, epoch, inputs, execution_id=None):
        return self.runner.execute_step(
            "cpu", execution_id=execution_id or self.runner.execution_id,
            command_sequence=sequence, epoch=epoch, expected_inputs=inputs)

    def test_lost_step_reply_retransmits_full_receipt_without_new_tick(self):
        first = self.command(1, 0, {})
        self.assertEqual(1, first.outputs["count"])
        self.assertTrue(first.events)
        self.runner.inject_source("cpu", "pin", 1, direction="CPU_TO_IP")
        repeated = self.command(1, 0, {})
        self.assertEqual(first, repeated)
        self.assertEqual(1, self.session.local_ticks)
        self.assertEqual(1, len([event for event in self.runner.events
                                 if event.get("component") == "cpu"
                                 and "outputs" in event]))
        with self.assertRaisesRegex(ValueError, "identity_conflict"):
            self.command(1, 0, {"pin": 1})
        self.assertEqual(2, self.command(2, 0, {"pin": 1}).outputs["count"])

    def test_reset_epoch_separates_reused_numeric_command_sequence(self):
        old = self.command(1, 0, {})
        self.runner.reset_all("warm_all")
        self.assertEqual(1, self.runner.command_epoch)
        fresh = self.command(1, 1, {})
        self.assertEqual(2, fresh.outputs["count"])
        self.assertEqual(old, self.command(1, 0, {}))
        self.assertEqual(2, self.session.local_ticks)
        with self.assertRaisesRegex(ValueError, "stale_execution"):
            self.command(2, 1, {}, execution_id="old-execution")
        with self.assertRaisesRegex(ValueError, "out_of_order_command"):
            self.command(3, 1, {})

    def test_unknown_step_effect_is_never_reexecuted_on_retry(self):
        self.session.fail_after_tick = True
        with self.assertRaisesRegex(RuntimeError, "reply lost"):
            self.command(1, 0, {})
        with self.assertRaisesRegex(RuntimeError, "uncertain_effect"):
            self.command(1, 0, {})
        self.assertEqual(1, self.session.local_ticks)

    def test_ordinary_scheduler_step_is_recorded_for_retransmission(self):
        self.assertEqual(1, self.runner.step("cpu")["count"])
        receipt = self.command(1, 0, {})
        self.assertEqual(1, receipt.outputs["count"])
        self.assertEqual(1, self.session.local_ticks)

    def test_public_event_snapshot_cannot_rewrite_authoritative_trace(self):
        self.runner.step("cpu")
        public = self.runner.events
        public[0]["outputs"]["count"] = 99
        self.assertEqual(1, self.runner.events[0]["outputs"]["count"])

    def test_old_execution_reply_cannot_enter_new_testcase(self):
        old_execution = self.runner.execution_id
        self.runner.step("cpu")
        fresh_session = CountingSession()
        ownership = compile_ownership(
            (InputField("cpu", "pin", 1),),
            (InputOwner("cpu", "pin", 0, 1, "source", "external"),))
        fresh = ScenarioRunner(sessions={"cpu": fresh_session},
                               ownership=ownership, bindings=())
        fresh.begin_test("next-case")
        try:
            with self.assertRaisesRegex(ValueError, "stale_execution"):
                fresh.execute_step("cpu", execution_id=old_execution,
                                   command_sequence=1, epoch=0,
                                   expected_inputs={})
            self.assertEqual(1, fresh.step("cpu")["count"])
            self.assertEqual(1, fresh_session.local_ticks)
        finally:
            fresh.finalize()


if __name__ == "__main__":
    unittest.main()
