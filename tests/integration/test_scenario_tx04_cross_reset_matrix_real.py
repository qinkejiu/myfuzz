"""TX-04: real queued GPIO writes keep identity and order across reset faults."""

from __future__ import annotations

from dataclasses import asdict
import os
import unittest
from unittest.mock import patch

from tests.integration.test_scenario_cross_reset_target_fault_real import (
    CaptureReplies, OldReplyAfterOneRealRead, make_runner, wait_for_mmio,
)


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealTx04CrossResetMatrixTests(unittest.TestCase):
    def test_cancelled_request_and_late_confirmed_result_do_not_reorder_new_write(self):
        runner = make_runner()
        cpu = runner.sessions["cpu"]
        gpio = runner.sessions["gpio"]
        router = cpu.router
        runner.begin_test("tx04-cancel-then-late-result")
        try:
            cancelled_key = wait_for_mmio(runner)
            self.assertEqual(("gpio",), router.pending_targets)
            self.assertEqual(0, gpio.read_register(0x14))
            runner.reset_all("warm_all")
            first_barrier = next(event for event in runner.events
                                 if event.get("kind") == "reset_barrier")
            self.assertIn(str(cancelled_key),
                          first_barrier["cancelled_target_requests"]["cpu"])
            self.assertEqual((), router.pending_targets)
            self.assertEqual([], router.deliveries)
            self.assertEqual(0, gpio.read_register(0x14))

            confirmed_key = wait_for_mmio(runner)
            self.assertEqual(cancelled_key.source_sequence,
                             confirmed_key.source_sequence)
            self.assertEqual(cancelled_key.source_epoch + 1,
                             confirmed_key.source_epoch)
            old_execution = gpio._wire_execution
            capture = CaptureReplies(gpio._process.stdout)
            gpio._process.stdout = capture
            runner.step("gpio")
            old_result = capture.lines[-1]
            self.assertTrue(old_result.startswith("RESULT " + old_execution + " "))
            self.assertEqual(0xa5, gpio.read_register(0x14))
            self.assertEqual([confirmed_key], [record["source_transaction"]
                                                   for record in router.deliveries])

            runner.reset_all("warm_all")
            self.assertNotEqual(old_execution, gpio._wire_execution)
            self.assertEqual(0, gpio.read_register(0x14))
            current_key = wait_for_mmio(runner)
            self.assertEqual(confirmed_key.source_sequence,
                             current_key.source_sequence)
            self.assertEqual(confirmed_key.source_epoch + 1,
                             current_key.source_epoch)
            stale = OldReplyAfterOneRealRead(gpio._process.stdout, old_result)
            gpio._process.stdout = stale
            runner.step("gpio")
            self.assertIsNone(stale.old_reply)
            self.assertEqual(2, stale.real_reads)
            self.assertEqual(0xa5, gpio.read_register(0x14))
            self.assertEqual((), router.pending_targets)
            self.assertEqual((), cpu.service.ledger.uncertain_keys)

            self.assertEqual([cancelled_key, confirmed_key, current_key],
                             [record["source_transaction"]
                              for record in router.acceptances])
            self.assertEqual([1, 2, 3], [record["acceptance_order"]
                                         for record in router.acceptances])
            self.assertEqual([confirmed_key, current_key],
                             [record["source_transaction"]
                              for record in router.deliveries])
            self.assertEqual([1, 1], [record["source_sequence"]
                                      for record in router.deliveries])
            self.assertEqual([1, 2], [record["delivery_order"]
                                      for record in router.deliveries])
            self.assertEqual([1, 2], [record["target_delivery_order"]
                                      for record in router.deliveries])
            delivered = [event for event in runner.events
                         if event.get("kind") == "mmio_delivery"]
            self.assertEqual([asdict(confirmed_key), asdict(current_key)],
                             [event["source_transaction"] for event in delivered])
            self.assertEqual([1, 2], [event["delivery_order"]
                                      for event in delivered])
            self.assertEqual([1, 2], [event["target_delivery_order"]
                                      for event in delivered])
        finally:
            runner.finalize()

    def test_write_after_effect_lost_reply_blocks_reset_and_both_retry_paths(self):
        runner = make_runner()
        cpu = runner.sessions["cpu"]
        gpio = runner.sessions["gpio"]
        router = cpu.router
        with patch.dict(os.environ, {"MYFUZZ_TEST_CRASH_AFTER_GPIO_WRITE": "1"}):
            runner.begin_test("tx04-uncertain-target")
            try:
                key = wait_for_mmio(runner)
                acceptance = router.acceptances[-1]
                step_id = runner._next_command_sequence
                step_inputs = runner._effective_inputs("gpio")
                step_epoch = runner.command_epoch
                step_execution = runner.execution_id
                with patch.object(gpio, "write_register",
                                  wraps=gpio.write_register) as target_write:
                    with self.assertRaisesRegex(RuntimeError, "lost_reply"):
                        runner.step("gpio")
                    self.assertEqual(1, target_write.call_count)
                    self.assertEqual(86, gpio._process.poll())
                    self.assertEqual("uncertain_effect", runner.failure_status)
                    self.assertEqual((key,), cpu.service.ledger.uncertain_keys)
                    self.assertEqual((), router.pending_targets)
                    self.assertEqual([], router.deliveries)

                    with self.assertRaisesRegex(RuntimeError, "uncertain_effect"):
                        router.enqueue(
                            cpu.service.ledger, key,
                            address=acceptance["address"], write=True,
                            wdata=acceptance["write_value"],
                            be=acceptance["byte_enable"],
                            beat_bytes=acceptance["beat_bytes"],
                            callback=lambda _reply: self.fail(
                                "uncertain retry must not complete"))
                    with self.assertRaisesRegex(RuntimeError, "uncertain_effect"):
                        runner.execute_step(
                            "gpio", execution_id=step_execution,
                            command_sequence=step_id, epoch=step_epoch,
                            expected_inputs=step_inputs)
                    with self.assertRaisesRegex(RuntimeError,
                                                "scenario is not running"):
                        runner.reset_all("warm_all")
                    self.assertEqual(1, target_write.call_count)
                self.assertEqual([key], [record["source_transaction"]
                                         for record in router.acceptances])
                self.assertEqual([1], [record["acceptance_order"]
                                       for record in router.acceptances])
                self.assertEqual([], router.deliveries)
                self.assertEqual(0, runner.command_epoch)
                self.assertFalse(any(event.get("kind") == "reset_barrier"
                                     for event in runner.events))
                failure = next(event for event in runner.events
                               if event.get("kind") == "harness_failure")
                self.assertIn(str(key), failure["uncertain_transactions"])
            finally:
                runner.finalize()


if __name__ == "__main__":
    unittest.main()
