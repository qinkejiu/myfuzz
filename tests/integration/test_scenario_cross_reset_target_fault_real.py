"""Real RTL checks for queued MMIO reset, lost receipt, and committed RAM Store."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


PROGRAM = (0x400000b7, 0x0a500113, 0x0020aa23,
           0x0140a183, 0x20302023, 0x0000006f)
SCENARIO_CONFIG = (Path(__file__).resolve().parents[2] / "configs" /
                   "scenario" / "ibex_gpio_deferred_mmio.json")


def make_runner(*, preload=True):
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x20000),),
        initialization_seed=61, max_initialized_bytes=0x20000)
    if preload:
        memory.preload(0x10080, b"".join(word.to_bytes(4, "little")
                                       for word in PROGRAM))
        memory.preload(0x200, bytes(4))
    gpio = OpenTitanGpioSession()
    router = DataflowRouter((DeviceWindow("gpio", 0x40000000, 0x1000, gpio),))
    cpu = IbexCpuSession(memory=memory, router=router, defer_mmio=True)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2), InputField("gpio", "gpio_in", 32)),
        (InputOwner("cpu", "irq", 0, 2, "fixed", "constant_zero"),
         InputOwner("gpio", "gpio_in", 0, 32, "source", "external_pins")))
    return ScenarioRunner(sessions={"cpu": cpu, "gpio": gpio},
                          ownership=ownership, bindings=())


def make_evidence_runner():
    return make_runner(preload=False)


def wait_for_mmio(runner):
    cpu = runner.sessions["cpu"]
    for _ in range(100):
        runner.step("cpu")
        if cpu.router.pending_targets:
            return cpu.router.acceptances[-1]["source_transaction"]
    raise AssertionError("real Ibex did not enqueue GPIO MMIO")


class CaptureReplies:
    def __init__(self, stream):
        self.stream = stream
        self.lines = []

    def readline(self):
        line = self.stream.readline()
        self.lines.append(line)
        return line

    def close(self):
        self.stream.close()


class OldReplyFirst:
    def __init__(self, stream, old_reply):
        self.stream = stream
        self.old_reply = old_reply
        self.real_reads = 0

    def readline(self):
        if self.old_reply is not None:
            reply, self.old_reply = self.old_reply, None
            return reply
        self.real_reads += 1
        return self.stream.readline()

    def close(self):
        self.stream.close()


class OldReplyAfterOneRealRead:
    """Put an old target RESULT just before the new target RESULT."""

    def __init__(self, stream, old_reply):
        self.stream = stream
        self.old_reply = old_reply
        self.real_reads = 0

    def readline(self):
        if self.real_reads == 1 and self.old_reply is not None:
            reply, self.old_reply = self.old_reply, None
            return reply
        self.real_reads += 1
        return self.stream.readline()

    def close(self):
        self.stream.close()


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealCrossResetTargetFaultTests(unittest.TestCase):
    def test_one_begin_keeps_three_real_state_accesses_in_same_epoch(self):
        runner = make_runner()
        cpu = runner.sessions["cpu"]
        gpio = runner.sessions["gpio"]
        calls = {name: {"begin": 0, "reset": 0}
                 for name in ("cpu", "gpio")}
        for name, session in (("cpu", cpu), ("gpio", gpio)):
            original_begin = session.begin_case
            original_reset = session.reset_local

            def counted_begin(testcase_id, *, component=name, begin=original_begin):
                calls[component]["begin"] += 1
                return begin(testcase_id)

            def counted_reset(*, component=name, reset=original_reset):
                calls[component]["reset"] += 1
                return reset()

            session.begin_case = counted_begin
            session.reset_local = counted_reset

        runner.begin_test("three-accesses-one-begin")
        initial_executions = (cpu._wire_execution, gpio._wire_execution)
        accepted_while_pending = []
        try:
            for _ in range(200):
                cpu_tick = runner.local_ticks["cpu"]
                gpio_tick = runner.local_ticks["gpio"]
                runner.step("cpu")
                self.assertEqual(cpu_tick + 1, runner.local_ticks["cpu"])
                self.assertEqual(gpio_tick, runner.local_ticks["gpio"])
                if cpu.router.pending_targets:
                    key = cpu.router.acceptances[-1]["source_transaction"]
                    accepted_while_pending.append((key, cpu.pending_responses))
                    self.assertEqual(("gpio",), cpu.router.pending_targets)
                    self.assertGreaterEqual(cpu.pending_responses, 1)
                    delivered = len(cpu.router.deliveries)
                    runner.step("gpio")
                    self.assertEqual(delivered + 1, len(cpu.router.deliveries))
                    self.assertEqual((), cpu.router.pending_targets)
                    self.assertGreater(runner.local_ticks["gpio"], gpio_tick)
                self.assertEqual(initial_executions,
                                 (cpu._wire_execution, gpio._wire_execution))
                self.assertEqual(0, cpu.reset_epoch)
                self.assertEqual(0, runner.command_epoch)
                if cpu.memory_write_count:
                    break
            else:
                self.fail("real Ibex did not complete three state accesses")

            self.assertEqual({"cpu": {"begin": 1, "reset": 0},
                              "gpio": {"begin": 1, "reset": 0}}, calls)
            self.assertEqual(2, len(accepted_while_pending))
            self.assertTrue(all(pending >= 1 for _, pending
                                in accepted_while_pending))
            self.assertEqual([True, False],
                             [item["write"] for item in cpu.router.deliveries])
            self.assertEqual([item[0] for item in accepted_while_pending],
                             [item["source_transaction"]
                              for item in cpu.router.deliveries])
            self.assertEqual(1, cpu.mmio_write_count)
            self.assertEqual(1, cpu.mmio_read_count)
            self.assertEqual(1, cpu.memory_write_count)
            writes = [event for event in runner.events
                      if event.get("kind") == "memory_write"
                      and event.get("address") == 0x200]
            self.assertEqual(1, len(writes))
            self.assertEqual(0xa5, writes[0]["value"])
            self.assertEqual(3, len(cpu.router.deliveries) + len(writes))
            self.assertGreater(cpu.pending_responses, 0)
            self.assertEqual((), cpu.router.pending_targets)
            self.assertFalse(any(event.get("kind") == "reset_barrier"
                                 for event in runner.events))
            self.assertEqual(cpu.local_ticks, runner.local_ticks["cpu"])
            self.assertEqual(gpio.local_ticks, runner.local_ticks["gpio"])
        finally:
            runner.finalize()

    def test_target_write_loses_receipt_and_reset_cannot_claim_recovery(self):
        runner = make_runner()
        cpu = runner.sessions["cpu"]
        gpio = runner.sessions["gpio"]
        with patch.dict(os.environ, {"MYFUZZ_TEST_CRASH_AFTER_GPIO_WRITE": "1"}):
            runner.begin_test("target-write-receipt-lost")
            try:
                old_key = wait_for_mmio(runner)
                self.assertTrue(cpu.router.acceptances[-1]["write"])
                failed_step_id = runner._next_command_sequence
                failed_step_inputs = runner._effective_inputs("gpio")
                failed_step_epoch = runner.command_epoch
                failed_step_execution = runner.execution_id
                with self.assertRaisesRegex(RuntimeError, "lost_reply"):
                    runner.step("gpio")
                self.assertEqual(86, gpio._process.poll())
                self.assertEqual("uncertain_effect", runner.failure_status)
                self.assertEqual((old_key,), cpu.service.ledger.uncertain_keys)
                self.assertEqual((), cpu.router.pending_targets)
                self.assertEqual((), tuple(cpu.router.deliveries))
                acceptance = cpu.router.acceptances[-1]
                with self.assertRaisesRegex(RuntimeError, "uncertain_effect"):
                    cpu.router.enqueue(
                        cpu.service.ledger, old_key,
                        address=acceptance["address"], write=True,
                        wdata=acceptance["write_value"],
                        be=acceptance["byte_enable"],
                        beat_bytes=acceptance["beat_bytes"],
                        callback=lambda _response: self.fail(
                            "uncertain target retry must not invoke callback"))
                self.assertEqual(1, len(cpu.router.acceptances))
                self.assertEqual((), cpu.router.pending_targets)
                with self.assertRaisesRegex(RuntimeError, "uncertain_effect"):
                    runner.execute_step(
                        "gpio", execution_id=failed_step_execution,
                        command_sequence=failed_step_id,
                        epoch=failed_step_epoch,
                        expected_inputs=failed_step_inputs)
                self.assertEqual((), tuple(cpu.router.deliveries))
                self.assertEqual(1, len(cpu.router.acceptances))
                failure = next(event for event in runner.events
                               if event.get("kind") == "harness_failure")
                self.assertIn(str(old_key), failure["uncertain_transactions"])
                with self.assertRaisesRegex(RuntimeError, "scenario is not running"):
                    runner.reset_all("warm_all")
                self.assertEqual(0, cpu.reset_epoch)
                self.assertFalse(any(event.get("kind") == "reset_barrier"
                                     for event in runner.events))
            finally:
                runner.finalize()

        genome = GenomeCodec.decode(SCENARIO_CONFIG.read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "crashed-target"
            with patch.dict(os.environ, {"MYFUZZ_TEST_CRASH_AFTER_GPIO_WRITE": "1"}):
                trace = save_evidence_bundle(genome, make_evidence_runner, bundle)
                comparison = replay_evidence_bundle(bundle, make_evidence_runner)
            self.assertEqual("uncertain_effect", trace.status)
            self.assertEqual("full", comparison.verification_scope)
            self.assertTrue(comparison.matches, comparison.first_difference)
            final_state = json.loads((bundle / "final_state.json").read_text())
            self.assertEqual(1, len(final_state["uncertain_transactions"]))
            self.assertFalse(any(event.get("kind") == "mmio_delivery"
                                 for event in trace.events))

    def test_warm_reset_cancels_old_target_then_new_epoch_reuses_sequence(self):
        runner = make_runner()
        cpu = runner.sessions["cpu"]
        gpio = runner.sessions["gpio"]
        runner.begin_test("cross-reset-cancelled-target")
        try:
            capture = CaptureReplies(cpu._process.stdout)
            cpu._process.stdout = capture
            old_key = wait_for_mmio(runner)
            self.assertEqual(0, old_key.source_epoch)
            old_wire_execution = cpu._wire_execution
            old_reply = capture.lines[0]
            self.assertTrue(old_reply.startswith(
                "RESULT " + old_wire_execution + " 1 "))
            self.assertEqual(0, gpio.read_register(0x14))
            reset = runner.reset_all("warm_all")
            self.assertGreaterEqual(reset.cancelled_responses["cpu"], 1)
            self.assertEqual((), cpu.service.ledger.unresolved_keys)
            self.assertEqual((), cpu.router.pending_targets)
            self.assertEqual((), tuple(cpu.router.deliveries))
            self.assertNotEqual(old_wire_execution, cpu._wire_execution)
            self.assertEqual(1, cpu.reset_epoch)
            barrier = next(event for event in runner.events
                           if event.get("kind") == "reset_barrier")
            self.assertIn(str(old_key), barrier["cancelled_target_requests"]["cpu"])
            runner.step("gpio")
            self.assertEqual(0, gpio.read_register(0x14))

            stale = OldReplyFirst(cpu._process.stdout, old_reply)
            cpu._process.stdout = stale
            new_key = wait_for_mmio(runner)
            self.assertIsNone(stale.old_reply)
            self.assertGreater(stale.real_reads, 0)
            self.assertEqual(old_key.source_sequence, new_key.source_sequence)
            self.assertEqual(1, new_key.source_epoch)
            self.assertNotEqual(old_key, new_key)
            outcome = runner.quiesce(8)
            self.assertEqual("drained", outcome.status)
            deliveries = [event for event in runner.events
                          if event.get("kind") == "mmio_delivery"]
            self.assertEqual([asdict(new_key)], [event["source_transaction"]
                                                 for event in deliveries])
            consumed = [event for event in runner.events
                        if event.get("component") == "cpu"
                        and event.get("outputs", {}).get("data_rsp_consumed") == 1]
            self.assertEqual(1, len(consumed))
            self.assertEqual(1, consumed[0]["outputs"]["data_rsp_source_epoch"])
            self.assertEqual(new_key.source_sequence,
                             consumed[0]["outputs"]["data_rsp_source_sequence"])
            self.assertEqual(0xa5, gpio.read_register(0x14))
            self.assertIsNone(runner.failure_status)
        finally:
            runner.finalize()

    def test_confirmed_old_gpio_target_result_cannot_complete_new_epoch_target(self):
        runner = make_runner()
        cpu = runner.sessions["cpu"]
        gpio = runner.sessions["gpio"]
        runner.begin_test("old-target-result-after-warm")
        try:
            old_key = wait_for_mmio(runner)
            old_execution = gpio._wire_execution
            capture = CaptureReplies(gpio._process.stdout)
            gpio._process.stdout = capture
            runner.step("gpio")
            self.assertEqual(2, gpio._command_sequence)
            old_target_reply = capture.lines[-1]
            self.assertTrue(old_target_reply.startswith(
                "RESULT " + old_execution + " 2 "))
            self.assertEqual([asdict(old_key)],
                             [event["source_transaction"] for event in runner.events
                              if event.get("kind") == "mmio_delivery"])
            self.assertEqual((), cpu.service.ledger.uncertain_keys)
            self.assertIsNotNone(cpu._pending_data)

            runner.reset_all("warm_all")
            self.assertNotEqual(old_execution, gpio._wire_execution)
            self.assertIsNone(cpu._pending_data)
            new_key = wait_for_mmio(runner)
            self.assertEqual(old_key.source_sequence, new_key.source_sequence)
            self.assertEqual(old_key.source_epoch + 1, new_key.source_epoch)
            stale = OldReplyAfterOneRealRead(gpio._process.stdout,
                                             old_target_reply)
            gpio._process.stdout = stale
            runner.step("gpio")
            self.assertIsNone(stale.old_reply)
            self.assertEqual(2, stale.real_reads)
            self.assertEqual(2, gpio._command_sequence)
            self.assertEqual([asdict(old_key), asdict(new_key)],
                             [event["source_transaction"] for event in runner.events
                              if event.get("kind") == "mmio_delivery"])
            self.assertEqual((), cpu.service.ledger.uncertain_keys)
            self.assertEqual("drained", runner.quiesce(8).status)
            consumed = [event for event in runner.events
                        if event.get("component") == "cpu"
                        and event.get("outputs", {}).get("data_rsp_consumed") == 1]
            self.assertEqual(1, len(consumed))
            self.assertEqual(new_key.source_epoch,
                             consumed[0]["outputs"]["data_rsp_source_epoch"])
            self.assertEqual(0xa5, gpio.read_register(0x14))
        finally:
            runner.finalize()

    def test_warm_reset_keeps_committed_ram_store_before_cpu_receipt(self):
        runner = make_runner()
        cpu = runner.sessions["cpu"]
        memory = cpu.memory
        runner.begin_test("committed-store-pending-receipt")
        try:
            for _ in range(200):
                runner.step("cpu")
                if cpu.router.pending_targets:
                    runner.step("gpio")
                if cpu.memory_write_count:
                    break
            else:
                self.fail("real Ibex did not commit its RAM Store")

            writes = [event for event in runner.events
                      if event.get("kind") == "memory_write"
                      and event.get("address") == 0x200]
            self.assertEqual(1, len(writes))
            write = writes[0]
            self.assertEqual(0xa5, write["value"])
            self.assertIsNotNone(write["version"])
            self.assertIsNotNone(cpu._pending_data)
            self.assertEqual(write["transaction"]["source_sequence"],
                             cpu._pending_data[2])
            last_cpu_step = [event for event in runner.events
                             if event.get("component") == "cpu"
                             and "outputs" in event][-1]
            self.assertEqual(last_cpu_step["event_id"],
                             write["producer_event_id"])
            self.assertEqual(0, last_cpu_step["outputs"]["data_rsp_consumed"])
            before = memory.read(0x200, 4, transaction_id="before-warm")
            self.assertEqual(0xa5, before.value)
            self.assertEqual((str(TransactionKey(**write["transaction"])),) * 4,
                             before.writer_event_ids)

            reset = runner.reset_all("warm_all")
            self.assertEqual(0, memory.generation)
            self.assertGreaterEqual(reset.cancelled_responses["cpu"], 1)
            self.assertIsNone(cpu._pending_data)
            after = memory.read(0x200, 4, transaction_id="after-warm")
            self.assertEqual(before.value, after.value)
            self.assertEqual(before.versions, after.versions)
            self.assertEqual(before.writer_event_ids, after.writer_event_ids)
            first_new_step = runner.step("cpu")
            self.assertEqual(0, first_new_step["data_rsp_consumed"])
            self.assertEqual(0, first_new_step["data_rsp_source_epoch"])
            self.assertFalse(any(event.get("kind") == "memory_write"
                                 and event["event_id"] > write["event_id"]
                                 for event in runner.events))
        finally:
            runner.finalize()


if __name__ == "__main__":
    unittest.main()
