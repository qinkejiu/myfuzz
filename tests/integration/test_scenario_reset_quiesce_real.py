"""Explicit reset and response draining against real Ibex and OpenTitan GPIO."""

from __future__ import annotations

import os
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.gpio_session import OpenTitanGpioSession, _binary as gpio_binary
from myfuzz.scenario.genome import GenomeCodec, MemoryImage, ResetAction, ScenarioGenome, Trigger
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.protocol_io import LocalCommandDeadlineExceeded
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.uart_session import OpenTitanUartSession


PROGRAM = (0x400000b7, 0x0a500113, 0x0020aa23,
           0x0140a183, 0x20302023, 0x0000006f)


def _case(*, preload=True, defer_mmio=False):
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x20000),),
        initialization_seed=61, max_initialized_bytes=0x20000)
    if preload:
        memory.preload(0x10080, b"".join(word.to_bytes(4, "little")
                                       for word in PROGRAM))
        memory.preload(0x200, bytes(4))
    gpio = OpenTitanGpioSession()
    router = DataflowRouter((DeviceWindow("gpio", 0x40000000, 0x1000, gpio),))
    cpu = IbexCpuSession(memory=memory, router=router,
                         defer_mmio=defer_mmio)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2), InputField("gpio", "gpio_in", 32)),
        (InputOwner("cpu", "irq", 0, 2, "fixed", "constant_zero"),
         InputOwner("gpio", "gpio_in", 0, 32, "source", "external_pins")))
    runner = ScenarioRunner(sessions={"cpu": cpu, "gpio": gpio},
                            ownership=ownership, bindings=())
    return memory, cpu, gpio, runner


def _run_until_store(runner, cpu, target):
    for _ in range(2000):
        runner.step("cpu")
        if cpu.memory_write_count >= target:
            return
    raise AssertionError("Ibex did not commit its RAM store")


def make_deferred_ibex_gpio_runner():
    return _case(preload=False, defer_mmio=True)[-1]


class _CaptureStdout:
    def __init__(self, stream):
        self.stream = stream
        self.lines = []

    def readline(self):
        line = self.stream.readline()
        self.lines.append(line)
        return line

    def close(self):
        self.stream.close()


class _OldReplyFirst:
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


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealResetQuiesceTests(unittest.TestCase):
    def test_deferred_real_gpio_effect_survives_lost_cpu_receipt_and_replays(self):
        genome = GenomeCodec.decode(
            Path("configs/scenario/ibex_gpio_deferred_mmio.json").read_bytes())
        instances = []

        def lost_receipt_factory():
            runner = make_deferred_ibex_gpio_runner()
            cpu = runner.sessions["cpu"]
            router = cpu.router
            real_enqueue = router.enqueue

            def enqueue_then_lose_receipt(ledger, key, *, address, write,
                                          wdata, be, beat_bytes, callback):
                del callback

                def lose_receipt(_response):
                    raise RuntimeError("lost_target_receipt")

                return real_enqueue(
                    ledger, key, address=address, write=write, wdata=wdata,
                    be=be, beat_bytes=beat_bytes, callback=lose_receipt)

            router.enqueue = enqueue_then_lose_receipt
            instances.append((runner, cpu, router))
            return runner

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "deferred-lost-receipt"
            trace = save_evidence_bundle(genome, lost_receipt_factory, bundle)
            self.assertEqual("uncertain_effect", trace.status)
            accepted = [event for event in trace.events
                        if event.get("kind") == "mmio_acceptance"]
            delivered = [event for event in trace.events
                         if event.get("kind") == "mmio_delivery"]
            self.assertEqual(1, len(accepted))
            self.assertEqual(1, len(delivered))
            self.assertEqual(accepted[0]["source_transaction"],
                             delivered[0]["source_transaction"])
            self.assertEqual(0xa5, delivered[0]["write_value"])
            self.assertLess(accepted[0]["event_id"],
                            delivered[0]["event_id"])
            self.assertEqual("RuntimeError",
                             next(event for event in trace.events
                                  if event.get("kind") == "harness_failure")["error_type"])
            self.assertEqual((), instances[0][2].pending_targets)
            self.assertEqual((), instances[0][1].service.ledger.uncertain_keys)
            with self.assertRaisesRegex(RuntimeError, "scenario is not running"):
                instances[0][0].reset_all("warm_all")
            compared = replay_evidence_bundle(bundle, lost_receipt_factory)
            self.assertTrue(compared.matches, compared.first_difference)
            self.assertEqual("full", compared.verification_scope)

    def test_deferred_target_timeout_bundle_replays_confirmed_prefix(self):
        genome = GenomeCodec.decode(
            Path("configs/scenario/ibex_gpio_deferred_mmio.json").read_bytes())

        def timeout_factory():
            runner = make_deferred_ibex_gpio_runner()
            gpio = runner.sessions["gpio"]
            cpu = runner.sessions["cpu"]
            real_step = gpio.step_local
            real_end = gpio.end_case
            streams = []

            def step_then_block(inputs):
                outputs = real_step(inputs)
                if cpu.router.pending_targets and not streams:
                    read_fd, write_fd = os.pipe()
                    original = gpio._process.stdout
                    gpio._process.stdout = os.fdopen(
                        read_fd, "r", encoding="ascii", buffering=1)
                    streams.extend((write_fd, original))
                return outputs

            def end():
                real_end()
                if streams:
                    os.close(streams[0])
                    streams[1].close()

            gpio.step_local = step_then_block
            gpio.end_case = end
            return runner

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "deferred-timeout"
            trace = save_evidence_bundle(
                genome, timeout_factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=1000,
                                      max_materialized_bytes_per_memory=0x20000))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual("inflight_step", trace.events[-1]["phase"])
            self.assertTrue(trace.events[-1]["effect_may_have_occurred"])
            self.assertTrue(any(e.get("kind") == "mmio_acceptance"
                                for e in trace.events))
            final_state = json.loads((bundle / "final_state.json").read_text())
            self.assertEqual(1, len(final_state["uncertain_transactions"]))
            compared = replay_evidence_bundle(
                bundle, make_deferred_ibex_gpio_runner,
                allow_factory_mismatch=True)
            self.assertTrue(compared.matches, compared.first_difference)
            self.assertEqual("semantic_prefix", compared.verification_scope)

    def test_deferred_gpio_mmio_reply_timeout_is_inflight_budget_cut(self):
        memory, cpu, gpio, runner = _case(defer_mmio=True)
        del memory
        runner.set_resource_budget(ResourceBudget(max_wall_time_ms=500))
        runner.begin_test("deferred-target-timeout")
        original_stdout = None
        blocked_write_fd = None
        try:
            for _ in range(100):
                runner.step("cpu")
                if cpu.router.pending_targets:
                    break
            else:
                self.fail("Ibex did not accept GPIO MMIO")
            real_step = gpio.step_local

            def step_then_block(inputs):
                nonlocal original_stdout, blocked_write_fd
                outputs = real_step(inputs)
                original_stdout = gpio._process.stdout
                read_fd, blocked_write_fd = os.pipe()
                gpio._process.stdout = os.fdopen(
                    read_fd, "r", encoding="ascii", buffering=1)
                return outputs

            gpio.step_local = step_then_block
            with self.assertRaises(LocalCommandDeadlineExceeded):
                runner.step("gpio")
            self.assertEqual("budget_exhausted", runner.failure_status)
            self.assertEqual("max_wall_time_ms", runner.events[-1]["limit"])
            self.assertEqual("inflight_step", runner.events[-1]["phase"])
            self.assertTrue(runner.events[-1]["effect_may_have_occurred"])
            self.assertEqual((), cpu.router.pending_targets)
            self.assertEqual(1, len(cpu.service.ledger.uncertain_keys))
            self.assertTrue(any(e.get("kind") == "mmio_acceptance"
                                for e in runner.events))
            self.assertFalse(any(e.get("kind") == "mmio_delivery"
                                 for e in runner.events))
        finally:
            runner.finalize()
            if blocked_write_fd is not None:
                os.close(blocked_write_fd)
            if original_stdout is not None:
                original_stdout.close()

    def test_deferred_real_cpu_target_cpu_chain_replays_from_initial_state(self):
        genome = ScenarioGenome(
            testcase_id="deferred-cpu-gpio-cpu", direction="CPU_TO_IP_TO_CPU",
            path_id="deferred-real-mmio", schedule_order=("cpu", "gpio"),
            max_steps=100, actions=(), initial_images=(
                MemoryImage("cpu.program", "cpu", 0x10080,
                            b"".join(word.to_bytes(4, "little")
                                     for word in PROGRAM).hex()),
                MemoryImage("cpu.data", "cpu", 0x200, "00000000")))
        self.assertEqual(
            GenomeCodec.encode(genome),
            (Path("configs/scenario/ibex_gpio_deferred_mmio.json")
             .read_bytes().rstrip(b"\n")))
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "deferred"
            trace = save_evidence_bundle(genome, make_deferred_ibex_gpio_runner,
                                         bundle)
            self.assertEqual("complete", trace.status)
            accepted = [e for e in trace.events
                        if e.get("kind") == "mmio_acceptance"]
            delivered = [e for e in trace.events
                         if e.get("kind") == "mmio_delivery"]
            consumed = [e for e in trace.events
                        if e.get("component") == "cpu"
                        and e.get("outputs", {}).get("data_rsp_consumed") == 1]
            self.assertGreaterEqual(len(accepted), 2)
            self.assertEqual(len(accepted), len(delivered))
            self.assertGreaterEqual(len(consumed), 2)
            for source, target in zip(accepted, delivered):
                self.assertEqual(source["source_transaction"],
                                 target["source_transaction"])
                self.assertEqual(source["address"], target["address"])
                self.assertEqual(source["byte_enable"],
                                 target["byte_enable"])
                self.assertEqual(source["write_value"], target["write_value"])
                self.assertLess(source["event_id"], target["event_id"])
                producer = next(e for e in trace.events
                                if e["event_id"] == source["producer_event_id"])
                self.assertEqual(source["address"],
                                 producer["outputs"]["data_addr"])
                self.assertEqual(source["write"],
                                 bool(producer["outputs"]["data_write"]))
                if source["write"]:
                    self.assertEqual(source["write_value"],
                                     producer["outputs"]["data_wdata"])
                matches = [e for e in consumed
                           if e["event_id"] > target["event_id"]
                           and e["outputs"]["data_rsp_source_sequence"] ==
                           source["source_sequence"]]
                self.assertEqual(1, len(matches))
                if not source["write"]:
                    self.assertEqual(target["read_value"],
                                     matches[0]["outputs"]["data_rsp_rdata"])
            comparison = replay_evidence_bundle(
                bundle, make_deferred_ibex_gpio_runner)
            self.assertTrue(comparison.matches, comparison.first_difference)

    def test_real_ibex_request_waits_for_separate_gpio_target_step(self):
        memory, cpu, gpio, runner = _case(defer_mmio=True)
        del memory, gpio
        runner.begin_test("deferred-real-mmio")
        try:
            for _ in range(100):
                runner.step("cpu")
                if cpu.router.pending_targets:
                    break
            else:
                self.fail("Ibex did not accept a GPIO request")
            self.assertEqual(("gpio",), cpu.router.pending_targets)
            self.assertEqual((), tuple(cpu.router.deliveries))
            self.assertEqual(1, cpu.pending_responses)
            self.assertEqual(0, cpu.mmio_write_count + cpu.mmio_read_count)
            accepted_tick = runner.local_ticks["cpu"]
            accepted = next(e for e in runner.events
                            if e.get("kind") == "mmio_acceptance")
            for _ in range(3):
                waiting = runner.step("cpu")
                self.assertEqual(0, waiting["data_rsp_consumed"])
                self.assertEqual(("gpio",), cpu.router.pending_targets)
                self.assertEqual(1, len(cpu.router.acceptances))
                self.assertEqual(0, cpu.mmio_write_count + cpu.mmio_read_count)
            accepted_tick = runner.local_ticks["cpu"]
            runner.step("gpio")
            self.assertEqual((), cpu.router.pending_targets)
            self.assertEqual(1, len(cpu.router.deliveries))
            self.assertEqual(1, cpu.mmio_write_count + cpu.mmio_read_count)
            self.assertEqual(accepted_tick, runner.local_ticks["cpu"])
            delivered = next(e for e in runner.events
                             if e.get("kind") == "mmio_delivery")
            consumed = runner.step("cpu")
            self.assertEqual(1, consumed["data_rsp_consumed"])
            self.assertEqual(accepted["source_transaction"],
                             delivered["source_transaction"])
            self.assertEqual(accepted["address"], delivered["address"])
            self.assertEqual(accepted["write_value"],
                             delivered["write_value"])
            self.assertEqual(accepted["byte_enable"],
                             delivered["byte_enable"])
            self.assertLess(accepted["event_id"], delivered["event_id"])
            self.assertGreater(runner.events[-1]["event_id"],
                               delivered["event_id"])
            self.assertIsNone(runner.failure_status)
        finally:
            runner.finalize()

    def test_warm_reset_cancels_real_ibex_mmio_before_gpio_target_step(self):
        memory, cpu, gpio, runner = _case(defer_mmio=True)
        del memory, gpio
        runner.begin_test("deferred-mmio-reset")
        try:
            for _ in range(100):
                runner.step("cpu")
                if cpu.router.pending_targets:
                    break
            else:
                self.fail("Ibex did not accept a GPIO request")
            self.assertEqual((), tuple(cpu.router.deliveries))
            reset = runner.reset_all("warm_all")
            self.assertGreaterEqual(reset.cancelled_responses["cpu"], 1)
            self.assertEqual((), cpu.router.pending_targets)
            self.assertEqual((), cpu.service.ledger.unresolved_keys)
            self.assertTrue(any(e.get("kind") == "reset_barrier"
                                and e.get("cancelled_target_requests", {}).get("cpu")
                                for e in runner.events))
            runner.step("gpio")
            self.assertEqual((), tuple(cpu.router.deliveries))
            self.assertEqual(1, cpu.reset_epoch)
        finally:
            runner.finalize()

    def test_quiesce_drains_deferred_real_gpio_request_before_cpu_receipt(self):
        memory, cpu, gpio, runner = _case(defer_mmio=True)
        del memory, gpio
        runner.begin_test("deferred-mmio-quiesce")
        try:
            for _ in range(100):
                runner.step("cpu")
                if cpu.router.pending_targets:
                    break
            else:
                self.fail("Ibex did not accept a GPIO request")
            outcome = runner.quiesce(8)
            self.assertEqual("drained", outcome.status)
            self.assertEqual((), cpu.router.pending_targets)
            self.assertEqual(0, cpu.pending_responses)
            deliveries = [e for e in runner.events
                          if e.get("kind") == "mmio_delivery"]
            consumed = [e for e in runner.events
                        if e.get("component") == "cpu"
                        and e.get("outputs", {}).get("data_rsp_consumed") == 1]
            self.assertEqual(1, len(deliveries))
            self.assertEqual(1, len(consumed))
            self.assertLess(deliveries[0]["event_id"], consumed[0]["event_id"])
        finally:
            runner.finalize()

    def test_old_real_uart_result_after_warm_reset_cannot_complete_new_step(self):
        uart = OpenTitanUartSession()
        ownership = compile_ownership(
            (InputField("uart", "uart_rx", 1),),
            (InputOwner("uart", "uart_rx", 0, 1, "source", "external_uart_rx"),))
        runner = ScenarioRunner(sessions={"uart": uart}, ownership=ownership,
                                bindings=())
        try:
            runner.begin_test("old-uart-result-after-warm")
            capture = _CaptureStdout(uart._process.stdout)
            uart._process.stdout = capture
            self.assertEqual(1, runner.step("uart")["tx_idle"])
            old_reply = capture.lines[0]
            self.assertTrue(old_reply.startswith(
                "RESULT " + uart._wire_execution + " 1 "))
            old_execution = uart._wire_execution
            runner.reset_all("warm_all")
            self.assertNotEqual(old_execution, uart._wire_execution)
            proxy = _OldReplyFirst(uart._process.stdout, old_reply)
            uart._process.stdout = proxy
            self.assertEqual(1, runner.step("uart")["tx_idle"])
            self.assertIsNone(proxy.old_reply)
            self.assertEqual(1, proxy.real_reads)
            self.assertEqual(2, runner.local_ticks["uart"])
        finally:
            runner.finalize()

    def test_old_real_gpio_result_after_warm_reset_cannot_complete_new_step(self):
        memory, cpu, gpio, runner = _case()
        del memory, cpu
        try:
            runner.begin_test("old-gpio-result-after-warm")
            capture = _CaptureStdout(gpio._process.stdout)
            gpio._process.stdout = capture
            self.assertEqual(0, runner.step("gpio")["irq"])
            old_reply = capture.lines[0]
            self.assertTrue(old_reply.startswith(
                "RESULT " + gpio._wire_execution + " 1 "))
            old_execution = gpio._wire_execution
            runner.reset_all("warm_all")
            self.assertNotEqual(old_execution, gpio._wire_execution)
            proxy = _OldReplyFirst(gpio._process.stdout, old_reply)
            gpio._process.stdout = proxy
            self.assertEqual(0, runner.step("gpio")["irq"])
            self.assertIsNone(proxy.old_reply)
            self.assertEqual(1, proxy.real_reads)
            self.assertEqual(2, runner.local_ticks["gpio"])
        finally:
            runner.finalize()

    def test_gpio_reset_ready_uses_remaining_case_wall_budget(self):
        real_binary = gpio_binary()
        ownership = compile_ownership(
            (InputField("gpio", "gpio_in", 32),),
            (InputOwner("gpio", "gpio_in", 0, 32, "source", "external"),))

        def factory():
            return ScenarioRunner(sessions={"gpio": OpenTitanGpioSession()},
                                  ownership=ownership, bindings=())

        genome = ScenarioGenome(
            testcase_id="gpio-reset-ready-deadline", direction="IP_TO_IP",
            path_id="gpio-reset", schedule_order=("gpio",), max_steps=1,
            actions=(), encoding_version=3,
            reset_actions=(ResetAction("restart", "warm_all", Trigger("START")),))
        with tempfile.TemporaryDirectory() as directory:
            silent = Path(directory) / "silent-ready"
            silent.write_text("#!/bin/sh\nexec sleep 2\n")
            silent.chmod(0o755)
            bundle = Path(directory) / "bundle"
            with patch("myfuzz.scenario.gpio_session._binary",
                       # prepare_local builds, the first begin starts the live
                       # case, and reset_local starts a second process.
                       side_effect=(real_binary, real_binary, silent)):
                trace = save_evidence_bundle(
                    genome, factory, bundle,
                    budget=ResourceBudget(max_wall_time_ms=40))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual("inflight_reset", trace.events[-1]["phase"])
            self.assertTrue(trace.events[-1]["effect_may_have_occurred"])
            with patch("myfuzz.scenario.gpio_session._binary",
                       return_value=real_binary):
                replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches)
            self.assertEqual("semantic_prefix", replay.verification_scope)

    def test_old_real_cpu_result_after_warm_reset_cannot_complete_new_step(self):
        memory, cpu, gpio, runner = _case()
        try:
            runner.begin_test("old-result-after-warm")
            capture = _CaptureStdout(cpu._process.stdout)
            cpu._process.stdout = capture
            for _ in range(100):
                runner.step("cpu")
                if cpu.pending_responses:
                    break
            else:
                self.fail("Ibex did not leave a pending response before reset")
            # Sequence one is reused after warm reset, so the old wire reply
            # has the same numeric command ID as the new execution's first step.
            old_reply = capture.lines[0]
            self.assertTrue(old_reply.startswith(
                "RESULT " + cpu._wire_execution + " "))
            self.assertGreaterEqual(cpu.pending_responses, 1)
            before = runner.local_ticks["cpu"]
            reset = runner.reset_all("warm_all")
            self.assertGreaterEqual(reset.cancelled_responses["cpu"], 1)
            proxy = _OldReplyFirst(cpu._process.stdout, old_reply)
            cpu._process.stdout = proxy
            runner.step("cpu")
            self.assertEqual(before + 1, runner.local_ticks["cpu"])
            self.assertEqual(1, cpu._command_sequence)
            self.assertEqual(1, proxy.real_reads)
            self.assertIsNone(proxy.old_reply)
        finally:
            runner.finalize()

    def test_genome_reset_replays_real_pre_and_post_reset_transactions(self):
        genome = ScenarioGenome(
            testcase_id="real-reset-replay", direction="CPU_TO_IP_TO_CPU",
            path_id="cpu-gpio-reset-cpu", schedule_order=("cpu", "gpio"),
            max_steps=500, actions=(), encoding_version=3,
            initial_images=(
                MemoryImage("program", "cpu", 0x10080,
                            b"".join(word.to_bytes(4, "little")
                                     for word in PROGRAM).hex()),
                MemoryImage("data", "cpu", 0x200, bytes(4).hex())),
            reset_actions=(ResetAction(
                "after-first-request", "warm_all",
                Trigger("AFTER_OUTPUT", "cpu", "data_req_valid", 1, 1)),),
            quiesce_steps=50)

        def factory():
            return _case(preload=False)[-1]

        reference = record_scenario(genome, factory)
        self.assertEqual("complete", reference.status)
        barriers = [index for index, event in enumerate(reference.events)
                    if event.get("kind") == "reset_barrier"]
        self.assertEqual(1, len(barriers))
        writes_before = [event for event in reference.events[:barriers[0]]
                         if event.get("kind") == "mmio_delivery" and event["write"]]
        writes_after = [event for event in reference.events[barriers[0] + 1:]
                        if event.get("kind") == "mmio_delivery" and event["write"]]
        self.assertGreaterEqual(len(writes_before), 1)
        self.assertGreaterEqual(len(writes_after), 1)
        self.assertTrue(replay_scenario(genome, factory, reference).matches)

    def test_warm_retains_ram_cold_restores_image_and_real_gpio_resets(self):
        memory, cpu, gpio, runner = _case()
        try:
            runner.begin_test("real-reset")
            _run_until_store(runner, cpu, 1)
            self.assertEqual(0xa5, memory.read(0x200, 4,
                                               transaction_id="before-warm").value)
            self.assertEqual(0xa5, gpio.read_register(0x14))
            old_cpu_execution = cpu._wire_execution
            old_gpio_execution = gpio._wire_execution
            self.assertGreater(cpu._command_sequence, 0)
            warm = runner.reset_all("warm_all")
            self.assertEqual(0, warm.memory_generations["ram"])
            self.assertEqual(1, cpu.reset_epoch)
            self.assertNotEqual(old_cpu_execution, cpu._wire_execution)
            self.assertNotEqual(old_gpio_execution, gpio._wire_execution)
            self.assertEqual(0, cpu._command_sequence)
            self.assertGreaterEqual(warm.cancelled_responses["cpu"], 1)
            self.assertEqual(0xa5, memory.read(0x200, 4,
                                               transaction_id="after-warm").value)
            self.assertEqual(0, gpio.read_register(0x14))
            _run_until_store(runner, cpu, 2)
            self.assertEqual(0xa5, gpio.read_register(0x14))
            cold = runner.reset_all("cold_all")
            self.assertEqual(1, cold.memory_generations["ram"])
            self.assertEqual(2, cpu.reset_epoch)
            self.assertEqual(0, memory.read(0x200, 4,
                                            transaction_id="after-cold").value)
            self.assertEqual(0, gpio.read_register(0x14))
            self.assertTrue(any(event.get("edge_kind") == "INVALIDATE"
                                and event.get("memory_id") == "ram"
                                for event in runner.events))
        finally:
            runner.finalize()

    def test_quiesce_delivers_existing_response_without_new_cpu_request(self):
        memory, cpu, gpio, runner = _case()
        try:
            runner.begin_test("real-quiesce")
            _run_until_store(runner, cpu, 1)
            self.assertGreaterEqual(cpu.pending_responses, 1)
            before = (cpu.memory_write_count, cpu.mmio_write_count,
                      cpu.mmio_read_count)
            outcome = runner.quiesce(50)
            self.assertEqual("drained", outcome.status)
            self.assertGreaterEqual(outcome.steps, 1)
            self.assertEqual(0, cpu.pending_responses)
            self.assertEqual(before, (cpu.memory_write_count, cpu.mmio_write_count,
                                      cpu.mmio_read_count))
            self.assertEqual(0xa5, memory.read(0x200, 4,
                                               transaction_id="after-drain").value)
        finally:
            runner.finalize()


if __name__ == "__main__":
    unittest.main()
