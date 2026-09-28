"""One RFuzz test transports one continuous scenario, with real-output feedback."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.replay import ScenarioTrace


class PinSession:
    def __init__(self, output):
        self.output = output
        self.begins = 0

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        return {self.output: inputs.get("pin", 0)}

    def end_case(self):
        pass


class RfuzzScenarioExecutorTests(unittest.TestCase):
    def test_input_invalid_and_environment_error_remain_distinct(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("a.pin", "a", "pin", 0, 1,
                                    ("IP_TO_IP",)),),
            rules=(DependencyRule("a.out", ("a.pin",), "ENV_PRECONDITION"),))
        ownership = compile_ownership(
            (InputField("a", "pin", 1),),
            (InputOwner("a", "pin", 0, 1, "source", "external"),))
        target = CoverageTarget("a.out", "a", "out", 1, 1)
        no_action = ScenarioGenome(
            testcase_id="empty", direction="IP_TO_IP", path_id="a",
            schedule_order=("a",), max_steps=1, actions=())
        invalid_decoder = GenomeRecordDecoder(
            graph=graph, ownership=ownership,
            templates=(DecoderTemplate("a.out", no_action),))
        factory_calls = []
        invalid = ScenarioRfuzzExecutor(
            run_id="invalid", decoder=invalid_decoder,
            factory=lambda: factory_calls.append(1), targets=(target,),
            allow_legacy_search=True)
        mutate = bytes((0, 0, 0, 0, 0, 1, 0, 0))
        self.assertEqual((b"\x00",), invalid.execute_batch(
            InputBatch(1, 8, ((mutate,),))))
        self.assertEqual("input_invalid", invalid.receipts[-1].status)
        self.assertEqual([], factory_calls)

        action = Action("pin", "a", "pin", 0, "IP_TO_IP", Trigger("START"))
        valid_decoder = GenomeRecordDecoder(
            graph=graph, ownership=ownership,
            templates=(DecoderTemplate("a.out", ScenarioGenome(
                testcase_id="valid", direction="IP_TO_IP", path_id="a",
                schedule_order=("a",), max_steps=1, actions=(action,))),))

        def broken_environment():
            raise RuntimeError("local harness setup failed")

        environment = ScenarioRfuzzExecutor(
            run_id="environment", decoder=valid_decoder,
            factory=broken_environment, targets=(target,),
            allow_legacy_search=True)
        self.assertEqual((b"\x00",), environment.execute_batch(
            InputBatch(2, 8, ((bytes(8),),))))
        self.assertEqual("environment_error", environment.receipts[-1].status)
        self.assertIn("local harness setup failed", environment.receipts[-1].error)

    def test_hint_does_not_rotate_before_a_source_is_executed(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("cpu.program", "cpu", "program", 0, 1,
                                    ("CPU_TO_IP",)),
                     FuzzableSource("spi.data", "spi", "data", 0, 1,
                                    ("CPU_TO_IP",))),
            rules=(DependencyRule("spi.transfer", ("cpu.program", "spi.data"),
                                  "PERSISTENT_STATE_RULE"),))
        ownership = compile_ownership(
            (InputField("cpu", "program", 1), InputField("spi", "data", 1)),
            (InputOwner("cpu", "program", 0, 1, "source", "program"),
             InputOwner("spi", "data", 0, 1, "source", "external")))
        genome = ScenarioGenome(
            testcase_id="seed", direction="CPU_TO_IP", path_id="cpu-spi",
            schedule_order=("cpu", "spi"), max_steps=2,
            actions=(Action("program", "cpu", "program", 0, "CPU_TO_IP",
                            Trigger("START"), width=1),
                     Action("data", "spi", "data", 0, "CPU_TO_IP",
                            Trigger("START"), width=1)))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=ownership,
            templates=(DecoderTemplate("spi.transfer", genome),))
        executor = ScenarioRfuzzExecutor(
            run_id="rotate", decoder=decoder, factory=lambda: None,
            targets=(CoverageTarget("spi.transfer", "spi", "done", 1, 1),),
            allow_legacy_search=True)
        self.assertEqual((0, 0), (executor.mutation_hint()["source"],
                                  executor.mutation_hint()["source"]))
        self.assertEqual({"cpu.program": 0, "spi.data": 0},
                         executor.applied_source_uses)

    def test_batch_slots_are_distinct_testcases_and_violation_is_preserved(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("a.pin", "a", "pin", 0, 1,
                                    ("IP_TO_IP",)),),
            rules=(DependencyRule("b.irq", ("a.pin",), "DATA_BINDING"),))
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 1)),
            (InputOwner("a", "pin", 0, 1, "source", "external"),
             InputOwner("b", "pin", 0, 1, "bound", "a.out")))
        genome = ScenarioGenome(
            testcase_id="seed", direction="IP_TO_IP", path_id="a-b",
            schedule_order=("a", "b"), max_steps=4,
            actions=(Action("edge", "a", "pin", 0, "IP_TO_IP",
                            Trigger("START"), width=1),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=ownership,
            templates=(DecoderTemplate("b.irq", genome),))
        sessions = []

        def factory():
            a, b = PinSession("out"), PinSession("irq")
            sessions.append((a, b))
            return ScenarioRunner(sessions={"a": a, "b": b}, ownership=ownership,
                                  bindings=(Binding("a", "out", "b", "pin", 1),))

        def checker(trace):
            return ("unexpected_irq",) if any(
                e.get("component") == "b"
                and e.get("outputs", {}).get("irq") == 1
                for e in trace.events) else ()

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        executor = ScenarioRfuzzExecutor(
            run_id="run-one", decoder=decoder, factory=factory,
            targets=(CoverageTarget("b.irq", "b", "irq", 1, 1),),
            checker=checker, evidence_dir=Path(temporary.name),
            allow_legacy_search=True)
        initial_hint = executor.mutation_hint()
        self.assertEqual(0, initial_hint["template"])
        self.assertEqual(64, initial_hint["energy"])
        no_change = bytes(8)
        flip = bytes((0, 0, 0, 0, 0, 1, 0, 0))
        batch = InputBatch(42, 8, ((no_change,), (flip, no_change)))
        observed = []

        def on_receipt(receipt):
            observed.append((receipt.slot, len(executor.receipts), len(sessions)))

        coverage = executor.execute_batch(batch, on_receipt=on_receipt)
        self.assertEqual((b"\x00", b"\x01"), coverage)
        self.assertEqual([(0, 1, 1), (1, 2, 2)], observed)
        self.assertEqual(8, executor.mutation_hint()["energy"])
        self.assertEqual(("complete", "dut_violation"),
                         tuple(receipt.status for receipt in executor.receipts))
        self.assertEqual((0, 1), tuple(receipt.slot for receipt in executor.receipts))
        self.assertEqual((4, 4), tuple(receipt.total_local_ticks
                                       for receipt in executor.receipts))
        self.assertEqual(("unexpected_irq",), executor.receipts[1].violations)
        self.assertEqual(executor.receipts[0].manifest_sha256,
                         executor.receipts[1].manifest_sha256)
        self.assertEqual(64, len(executor.receipts[0].manifest_sha256))
        self.assertEqual(2, len(sessions))
        self.assertTrue(all(a.begins == b.begins == 1 for a, b in sessions))
        failures = list(Path(temporary.name).glob("dut_violation_*.json"))
        self.assertEqual(1, len(failures))
        evidence = json.loads(failures[0].read_text())
        self.assertEqual(["unexpected_irq"], evidence["violations"])
        self.assertEqual(1, evidence["slot"])
        self.assertTrue(evidence["trace"]["events"])
        self.assertEqual(coverage, executor.execute_batch(batch))
        self.assertEqual(2, len(sessions))  # retry did not restart or reexecute RTL
        self.assertEqual(1, len(list(Path(temporary.name).glob("dut_violation_*.json"))))
        altered = InputBatch(42, 8, ((no_change,), (no_change,)))
        with self.assertRaisesRegex(ValueError, "identity reused"):
            executor.execute_batch(altered)
        # The target was already hit by slot 1. A new testcase with the same
        # violating genome must still be retained even with no new coverage.
        known_hits = set(executor._target_hits)
        repeated_violation = InputBatch(43, 8, ((flip, no_change),))
        self.assertEqual((b"\x01",), executor.execute_batch(repeated_violation))
        self.assertEqual(known_hits, executor._target_hits)
        self.assertEqual("dut_violation", executor.receipts[-1].status)
        self.assertEqual(2, len(list(Path(temporary.name).glob("dut_violation_*.json"))))

        # A failed receipt sink preserves the completed prefix. Retrying the
        # same buffer must not execute its first testcase twice.
        interrupted = InputBatch(44, 8, ((no_change,), (flip, no_change)))
        prior_receipts, prior_sessions = len(executor.receipts), len(sessions)
        with self.assertRaisesRegex(OSError, "receipt storage failed"):
            executor.execute_batch(
                interrupted,
                on_receipt=lambda receipt: (_ for _ in ()).throw(
                    OSError("receipt storage failed")))
        self.assertEqual(prior_receipts + 1, len(executor.receipts))
        self.assertEqual(prior_sessions + 1, len(sessions))
        self.assertEqual((b"\x00", b"\x01"), executor.execute_batch(interrupted))
        self.assertEqual(prior_sessions + 2, len(sessions))

        marker = {"kind": "budget_exhausted", "limit": "max_wall_time_ms",
                  "phase": "before_step", "prefix_local_ticks": {"a": 2, "b": 2}}
        wall_trace = ScenarioTrace("g" * 64, "budget_exhausted", (marker,),
                                   {"a": 2, "b": 2}, "s" * 64, "m" * 64)
        with patch("myfuzz.integration.scenario_rfuzz.record_scenario",
                   return_value=wall_trace):
            executor.execute_batch(InputBatch(45, 8, ((no_change,),)))
        self.assertEqual({**marker, "semantic_prefix_sha256":
                          "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"},
                         executor.receipts[-1].wall_cut)
        self.assertIs(wall_trace, executor.receipts[-1].trace)


if __name__ == "__main__":
    unittest.main()
