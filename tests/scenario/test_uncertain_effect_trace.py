"""A lost result after a real target effect must remain visible and replayable."""

import unittest
from pathlib import Path
import json
import tempfile

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


class _Service:
    def __init__(self):
        self.ledger = TransactionLedger()
        self.events = []


class _EffectThenLostReply:
    def __init__(self):
        self.service = _Service()
        self.target_effects = 0
        self.local_ticks = 0
        self.ended = False

    def begin_case(self, testcase_id):
        self.testcase_id = testcase_id

    def step_local(self, inputs):
        self.local_ticks += 1
        key = TransactionKey("execution", self.testcase_id, "cpu", 0, "data", 1)

        def target():
            self.target_effects += 1
            self.service.events.append({"kind": "target_effect_observed",
                                        "value": self.target_effects})
            raise RuntimeError("target reply lost")

        self.service.ledger.execute_once(key, {"op": "write", "value": 1}, target)

    def end_case(self):
        self.ended = True


class UncertainEffectTraceTests(unittest.TestCase):
    def test_queued_target_receipt_loss_keeps_committed_delivery_fact(self):
        instances = []

        class Target:
            def __init__(self):
                self.effects = 0

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                return {"out": self.effects}

            def write_register(self, offset, value, *, be=15):
                self.effects += 1

            def read_register(self, offset):
                return self.effects

            def end_case(self):
                pass

        class Source:
            def __init__(self, target):
                self.service = _Service()
                self.router = DataflowRouter((DeviceWindow(
                    "target", 0x40000000, 0x1000, target),))

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                self.router.enqueue(
                    self.service.ledger,
                    TransactionKey("exec", "case", "cpu", 0, "data", 1),
                    address=0x40000014, write=True, wdata=1, be=15,
                    beat_bytes=4,
                    callback=lambda _receipt: (_ for _ in ()).throw(
                        RuntimeError("lost_target_receipt")))
                return {"out": 0}

            def end_case(self):
                pass

        ownership = compile_ownership((), ())

        def factory():
            target = Target()
            source = Source(target)
            instances.append(target)
            return ScenarioRunner(sessions={"cpu": source, "target": target},
                                  ownership=ownership, bindings=())

        genome = ScenarioGenome(
            testcase_id="queued-reply-loss", direction="CPU_TO_IP",
            path_id="cpu-target", schedule_order=("cpu", "target"),
            max_steps=2, actions=())
        trace = record_scenario(genome, factory)
        self.assertEqual("uncertain_effect", trace.status)
        self.assertEqual(1, instances[0].effects)
        self.assertTrue(any(e.get("kind") == "mmio_acceptance"
                            for e in trace.events))
        self.assertTrue(any(e.get("kind") == "mmio_delivery"
                            for e in trace.events))
        self.assertTrue(replay_scenario(genome, factory, trace).matches)

    def setUp(self):
        self.instances = []
        self.genome = ScenarioGenome(
            testcase_id="uncertain", direction="CPU_TO_IP", path_id="cpu-ip",
            schedule_order=("cpu",), max_steps=2, actions=())

    def factory(self):
        session = _EffectThenLostReply()
        self.instances.append(session)
        ownership = compile_ownership(
            (InputField("cpu", "pin", 1),),
            (InputOwner("cpu", "pin", 0, 1, "source", "external"),))
        return ScenarioRunner(sessions={"cpu": session},
                              ownership=ownership, bindings=())

    def test_partial_effect_is_uncertain_and_replayable(self):
        trace = record_scenario(self.genome, self.factory)
        self.assertEqual("uncertain_effect", trace.status)
        self.assertEqual(1, self.instances[0].target_effects)
        self.assertTrue(self.instances[0].ended)
        failure = next(event for event in trace.events
                       if event["kind"] == "harness_failure")
        self.assertEqual("uncertain_effect", failure["status"])
        self.assertEqual(1, len(failure["uncertain_transactions"]))
        self.assertTrue(any(event.get("value") == 1 and
                            event.get("kind") == "target_effect_observed"
                            for event in trace.events))
        self.assertTrue(replay_scenario(self.genome, self.factory, trace).matches)
        self.assertEqual(1, self.instances[1].target_effects)

    def test_rfuzz_receipt_keeps_uncertain_trace_and_evidence(self):
        ownership = compile_ownership(
            (InputField("cpu", "pin", 1),),
            (InputOwner("cpu", "pin", 0, 1, "source", "external"),))
        graph = DependencyGraph(
            sources=(FuzzableSource("cpu.pin", "cpu", "pin", 0, 1,
                                    ("CPU_TO_IP",)),),
            rules=(DependencyRule("target", ("cpu.pin",), "DATA_BINDING"),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=ownership,
            templates=(DecoderTemplate("target", self.genome),))
        with tempfile.TemporaryDirectory() as directory:
            executor = ScenarioRfuzzExecutor(
                run_id="uncertain", decoder=decoder, factory=self.factory,
                targets=(CoverageTarget("target", "cpu", "done", 1, 1),),
                evidence_dir=Path(directory), allow_legacy_search=True)
            executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
            receipt = executor.receipts[0]
            self.assertEqual("uncertain_effect", receipt.status)
            self.assertIsNotNone(receipt.trace)
            self.assertEqual(receipt.trace.semantic_sha256,
                             receipt.semantic_sha256)
            evidence = list(Path(directory).glob("uncertain_effect_*.json"))
            self.assertEqual(1, len(evidence))
            self.assertEqual("uncertain_effect",
                             json.loads(evidence[0].read_text())["status"])

    def test_post_step_binding_failure_is_uncertain(self):
        class BadOutput:
            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                return {"out": -1}

            def end_case(self):
                pass

        class Target(BadOutput):
            def step_local(self, inputs):
                return {"out": 0}

        ownership = compile_ownership(
            (InputField("source", "pin", 1), InputField("target", "pin", 1)),
            (InputOwner("source", "pin", 0, 1, "source", "external"),
             InputOwner("target", "pin", 0, 1, "bound", "source.out")))

        def factory():
            return ScenarioRunner(sessions={"source": BadOutput(),
                                            "target": Target()},
                                  ownership=ownership,
                                  bindings=(Binding("source", "out", "target", "pin", 1),))

        genome = ScenarioGenome(
            testcase_id="bad-output", direction="IP_TO_IP", path_id="source-target",
            schedule_order=("source", "target"), max_steps=2, actions=())
        trace = record_scenario(genome, factory)
        self.assertEqual("uncertain_effect", trace.status)
        self.assertTrue(any(e.get("kind") == "harness_failure"
                            and e.get("phase") == "post_step_processing"
                            for e in trace.events))


if __name__ == "__main__":
    unittest.main()
