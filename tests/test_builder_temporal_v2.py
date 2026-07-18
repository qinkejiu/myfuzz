import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    InputValidationError, TemporalConstraintEvaluator, build_temporal_constraint_ir_v2,
)


def build(*constraints, fault_sinks=()):
    return build_temporal_constraint_ir_v2(
        rawbits_layout_digest="1" * 64, soc_digest="2" * 64,
        constraints=constraints, fault_capable_sinks=fault_sinks,
    )


def rule(identifier, primitive, priority, **values):
    return {"id": identifier, "primitive": primitive, "priority": priority, "domain": "global", **values}


class TemporalGoldenVectorsTest(unittest.TestCase):
    def test_stable_hold_update_dependency_and_domain_reset(self):
        ir = build(
            rule("stable", "STABLE_UNTIL", 1, dst="stable_o", sample="sample", activate="activate", release="release", width=8, reset=0),
            rule("hold", "HOLD_WHEN", 2, dst="hold_o", sample="sample", hold="hold", width=8, reset=3),
            rule("update", "UPDATE_ON", 3, dst="update_o", sample="sample", event="event", width=8, reset=4),
            rule("dep", "DEPENDENCY", 4, dst="dep_o", predicate="stable_o", true_value=9, false_value=2, width=8),
        )
        evaluator = TemporalConstraintEvaluator(ir)
        first = evaluator.step({"sample": 7, "activate": 1, "release": 0, "hold": 0, "event": 0})
        self.assertEqual(first.outputs, {"stable_o": 7, "hold_o": 7, "update_o": 4, "dep_o": 9})
        released = evaluator.step({"sample": 8, "activate": 1, "release": 1, "hold": 1, "event": 1})
        self.assertEqual(released.outputs["stable_o"], 7)
        self.assertEqual(released.outputs["hold_o"], 7)
        self.assertEqual(released.outputs["update_o"], 8)
        reset = evaluator.step({}, domain_resets=("global",))
        self.assertEqual((reset.outputs["stable_o"], reset.outputs["hold_o"], reset.outputs["update_o"]), (0, 3, 4))

    def test_valid_ready_and_pulse_retrigger_set_sticky_error(self):
        valid_ir = build(rule("vr", "VALID_READY", 1, valid="valid_o", payload="payload_o", sample="data", activate="go", ready="ready", width=8, reset_payload=0))
        evaluator = TemporalConstraintEvaluator(valid_ir)
        first = evaluator.step({"go": 1, "ready": 0, "data": 5})
        self.assertEqual((first.outputs["valid_o"], first.outputs["payload_o"]), (1, 5))
        evaluator = TemporalConstraintEvaluator(valid_ir)
        evaluator.step({"go": 1, "ready": 0, "data": 5})
        error = evaluator.step({"go": 1, "ready": 0, "data": 9}, record_valid=True)
        self.assertTrue(error.runtime_error)
        self.assertFalse(error.accepted)
        self.assertFalse(evaluator.raw_bits_ready)

        pulse = TemporalConstraintEvaluator(build(rule("pulse", "PULSE_WIDTH", 1, dst="pulse_o", start="start", cycles=2)))
        self.assertEqual(pulse.step({"start": 1}).outputs["pulse_o"], 1)
        self.assertTrue(pulse.step({"start": 1}).runtime_error)

    def test_wait_success_wins_timeout_and_timeout_fires_once(self):
        ir = build(
            rule("wait", "WAIT_UNTIL", 1, activate="wait_start", predicate="done", limit=2, success="success_o", expired="expired_o"),
            rule("timeout", "TIMEOUT", 2, active="active", clear="clear", limit=2, fired="fired_o"),
        )
        evaluator = TemporalConstraintEvaluator(ir)
        evaluator.step({"wait_start": 1, "done": 0, "active": 1, "clear": 0})
        edge = evaluator.step({"wait_start": 0, "done": 0, "active": 1, "clear": 0})
        self.assertEqual(edge.outputs["fired_o"], 1)
        success = evaluator.step({"wait_start": 0, "done": 1, "active": 1, "clear": 0})
        self.assertEqual((success.outputs["success_o"], success.outputs["expired_o"], success.outputs["fired_o"]), (1, 0, 0))

    def test_choice_consumes_only_on_acceptance_and_fault_is_bounded(self):
        ir = build(
            rule("choice", "CHOICE_WEIGHT", 1, dst="choice_o", raw_slice="raw", slice_width=2, choices=(10, 20), integer_weights=(1, 3), width=8),
            rule("fault", "FAULT_INJECT", 2, dst="pin", enable="fault_enable", kind="stuck", value=1, cycles=2, width=1),
            fault_sinks=("pin",),
        )
        evaluator = TemporalConstraintEvaluator(ir)
        stalled = evaluator.step({"raw": 3, "fault_enable": 1}, record_valid=False)
        self.assertEqual(stalled.outputs["choice_o"], 10)
        accepted = evaluator.step({"raw": 3, "fault_enable": 1}, record_valid=True)
        self.assertEqual(accepted.outputs["choice_o"], 20)
        self.assertTrue(accepted.accepted)
        self.assertEqual(evaluator.step({"raw": 0, "fault_enable": 1}).outputs["pin"], 0)

    def test_reset_sequence_expands_and_feedback_priority_is_canonical(self):
        ir = build(rule(
            "reset", "RESET_SEQUENCE", 1, domain="peripheral", start="start",
            drain_limit=1, isolate_limit=2, assert_cycles=1, complete_limit=3,
            drained="drained", isolated="isolated", reset_done="reset_done", error="error",
            request="request_o", force_isolate="force_o", success="success_o", failed="failed_o",
        ))
        self.assertNotIn("RESET_SEQUENCE", {item["primitive"] for item in ir.constraints})
        self.assertEqual(sum(item["primitive"] == "TIMEOUT" for item in ir.constraints), 3)
        evaluator = TemporalConstraintEvaluator(ir)
        evaluator.step({"start": 1, "drained": 0, "isolated": 0, "reset_done": 0, "error": 0})
        isolate = evaluator.step({"start": 1, "drained": 0, "isolated": 0, "reset_done": 0, "error": 0})
        self.assertEqual(isolate.outputs["reset.state"], "ISOLATE")
        failed = evaluator.step({"start": 0, "drained": 0, "isolated": 1, "reset_done": 0, "error": 1})
        self.assertEqual(failed.outputs["reset.state"], "FAILED")
        pulse = evaluator.step({})
        self.assertEqual((pulse.outputs["failed_o"], pulse.outputs["reset.state"]), (1, "IDLE"))

        evaluator = TemporalConstraintEvaluator(ir)
        evaluator.step({"start": 1})
        evaluator.step({})  # DRAIN timeout enters ISOLATE.
        evaluator.step({})
        coincident = evaluator.step({"isolated": 1})
        self.assertEqual(coincident.outputs["reset.state"], "RESET")


class TemporalValidationTest(unittest.TestCase):
    def test_bit_mask_is_combinational_and_width_checked(self):
        ir = build(rule("mask", "BIT_MASK", 1, dst="masked", sample="raw", mask=0xfc, width=8))
        evaluator = TemporalConstraintEvaluator(ir)
        self.assertEqual(evaluator.step({"raw": 0xff}).outputs["masked"], 0xfc)
        self.assertEqual(evaluator.step({"raw": 0x53}).outputs["masked"], 0x50)
        with self.assertRaisesRegex(InputValidationError, "does not fit width"):
            build(rule("mask", "BIT_MASK", 1, dst="masked", sample="raw", mask=0x100, width=8))

    def test_multiple_writer_priority_cycle_and_fault_boundary_reject(self):
        duplicate = (
            rule("a", "UPDATE_ON", 1, dst="x", sample="b", event=1, width=1, reset=0),
            rule("b", "UPDATE_ON", 2, dst="x", sample="a", event=1, width=1, reset=0),
        )
        with self.assertRaisesRegex(InputValidationError, "multiple writers"):
            build(*duplicate)
        with self.assertRaisesRegex(InputValidationError, "priorities must be unique"):
            build(rule("a", "PULSE_WIDTH", 1, dst="a", start="go", cycles=1),
                  rule("b", "PULSE_WIDTH", 1, dst="b", start="go", cycles=1))
        with self.assertRaisesRegex(InputValidationError, "fault-capable"):
            build(rule("fault", "FAULT_INJECT", 1, dst="internal_axi", enable="go", kind="stuck", value=1, cycles=1, width=1))
        with self.assertRaisesRegex(InputValidationError, "dependency cycle"):
            build(rule("a", "DEPENDENCY", 1, dst="a", predicate="b", true_value=1, false_value=0, width=1),
                  rule("b", "DEPENDENCY", 2, dst="b", predicate="a", true_value=1, false_value=0, width=1))


if __name__ == "__main__":
    unittest.main()
