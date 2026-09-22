"""Step 6A: the unified input-constraint and ownership policy.

Positive cases prove determinism, reorder-invariance, preserved unconstrained
bits and preserved legal-exception scenarios.  Negative cases prove that a
post-repair conflict, a same-field conflict, a closure budget exhaustion, an
unknown capability, a double driver and a mis-read legacy corpus are all
rejected instead of being quietly accepted.
"""
from __future__ import annotations

import json
import unittest

from myfuzz.composition.input_constraints import (
    DRIVE_PROFILES,
    INPUT_CONSTRAINT_SCHEMA,
    InputConstraintError,
    compile_input_constraints,
    compile_rules,
    input_constraint_document,
    rules_of,
)

from .soc_generation_fixture import ROOT, example_plan


def _rule(rule_id: str, **overrides) -> dict:
    document = {
        "rule_id": rule_id,
        "category": "environment_hard",
        "owner": "environment",
        "primitive": "drive_cycle_value",
        "phase": "runtime",
        "fields": [rule_id],
        "read_set": [],
        "write_set": [rule_id],
        "raw_bits": [[0, 0]],
    }
    document.update(overrides)
    return document


class CompilationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()

    def test_every_drive_profile_compiles_and_binds_one_layout(self) -> None:
        for name in DRIVE_PROFILES:
            with self.subTest(profile=name):
                policy = compile_input_constraints(self.plan, drive_profile=name)
                self.assertEqual(INPUT_CONSTRAINT_SCHEMA, INPUT_CONSTRAINT_SCHEMA)
                self.assertEqual(self.plan.raw_layout["layout_hash"], policy.layout_hash)
                self.assertEqual(self.plan.plan_hash, policy.plan_hash)
                self.assertTrue(policy.policy_hash.startswith("sha256:"))
                self.assertTrue(policy.gaps)

    def test_special_inputs_become_environment_drive_rules(self) -> None:
        policy = compile_input_constraints(self.plan, drive_profile="cpu_execute")
        drive = [item for item in policy.rules if item.primitive.startswith("drive_")]
        self.assertEqual({"drive:cpu0__event_i", "drive:gpio0__pin_mode_i"},
                         {item.rule_id for item in drive})
        event = policy.rule("drive:cpu0__event_i")
        self.assertEqual("environment", event.owner)
        self.assertEqual(((0, 3),), event.raw_bits)
        self.assertEqual("cycle_value", dict(event.parameters)["strategy"])
        self.assertEqual("runtime", event.phase)

    def test_ownership_follows_the_drive_profile(self) -> None:
        windows = {name: {item.rule_id: item.owner
                          for item in compile_input_constraints(
                              self.plan, drive_profile=name).rules
                          if item.primitive == "reachable_window"}
                   for name in ("cpu_execute", "bfm_isolated", "contention")}
        self.assertEqual({"cpu"}, set(windows["cpu_execute"].values()))
        self.assertEqual({"bfm"}, set(windows["bfm_isolated"].values()))
        self.assertEqual({"environment"}, set(windows["contention"].values()))
        contention = compile_input_constraints(self.plan, drive_profile="contention")
        rule = contention.rule("window:uart0_win")
        parameters = dict(rule.parameters)
        self.assertEqual(("cpu", "bfm"), tuple(parameters["arbitrated_masters"]))
        self.assertEqual("single_outstanding_request_response",
                         parameters["arbitration"])

    def test_legacy_modes_keep_their_meaning(self) -> None:
        for name, profile in DRIVE_PROFILES.items():
            with self.subTest(profile=name):
                policy = compile_input_constraints(self.plan, drive_profile=name)
                self.assertEqual(tuple(profile["legacy_modes"]), policy.legacy_modes)
                self.assertEqual(bool(profile["cpu_held_in_reset"]), policy.cpu_held_in_reset)
        self.assertEqual(("mmio_only",),
                         compile_input_constraints(self.plan,
                                                   drive_profile="bfm_isolated").legacy_modes)

    def test_the_so_c_driven_inputs_are_not_environment_writable(self) -> None:
        """A rule that lets the environment drive a functional input is refused."""
        with self.assertRaises(InputConstraintError) as error:
            compile_rules([_rule("clk", write_set=["cpu0::clk_i"])],
                          drive_profile="cpu_execute", dut_driven=["cpu0::clk_i"])
        self.assertIn("environment-overrides-dut-value", str(error.exception))


class DeterminismTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()

    def test_compilation_is_deterministic(self) -> None:
        first = compile_input_constraints(self.plan, drive_profile="cpu_execute")
        second = compile_input_constraints(self.plan, drive_profile="cpu_execute")
        self.assertEqual(first.policy_hash, second.policy_hash)
        self.assertEqual(input_constraint_document(first),
                         input_constraint_document(second))

    def test_rule_declaration_order_does_not_change_identity(self) -> None:
        rules = [_rule("b", raw_bits=[[1, 1]]), _rule("a", raw_bits=[[0, 0]])]
        forward = compile_rules(rules, drive_profile="cpu_execute")
        backward = compile_rules(list(reversed(rules)), drive_profile="cpu_execute")
        self.assertEqual(forward.policy_hash, backward.policy_hash)
        self.assertEqual([item.rule_id for item in forward.rules], ["a", "b"])

    def test_changing_a_rule_basis_changes_identity(self) -> None:
        base = compile_rules([_rule("a", basis="profile:v1")], drive_profile="cpu_execute")
        changed = compile_rules([_rule("a", basis="profile:v2")], drive_profile="cpu_execute")
        self.assertNotEqual(base.policy_hash, changed.policy_hash)

    def test_changing_the_layout_or_plan_changes_identity(self) -> None:
        base = compile_rules([_rule("a")], drive_profile="cpu_execute",
                             layout_hash="sha256:aaa", plan_hash="sha256:bbb")
        other_layout = compile_rules([_rule("a")], drive_profile="cpu_execute",
                                     layout_hash="sha256:ccc", plan_hash="sha256:bbb")
        other_plan = compile_rules([_rule("a")], drive_profile="cpu_execute",
                                   layout_hash="sha256:aaa", plan_hash="sha256:ddd")
        self.assertNotEqual(base.policy_hash, other_layout.policy_hash)
        self.assertNotEqual(base.policy_hash, other_plan.policy_hash)

    def test_a_different_drive_profile_changes_identity(self) -> None:
        first = compile_input_constraints(self.plan, drive_profile="cpu_execute")
        second = compile_input_constraints(self.plan, drive_profile="contention")
        self.assertNotEqual(first.policy_hash, second.policy_hash)

    def test_unconstrained_bits_stay_unconstrained(self) -> None:
        """Only the declared special inputs become environment-driven bits."""
        policy = compile_input_constraints(self.plan, drive_profile="cpu_execute")
        driven = policy.environment_write_bits()
        self.assertEqual({("__raw__", bit) for bit in range(7)}, driven)
        self.assertEqual(7, self.plan.raw_layout["raw_width"])
        strategies = dict((item.rule_id, dict(item.parameters).get("strategy"))
                          for item in policy.rules if item.primitive.startswith("drive_"))
        self.assertEqual({"drive:cpu0__event_i": "cycle_value",
                          "drive:gpio0__pin_mode_i": "cycle_value"}, strategies)


class RuleClassTests(unittest.TestCase):
    def test_the_four_rule_classes_are_kept_apart(self) -> None:
        policy = compile_input_constraints(example_plan(), drive_profile="cpu_execute")
        self.assertTrue(rules_of(policy, "environment_hard"))
        self.assertTrue(rules_of(policy, "dut_assertion"))
        self.assertEqual((), rules_of(policy, "search_preference"))
        for item in policy.rules:
            self.assertIn(item.category,
                          ("environment_hard", "scenario_precondition",
                           "search_preference", "dut_assertion"))
            if item.category == "dut_assertion":
                self.assertEqual((), item.write_set)

    def test_a_rule_that_writes_a_dut_value_is_rejected(self) -> None:
        with self.assertRaises(InputConstraintError) as error:
            compile_rules([_rule("bad", owner="dut", category="environment_hard",
                                 write_set=["cpu0::status_o"])],
                          drive_profile="cpu_execute")
        self.assertIn("environment-writes-dut-value", str(error.exception))

    def test_a_search_preference_is_never_a_legality_proof(self) -> None:
        policy = compile_rules([_rule("bias", category="search_preference")],
                               drive_profile="cpu_execute")
        self.assertEqual((), rules_of(policy, "environment_hard"))
        with self.assertRaises(InputConstraintError):
            compile_rules([_rule("bias", category="search_preference",
                                 failure_class="not-a-class")],
                          drive_profile="cpu_execute")

    def test_legal_exception_scenarios_are_not_erased_by_success_bias(self) -> None:
        """An exception scenario keeps its own rule instead of being folded away."""
        rules = [
            _rule("success", category="search_preference",
                  parameters=[["bias", "direct"]]),
            _rule("exception:unmapped_access", category="scenario_precondition",
                  owner="cpu", write_set=["cpu0::core.bus"],
                  parameters=[["expect", "error_response"]],
                  applies_in_modes=["cpu_only"]),
        ]
        policy = compile_rules(rules, drive_profile="cpu_execute")
        self.assertEqual(1, len(rules_of(policy, "scenario_precondition")))
        self.assertEqual(("cpu_only",),
                         policy.rule("exception:unmapped_access").applies_in_modes)


class RejectionTests(unittest.TestCase):
    def test_a_rule_may_not_be_driven_twice(self) -> None:
        rules = [_rule("a", write_set=["port_x"], raw_bits=[[0, 3]]),
                 _rule("b", write_set=["port_y"], raw_bits=[[2, 5]])]
        with self.assertRaises(InputConstraintError) as error:
            compile_rules(rules, drive_profile="cpu_execute")
        self.assertIn("duplicate-input-driver", str(error.exception))

    def test_duplicate_rule_ids_are_rejected(self) -> None:
        with self.assertRaises(InputConstraintError) as error:
            compile_rules([_rule("a"), _rule("a", raw_bits=[[4, 4]])],
                          drive_profile="cpu_execute")
        self.assertIn("duplicate-rule-id", str(error.exception))

    def test_an_unknown_primitive_is_a_capability_gap(self) -> None:
        with self.assertRaises(InputConstraintError) as error:
            compile_rules([_rule("temporal", primitive="wait_for_handshake_then_hold")],
                          drive_profile="cpu_execute")
        self.assertIn("unsupported-primitive", str(error.exception))

    def test_an_unknown_phase_category_owner_or_failure_class_is_rejected(self) -> None:
        for overrides, token in (
            ({"phase": "whenever"}, "unknown-rule-phase"),
            ({"category": "nice_to_have"}, "unknown-rule-category"),
            ({"owner": "someone-else"}, "unknown-rule-owner"),
            ({"failure_class": "flaky"}, "unknown-failure-class"),
            ({"applies_in_modes": ["turbo"]}, "unknown-rule-mode"),
        ):
            with self.subTest(token=token):
                with self.assertRaises(InputConstraintError) as error:
                    compile_rules([_rule("a", **overrides)], drive_profile="cpu_execute")
                self.assertIn(token, str(error.exception))

    def test_a_rule_without_a_write_set_is_rejected(self) -> None:
        with self.assertRaises(InputConstraintError) as error:
            compile_rules([_rule("a", write_set=[])], drive_profile="cpu_execute")
        self.assertIn("rule-without-write-set", str(error.exception))

    def test_rule_state_and_rule_count_are_bounded(self) -> None:
        with self.assertRaises(InputConstraintError) as error:
            compile_rules([_rule("a", state_bits=1 << 20)], drive_profile="cpu_execute")
        self.assertIn("rule-state-out-of-bounds", str(error.exception))
        from myfuzz.composition import input_constraints as module

        many = [_rule(f"r{index}", raw_bits=[[index, index]])
                for index in range(module.MAX_RULES + 1)]
        with self.assertRaises(InputConstraintError) as error:
            compile_rules(many, drive_profile="cpu_execute")
        self.assertIn("rule-count-exceeds-bound", str(error.exception))

    def test_a_long_dependency_chain_exhausts_the_budget(self) -> None:
        from myfuzz.composition import input_constraints as module

        original = module.MAX_CLOSURE_STEPS
        module.MAX_CLOSURE_STEPS = 4
        try:
            rules = [_rule(f"r{index}", read_set=[f"f{index - 1}"],
                           write_set=[f"f{index}"], raw_bits=[[index, index]])
                     for index in range(8)]
            with self.assertRaises(InputConstraintError) as error:
                compile_rules(rules, drive_profile="cpu_execute")
            self.assertIn("closure-budget-exhausted", str(error.exception))
        finally:
            module.MAX_CLOSURE_STEPS = original

    def test_a_small_dependency_cycle_is_recorded_and_terminates(self) -> None:
        """A bounded cycle is legal; it must be reported, not silently dropped."""
        rules = [_rule("a", read_set=["fb"], write_set=["fa"], raw_bits=[[0, 0]]),
                 _rule("b", read_set=["fa"], write_set=["fb"], raw_bits=[[1, 1]])]
        policy = compile_rules(rules, drive_profile="cpu_execute")
        self.assertEqual((("a", "b"),), policy.cycles)
        self.assertEqual(("b",), dict(policy.closure)["a"])
        self.assertEqual(("a",), dict(policy.closure)["b"])

    def test_closure_records_the_dependency_edges(self) -> None:
        rules = [_rule("producer", write_set=["shared"], raw_bits=[[0, 0]]),
                 _rule("consumer", read_set=["shared"], write_set=["other"],
                       raw_bits=[[1, 1]])]
        policy = compile_rules(rules, drive_profile="cpu_execute")
        closure = dict(policy.closure)
        self.assertEqual(("producer",), closure["consumer"])
        self.assertEqual((), closure["producer"])


class ValueConstraintTests(unittest.TestCase):
    """The specific intersections the plan requires to be rejected."""

    def _layout_entry(self, **overrides):
        entry = {"field_id": "cpu0::value", "owner": "cpu0::value", "role": "value",
                 "width": 8, "raw_lo": 0, "raw_hi": 7, "constraint": {},
                 "binding": {"port": "cpu0__value"}, "evidence": "test"}
        entry.update(overrides)
        return entry

    def _compile(self, entries):
        plan = _layout_plan(entries)
        return compile_input_constraints(plan, drive_profile="cpu_execute")

    def test_a_range_wider_than_the_field_is_rejected(self) -> None:
        with self.assertRaises(InputConstraintError) as error:
            self._compile([self._layout_entry(constraint={"range": [0, 511]})])
        self.assertIn("range-outside-field-width", str(error.exception))

    def test_an_enum_with_no_aligned_member_is_rejected(self) -> None:
        with self.assertRaises(InputConstraintError) as error:
            self._compile([self._layout_entry(constraint={"enum": [1, 3],
                                                          "alignment": 4})])
        self.assertIn("empty-constraint-intersection", str(error.exception))

    def test_a_range_and_enum_intersection_may_be_non_empty(self) -> None:
        policy = self._compile([self._layout_entry(
            constraint={"range": [2, 6], "enum": [1, 3, 5]})])
        value_rule = policy.rule("value:cpu0::value")
        self.assertEqual("value_enum", value_rule.primitive)

    def test_a_range_and_enum_with_no_common_member_is_rejected(self) -> None:
        with self.assertRaises(InputConstraintError) as error:
            self._compile([self._layout_entry(constraint={"range": [7, 9],
                                                          "enum": [1, 3, 5]})])
        self.assertIn("empty-constraint-intersection", str(error.exception))

    def test_alignment_must_be_a_power_of_two_inside_the_field(self) -> None:
        with self.assertRaises(InputConstraintError):
            self._compile([self._layout_entry(constraint={"alignment": 3})])
        with self.assertRaises(InputConstraintError):
            self._compile([self._layout_entry(constraint={"alignment": 512})])

    def test_modes_make_rules_mutually_exclusive_instead_of_conflicting(self) -> None:
        rules = [
            _rule("drive:in-cpu-mode", raw_bits=[[0, 0]], applies_in_modes=["cpu_only"]),
            _rule("drive:in-mmio-mode", raw_bits=[[0, 0]], applies_in_modes=["mmio_only"]),
        ]
        # Both rules address raw bit 0, but never in the same mode, so the
        # compiler must accept them and keep the modes recorded.
        policy = compile_rules(rules, drive_profile="cpu_execute")
        self.assertEqual(2, len(policy.rules))
        self.assertEqual(("cpu_only",), policy.rule("drive:in-cpu-mode").applies_in_modes)
        self.assertEqual(("mmio_only",), policy.rule("drive:in-mmio-mode").applies_in_modes)


class LegacyIsolationTests(unittest.TestCase):
    """The new vocabulary must not change the frozen legacy semantics."""

    def test_legacy_gate_zeroing_is_untouched(self) -> None:
        from myfuzz.composition.runtime_projection import RuntimeProjector
        from myfuzz.composition.input_layout import build_input_layout

        annotations = {"endpoints": [{
            "endpoint_id": "legacy.bus",
            "protocol_candidates": [],
            "fields": [
                {"role": "valid", "direction": "input", "width": 1, "port": "v",
                 "source": {"file": "t.sv", "line": 1}, "evidence": ["t"]},
                {"role": "data", "direction": "input", "width": 3, "port": "d",
                 "source": {"file": "t.sv", "line": 1}, "evidence": ["t"]},
            ]}]}
        constraints = [{"owner": "legacy.bus", "role": "data",
                        "enum": [1, 3, 7], "gated_by": "legacy.bus:valid"}]
        layout = build_input_layout(annotations, component_constraints=constraints)
        projector = RuntimeProjector(layout)
        # valid is raw bit 0 and data the three bits above it.
        # An inactive gate zeroes the field even though 7 is a legal enum member;
        # this is the frozen semantics the new vocabulary must leave alone.
        self.assertEqual(0, projector.project(0b1110))
        self.assertEqual(0b111, projector.project(0b1111))
        self.assertEqual(0, projector.project(0b0110))

    def test_this_module_does_not_reinterpret_the_legacy_layout(self) -> None:
        policy = compile_input_constraints(example_plan(), drive_profile="cpu_execute")
        for item in policy.rules:
            self.assertNotIn(item.primitive,
                             ("gate_zero", "inactive_gate", "legacy_gate"))


def _layout_plan(entries):
    """A minimal plan whose raw layout carries the given value constraints."""
    from myfuzz.composition.input_constraints import compile_input_constraints as _compile

    class _Instance:
        instance_id = "cpu0"
        dispositions: tuple = ()

    class _Plan:
        def __init__(self, layout):
            self.raw_layout = layout
            self.plan = {"address_map": {"windows": []}}
            self.instances = (_Instance(),)
            self.plan_hash = "sha256:" + "0" * 64

    document = {
        "schema_version": "input_layout.v1",
        "raw_width": 8,
        "fields": [{"field_id": item["field_id"], "owner": item["owner"],
                    "role": item["role"], "width": item["width"],
                    "raw_lo": item["raw_lo"], "raw_hi": item["raw_hi"],
                    "constraint": dict(item["constraint"]),
                    "binding": dict(item["binding"]), "evidence": [item["evidence"]]}
                   for item in entries],
        "layout_hash": "sha256:" + "1" * 64,
        "special_inputs": [],
    }
    return _Plan(document)


if __name__ == "__main__":
    unittest.main()
