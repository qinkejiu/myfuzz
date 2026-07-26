from __future__ import annotations

import copy
import unittest

from myfuzz.harness.abi import RawBitAbi, RawBitUse, RawDestination, content_hash
from myfuzz.harness.static_policy import (
    StaticAction,
    StaticPolicyParameters,
    compile_static_policy,
)


BALANCED_POLICY = StaticPolicyParameters(2, 4, 2, "one_hot")


def raw_abi() -> RawBitAbi:
    destinations = (
        RawDestination(10, 100, 10, 4),
        RawDestination(20, 100, 20, 3),
        RawDestination(30, 100, 30, 1),
        RawDestination(40, 100, 40, 1),
        RawDestination(50, 100, 50, 1),
    )
    uses = (
        RawBitUse(0, 3, 10, 0, "direct", "direct"),
        RawBitUse(4, 6, 20, 0, "direct", "direct"),
        RawBitUse(7, 7, 30, 0, "direct", "direct"),
        RawBitUse(8, 8, 40, 0, "direct", "direct"),
        RawBitUse(9, 9, 50, 0, "direct", "direct"),
    )
    document = {
        "raw_width": 10,
        "destinations": [
            {
                "destination_id": item.destination_id,
                "component_id": item.component_id,
                "port_id": item.port_id,
                "width": item.width,
            }
            for item in destinations
        ],
        "uses": [
            {
                "raw_lo": item.raw_lo,
                "raw_hi": item.raw_hi,
                "destination_id": item.destination_id,
                "destination_lo": item.destination_lo,
                "action": item.action,
                "category": item.category,
            }
            for item in uses
        ],
    }
    return RawBitAbi(10, destinations, uses, content_hash(document))


def declarations() -> dict[str, object]:
    return {
        "diagnostics": {"display": "original declaration labels"},
        "mask_align": [{"action_id": 20, "destination_id": 10, "alignment": 4}],
        "legal_set": [{"action_id": 10, "destination_id": 20, "values": [5, 1, 3]}],
        "dependency_gate": [{"action_id": 30, "destination_id": 30, "gate_bit": 0}],
        "mutual_exclusion": [
            {"action_id": 40, "destination_id": 40, "peer_ids": [30]}
        ],
        "rarity_fold": [
            {"action_id": 50, "destination_id": 50, "fold_bits": [8, 9]}
        ],
        "entropy_mix": [
            {"action_id": 60, "destination_id": 10, "selector_bits": [0, 1]}
        ],
    }


def rename_diagnostics(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    result["diagnostics"] = {"display": "renamed declaration labels"}
    return result


class StaticPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.abi = raw_abi()
        self.declarations = declarations()

    def test_plan_is_deterministic_name_invariant_and_preserves_geometry(self) -> None:
        first = compile_static_policy(self.abi, self.declarations, BALANCED_POLICY)
        reordered = dict(reversed(tuple(self.declarations.items())))
        reordered["legal_set"] = list(reversed(self.declarations["legal_set"]))  # type: ignore[arg-type]
        renamed = compile_static_policy(self.abi, rename_diagnostics(self.declarations), BALANCED_POLICY)

        self.assertEqual(first, compile_static_policy(self.abi, reordered, BALANCED_POLICY))
        self.assertEqual(first, renamed)
        self.assertEqual(first.raw_abi.raw_width, self.abi.raw_width)
        self.assertEqual(first.raw_abi.uses, self.abi.uses)
        self.assertEqual(first.actions, tuple(sorted(first.actions, key=lambda action: action.action_id)))

    def test_policy_rejects_forbidden_metadata_and_output_dependencies(self) -> None:
        for key in ("module_name", "target_id", "coverage_bits", "dut_output"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                compile_static_policy(self.abi, {key: "forbidden"}, BALANCED_POLICY)

    def test_allowed_primitives_compile_to_canonical_actions(self) -> None:
        plan = compile_static_policy(self.abi, self.declarations, BALANCED_POLICY)
        by_kind = {action.kind: action for action in plan.actions if action.kind != "entropy_mix"}
        declared_entropy = next(action for action in plan.actions if action.action_id == 60)

        self.assertEqual(by_kind["mask_align"].parameters, (("alignment", 4), ("mask", 12)))
        self.assertEqual(by_kind["legal_set"].parameters, (("strength", 2), ("values", (1, 3, 5))))
        self.assertEqual(by_kind["dependency_gate"].parameters, (("gate_bit", 0),))
        self.assertEqual(
            by_kind["mutual_exclusion"].parameters,
            (("mode", "one_hot"), ("peer_ids", (30,))),
        )
        self.assertEqual(by_kind["rarity_fold"].parameters, (("fold_bits", (8, 9)), ("rarity", 4)))
        self.assertEqual(
            declared_entropy.parameters,
            (("direct_ratio", 2), ("selector_bits", (0, 1))),
        )

    def test_every_transformed_destination_retains_a_direct_branch(self) -> None:
        plan = compile_static_policy(self.abi, self.declarations, BALANCED_POLICY)
        transformed = {action.destination_id for action in plan.actions if action.kind != "entropy_mix"}
        direct_branches = {
            action.destination_id for action in plan.actions if action.kind == "entropy_mix"
        }

        self.assertTrue(transformed <= direct_branches)

    def test_direct_only_plan_preserves_fragmented_raw_abi_geometry(self) -> None:
        fragmented = RawBitAbi(
            raw_width=4,
            destinations=(RawDestination(7, 100, 7, 4),),
            uses=(
                RawBitUse(0, 1, 7, 2, "direct", "direct"),
                RawBitUse(2, 3, 7, 0, "direct", "direct"),
            ),
            abi_hash=content_hash({"fixture": "fragmented-static-policy"}),
        )

        plan = compile_static_policy(fragmented, {}, BALANCED_POLICY)

        self.assertEqual(plan.raw_abi, fragmented)
        self.assertEqual(plan.actions, ())

    def test_rejects_invalid_parameters_unknown_keys_and_non_boolean_integers(self) -> None:
        with self.assertRaisesRegex(ValueError, "direct_ratio"):
            StaticPolicyParameters(True, 4, 2, "one_hot")
        with self.assertRaisesRegex(ValueError, "unknown static declaration"):
            compile_static_policy(self.abi, {"unexpected": []}, BALANCED_POLICY)
        invalid = declarations()
        invalid["mask_align"] = [{"action_id": 20, "destination_id": 10, "alignment": True}]
        with self.assertRaisesRegex(ValueError, "alignment"):
            compile_static_policy(self.abi, invalid, BALANCED_POLICY)

        with self.assertRaisesRegex(ValueError, "static action parameter values"):
            StaticAction(1, "legal_set", 20, 4, 6, (("values", (1 << 31,)),))


if __name__ == "__main__":
    unittest.main()
