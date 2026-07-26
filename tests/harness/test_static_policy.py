from __future__ import annotations

import copy
from dataclasses import replace
import unittest
from unittest.mock import patch

from myfuzz.harness.abi import RawBitAbi, RawBitUse, RawDestination, content_hash
from myfuzz.harness.static_policy import (
    StaticAction,
    StaticPolicyParameters,
    StaticPolicyPlan,
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
            {"action_id": 60, "destination_id": 10, "selector_bits": [4, 5]}
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
            (("direct_ratio", 2), ("selector_bits", (4, 5))),
        )

    def test_every_transformed_destination_retains_a_direct_branch(self) -> None:
        plan = compile_static_policy(self.abi, self.declarations, BALANCED_POLICY)
        transformed = {action.destination_id for action in plan.actions if action.kind != "entropy_mix"}
        direct_branches = {
            action.destination_id for action in plan.actions if action.kind == "entropy_mix"
        }

        self.assertTrue(transformed <= direct_branches)
        for destination_id in transformed:
            transform_ids = [
                action.action_id
                for action in plan.actions
                if action.destination_id == destination_id and action.kind != "entropy_mix"
            ]
            direct_ids = [
                action.action_id
                for action in plan.actions
                if action.destination_id == destination_id and action.kind == "entropy_mix"
            ]
            self.assertGreater(max(direct_ids), max(transform_ids))

    def test_generated_direct_selector_has_enough_independent_entropy(self) -> None:
        plan = compile_static_policy(
            self.abi,
            {
                "dependency_gate": [
                    {"action_id": 1, "destination_id": 30, "gate_bit": 0},
                ],
            },
            StaticPolicyParameters(4, 4, 2, "none"),
        )

        direct = next(action for action in plan.actions if action.kind == "entropy_mix")
        self.assertEqual(dict(direct.parameters)["selector_bits"], (1, 2))

        forged = replace(
            direct,
            parameters=(("direct_ratio", 4), ("selector_bits", (0,))),
        )
        actions = tuple(forged if action is direct else action for action in plan.actions)
        with self.assertRaisesRegex(ValueError, "too few bits for direct_ratio"):
            StaticPolicyPlan(plan.raw_abi, plan.parameters, actions, plan.plan_hash)

    def test_direct_selector_rejects_correlated_destination_entropy(self) -> None:
        minimal = RawBitAbi(
            raw_width=1,
            destinations=(RawDestination(1, 100, 1, 1),),
            uses=(RawBitUse(0, 0, 1, 0, "direct", "direct"),),
            abi_hash="not-trusted",
        )
        parameters = StaticPolicyParameters(2, 4, 2, "none")
        declarations = {
            "mask_align": [
                {"action_id": 1, "destination_id": 1, "alignment": 2},
            ],
        }

        with self.assertRaisesRegex(ValueError, "independent entropy"):
            compile_static_policy(minimal, declarations, parameters)

        explicit = {
            **declarations,
            "entropy_mix": [
                {"action_id": 2, "destination_id": 1, "selector_bits": [0]},
            ],
        }
        with self.assertRaisesRegex(ValueError, "independent entropy"):
            compile_static_policy(minimal, explicit, parameters)

        safe_abi = raw_abi()
        safe = compile_static_policy(
            safe_abi,
            {
                "mask_align": [
                    {"action_id": 1, "destination_id": 10, "alignment": 2},
                ],
                "entropy_mix": [
                    {"action_id": 2, "destination_id": 10, "selector_bits": [4]},
                ],
            },
            parameters,
        )
        direct = next(action for action in safe.actions if action.kind == "entropy_mix")
        forged = replace(
            direct,
            parameters=(("direct_ratio", 2), ("selector_bits", (0,))),
        )
        actions = tuple(forged if action is direct else action for action in safe.actions)
        with self.assertRaisesRegex(ValueError, "independent entropy"):
            StaticPolicyPlan(safe.raw_abi, safe.parameters, actions, safe.plan_hash)

    def test_priority_exclusion_requires_lower_stable_id_peers(self) -> None:
        with self.assertRaisesRegex(ValueError, "priority peers must have lower stable IDs"):
            compile_static_policy(
                self.abi,
                {
                    "mutual_exclusion": [
                        {"action_id": 1, "destination_id": 30, "peer_ids": [40]},
                    ],
                },
                StaticPolicyParameters(2, 4, 2, "priority"),
            )

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

        self.assertEqual(plan.raw_abi.destinations, fragmented.destinations)
        self.assertEqual(plan.raw_abi.uses, fragmented.uses)
        self.assertNotEqual(plan.raw_abi.abi_hash, fragmented.abi_hash)
        self.assertEqual(plan.actions, ())

    def test_legal_set_validates_32_bit_values_without_range_materialization(self) -> None:
        wide = RawBitAbi(
            raw_width=32,
            destinations=(RawDestination(70, 100, 70, 32),),
            uses=(RawBitUse(0, 31, 70, 0, "direct", "direct"),),
            abi_hash="not-trusted",
        )
        semantic = {
            "legal_set": [{"action_id": 1, "destination_id": 70, "values": [0, (1 << 32) - 1]}],
            "entropy_mix": [{"action_id": 2, "destination_id": 70, "selector_bits": [0]}],
        }

        with patch("builtins.range", side_effect=AssertionError("range materialization")):
            plan = compile_static_policy(
                wide,
                semantic,
                StaticPolicyParameters(1, 4, 2, "one_hot"),
            )

        action = next(item for item in plan.actions if item.kind == "legal_set")
        self.assertEqual(dict(action.parameters)["values"], (0, (1 << 32) - 1))

    def test_transforms_reassemble_fragmented_destination_slices(self) -> None:
        fragmented = RawBitAbi(
            raw_width=4,
            destinations=(RawDestination(7, 100, 7, 4),),
            uses=(
                RawBitUse(0, 1, 7, 2, "direct", "direct"),
                RawBitUse(2, 3, 7, 0, "direct", "direct"),
            ),
            abi_hash="not-trusted",
        )
        plan = compile_static_policy(
            fragmented,
            {"mask_align": [{"action_id": 1, "destination_id": 7, "alignment": 2}]},
            StaticPolicyParameters(1, 4, 2, "one_hot"),
        )

        action = next(item for item in plan.actions if item.kind == "mask_align")
        self.assertEqual((action.raw_lo, action.raw_hi), (0, 3))
        self.assertEqual(dict(action.parameters)["fragments"], (0, 1, 2, 2, 3, 0))
        self.assertEqual(plan.raw_abi.uses, tuple(sorted(fragmented.uses, key=lambda item: item.raw_lo)))

    def test_equivalent_abi_order_and_untrusted_digest_produce_one_canonical_plan(self) -> None:
        first = RawBitAbi(
            raw_width=5,
            destinations=(RawDestination(20, 100, 20, 4), RawDestination(10, 100, 10, 1)),
            uses=(RawBitUse(1, 4, 20, 0, "direct", "direct"), RawBitUse(0, 0, 10, 0, "direct", "direct")),
            abi_hash="first-forgery",
        )
        second = RawBitAbi(
            raw_width=5,
            destinations=tuple(reversed(first.destinations)),
            uses=tuple(reversed(first.uses)),
            abi_hash="second-forgery",
        )

        left = compile_static_policy(first, {}, BALANCED_POLICY)
        right = compile_static_policy(second, {}, BALANCED_POLICY)

        self.assertEqual(left, right)
        self.assertEqual([item.destination_id for item in left.raw_abi.destinations], [10, 20])
        self.assertEqual([item.raw_lo for item in left.raw_abi.uses], [0, 1])
        self.assertNotIn(left.raw_abi.abi_hash, {"first-forgery", "second-forgery"})

    def test_unrelated_maximum_action_id_does_not_block_generated_direct_action(self) -> None:
        plan = compile_static_policy(
            self.abi,
            {
                "mask_align": [{"action_id": 5, "destination_id": 10, "alignment": 2}],
                "entropy_mix": [
                    {
                        "action_id": (1 << 31) - 1,
                        "destination_id": 20,
                        "selector_bits": [4],
                    }
                ],
            },
            BALANCED_POLICY,
        )

        generated = next(
            action
            for action in plan.actions
            if action.kind == "entropy_mix" and action.destination_id == 10
        )
        self.assertEqual(generated.action_id, 6)

    def test_public_plan_rejects_direct_branch_before_destination_transform(self) -> None:
        plan = compile_static_policy(self.abi, self.declarations, BALANCED_POLICY)
        direct = next(
            action
            for action in plan.actions
            if action.kind == "entropy_mix" and action.destination_id == 10
        )
        forged = replace(direct, action_id=19)
        actions = tuple(
            sorted(
                (forged if action is direct else action for action in plan.actions),
                key=lambda action: action.action_id,
            )
        )

        with self.assertRaisesRegex(ValueError, "direct branch must follow"):
            StaticPolicyPlan(plan.raw_abi, plan.parameters, actions, plan.plan_hash)

    def test_public_constructors_reject_forged_action_and_plan_invariants(self) -> None:
        with self.assertRaisesRegex(ValueError, "must declare exactly"):
            StaticAction(1, "mask_align", 10, 0, 3, (("mask", 12),))

        plan = compile_static_policy(self.abi, self.declarations, BALANCED_POLICY)
        first = plan.actions[0]
        with self.assertRaisesRegex(ValueError, "raw range"):
            StaticPolicyPlan(
                plan.raw_abi,
                plan.parameters,
                (replace(first, raw_hi=first.raw_hi - 1), *plan.actions[1:]),
                plan.plan_hash,
            )
        with self.assertRaisesRegex(ValueError, "direct branch"):
            StaticPolicyPlan(
                plan.raw_abi,
                plan.parameters,
                tuple(item for item in plan.actions if item.kind != "entropy_mix"),
                plan.plan_hash,
            )
        with self.assertRaisesRegex(ValueError, "content hash"):
            StaticPolicyPlan(plan.raw_abi, plan.parameters, plan.actions, "0" * 64)

    def test_public_plan_rejects_legal_set_strength_that_differs_from_policy(self) -> None:
        plan = compile_static_policy(self.abi, self.declarations, BALANCED_POLICY)
        legal_set = next(action for action in plan.actions if action.kind == "legal_set")
        forged = replace(
            legal_set,
            parameters=(("strength", 1), ("values", dict(legal_set.parameters)["values"])),
        )
        actions = tuple(forged if action is legal_set else action for action in plan.actions)

        with self.assertRaisesRegex(ValueError, "legal_set action strength does not match the policy"):
            StaticPolicyPlan(plan.raw_abi, plan.parameters, actions, plan.plan_hash)

    def test_canonical_abi_rejects_invalid_records_before_hashing(self) -> None:
        valid_destination = RawDestination(1, 100, 1, 1)
        invalid_abis = {
            "display component": RawBitAbi(
                1,
                (RawDestination(1, "display-name", 1, 1),),
                (RawBitUse(0, 0, 1, 0, "direct", "direct"),),
                "not-trusted",
            ),
            "overlapping destination slices": RawBitAbi(
                2,
                (RawDestination(1, 100, 1, 2),),
                (
                    RawBitUse(0, 0, 1, 0, "direct", "direct"),
                    RawBitUse(1, 1, 1, 0, "direct", "direct"),
                ),
                "not-trusted",
            ),
            "non-semantic action": RawBitAbi(
                1,
                (valid_destination,),
                (RawBitUse(0, 0, 1, 0, "target-label", "direct"),),
                "not-trusted",
            ),
            "non-semantic category": RawBitAbi(
                1,
                (valid_destination,),
                (RawBitUse(0, 0, 1, 0, "direct", "target-label"),),
                "not-trusted",
            ),
        }

        for label, invalid_abi in invalid_abis.items():
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "raw ABI"):
                compile_static_policy(invalid_abi, {}, BALANCED_POLICY)

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
            StaticAction(
                1,
                "legal_set",
                20,
                4,
                6,
                (("strength", 2), ("values", (-1,))),
            )


if __name__ == "__main__":
    unittest.main()
