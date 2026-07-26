from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path

from myfuzz.experiments.static_portfolio import (
    PORTFOLIO,
    freeze_policy,
    promote,
    screen,
)


def pair(
    *,
    policy_id: str = "policy-1",
    target_id: str = "target-a",
    coverage_ratio: float = 1.0,
    throughput_ratio: float = 1.0,
    return_code: int = 0,
) -> dict[str, object]:
    return {
        "policy_id": policy_id,
        "plan_hash": "sha256:" + policy_id[-1] * 64,
        "parameters": {
            "direct_ratio": 2,
            "event_rarity": 4,
            "legal_set_strength": 2,
            "mutual_exclusion": "one_hot",
        },
        "target_id": target_id,
        "baseline": {
            "covered": 100.0,
            "tests_per_second": 100.0,
            "return_code": 0,
        },
        "candidate": {
            "covered": 100.0 * coverage_ratio,
            "tests_per_second": 100.0 * throughput_ratio,
            "return_code": return_code,
        },
    }


def abnormal_pair() -> dict[str, object]:
    return pair(return_code=1)


class StaticPortfolioTest(unittest.TestCase):
    def setUp(self) -> None:
        self.training_results = [
            pair(policy_id="policy-1", target_id="target-a", coverage_ratio=1.10, throughput_ratio=.90),
            pair(policy_id="policy-1", target_id="target-b", coverage_ratio=1.15, throughput_ratio=.95),
            pair(policy_id="policy-2", target_id="target-a", coverage_ratio=1.20),
            pair(policy_id="policy-3", target_id="target-a", coverage_ratio=1.12, throughput_ratio=.92),
            pair(policy_id="policy-3", target_id="target-b", coverage_ratio=1.12, throughput_ratio=.91),
        ]

    def test_screen_rejects_abnormal_loss_and_low_throughput(self) -> None:
        self.assertEqual(screen(abnormal_pair()).reason, "abnormal_exit")
        self.assertEqual(screen(pair(coverage_ratio=.94)).reason, "coverage_loss")
        self.assertEqual(screen(pair(throughput_ratio=.849)).reason, "throughput")

    def test_screen_accepts_exact_five_and_eighty_five_percent_boundaries(self) -> None:
        self.assertTrue(screen(pair(coverage_ratio=.95, throughput_ratio=.85)).accepted)

    def test_screen_fails_closed_for_missing_nonfinite_and_zero_denominator_metrics(self) -> None:
        for mutation in (
            lambda value: value["candidate"].pop("covered"),
            lambda value: value["candidate"].__setitem__("covered", math.nan),
            lambda value: value["baseline"].__setitem__("covered", 0.0),
            lambda value: value["baseline"].__setitem__("tests_per_second", 0.0),
        ):
            value = pair()
            mutation(value)
            with self.subTest(value=value):
                decision = screen(value)
                self.assertFalse(decision.accepted)
                self.assertEqual(decision.reason, "invalid")

    def test_promotion_requires_both_targets_and_ranks_worst_target_first(self) -> None:
        decisions = promote(self.training_results)
        self.assertEqual([item.policy_id for item in decisions], ["policy-3", "policy-1"])

    def test_promotion_accepts_exact_ten_two_and_ninety_percent_boundaries(self) -> None:
        results = [
            pair(policy_id="boundary", target_id="target-a", coverage_ratio=1.10, throughput_ratio=.90),
            pair(policy_id="boundary", target_id="target-a", coverage_ratio=1.10, throughput_ratio=.90),
            pair(policy_id="boundary", target_id="target-a", coverage_ratio=.98, throughput_ratio=.90),
            pair(policy_id="boundary", target_id="target-b", coverage_ratio=1.10, throughput_ratio=.90),
        ]
        decisions = promote(results)
        self.assertEqual([item.policy_id for item in decisions], ["boundary"])

    def test_promotion_fails_closed_for_invalid_or_below_boundary_pairs(self) -> None:
        invalid = pair(policy_id="invalid", target_id="target-a")
        invalid["baseline"]["covered"] = 0.0  # type: ignore[index]
        cases = (
            [invalid, pair(policy_id="invalid", target_id="target-b", coverage_ratio=1.20)],
            [
                pair(policy_id="low-improvement", target_id="target-a", coverage_ratio=1.099),
                pair(policy_id="low-improvement", target_id="target-b", coverage_ratio=1.20),
            ],
            [
                pair(policy_id="coverage-regression", target_id="target-a", coverage_ratio=.979),
                pair(policy_id="coverage-regression", target_id="target-b", coverage_ratio=1.20),
            ],
            [
                pair(policy_id="throughput", target_id="target-a", coverage_ratio=1.20, throughput_ratio=.899),
                pair(policy_id="throughput", target_id="target-b", coverage_ratio=1.20, throughput_ratio=.90),
            ],
        )
        for results in cases:
            with self.subTest(results=results):
                self.assertEqual(promote(results), ())

    def test_promotion_does_not_ignore_an_unidentifiable_malformed_pair(self) -> None:
        results = [
            pair(policy_id="valid", target_id="target-a", coverage_ratio=1.20),
            pair(policy_id="valid", target_id="target-b", coverage_ratio=1.20),
            {"baseline": {}},
        ]
        self.assertEqual(promote(results), ())

    def test_global_portfolio_is_deterministic_and_contains_only_generic_parameters(self) -> None:
        self.assertEqual(len(PORTFOLIO), 54)
        self.assertEqual(len(set(PORTFOLIO)), 54)
        self.assertEqual((1, 2, 1, "none"), self._parameter_values(PORTFOLIO[0]))
        self.assertEqual((4, 8, 2, "priority"), self._parameter_values(PORTFOLIO[-1]))

    def test_freeze_publishes_canonical_immutable_evidence(self) -> None:
        decision = promote(self.training_results)[0]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "frozen.json"
            document = freeze_policy(decision, destination)

            self.assertEqual(document, json.loads(destination.read_text(encoding="utf-8")))
            self.assertEqual("static-policy-freeze.v1", document["schema_version"])
            self.assertEqual(decision.policy_id, document["policy_id"])
            self.assertEqual(decision.plan_hash, document["plan_hash"])
            self.assertEqual(decision.training_evidence_hash, document["training_evidence_hash"])
            with self.assertRaises(FileExistsError):
                freeze_policy(decision, destination)

    @staticmethod
    def _parameter_values(parameters: object) -> tuple[object, object, object, object]:
        return (
            parameters.direct_ratio,  # type: ignore[attr-defined]
            parameters.event_rarity,  # type: ignore[attr-defined]
            parameters.legal_set_strength,  # type: ignore[attr-defined]
            parameters.mutual_exclusion,  # type: ignore[attr-defined]
        )


if __name__ == "__main__":
    unittest.main()
