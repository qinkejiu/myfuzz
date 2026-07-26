from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from myfuzz.experiments import static_portfolio as portfolio_module
from myfuzz.experiments.static_portfolio import (
    PORTFOLIO,
    compile_portfolio,
    freeze_policy,
    promote,
    screen,
)
from myfuzz.harness.abi import RawBitAbi, RawBitUse, RawDestination, content_hash
from myfuzz.harness.static_policy import compile_static_policy


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


def report_pair(**kwargs: object) -> dict[str, object]:
    value = pair(**kwargs)
    for summary in (value["baseline"], value["candidate"]):
        summary["runtime"] = {
            "tests_per_second": summary.pop("tests_per_second"),
            "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
        }
        summary.pop("return_code")
    return value


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

    def test_nested_report_failure_status_rejects_screen_and_promotion(self) -> None:
        abnormal = report_pair(policy_id="runtime", target_id="target-a", coverage_ratio=1.20)
        abnormal["candidate"]["runtime"]["failure_reasons"]["dut_crash"] = 1  # type: ignore[index]
        normal = report_pair(policy_id="runtime", target_id="target-b", coverage_ratio=1.20)

        self.assertEqual(screen(abnormal).reason, "abnormal_exit")
        self.assertEqual(promote([abnormal, normal]), ())

    def test_status_representations_are_consistent_and_malformed_values_fail_closed(self) -> None:
        duplicate = report_pair()
        duplicate["candidate"]["failure_reasons"] = {}  # type: ignore[index]
        malformed = report_pair()
        malformed["candidate"]["runtime"]["failure_reasons"] = []  # type: ignore[index]
        null_runtime = pair()
        null_runtime["candidate"]["runtime"] = None  # type: ignore[index]
        for value in (duplicate, malformed, null_runtime):
            with self.subTest(value=value):
                self.assertEqual(screen(value).reason, "invalid")

    def test_json_shaped_parameter_type_errors_fail_closed(self) -> None:
        malformed = pair(policy_id="bad-parameters", target_id="target-a")
        malformed["parameters"]["mutual_exclusion"] = []  # type: ignore[index]
        normal = pair(policy_id="bad-parameters", target_id="target-b", coverage_ratio=1.20)

        self.assertEqual(screen(malformed).reason, "invalid")
        self.assertEqual(promote([malformed, normal]), ())

    def test_duplicate_flat_and_runtime_metrics_fail_closed_for_screen_and_promotion(self) -> None:
        mixed = pair(policy_id="mixed-metrics", target_id="target-a", coverage_ratio=1.20)
        mixed["candidate"]["runtime"] = {"tests_per_second": 10.0}  # type: ignore[index]
        equal_duplicate = pair(policy_id="equal-metrics", target_id="target-a", coverage_ratio=1.20)
        equal_duplicate["candidate"]["runtime"] = {"tests_per_second": 100.0}  # type: ignore[index]
        normal = pair(policy_id="mixed-metrics", target_id="target-b", coverage_ratio=1.20)
        equal_normal = pair(policy_id="equal-metrics", target_id="target-b", coverage_ratio=1.20)

        self.assertEqual(screen(mixed).reason, "invalid")
        self.assertEqual(screen(equal_duplicate).reason, "invalid")
        self.assertEqual(promote([mixed, normal]), ())
        self.assertEqual(promote([equal_duplicate, equal_normal]), ())

    def test_missing_exit_evidence_fails_closed_for_screen_and_promotion(self) -> None:
        missing = pair(policy_id="missing-status", target_id="target-a", coverage_ratio=1.20)
        missing["baseline"].pop("return_code")  # type: ignore[index]
        missing["candidate"].pop("return_code")  # type: ignore[index]
        partial = pair(policy_id="partial-status", target_id="target-a", coverage_ratio=1.20)
        partial["candidate"].pop("return_code")  # type: ignore[index]
        normal = pair(policy_id="missing-status", target_id="target-b", coverage_ratio=1.20)
        partial_normal = pair(policy_id="partial-status", target_id="target-b", coverage_ratio=1.20)

        self.assertEqual(screen(missing).reason, "invalid")
        self.assertEqual(screen(partial).reason, "invalid")
        self.assertEqual(promote([missing, normal]), ())
        self.assertEqual(promote([partial, partial_normal]), ())

    def test_incomplete_counter_only_exit_evidence_fails_closed(self) -> None:
        counter_maps = {
            "empty": {},
            "dut-crash-only": {"dut_crash": 0},
            "resource-terminated-only": {"resource_terminated": 0},
            "unrelated-only": {"timeout": 0},
        }
        for label, counter_map in counter_maps.items():
            with self.subTest(label=label):
                invalid = report_pair(policy_id=label, target_id="target-a", coverage_ratio=1.20)
                invalid["candidate"]["runtime"]["failure_reasons"] = counter_map  # type: ignore[index]
                normal = report_pair(policy_id=label, target_id="target-b", coverage_ratio=1.20)

                self.assertEqual(screen(invalid).reason, "invalid")
                self.assertEqual(promote([invalid, normal]), ())

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

    def test_ranking_uses_the_mean_of_target_median_improvements(self) -> None:
        results = [
            *[
                pair(policy_id="target-median", target_id="target-a", coverage_ratio=1.10)
                for _ in range(9)
            ],
            pair(policy_id="target-median", target_id="target-b", coverage_ratio=1.50),
            pair(policy_id="raw-pair", target_id="target-a", coverage_ratio=1.10),
            *[
                pair(policy_id="raw-pair", target_id="target-b", coverage_ratio=1.30)
                for _ in range(9)
            ],
        ]

        self.assertEqual(
            [decision.policy_id for decision in promote(results)],
            ["target-median", "raw-pair"],
        )

    def test_ranking_breaks_ties_by_mean_throughput_then_stable_policy_id(self) -> None:
        results = [
            pair(policy_id="mean-high", target_id="target-a", coverage_ratio=1.11),
            pair(policy_id="mean-high", target_id="target-b", coverage_ratio=1.20),
            pair(policy_id="mean-low", target_id="target-a", coverage_ratio=1.11),
            pair(policy_id="mean-low", target_id="target-b", coverage_ratio=1.18),
            pair(policy_id="throughput-high", target_id="target-a", coverage_ratio=1.10, throughput_ratio=.95),
            pair(policy_id="throughput-high", target_id="target-b", coverage_ratio=1.10, throughput_ratio=.95),
            pair(policy_id="throughput-low", target_id="target-a", coverage_ratio=1.10, throughput_ratio=.90),
            pair(policy_id="throughput-low", target_id="target-b", coverage_ratio=1.10, throughput_ratio=.90),
            pair(policy_id="policy-a", target_id="target-a", coverage_ratio=1.10, throughput_ratio=.90),
            pair(policy_id="policy-a", target_id="target-b", coverage_ratio=1.10, throughput_ratio=.90),
            pair(policy_id="policy-b", target_id="target-a", coverage_ratio=1.10, throughput_ratio=.90),
            pair(policy_id="policy-b", target_id="target-b", coverage_ratio=1.10, throughput_ratio=.90),
        ]

        self.assertEqual(
            [decision.policy_id for decision in promote(results)],
            [
                "mean-high",
                "mean-low",
                "throughput-high",
                "policy-a",
                "policy-b",
                "throughput-low",
            ],
        )

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

    def test_compile_portfolio_deduplicates_real_compiler_plan_hashes(self) -> None:
        destination = RawDestination(1, 1, 1, 1)
        raw_use = RawBitUse(0, 0, 1, 0, "direct", "direct")
        raw_abi = RawBitAbi(
            1,
            (destination,),
            (raw_use,),
            content_hash(
                {
                    "raw_width": 1,
                    "destinations": [{"destination_id": 1, "component_id": 1, "port_id": 1, "width": 1}],
                    "uses": [{"raw_lo": 0, "raw_hi": 0, "destination_id": 1, "destination_lo": 0, "action": "direct", "category": "direct"}],
                }
            ),
        )
        with patch.object(portfolio_module, "PORTFOLIO", (PORTFOLIO[0], PORTFOLIO[0])):
            plans = compile_portfolio(raw_abi, {})

        self.assertEqual(1, len(plans))
        self.assertEqual(plans[0], compile_static_policy(raw_abi, {}, PORTFOLIO[0]))

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
