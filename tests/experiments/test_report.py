from __future__ import annotations

import copy
import hashlib
import json
import math
import unittest
from pathlib import Path

from myfuzz.contracts import ContractError, canonical_bytes
from myfuzz.experiments import ExperimentJob, plan_experiment
from myfuzz.experiments.report import ReportError, build_report


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "contracts"
CONFIGS = ROOT / "configs" / "experiments"
MIB = 1024 * 1024
_BUDGET_SCALE = {"long": 3, "short": 2, "smoke": 1}


def load_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def sha256_id(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def candidate_manifest(candidate_id: str, point_base: int) -> dict[str, object]:
    document = load_json(FIXTURES / "candidate_manifest.v1.valid.json")
    document["candidate_id"] = candidate_id
    document["composition_ir_hash"] = sha256_id(f"{candidate_id}-composition")
    document["top"]["content_hash"] = sha256_id(f"{candidate_id}-top")
    document["build_cache_key"] = sha256_id(f"{candidate_id}-build")
    document["resources"]["peak_rss_bytes"] = MIB
    document["coverage_universe"] = [
        {
            "point_id": point_base + 1,
            "stable_source_id": "cpu.shared",
            "component_id": point_base + 11,
            "component_role": "cpu",
            "source": {"file_id": point_base + 21, "line": 10, "column": 0},
        },
        {
            "point_id": point_base + 2,
            "stable_source_id": f"{candidate_id}.direct",
            "component_id": point_base + 12,
            "component_role": "uart",
            "source": {"file_id": point_base + 22, "line": 20, "column": 1},
        },
        {
            "point_id": point_base + 3,
            "stable_source_id": f"{candidate_id}.depaware",
            "component_id": point_base + 13,
            "component_role": "gpio",
            "source": {"file_id": point_base + 23, "line": 30, "column": 2},
        },
        {
            "point_id": point_base + 4,
            "stable_source_id": f"{candidate_id}.overlap",
            "component_id": point_base + 11,
            "component_role": "cpu",
            "source": {"file_id": point_base + 21, "line": 40, "column": 3},
        },
    ]
    return document


def experiment_samples(
    plan: object,
    manifests: list[dict[str, object]],
    flat_total: int,
) -> list[dict[str, object]]:
    points_by_candidate = {
        manifest["candidate_id"]: [point["point_id"] for point in manifest["coverage_universe"]]
        for manifest in manifests
    }
    samples: list[dict[str, object]] = []
    for job in plan.jobs:
        point_ids = points_by_candidate[job.candidate_id]
        coverage_steps = {
            "flat-direct": ((), (9_001,), (9_001, 9_002)),
            "candidate-direct": (
                (),
                (point_ids[0], point_ids[1]),
                (point_ids[0], point_ids[1], point_ids[3]),
            ),
            "candidate-depaware": (
                (),
                (point_ids[0], point_ids[2]),
                (point_ids[0], point_ids[2], point_ids[3]),
            ),
        }
        scale = _BUDGET_SCALE[job.budget_name]
        for sequence, (elapsed_seconds, covered_point_ids) in enumerate(
            zip((0, 10, 20), coverage_steps[job.harness], strict=True)
        ):
            projection_count = (
                scale * 10 * sequence if job.harness == "candidate-depaware" else 0
            )
            correction_counts = (
                {
                    "dependency_consistency": scale * sequence,
                    "protocol_legality": scale * 2 * sequence,
                }
                if job.harness == "candidate-depaware"
                else {}
            )
            samples.append(
                {
                    "job_id": job.job_id,
                    "candidate_id": job.candidate_id,
                    "harness": job.harness,
                    "seed": job.seed,
                    "elapsed_seconds": elapsed_seconds,
                    "sequence": sequence,
                    "common_total": flat_total if job.harness == "flat-direct" else len(point_ids),
                    "covered_point_ids": list(covered_point_ids),
                    "tests_executed": scale * 100 * sequence,
                    "cycles_executed": scale * 1_000 * sequence,
                    "peak_rss_bytes": (64 + 32 * sequence) * MIB,
                    "projection_count": projection_count,
                    "correction_counts": correction_counts,
                    "protocol_event_count": scale * 3 * sequence,
                    "no_progress_cycles": scale * 4 * sequence,
                    "generation_count": scale * 5 * sequence,
                    "validation_passed": scale * 4 * sequence,
                    "failure_reasons": {
                        "dut_crash": scale * 2 * sequence,
                        "protocol_timeout": scale * 3 * sequence,
                        "resource_terminated": scale * sequence,
                    },
                }
            )
    return samples


class ExperimentReportTest(unittest.TestCase):
    def setUp(self) -> None:
        config = load_json(CONFIGS / "rvx.json")
        self.manifests = [
            candidate_manifest("candidate-a", 0),
            candidate_manifest("candidate-b", 100),
        ]
        self.plan = plan_experiment(config, self.manifests)
        self.samples = experiment_samples(self.plan, self.manifests, flat_total=6)
        self.reference = {
            "stable_source_ids": ["cpu.shared", "candidate-a.direct", "reference.extra"],
            "covered_stable_source_ids": ["cpu.shared", "reference.extra"],
        }

    def job(
        self,
        candidate_id: str,
        budget_name: str,
        harness: str,
        seed: int,
    ) -> ExperimentJob:
        return next(
            job
            for job in self.plan.jobs
            if job.candidate_id == candidate_id
            and job.budget_name == budget_name
            and job.harness == harness
            and job.seed == seed
        )

    def samples_for(self, job: ExperimentJob, samples: list[dict[str, object]] | None = None) -> list[dict[str, object]]:
        source = self.samples if samples is None else samples
        return [sample for sample in source if sample["job_id"] == job.job_id]

    def test_reports_every_planned_job_in_separate_budget_sections(self) -> None:
        report = build_report(self.plan, self.manifests, self.samples, self.reference)

        self.assertEqual("experiment_report.v1", report["schema_version"])
        self.assertEqual(self.plan.plan_hash, report["plan_hash"])
        self.assertEqual(["candidate-a", "candidate-b"], list(report["candidates"]))
        self.assertNotIn("coverage_union", report)
        self.assertEqual(
            {job.job_id for job in self.plan.jobs},
            {sample["job_id"] for sample in self.samples},
        )

        candidate_a = report["candidates"]["candidate-a"]
        candidate_b = report["candidates"]["candidate-b"]
        self.assertEqual(["long", "short", "smoke"], list(candidate_a["budgets"]))
        self.assertEqual("seconds", candidate_a["budgets"]["long"]["budget_kind"])
        self.assertEqual(3_600, candidate_a["budgets"]["long"]["budget_value"])
        self.assertEqual("cycles", candidate_a["budgets"]["smoke"]["budget_kind"])
        self.assertEqual(1_000, candidate_a["budgets"]["smoke"]["budget_value"])

        for budget_name in ("long", "short", "smoke"):
            direct_a = candidate_a["budgets"][budget_name]["harnesses"]["candidate-direct"]
            direct_b = candidate_b["budgets"][budget_name]["harnesses"]["candidate-direct"]
            depaware_a = candidate_a["budgets"][budget_name]["harnesses"]["candidate-depaware"]
            flat_a = candidate_a["budgets"][budget_name]["harnesses"]["flat-direct"]
            self.assertEqual([1, 2, 4], direct_a["covered_point_ids"])
            self.assertEqual([101, 102, 104], direct_b["covered_point_ids"])
            self.assertTrue(set(direct_a["covered_point_ids"]).isdisjoint(direct_b["covered_point_ids"]))
            self.assertEqual(3, direct_a["covered"])
            self.assertEqual(3, depaware_a["covered"])
            self.assertEqual(4, direct_a["common_total"])
            self.assertEqual(direct_a["common_total"], depaware_a["common_total"])
            self.assertNotEqual(flat_a["coverage_universe"], direct_a["coverage_universe"])
            self.assertEqual(6, flat_a["common_total"])
            self.assertIsNone(candidate_a["budgets"][budget_name]["flat_scope"]["percentage_comparison"])
            self.assertNotIn("percentage_delta", candidate_a["budgets"][budget_name]["flat_scope"])

    def test_budget_timelines_and_runtime_never_combine(self) -> None:
        report = build_report(self.plan, self.manifests, self.samples, self.reference)
        budgets = report["candidates"]["candidate-a"]["budgets"]
        long_direct = budgets["long"]["harnesses"]["candidate-direct"]
        long_depaware = budgets["long"]["harnesses"]["candidate-depaware"]
        long_flat = budgets["long"]["harnesses"]["flat-direct"]
        seed_one_job = self.job("candidate-a", "long", "candidate-direct", 1)

        self.assertEqual(
            [
                {
                    "job_id": seed_one_job.job_id,
                    "seed": 1,
                    "elapsed_seconds": 0,
                    "sequence": 0,
                    "covered": 0,
                    "common_total": 4,
                },
                {
                    "job_id": seed_one_job.job_id,
                    "seed": 1,
                    "elapsed_seconds": 10,
                    "sequence": 1,
                    "covered": 2,
                    "common_total": 4,
                },
                {
                    "job_id": seed_one_job.job_id,
                    "seed": 1,
                    "elapsed_seconds": 20,
                    "sequence": 2,
                    "covered": 3,
                    "common_total": 4,
                },
            ],
            long_direct["coverage_over_time"][:3],
        )
        self.assertEqual(9, len(long_direct["coverage_over_time"]))
        self.assertEqual(105.0, long_direct["coverage_auc"])
        self.assertEqual(105.0, long_depaware["coverage_auc"])
        self.assertEqual(60.0, long_flat["coverage_auc"])
        self.assertEqual(10, long_direct["first_discovery_seconds"])
        self.assertEqual(3, long_direct["discovery_count"])
        self.assertEqual(
            {"covered": 2, "common_total": 2, "covered_point_ids": [1, 4]},
            long_direct["component_roles"]["cpu"],
        )
        self.assertEqual(1, long_direct["component_roles"]["uart"]["covered"])
        self.assertEqual(0, long_direct["component_roles"]["gpio"]["covered"])

        runtime = long_depaware["runtime"]
        self.assertEqual(30.0, runtime["tests_per_second"])
        self.assertEqual(300.0, runtime["cycles_per_second"])
        self.assertEqual(128 * MIB, runtime["peak_rss_bytes"])
        self.assertEqual(0.1, runtime["projection_rate"])
        self.assertEqual(
            {"dependency_consistency": 18, "protocol_legality": 36},
            runtime["correction_distribution"],
        )
        self.assertEqual(54, runtime["protocol_event_count"])
        self.assertEqual(72, runtime["no_progress_cycles"])
        self.assertEqual(90, runtime["generation_count"])
        self.assertEqual(0.8, runtime["validation_rate"])
        self.assertEqual(20.0, budgets["short"]["harnesses"]["candidate-depaware"]["runtime"]["tests_per_second"])
        self.assertEqual(10.0, budgets["smoke"]["harnesses"]["candidate-depaware"]["runtime"]["tests_per_second"])
        self.assertEqual(0.0, long_direct["runtime"]["projection_rate"])

    def test_attributes_pair_coverage_and_keeps_failure_classes_separate(self) -> None:
        report = build_report(self.plan, self.manifests, self.samples, self.reference)
        budget = report["candidates"]["candidate-a"]["budgets"]["long"]

        attribution = budget["coverage_attribution"]
        self.assertEqual("harness-attribution", attribution["comparison_scope"])
        self.assertEqual(4, attribution["common_total"])
        self.assertEqual([2], attribution["direct_only_point_ids"])
        self.assertEqual([3], attribution["depaware_only_point_ids"])
        self.assertEqual([1, 4], attribution["overlap_point_ids"])
        self.assertEqual(
            "structure-and-projection",
            budget["structure_and_projection"]["comparison_scope"],
        )

        failures = budget["harnesses"]["candidate-depaware"]["runtime"]["failure_reasons"]
        self.assertEqual(18, failures["resource_terminated"])
        self.assertEqual(36, failures["dut_crash"])
        self.assertNotEqual(failures["resource_terminated"], failures["dut_crash"])

    def test_reference_comparison_uses_only_stable_source_intersection(self) -> None:
        report = build_report(self.plan, self.manifests, self.samples, self.reference)
        comparison = report["candidates"]["candidate-a"]["budgets"]["long"]["reference_comparison"]

        self.assertEqual("reference-descriptive", comparison["comparison_scope"])
        self.assertEqual(
            ["candidate-a.direct", "cpu.shared"],
            comparison["shared_stable_source_ids"],
        )
        self.assertEqual(["cpu.shared"], comparison["reference_covered_stable_source_ids"])
        self.assertEqual(
            ["candidate-a.direct", "cpu.shared"],
            comparison["harness_covered_stable_source_ids"]["candidate-direct"],
        )
        self.assertNotIn("reference.extra", canonical_bytes(comparison).decode("ascii"))

    def test_flat_universe_accepts_own_points_without_fabricated_metadata(self) -> None:
        samples = copy.deepcopy(self.samples)
        for sample in samples:
            if sample["harness"] != "flat-direct":
                continue
            covered_count = len(sample["covered_point_ids"])
            sample["covered_point_ids"] = [9_001, 9_002][:covered_count]

        try:
            report = build_report(self.plan, self.manifests, samples, self.reference)
        except ReportError as error:
            self.fail(f"flat-only point IDs were rejected: {error}")

        budget = report["candidates"]["candidate-a"]["budgets"]["long"]
        flat = budget["harnesses"]["flat-direct"]
        self.assertEqual([9_001, 9_002], flat["covered_point_ids"])
        self.assertEqual({}, flat["component_roles"])
        self.assertFalse(flat["component_roles_available"])
        self.assertEqual(
            ["candidate-depaware", "candidate-direct"],
            list(budget["reference_comparison"]["harness_covered_stable_source_ids"]),
        )

    def test_flat_denominator_is_consistent_for_one_shared_universe(self) -> None:
        samples = copy.deepcopy(self.samples)
        for sample in samples:
            if sample["candidate_id"] == "candidate-b" and sample["harness"] == "flat-direct":
                sample["common_total"] = 7

        with self.assertRaisesRegex(ReportError, "flat.*common_total"):
            build_report(self.plan, self.manifests, samples, self.reference)

        too_many = copy.deepcopy(self.samples)
        flat_sample = next(sample for sample in too_many if sample["harness"] == "flat-direct")
        flat_sample["covered_point_ids"] = list(range(1, 8))
        with self.assertRaisesRegex(ReportError, "covered_point_ids.*common_total"):
            build_report(self.plan, self.manifests, too_many, self.reference)

    def test_reversed_inputs_produce_byte_identical_canonical_output(self) -> None:
        forward = build_report(self.plan, self.manifests, self.samples, self.reference)
        reversed_reference = {
            "stable_source_ids": list(reversed(self.reference["stable_source_ids"])),
            "covered_stable_source_ids": list(
                reversed(self.reference["covered_stable_source_ids"])
            ),
        }
        reverse = build_report(
            self.plan,
            list(reversed(self.manifests)),
            list(reversed(self.samples)),
            reversed_reference,
        )

        self.assertEqual(canonical_bytes(forward), canonical_bytes(reverse))

    def test_transport_composition_hash_does_not_invalidate_candidate_identity(self) -> None:
        rehashed = copy.deepcopy(self.manifests)
        rehashed[0]["composition_ir_hash"] = sha256_id("same-semantics-new-order")

        self.assertEqual(
            build_report(self.plan, self.manifests, self.samples, self.reference),
            build_report(self.plan, rehashed, self.samples, self.reference),
        )

    def test_rejects_unknown_missing_and_mismatched_job_samples(self) -> None:
        unknown = copy.deepcopy(self.samples)
        unknown[0]["job_id"] = "fuzz-unknown"
        with self.assertRaisesRegex(ReportError, "job_id"):
            build_report(self.plan, self.manifests, unknown, self.reference)

        missing_job = self.plan.jobs[0]
        missing = [sample for sample in self.samples if sample["job_id"] != missing_job.job_id]
        with self.assertRaisesRegex(ReportError, "missing.*job"):
            build_report(self.plan, self.manifests, missing, self.reference)

        matched_job = self.plan.jobs[0]
        for field, value in (
            ("candidate_id", "candidate-b"),
            ("harness", "candidate-direct"),
            ("seed", 7),
        ):
            mismatched = copy.deepcopy(self.samples)
            sample = next(item for item in mismatched if item["job_id"] == matched_job.job_id)
            sample[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(ReportError, field):
                    build_report(self.plan, self.manifests, mismatched, self.reference)

    def test_rejects_invalid_frozen_manifest_before_aggregation(self) -> None:
        invalid = copy.deepcopy(self.manifests[0])
        invalid["schema_version"] = "candidate_manifest.v2"

        with self.assertRaises(ContractError):
            build_report(self.plan, [invalid, self.manifests[1]], self.samples, self.reference)

    def test_rejects_stale_manifest_universe_and_adjacent_job_identity(self) -> None:
        for field in (
            "coverage_universe",
            "candidate_hash",
            "build_cache_key",
            "raw_width",
            "instrumented_rtl_hash",
        ):
            invalid = copy.deepcopy(self.manifests[0])
            if field == "coverage_universe":
                invalid["coverage_universe"][0]["stable_source_id"] = "cpu.changed"
            elif field == "candidate_hash":
                invalid["top"]["content_hash"] = sha256_id("stale-top")
            elif field == "build_cache_key":
                invalid["build_cache_key"] = sha256_id("stale-build")
            elif field == "raw_width":
                invalid["top_port_abi"][0]["width"] = 2
            else:
                invalid["harnesses"]["candidate-direct"] = {
                    "instrumented_rtl_hash": sha256_id("stale-rtl")
                }

            with self.subTest(field=field):
                with self.assertRaisesRegex(ReportError, field):
                    build_report(
                        self.plan,
                        [invalid, self.manifests[1]],
                        self.samples,
                        self.reference,
                    )

    def test_accepts_planner_coverage_universe_override_priority(self) -> None:
        cases = (
            (
                "coverage_universe",
                {"coverage_universe": sha256_id("candidate-primary")},
                {"coverage_universe": sha256_id("flat-primary")},
                sha256_id("candidate-primary"),
                sha256_id("flat-primary"),
            ),
            (
                "coverage_universe_id",
                {"coverage_universe_id": sha256_id("candidate-id")},
                {"coverage_universe_id": sha256_id("flat-id")},
                sha256_id("candidate-id"),
                sha256_id("flat-id"),
            ),
            (
                "coverage_universe_hash",
                {"coverage_universe_hash": sha256_id("candidate-hash")},
                {"coverage_universe_hash": sha256_id("flat-hash")},
                sha256_id("candidate-hash"),
                sha256_id("flat-hash"),
            ),
            (
                "priority",
                {
                    "coverage_universe": sha256_id("candidate-first"),
                    "coverage_universe_id": sha256_id("candidate-second"),
                    "coverage_universe_hash": sha256_id("candidate-third"),
                },
                {
                    "coverage_universe": sha256_id("flat-first"),
                    "coverage_universe_id": sha256_id("flat-second"),
                    "coverage_universe_hash": sha256_id("flat-third"),
                },
                sha256_id("candidate-first"),
                sha256_id("flat-first"),
            ),
        )
        for label, candidate_record, flat_record, expected_candidate, expected_flat in cases:
            manifests = copy.deepcopy(self.manifests)
            for manifest in manifests:
                manifest["harnesses"]["candidate-direct"] = copy.deepcopy(candidate_record)
                manifest["harnesses"]["candidate-depaware"] = copy.deepcopy(candidate_record)
                manifest["harnesses"]["flat-direct"] = copy.deepcopy(flat_record)
            plan = plan_experiment(load_json(CONFIGS / "rvx.json"), manifests)
            samples = experiment_samples(plan, manifests, flat_total=6)

            with self.subTest(label=label):
                report = build_report(plan, manifests, samples, self.reference)
                budget = report["candidates"]["candidate-a"]["budgets"]["long"]
                self.assertEqual(
                    expected_candidate,
                    budget["harnesses"]["candidate-direct"]["coverage_universe"],
                )
                self.assertEqual(
                    expected_flat,
                    budget["harnesses"]["flat-direct"]["coverage_universe"],
                )

    def test_rejects_stale_candidate_point_metadata_with_explicit_universe_id(self) -> None:
        manifests = copy.deepcopy(self.manifests)
        explicit_id = sha256_id("candidate-explicit-universe")
        for manifest in manifests:
            manifest["harnesses"]["candidate-direct"] = {
                "coverage_universe_id": explicit_id,
            }
            manifest["harnesses"]["candidate-depaware"] = {
                "coverage_universe_id": explicit_id,
            }
        plan = plan_experiment(load_json(CONFIGS / "rvx.json"), manifests)
        samples = experiment_samples(plan, manifests, flat_total=6)

        for field, replacement in (
            ("component_role", "changed-role"),
            ("stable_source_id", "changed.stable.source"),
        ):
            stale = copy.deepcopy(manifests)
            stale[0]["coverage_universe"][0][field] = replacement
            with self.subTest(field=field):
                with self.assertRaisesRegex(ReportError, "coverage_metadata_hash"):
                    build_report(plan, stale, samples, self.reference)

    def test_rejects_coverage_override_added_after_planning_for_every_harness(self) -> None:
        cases = (
            (
                "candidate-pair",
                ("candidate-direct", "candidate-depaware"),
                "coverage_universe_id",
            ),
            (
                "flat-direct",
                ("flat-direct",),
                "coverage_universe_hash",
            ),
        )
        for label, harnesses, field in cases:
            stale_manifests = copy.deepcopy(self.manifests)
            for harness in harnesses:
                stale_manifests[0]["harnesses"][harness] = {
                    field: sha256_id(f"stale-{label}")
                }
            with self.subTest(label=label):
                with self.assertRaisesRegex(ReportError, "coverage_universe"):
                    build_report(
                        self.plan,
                        stale_manifests,
                        self.samples,
                        self.reference,
                    )

    def test_accepts_planner_unknown_rss_fallback(self) -> None:
        manifests = copy.deepcopy(self.manifests)
        for manifest in manifests:
            manifest["resources"]["peak_rss_bytes"] = None
        plan = plan_experiment(load_json(CONFIGS / "rvx.json"), manifests)
        samples = experiment_samples(plan, manifests, flat_total=6)

        report = build_report(plan, manifests, samples, self.reference)

        self.assertEqual(
            {plan.runtime_policy.unknown_rss_bytes},
            {job.estimated_rss_bytes for job in plan.jobs},
        )
        self.assertEqual(plan.plan_hash, report["plan_hash"])

    def test_rejects_stale_manifest_estimated_rss_identity(self) -> None:
        stale_explicit = copy.deepcopy(self.manifests)
        stale_explicit[0]["resources"]["peak_rss_bytes"] = 2 * MIB
        with self.subTest(source="explicit"):
            with self.assertRaisesRegex(ReportError, "estimated_rss_bytes"):
                build_report(
                    self.plan,
                    stale_explicit,
                    self.samples,
                    self.reference,
                )

        fallback_manifests = copy.deepcopy(self.manifests)
        for manifest in fallback_manifests:
            manifest["resources"]["peak_rss_bytes"] = None
        fallback_plan = plan_experiment(
            load_json(CONFIGS / "rvx.json"),
            fallback_manifests,
        )
        fallback_samples = experiment_samples(
            fallback_plan,
            fallback_manifests,
            flat_total=6,
        )
        stale_fallback = copy.deepcopy(fallback_manifests)
        stale_fallback[0]["resources"]["peak_rss_bytes"] = (
            fallback_plan.runtime_policy.unknown_rss_bytes + 1
        )
        with self.subTest(source="fallback"):
            with self.assertRaisesRegex(ReportError, "estimated_rss_bytes"):
                build_report(
                    fallback_plan,
                    stale_fallback,
                    fallback_samples,
                    self.reference,
                )

    def test_rejects_out_of_bounds_manifest_and_sample_numbers(self) -> None:
        invalid_manifest = copy.deepcopy(self.manifests[0])
        invalid_manifest["coverage_universe"][0]["point_id"] = 1 << 32
        with self.assertRaisesRegex(ReportError, "point_id"):
            build_report(
                self.plan,
                [invalid_manifest, self.manifests[1]],
                self.samples,
                self.reference,
            )

        for field, value in (
            ("elapsed_seconds", -1),
            ("elapsed_seconds", math.inf),
            ("tests_executed", 1 << 64),
            ("sequence", True),
        ):
            samples = copy.deepcopy(self.samples)
            samples[0][field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(ReportError, field):
                    build_report(self.plan, self.manifests, samples, self.reference)

    def test_rejects_elapsed_values_that_overflow_runtime_rates(self) -> None:
        samples = copy.deepcopy(self.samples)
        for seed in (1, 7, 19):
            job = self.job("candidate-a", "long", "candidate-direct", seed)
            job_samples = self.samples_for(job, samples)
            job_samples[0]["elapsed_seconds"] = 0.0
            job_samples[1]["elapsed_seconds"] = 0.0
            job_samples[2]["elapsed_seconds"] = 5e-324

        with self.assertRaisesRegex(ReportError, "elapsed_seconds"):
            build_report(self.plan, self.manifests, samples, self.reference)

    def test_rejects_covered_set_and_common_total_rollback_within_one_job(self) -> None:
        job = self.job("candidate-a", "long", "candidate-depaware", 1)

        covered_rollback = copy.deepcopy(self.samples)
        job_samples = sorted(
            self.samples_for(job, covered_rollback),
            key=lambda sample: sample["sequence"],
        )
        job_samples[2]["covered_point_ids"] = [1]
        with self.assertRaisesRegex(ReportError, "covered_point_ids.*non-decreasing"):
            build_report(self.plan, self.manifests, covered_rollback, self.reference)

        total_change = copy.deepcopy(self.samples)
        job_samples = sorted(
            self.samples_for(job, total_change),
            key=lambda sample: sample["sequence"],
        )
        job_samples[2]["common_total"] = 5
        with self.assertRaisesRegex(ReportError, "common_total"):
            build_report(self.plan, self.manifests, total_change, self.reference)

    def test_rejects_scalar_counter_rollback_within_one_job(self) -> None:
        job = self.job("candidate-a", "long", "candidate-depaware", 1)
        fields = (
            "tests_executed",
            "cycles_executed",
            "peak_rss_bytes",
            "projection_count",
            "protocol_event_count",
            "no_progress_cycles",
            "generation_count",
            "validation_passed",
        )
        for field in fields:
            samples = copy.deepcopy(self.samples)
            job_samples = sorted(
                self.samples_for(job, samples),
                key=lambda sample: sample["sequence"],
            )
            job_samples[2][field] = job_samples[1][field] - 1
            if field == "generation_count":
                job_samples[2]["validation_passed"] = job_samples[1]["validation_passed"]
            with self.subTest(field=field):
                with self.assertRaisesRegex(ReportError, f"{field}.*non-decreasing"):
                    build_report(self.plan, self.manifests, samples, self.reference)

    def test_rejects_counter_map_rollback_and_disappeared_keys(self) -> None:
        job = self.job("candidate-a", "long", "candidate-depaware", 1)
        cases = (
            ("correction_counts", "dependency_consistency", False),
            ("correction_counts", "protocol_legality", True),
            ("failure_reasons", "dut_crash", False),
            ("failure_reasons", "protocol_timeout", True),
        )
        for field, key, disappear in cases:
            samples = copy.deepcopy(self.samples)
            job_samples = sorted(
                self.samples_for(job, samples),
                key=lambda sample: sample["sequence"],
            )
            if disappear:
                del job_samples[2][field][key]
            else:
                job_samples[2][field][key] = job_samples[1][field][key] - 1
            with self.subTest(field=field, key=key, disappear=disappear):
                with self.assertRaisesRegex(
                    ReportError,
                    f"{field}.{key}.*non-decreasing",
                ):
                    build_report(self.plan, self.manifests, samples, self.reference)

    def test_public_api_exports_report_builder(self) -> None:
        from myfuzz.experiments import ReportError as PublicReportError
        from myfuzz.experiments import build_report as public_build_report

        self.assertIs(ReportError, PublicReportError)
        self.assertIs(build_report, public_build_report)


if __name__ == "__main__":
    unittest.main()
