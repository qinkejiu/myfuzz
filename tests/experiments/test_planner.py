from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

from myfuzz.contracts import ContractError, canonical_bytes
from myfuzz.experiments import ExperimentPlanError, Job, JobKind, plan_experiment, run_job
from myfuzz.experiments import planner as planner_module


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "contracts"
CONFIGS = ROOT / "configs" / "experiments"


def load_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def candidate_manifest(candidate_id: str = "candidate-000") -> dict[str, object]:
    document = load_json(FIXTURES / "candidate_manifest.v1.valid.json")
    document["candidate_id"] = candidate_id
    document["build_cache_key"] = "sha256:" + hashlib.sha256(candidate_id.encode("utf-8")).hexdigest()
    return document


class ExperimentPlannerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.rvx = load_json(CONFIGS / "rvx.json")
        self.ibex = load_json(CONFIGS / "ibex_opentitan.json")
        self.manifest = candidate_manifest()

    def test_checked_in_configs_declare_the_bounded_experiment_contract(self) -> None:
        required_budgets = (
            {"name": "smoke", "kind": "cycles", "value": 1_000},
            {"name": "short", "kind": "seconds", "value": 300},
            {"name": "long", "kind": "seconds", "value": 3_600},
        )
        for config in (self.rvx, self.ibex):
            with self.subTest(target=config["target"]):
                self.assertEqual("experiment.v1", config["schema_version"])
                self.assertIsInstance(config["target"]["target_id"], str)
                self.assertEqual(3, config["candidate_selection"]["k"])
                self.assertEqual([1, 7, 19], config["candidate_pair"]["seeds"])
                self.assertEqual(
                    ["flat-direct", "candidate-direct", "candidate-depaware"],
                    config["harness_groups"],
                )
                self.assertEqual(required_budgets, tuple(config["budgets"]))
                self.assertEqual(1, config["build_concurrency"])
                self.assertIs(config["waveforms"], False)
                self.assertEqual(128, config["replay_queue_capacity"])
                self.assertEqual(4_096, config["event_ring_capacity"])
                self.assertEqual(64, config["field_groups_per_batch"])
                self.assertEqual(6_000_000_000, config["soft_memory_bytes"])
                self.assertEqual(7_000_000_000, config["hard_memory_bytes"])
                self.assertEqual(64_000_000, config["token_bytes"])

        self.assertEqual(self.rvx["mutation"], self.ibex["mutation"])
        self.assertEqual(
            {
                "mode": "evaluation-only",
                "allowed_stage": "report",
                "comparison": "shared-stable-source-id",
            },
            self.rvx["reference"],
        )
        self.assertNotIn("reference_top", self.rvx)
        self.assertNotIn("reference", self.ibex)
        self.assertNotIn("reference_top", self.ibex)

        roles = {component["role"] for component in self.ibex["components"]}
        self.assertEqual(
            {"cpu", "uart", "gpio", "timer", "obi-tlul-adapter", "interconnect", "memory-endpoint"},
            roles,
        )
        self.assertNotIn("spi", roles)

    def test_plan_is_immutable_deterministic_and_covers_the_full_matrix(self) -> None:
        plan = plan_experiment(self.rvx, [self.manifest])

        self.assertEqual(plan, plan_experiment(self.rvx, [self.manifest]))
        self.assertEqual(27, len(plan.jobs))
        self.assertEqual(
            {"flat-direct", "candidate-direct", "candidate-depaware"},
            {job.harness for job in plan.jobs},
        )
        self.assertEqual({1, 7, 19}, {job.seed for job in plan.jobs})
        self.assertEqual(
            {("cycles", 1_000), ("seconds", 300), ("seconds", 3_600)},
            {(job.budget_kind, job.budget_value) for job in plan.jobs},
        )
        self.assertEqual({self.rvx["target"]["target_id"]}, {job.target_id for job in plan.jobs})
        self.assertTrue(plan.fairness.candidate_pair_has_equal_budget)
        self.assertTrue(plan.fairness.candidate_pair_has_equal_seeds)
        self.assertTrue(plan.fairness.candidate_pair_has_equal_raw_width)
        self.assertTrue(plan.fairness.shared_instrumented_rtl)
        self.assertTrue(plan.fairness.shared_coverage_universe)
        self.assertRegex(plan.plan_hash, r"^sha256:[0-9a-f]{64}$")
        self.assertIsInstance(plan.jobs, tuple)
        self.assertIsInstance(plan.run_blocks, tuple)
        self.assertTrue(all(isinstance(block, tuple) for block in plan.run_blocks))
        with self.assertRaises(FrozenInstanceError):
            plan.plan_hash = "changed"

    def test_jobs_are_directly_runnable_by_b7_and_build_prerequisites_are_exposed(self) -> None:
        measured = copy.deepcopy(self.manifest)
        measured["resources"]["peak_rss_bytes"] = 1024 * 1024
        plan = plan_experiment(self.rvx, [measured])

        self.assertEqual(27, len(plan.jobs))
        self.assertTrue(all(isinstance(job, Job) and job.kind is JobKind.FUZZ for job in plan.jobs))
        self.assertEqual(1, len(plan.build_jobs))
        self.assertTrue(all(isinstance(job, Job) and job.kind is JobKind.BUILD for job in plan.build_jobs))
        self.assertTrue(all(job.gate_name == "build" and job.worker_limit == 1 for job in plan.build_jobs))
        self.assertEqual(plan.build_jobs + plan.jobs, plan.execution_jobs)

        runnable = plan.jobs[0]
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"MYFUZZ_MEMORY_GATE_DIR": directory},
        ):
            result = run_job(runnable, lambda job: job.job_id, timeout_seconds=0)
            self.assertEqual(runnable.job_id, result)
            self.assertFalse((Path(directory) / f"{runnable.gate_name}.lock").exists())

    def test_budget_declaration_order_is_canonical(self) -> None:
        reversed_budgets = copy.deepcopy(self.rvx)
        reversed_budgets["budgets"] = list(reversed(reversed_budgets["budgets"]))

        self.assertEqual(
            plan_experiment(self.rvx, [self.manifest]),
            plan_experiment(reversed_budgets, [self.manifest]),
        )

    def test_runtime_policy_is_immutable_and_part_of_the_plan_hash(self) -> None:
        baseline = plan_experiment(self.rvx, [self.manifest])
        changed_config = copy.deepcopy(self.rvx)
        changed_config["event_ring_capacity"] = 2_048
        changed = plan_experiment(changed_config, [self.manifest])

        policy = baseline.runtime_policy
        self.assertEqual(1, policy.build_concurrency)
        self.assertIs(policy.waveforms, False)
        self.assertEqual(128, policy.replay_queue_capacity)
        self.assertEqual(4_096, policy.event_ring_capacity)
        self.assertEqual(64, policy.field_groups_per_batch)
        self.assertEqual(6_000_000_000, policy.soft_memory_bytes)
        self.assertEqual(7_000_000_000, policy.hard_memory_bytes)
        self.assertEqual(64_000_000, policy.token_bytes)
        with self.assertRaises(FrozenInstanceError):
            policy.event_ring_capacity = 1
        self.assertNotEqual(baseline.runtime_policy, changed.runtime_policy)
        self.assertNotEqual(baseline.plan_hash, changed.plan_hash)

    def test_unknown_rss_conservatively_reserves_the_soft_memory_limit(self) -> None:
        plan = plan_experiment(self.rvx, [self.manifest])
        expected_bytes = plan.runtime_policy.soft_memory_bytes
        expected_mib = (expected_bytes + 1024 * 1024 - 1) // (1024 * 1024)

        self.assertNotEqual(plan.runtime_policy.token_bytes, expected_bytes)
        self.assertEqual({expected_bytes}, {job.estimated_rss_bytes for job in plan.jobs})
        self.assertEqual({expected_mib}, {job.requested_mib for job in plan.execution_jobs})
        self.assertEqual({1}, {job.worker_limit for job in plan.execution_jobs})

    def test_measured_rss_equal_to_soft_memory_is_accepted_with_one_worker(self) -> None:
        measured = copy.deepcopy(self.manifest)
        soft_memory = self.rvx["soft_memory_bytes"]
        measured["resources"]["peak_rss_bytes"] = soft_memory

        plan = plan_experiment(self.rvx, [measured])

        self.assertEqual(27, len(plan.jobs))
        self.assertEqual({soft_memory}, {job.estimated_rss_bytes for job in plan.jobs})
        self.assertEqual({1}, {job.worker_limit for job in plan.execution_jobs})

    def test_measured_rss_above_soft_memory_is_rejected_before_job_creation(self) -> None:
        measured = copy.deepcopy(self.manifest)
        measured["resources"]["peak_rss_bytes"] = self.rvx["soft_memory_bytes"] + 1

        with patch.object(planner_module, "_make_build_jobs", wraps=planner_module._make_build_jobs) as builds:
            with self.assertRaisesRegex(
                ExperimentPlanError,
                r"^measured peak_rss_bytes cannot fit soft memory policy$",
            ):
                plan_experiment(self.rvx, [measured])

        builds.assert_not_called()

    def test_measured_rss_above_hard_memory_is_rejected_by_soft_policy(self) -> None:
        measured = copy.deepcopy(self.manifest)
        measured["resources"]["peak_rss_bytes"] = self.rvx["hard_memory_bytes"] + 1

        with self.assertRaisesRegex(
            ExperimentPlanError,
            r"^measured peak_rss_bytes cannot fit soft memory policy$",
        ):
            plan_experiment(self.rvx, [measured])

    def test_candidate_pairs_share_fairness_inputs_and_flat_has_its_own_universe(self) -> None:
        plan = plan_experiment(self.rvx, [self.manifest])

        for seed in (1, 7, 19):
            for budget in (("cycles", 1_000), ("seconds", 300), ("seconds", 3_600)):
                jobs = {
                    job.harness: job
                    for job in plan.jobs
                    if job.seed == seed and (job.budget_kind, job.budget_value) == budget
                }
                direct = jobs["candidate-direct"]
                depaware = jobs["candidate-depaware"]
                self.assertEqual(direct.raw_width, depaware.raw_width)
                self.assertEqual(direct.instrumented_rtl_hash, depaware.instrumented_rtl_hash)
                self.assertEqual(direct.coverage_universe, depaware.coverage_universe)
                self.assertEqual(direct.mutation, depaware.mutation)
                self.assertNotEqual(jobs["flat-direct"].coverage_universe, direct.coverage_universe)

    def test_run_blocks_use_the_declared_sha256_pair_order(self) -> None:
        plan = plan_experiment(self.rvx, [self.manifest])
        jobs = {job.job_id: job for job in plan.jobs}

        self.assertEqual(9, len(plan.run_blocks))
        self.assertEqual(set(jobs), {job_id for block in plan.run_blocks for job_id in block})
        for block in plan.run_blocks:
            self.assertEqual(3, len(block))
            self.assertEqual("flat-direct", jobs[block[0]].harness)
            pair = tuple(jobs[job_id].harness for job_id in block[1:])
            seed = jobs[block[0]].seed
            digest = hashlib.sha256(
                canonical_bytes({"seed": seed, "candidate_id": self.manifest["candidate_id"]})
            ).digest()
            expected = (
                ("candidate-direct", "candidate-depaware")
                if digest[0] & 1 == 0
                else ("candidate-depaware", "candidate-direct")
            )
            self.assertEqual(expected, pair)

    def test_reference_is_evaluation_only_and_cannot_change_generated_jobs(self) -> None:
        without_reference = copy.deepcopy(self.rvx)
        del without_reference["reference"]

        self.assertEqual(
            plan_experiment(self.rvx, [self.manifest]),
            plan_experiment(without_reference, [self.manifest]),
        )

    def test_reference_free_target_never_creates_a_reference_job(self) -> None:
        plan = plan_experiment(self.ibex, [self.manifest])

        self.assertEqual({self.manifest["candidate_id"]}, {job.candidate_id for job in plan.jobs})
        self.assertNotIn("reference-original", {job.harness for job in plan.jobs})

    def test_manifest_input_order_and_top_k_selection_are_stable(self) -> None:
        manifests = [candidate_manifest(candidate_id) for candidate_id in ("candidate-d", "candidate-b", "candidate-a", "candidate-c")]

        forward = plan_experiment(self.rvx, manifests)
        reverse = plan_experiment(self.rvx, list(reversed(manifests)))

        self.assertEqual(forward, reverse)
        self.assertEqual(
            {"candidate-a", "candidate-b", "candidate-c"},
            {job.candidate_id for job in forward.jobs},
        )

    def test_display_and_component_strings_are_inert(self) -> None:
        misleading = copy.deepcopy(self.ibex)
        misleading["target"]["display"] = "rvx reference_top fixed_address"
        for index, component in enumerate(misleading["components"]):
            component["display"] = f"misleading-module-{index}"
            component["role"] = f"misleading-role-{index}"

        self.assertEqual(
            plan_experiment(self.ibex, [self.manifest]),
            plan_experiment(misleading, [self.manifest]),
        )

    def test_invalid_manifest_is_rejected_by_the_frozen_contract(self) -> None:
        invalid = copy.deepcopy(self.manifest)
        invalid["schema_version"] = "candidate_manifest.v2"

        with self.assertRaises(ContractError):
            plan_experiment(self.rvx, [invalid])

    def test_duplicate_candidate_ids_are_rejected(self) -> None:
        with self.assertRaisesRegex(ExperimentPlanError, "candidate IDs must be unique"):
            plan_experiment(self.rvx, [self.manifest, copy.deepcopy(self.manifest)])

    def test_candidate_pair_with_different_raw_width_is_rejected(self) -> None:
        unfair = copy.deepcopy(self.manifest)
        unfair["harnesses"]["candidate-direct"] = {"raw_width": 8}
        unfair["harnesses"]["candidate-depaware"] = {"raw_width": 9}

        with self.assertRaisesRegex(ExperimentPlanError, "candidate pair raw width"):
            plan_experiment(self.rvx, [unfair])

    def test_cross_universe_percentage_comparison_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.rvx)
        invalid["coverage"]["comparisons"][1]["measure"] = "percentage"

        with self.assertRaisesRegex(
            ExperimentPlanError,
            "coverage percentages across distinct universes",
        ):
            plan_experiment(invalid, [self.manifest])

    def test_concurrent_build_configuration_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.rvx)
        invalid["build_concurrency"] = 2

        with self.assertRaisesRegex(ExperimentPlanError, "build_concurrency must be 1"):
            plan_experiment(invalid, [self.manifest])


if __name__ == "__main__":
    unittest.main()
