from __future__ import annotations

import copy
import json
import math
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from myfuzz.experiments import ExperimentJob, JobKind, plan_experiment
from myfuzz.integration import BuildJobResult, FuzzJobResult

from scripts.runs.run_static_projection_campaign import (
    load_campaign,
    main,
    materialize_derived_design_config,
    run_campaign,
    validate_training_pair,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "experiments" / "static_projection_training.json"


def valid_pair() -> dict[str, object]:
    shared = {
        "coverage_identity": "sha256:" + "1" * 64,
        "raw_width": 8,
        "mutation": {"max_len": 4096},
        "seed": 7,
        "budget": {"kind": "seconds", "value": 600},
        "return_code": 0,
        "tests_executed": 10,
        "expected_coverage": [1, 2],
        "elapsed_seconds": 600,
        "declared_artifact_hash": "sha256:" + "2" * 64,
        "observed_artifact_hash": "sha256:" + "2" * 64,
        "fifo_paths": [],
    }
    return {"baseline": copy.deepcopy(shared), "candidate": copy.deepcopy(shared)}


class SuccessfulMatrixRunner:
    def __call__(self, job: object) -> object:
        if job.kind is JobKind.BUILD:
            return BuildJobResult(job.job_id, 1, job.artifact_id)
        assert isinstance(job, ExperimentJob)
        sample = {
            "job_id": job.job_id,
            "candidate_id": job.candidate_id,
            "harness": job.harness,
            "seed": job.seed,
            "elapsed_seconds": 0,
            "sequence": 0,
            "common_total": 1,
            "covered_point_ids": [],
            "tests_executed": 0,
            "cycles_executed": 0,
            "peak_rss_bytes": 1024 * 1024,
            "projection_count": 0,
            "correction_counts": {},
            "protocol_event_count": 0,
            "no_progress_cycles": 0,
            "generation_count": 0,
            "validation_passed": 0,
            "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
        }
        return FuzzJobResult(job.job_id, 1, (sample,), 1024 * 1024)

    def persist_checkpoint(self, _event: object) -> None:
        raise AssertionError("unexpected resource checkpoint")


class StaticProjectionCampaignTest(unittest.TestCase):
    def test_target_manifests_publish_report_compatible_coverage_points(self) -> None:
        config = load_campaign(CONFIG)
        for target in config.targets:
            manifest = json.loads((ROOT / target.candidate_manifest_path).read_text(encoding="utf-8"))
            for point in manifest["coverage_universe"]:
                with self.subTest(target=target.target_id, point=point["point_id"]):
                    self.assertTrue(point["stable_source_id"])
                    self.assertGreater(point["component_id"], 0)
                    self.assertTrue(point["component_role"])
                    self.assertGreater(point["source"]["file_id"], 0)
                    self.assertGreater(point["source"]["line"], 0)
                    self.assertGreaterEqual(point["source"]["column"], 0)

    def test_campaign_uses_exact_training_budgets_seeds_and_shared_portfolio(self) -> None:
        config = load_campaign(CONFIG)
        self.assertEqual(60, config.screen.seconds)
        self.assertEqual((1,), config.screen.seeds)
        self.assertEqual(600, config.promotion.seconds)
        self.assertEqual((1, 7, 19), config.promotion.seeds)
        self.assertEqual(3600, config.validation.seconds)
        self.assertEqual((1, 7, 19), config.validation.seeds)
        self.assertEqual(2, len(config.targets))
        for target in config.targets:
            declaration = json.loads((ROOT / target.config_path).read_text())
            self.assertEqual("static_projection.PORTFOLIO", declaration["portfolio"])
            self.assertNotIn("parameters", declaration["static_projection"])
            self.assertNotIn("policy", declaration["static_projection"])

    def test_campaign_loader_rejects_unknown_keys_unsafe_paths_and_duplicates(self) -> None:
        base = json.loads(CONFIG.read_text(encoding="utf-8"))
        cases: list[tuple[str, dict[str, object]]] = []

        unknown = copy.deepcopy(base)
        unknown["unexpected"] = True
        cases.append(("unexpected", unknown))

        unknown_stage = copy.deepcopy(base)
        unknown_stage["screen"]["unexpected"] = 1
        cases.append(("unexpected", unknown_stage))

        unknown_target = copy.deepcopy(base)
        unknown_target["targets"][0]["unexpected"] = 1
        cases.append(("unexpected", unknown_target))

        unsafe = copy.deepcopy(base)
        unsafe["targets"][0]["config_path"] = "../outside.json"
        cases.append(("repository-relative", unsafe))

        absolute = copy.deepcopy(base)
        absolute["targets"][0]["candidate_manifest_path"] = "/tmp/manifest.json"
        cases.append(("repository-relative", absolute))

        duplicate_target = copy.deepcopy(base)
        duplicate_target["targets"][1]["target_id"] = duplicate_target["targets"][0]["target_id"]
        cases.append(("duplicate", duplicate_target))

        duplicate_seed = copy.deepcopy(base)
        duplicate_seed["promotion"]["seeds"] = [1, 1, 19]
        cases.append(("unique", duplicate_seed))

        wrong_target = copy.deepcopy(base)
        wrong_target["targets"][1]["target_id"] = "not-the-rvx-training-target"
        cases.append(("exact two training targets", wrong_target))

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            for label, value in cases:
                path = Path(directory) / f"{len(label)}-{len(cases)}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.subTest(label=label, value=value), self.assertRaisesRegex(ValueError, label):
                    load_campaign(path)

    def test_campaign_loader_rejects_non_exact_stage_values_and_boolean_integers(self) -> None:
        base = json.loads(CONFIG.read_text(encoding="utf-8"))
        mutations = (
            ("screen", "seconds", 61),
            ("screen", "seconds", True),
            ("screen", "seeds", [True]),
            ("promotion", "seeds", [1, 7, 20]),
            ("validation", "seconds", 3599),
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            for index, (stage, field, value) in enumerate(mutations):
                document = copy.deepcopy(base)
                document[stage][field] = value
                path = Path(directory) / f"invalid-{index}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.subTest(stage=stage, field=field, value=value), self.assertRaises(ValueError):
                    load_campaign(path)

    def test_pair_validation_rejects_every_fairness_mismatch(self) -> None:
        for field in ("coverage_identity", "raw_width", "mutation", "seed", "budget"):
            pair = valid_pair()
            pair["candidate"][field] = "mismatch"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                validate_training_pair(pair)

    def test_preflight_fails_closed_on_invalid_runtime_evidence(self) -> None:
        mutations = {
            "abnormal exit": ("return_code", 1),
            "early exit": ("elapsed_seconds", 599),
            "zero tests": ("tests_executed", 0),
            "empty expected coverage": ("expected_coverage", []),
            "artifact hash": ("observed_artifact_hash", "sha256:" + "3" * 64),
        }
        for label, (field, value) in mutations.items():
            pair = valid_pair()
            pair["candidate"][field] = value
            with self.subTest(label=label), self.assertRaises(ValueError):
                validate_training_pair(pair)

        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "rfuzz.fifo"
            fifo.touch()
            pair = valid_pair()
            pair["candidate"]["fifo_paths"] = [fifo.as_posix()]
            with self.assertRaisesRegex(ValueError, "FIFO"):
                validate_training_pair(pair)

    def test_pair_validation_rejects_boolean_nonfinite_malformed_and_missing_evidence(self) -> None:
        cases = {
            "boolean return code": ("return_code", True),
            "boolean tests": ("tests_executed", True),
            "boolean raw width": ("raw_width", True),
            "nonfinite elapsed": ("elapsed_seconds", math.inf),
            "nan elapsed": ("elapsed_seconds", math.nan),
            "malformed coverage hash": ("coverage_identity", "policy-1"),
            "malformed artifact hash": ("declared_artifact_hash", "sha256:nope"),
        }
        for label, (field, value) in cases.items():
            pair = valid_pair()
            pair["candidate"][field] = value
            with self.subTest(label=label), self.assertRaises(ValueError):
                validate_training_pair(pair)
        for field in tuple(valid_pair()["candidate"]):
            pair = valid_pair()
            pair["candidate"].pop(field)
            with self.subTest(missing=field), self.assertRaisesRegex(ValueError, "missing"):
                validate_training_pair(pair)

    def test_derived_config_is_atomic_repo_relative_and_parseable_by_existing_flow(self) -> None:
        target = load_campaign(CONFIG).targets[0]
        parameters = {
            "direct_ratio": 2,
            "event_rarity": 4,
            "legal_set_strength": 1,
            "mutual_exclusion": "one_hot",
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory)
            derived = materialize_derived_design_config(
                target,
                parameters,
                output_dir=output,
                policy_id="policy-atomic",
            )
            self.assertFalse(derived.is_absolute())
            absolute = ROOT / derived
            self.assertTrue(absolute.is_file())
            document = json.loads(absolute.read_text(encoding="utf-8"))
            self.assertEqual(target.candidate_manifest_path, document["candidate_manifest"])
            self.assertEqual(parameters, document["static_projection"]["parameters"])
            self.assertEqual(7_000_000_000, document["hard_memory_bytes"])
            self.assertFalse(any(path.suffix == ".tmp" for path in absolute.parent.iterdir()))

    def test_each_training_stage_uses_the_existing_experiment_matrix(self) -> None:
        config = load_campaign(CONFIG)
        policy = __import__("myfuzz.harness", fromlist=["StaticPolicyParameters"]).StaticPolicyParameters(1, 2, 1, "none")
        matrix_results = [{"report": {}} for _ in range(6)]
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO", (policy,)
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=matrix_results,
        ) as matrix:
            report = run_campaign(
                config,
                runner=object(),
                output_dir=Path(directory),
                promotion_selector=lambda _results: {
                    "policy_id": "policy-1",
                    "plan_hash": "sha256:" + "4" * 64,
                    "parameters": {
                        "direct_ratio": 1,
                        "event_rarity": 2,
                        "legal_set_strength": 1,
                        "mutual_exclusion": "none",
                    },
                    "training_evidence_hash": "sha256:" + "5" * 64,
                },
            )

        self.assertEqual(6, matrix.call_count)
        self.assertEqual(["screen", "promotion", "validation"], report["stages"])
        for call in matrix.call_args_list:
            planner = call.args[0]["planner_config"]
            self.assertEqual(
                ["flat-direct", "candidate-direct", "candidate-static"],
                planner["harness_groups"],
            )
            comparison = planner["coverage"]["comparisons"][0]
            self.assertEqual("candidate-direct", comparison["left_harness"])
            self.assertEqual("candidate-static", comparison["right_harness"])
        paths = [call.kwargs["report_path"] for call in matrix.call_args_list]
        self.assertEqual(6, len(set(paths)))
        self.assertEqual(
            {"ibex_opentitan_real_ip", "rvx_multicomponent"},
            {call.args[0]["planner_config"]["target"]["target_id"] for call in matrix.call_args_list},
        )
        for call in matrix.call_args_list:
            matrix_input = call.args[0]
            plan = plan_experiment(
                matrix_input["planner_config"], matrix_input["candidate_manifests"]
            )
            builds = {build.harness: build for build in plan.build_jobs}
            self.assertNotEqual(
                builds["candidate-direct"].artifact_id,
                builds["candidate-static"].artifact_id,
            )
            for job in plan.jobs:
                self.assertTrue(job.build_job_id)
                self.assertEqual(
                    builds[job.harness].artifact_id,
                    job.execution.server_artifact_id,
                )

    def test_campaign_prepares_measured_coverage_before_every_matrix_plan(self) -> None:
        config = load_campaign(CONFIG)
        policy = __import__("myfuzz.harness", fromlist=["StaticPolicyParameters"]).StaticPolicyParameters(1, 2, 1, "none")
        prepared: list[str] = []

        def preparer(manifest: dict[str, object], design_config: Path) -> dict[str, object]:
            prepared.append(design_config.as_posix())
            result = copy.deepcopy(manifest)
            result["prepared_coverage"] = True
            return result

        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO", (policy,)
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=[{"report": {}} for _ in range(6)],
        ) as matrix:
            run_campaign(
                config,
                runner=object(),
                preparer=preparer,
                output_dir=Path(directory),
                promotion_selector=lambda _results: {
                    "policy_id": "policy-1",
                    "plan_hash": "sha256:" + "4" * 64,
                    "parameters": {
                        "direct_ratio": 1, "event_rarity": 2,
                        "legal_set_strength": 1, "mutual_exclusion": "none",
                    },
                    "training_evidence_hash": "sha256:" + "5" * 64,
                },
            )

        self.assertEqual(6, len(prepared))
        self.assertTrue(all(call.args[0]["candidate_manifests"][0]["prepared_coverage"] for call in matrix.call_args_list))

    def test_smoke_runs_first_policy_for_both_targets_at_one_second_seed_one(self) -> None:
        config = load_campaign(CONFIG)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=[{"report": {}} for _ in range(2)],
        ) as matrix:
            report = run_campaign(
                config,
                runner=object(),
                preparer=lambda manifest, _path: manifest,
                output_dir=Path(directory),
                stage="smoke",
            )

        self.assertEqual(["smoke"], report["stages"])
        self.assertEqual(2, matrix.call_count)
        for call in matrix.call_args_list:
            planner = call.args[0]["planner_config"]
            self.assertEqual([{"name": "smoke", "kind": "seconds", "value": 1}], planner["budgets"])
            self.assertEqual({1}, set(planner["candidate_pair"]["seeds"]))

    def test_cli_constructs_concrete_runner_and_preparer_for_smoke(self) -> None:
        fake_runner = Mock()
        preparer = object()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.RfuzzExperimentRunner"
        ) as runner_type, patch(
            "scripts.runs.run_static_projection_campaign.run_campaign"
        ) as campaign_run:
            runner_type.return_value = fake_runner
            runner_type.return_value.prepare_manifest = preparer
            result = main([
                "--stage", "smoke", "--config", CONFIG.as_posix(),
                "--out", directory,
            ])

        self.assertEqual(0, result)
        runner_type.assert_called_once_with(ROOT.resolve(), Path(directory) / "rfuzz-results")
        self.assertIs(fake_runner, campaign_run.call_args.kwargs["runner"])
        self.assertIs(preparer, campaign_run.call_args.kwargs["preparer"])
        self.assertEqual("smoke", campaign_run.call_args.kwargs["stage"])

    def test_campaign_publishes_all_stage_reports_through_the_real_matrix(self) -> None:
        config = load_campaign(CONFIG)
        policy = __import__(
            "myfuzz.harness", fromlist=["StaticPolicyParameters"]
        ).StaticPolicyParameters(1, 2, 1, "none")
        decision = {
            "policy_id": "policy-real-matrix",
            "plan_hash": "sha256:" + "4" * 64,
            "parameters": {
                "direct_ratio": 1,
                "event_rarity": 2,
                "legal_set_strength": 1,
                "mutual_exclusion": "none",
            },
            "training_evidence_hash": "sha256:" + "5" * 64,
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO", (policy,)
        ), patch.dict(
            os.environ,
            {"MYFUZZ_MEMORY_GATE_DIR": str(Path(directory) / "gates")},
        ):
            result = run_campaign(
                config,
                runner=SuccessfulMatrixRunner(),
                output_dir=Path(directory),
                promotion_selector=lambda _results: decision,
            )
            reports = sorted(Path(directory).glob("*/*/*-matrix.json"))

        self.assertEqual(["screen", "promotion", "validation"], result["stages"])
        self.assertEqual(6, len(reports))

    def test_real_static_bundle_provenance_is_forwarded_to_matrix_manifest(self) -> None:
        config = load_campaign(CONFIG)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO",
            config.targets[:1] and (__import__("myfuzz.harness", fromlist=["StaticPolicyParameters"]).StaticPolicyParameters(1, 2, 1, "none"),),
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=[{"report": {}} for _ in range(6)],
        ) as matrix:
            run_campaign(
                config,
                runner=object(),
                output_dir=Path(directory),
                promotion_selector=lambda _results: {
                    "policy_id": "policy-1",
                    "plan_hash": "sha256:" + "4" * 64,
                    "parameters": {
                        "direct_ratio": 1,
                        "event_rarity": 2,
                        "legal_set_strength": 1,
                        "mutual_exclusion": "none",
                    },
                    "training_evidence_hash": "sha256:" + "5" * 64,
                },
            )
        for call in matrix.call_args_list:
            for manifest in call.args[0]["candidate_manifests"]:
                static = manifest["harnesses"]["candidate-static"]
                self.assertRegex(static["content_hash"], r"^sha256:[0-9a-f]{64}$")
                self.assertRegex(static["abi_hash"], r"^sha256:[0-9a-f]{64}$")
                self.assertRegex(static["projection_plan_hash"], r"^sha256:[0-9a-f]{64}$")
                self.assertNotEqual(manifest["candidate_id"], static["content_hash"])

    def test_no_promotion_publishes_deterministic_negative_result_without_validation(self) -> None:
        config = load_campaign(CONFIG)
        policy = __import__("myfuzz.harness", fromlist=["StaticPolicyParameters"]).StaticPolicyParameters(1, 2, 1, "none")
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO", (policy,)
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=[{"report": {}} for _ in range(8)],
        ) as matrix:
            first = run_campaign(
                config,
                runner=object(),
                output_dir=Path(directory),
                promotion_selector=lambda _results: None,
            )
            second = run_campaign(
                config,
                runner=object(),
                output_dir=Path(directory),
                promotion_selector=lambda _results: None,
            )
        self.assertEqual(8, matrix.call_count)
        self.assertEqual(["screen", "promotion"], first["stages"])
        self.assertEqual(first["promotion"], second["promotion"])
        self.assertEqual("no-policy-promoted", first["promotion"]["reason"])
        self.assertFalse(first["promotion"]["promoted"])

    def test_promotion_freeze_is_deterministic_and_atomic(self) -> None:
        config = load_campaign(CONFIG)
        decision = {
            "policy_id": "policy-frozen",
            "plan_hash": "sha256:" + "4" * 64,
            "parameters": {
                "direct_ratio": 1,
                "event_rarity": 2,
                "legal_set_strength": 1,
                "mutual_exclusion": "none",
            },
            "training_evidence_hash": "sha256:" + "5" * 64,
        }
        policy = __import__("myfuzz.harness", fromlist=["StaticPolicyParameters"]).StaticPolicyParameters(1, 2, 1, "none")
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO", (policy,)
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=[{"report": {}} for _ in range(6)],
        ):
            first = run_campaign(config, runner=object(), output_dir=Path(directory), promotion_selector=lambda _: decision)
            frozen_path = Path(directory) / "frozen-policy.json"
            payload = frozen_path.read_bytes()
            frozen_path.unlink()
            with patch(
                "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
                side_effect=[{"report": {}} for _ in range(6)],
            ):
                second = run_campaign(config, runner=object(), output_dir=Path(directory), promotion_selector=lambda _: decision)
            self.assertEqual(payload, frozen_path.read_bytes())
            self.assertEqual(first["frozen"], second["frozen"])
            self.assertFalse(any(path.suffix == ".tmp" for path in Path(directory).iterdir()))


if __name__ == "__main__":
    unittest.main()
