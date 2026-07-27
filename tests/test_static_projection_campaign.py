from __future__ import annotations

import copy
import json
import math
import os
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock, patch

from myfuzz.contracts import content_hash
from myfuzz.experiments import ExperimentJob, JobKind, plan_experiment, promote
from myfuzz.harness import StaticPolicyParameters
from myfuzz.integration import (
    BuildJobResult,
    FuzzJobResult,
    matrix_promotion_pairs,
)

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


def promotion_decision(parameters: StaticPolicyParameters) -> dict[str, object]:
    plan_hash = content_hash(asdict(parameters))
    return {
        "policy_id": "policy-" + plan_hash.removeprefix("sha256:")[:16],
        "plan_hash": plan_hash,
        "parameters": asdict(parameters),
        "training_evidence_hash": "sha256:" + "5" * 64,
    }


def authoritative_mapping(results: object) -> dict[str, object]:
    decision = promote(matrix_promotion_pairs(results))[0]
    return {
        "policy_id": decision.policy_id,
        "plan_hash": decision.plan_hash,
        "parameters": asdict(decision.parameters),
        "training_evidence_hash": decision.training_evidence_hash,
    }


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
            "elapsed_seconds": 1,
            "sequence": 0,
            "common_total": 1,
            "covered_point_ids": [1],
            "tests_executed": 1,
            "cycles_executed": 0,
            "peak_rss_bytes": 1024 * 1024,
            "projection_count": 0,
            "correction_counts": {},
            "protocol_event_count": 0,
            "no_progress_cycles": 0,
            "generation_count": 0,
            "validation_passed": 0,
            "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
            "artifact_id": job.execution.server_artifact_id,
            "server_returncode": -15,
            "fuzzer_returncode": -15,
            "handshake_succeeded": True,
            "fifo_cleanup_succeeded": True,
            "crash_restart_count": 0,
        }
        return FuzzJobResult(job.job_id, 1, (sample,), 1024 * 1024)

    def persist_checkpoint(self, _event: object) -> None:
        raise AssertionError("unexpected resource checkpoint")


class StaticProjectionCampaignTest(unittest.TestCase):
    @staticmethod
    def _matrix_pairs(
        metadata: dict[str, object],
        target_id: str,
        seeds: list[int],
        *,
        candidate_covered: int,
    ) -> dict[str, object]:
        return {
            "schema_version": "experiment_matrix_run.v1",
            "report": {},
            "execution": {},
            "promotion_pairs": [
                {
                    **copy.deepcopy(metadata),
                    "target_id": target_id,
                    "seed": seed,
                    "baseline": {
                        "covered": 10,
                        "tests_per_second": 10.0,
                        "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
                    },
                    "candidate": {
                        "covered": candidate_covered,
                        "tests_per_second": 10.0,
                        "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
                    },
                }
                for seed in seeds
            ],
        }

    def _passing_matrix(self, config_value, *, runner, report_path):
        del runner, report_path
        planner = config_value["planner_config"]
        return self._matrix_pairs(
            config_value["pair_metadata"],
            planner["target"]["target_id"],
            planner["candidate_pair"]["seeds"],
            candidate_covered=(
                10 if planner["budgets"][0]["name"] == "screen" else 12
            ),
        )

    def test_public_campaign_requires_measured_preparer(self) -> None:
        config = load_campaign(CONFIG)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            with self.assertRaisesRegex(TypeError, "preparer.*required"):
                run_campaign(config, runner=object(), output_dir=Path(directory))

    def test_screen_gates_promotion_and_validation_runs_only_after_freeze(self) -> None:
        config = load_campaign(CONFIG)
        policy_type = __import__(
            "myfuzz.harness", fromlist=["StaticPolicyParameters"]
        ).StaticPolicyParameters
        accepted = policy_type(1, 2, 1, "none")
        rejected = policy_type(1, 4, 1, "none")
        calls: list[tuple[str, str, list[int], bool]] = []

        def matrix(config_value, *, runner, report_path):
            del runner
            planner = config_value["planner_config"]
            stage_name = planner["budgets"][0]["name"]
            target_id = planner["target"]["target_id"]
            seeds = planner["candidate_pair"]["seeds"]
            metadata = config_value["pair_metadata"]
            frozen = (Path(directory) / "frozen-policy.json").is_file()
            calls.append((stage_name, metadata["policy_id"], seeds, frozen))
            candidate_covered = 1 if metadata["parameters"]["event_rarity"] == 4 else (
                10 if stage_name == "screen" else 12
            )
            return self._matrix_pairs(
                metadata, target_id, seeds, candidate_covered=candidate_covered
            )

        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO", (accepted, rejected)
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=matrix,
        ):
            result = run_campaign(
                config,
                runner=object(),
                preparer=lambda manifest, _path: manifest,
                output_dir=Path(directory),
            )

        self.assertEqual(["screen", "promotion", "validation"], result["stages"])
        screen_calls = [call for call in calls if call[0] == "screen"]
        promotion_calls = [call for call in calls if call[0] == "promotion"]
        validation_calls = [call for call in calls if call[0] == "validation"]
        self.assertEqual(4, len(screen_calls))
        self.assertEqual(2, len(promotion_calls))
        self.assertEqual({(1, 7, 19)}, {tuple(call[2]) for call in promotion_calls})
        self.assertEqual({promotion_calls[0][1]}, {call[1] for call in promotion_calls})
        self.assertEqual(2, len(validation_calls))
        self.assertTrue(all(call[3] for call in validation_calls))

    def test_selector_cannot_promote_policy_rejected_by_screen(self) -> None:
        config = load_campaign(CONFIG)
        accepted = StaticPolicyParameters(1, 2, 1, "none")
        rejected = StaticPolicyParameters(1, 4, 1, "none")
        calls: list[str] = []

        def matrix(config_value, *, runner, report_path):
            del runner, report_path
            planner = config_value["planner_config"]
            metadata = config_value["pair_metadata"]
            stage_name = planner["budgets"][0]["name"]
            calls.append(stage_name)
            candidate_covered = (
                1
                if metadata["parameters"]["event_rarity"] == 4
                else (10 if stage_name == "screen" else 12)
            )
            return self._matrix_pairs(
                metadata,
                planner["target"]["target_id"],
                planner["candidate_pair"]["seeds"],
                candidate_covered=candidate_covered,
            )

        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO",
            (accepted, rejected),
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=matrix,
        ):
            with self.assertRaisesRegex(ValueError, "did not pass screening"):
                run_campaign(
                    config,
                    runner=object(),
                    preparer=lambda manifest, _path: manifest,
                    output_dir=Path(directory),
                    promotion_selector=lambda _results: promotion_decision(rejected),
                )

        self.assertNotIn("validation", calls)

    def test_selector_cannot_promote_policy_rejected_by_promotion_evidence(self) -> None:
        config = load_campaign(CONFIG)
        policy = StaticPolicyParameters(1, 2, 1, "none")
        calls: list[str] = []

        def matrix(config_value, *, runner, report_path):
            del runner, report_path
            planner = config_value["planner_config"]
            stage_name = planner["budgets"][0]["name"]
            calls.append(stage_name)
            return self._matrix_pairs(
                config_value["pair_metadata"],
                planner["target"]["target_id"],
                planner["candidate_pair"]["seeds"],
                candidate_covered=10,
            )

        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO", (policy,)
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=matrix,
        ):
            with self.assertRaisesRegex(ValueError, "authoritative promotion"):
                run_campaign(
                    config,
                    runner=object(),
                    preparer=lambda manifest, _path: manifest,
                    output_dir=Path(directory),
                    promotion_selector=lambda _results: promotion_decision(policy),
                )

        self.assertNotIn("validation", calls)
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
            self.assertNotIn("hard_memory_bytes", document)
            self.assertFalse(any(path.suffix == ".tmp" for path in absolute.parent.iterdir()))

    def test_each_training_stage_uses_the_existing_experiment_matrix(self) -> None:
        config = load_campaign(CONFIG)
        policy = __import__("myfuzz.harness", fromlist=["StaticPolicyParameters"]).StaticPolicyParameters(1, 2, 1, "none")
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO", (policy,)
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=self._passing_matrix,
        ) as matrix:
            report = run_campaign(
                config,
                runner=object(),
                preparer=lambda manifest, _path: manifest,
                output_dir=Path(directory),
                promotion_selector=authoritative_mapping,
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
            side_effect=self._passing_matrix,
        ) as matrix:
            run_campaign(
                config,
                runner=object(),
                preparer=preparer,
                output_dir=Path(directory),
                promotion_selector=authoritative_mapping,
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

    def test_campaign_publishes_negative_real_matrix_evidence_without_validation(self) -> None:
        config = load_campaign(CONFIG)
        policy = __import__(
            "myfuzz.harness", fromlist=["StaticPolicyParameters"]
        ).StaticPolicyParameters(1, 2, 1, "none")
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO", (policy,)
        ), patch.dict(
            os.environ,
            {"MYFUZZ_MEMORY_GATE_DIR": str(Path(directory) / "gates")},
        ):
            result = run_campaign(
                config,
                runner=SuccessfulMatrixRunner(),
                preparer=lambda manifest, _path: manifest,
                output_dir=Path(directory),
            )
            reports = sorted(Path(directory).glob("*/*/*-matrix.json"))

        self.assertEqual(["screen", "promotion"], result["stages"])
        self.assertFalse(result["promotion"]["promoted"])
        self.assertEqual(4, len(reports))

    def test_real_static_bundle_provenance_is_forwarded_to_matrix_manifest(self) -> None:
        config = load_campaign(CONFIG)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO",
            config.targets[:1] and (__import__("myfuzz.harness", fromlist=["StaticPolicyParameters"]).StaticPolicyParameters(1, 2, 1, "none"),),
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=self._passing_matrix,
        ) as matrix:
            run_campaign(
                config,
                runner=object(),
                preparer=lambda manifest, _path: manifest,
                output_dir=Path(directory),
                promotion_selector=authoritative_mapping,
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
            side_effect=self._passing_matrix,
        ) as matrix:
            first = run_campaign(
                config,
                runner=object(),
                preparer=lambda manifest, _path: manifest,
                output_dir=Path(directory),
                promotion_selector=lambda _results: None,
            )
            second = run_campaign(
                config,
                runner=object(),
                preparer=lambda manifest, _path: manifest,
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
        policy = __import__("myfuzz.harness", fromlist=["StaticPolicyParameters"]).StaticPolicyParameters(1, 2, 1, "none")
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, patch(
            "scripts.runs.run_static_projection_campaign.PORTFOLIO", (policy,)
        ), patch(
            "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
            side_effect=self._passing_matrix,
        ):
            first = run_campaign(
                config,
                runner=object(),
                preparer=lambda manifest, _path: manifest,
                output_dir=Path(directory),
                promotion_selector=authoritative_mapping,
            )
            frozen_path = Path(directory) / "frozen-policy.json"
            payload = frozen_path.read_bytes()
            frozen_path.unlink()
            with patch(
                "scripts.runs.run_static_projection_campaign.run_experiment_matrix",
                side_effect=self._passing_matrix,
            ):
                second = run_campaign(
                    config,
                    runner=object(),
                    preparer=lambda manifest, _path: manifest,
                    output_dir=Path(directory),
                    promotion_selector=authoritative_mapping,
                )
            self.assertEqual(payload, frozen_path.read_bytes())
            self.assertEqual(first["frozen"], second["frozen"])
            self.assertFalse(any(path.suffix == ".tmp" for path in Path(directory).iterdir()))


if __name__ == "__main__":
    unittest.main()
