from __future__ import annotations

import copy
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from myfuzz.experiments import RfuzzAdapter, plan_experiment


SCRIPT_DIR = Path(__file__).resolve().parents[2] / "src" / "myfuzz" / "scripts"
ROOT = Path(__file__).resolve().parents[2]
if SCRIPT_DIR.as_posix() not in sys.path:
    sys.path.insert(0, SCRIPT_DIR.as_posix())

import frontend_manifest_to_rfuzz_toml  # noqa: E402
from frontend_manifest_to_rfuzz_toml import write_toml  # noqa: E402
import run_design_flow  # noqa: E402


def candidate_manifest() -> dict[str, object]:
    return {
        "schema_version": "candidate_manifest.v1",
        "combinational_design": False,
        "candidate_id": "candidate-flow",
        "top": {"module": "generated_top"},
        "top_port_abi": [
            {"port_id": 1, "emitted_name": "wire_17", "direction": "input", "width": 1, "semantic_role": "clock", "active_level": 1, "fuzzable": False},
            {"port_id": 2, "emitted_name": "data_3", "direction": "input", "width": 1, "semantic_role": "reset", "active_level": 0, "synchronous": False, "reset_value": 0, "fuzzable": False},
            {"port_id": 3, "emitted_name": "payload_opaque", "direction": "input", "width": 8, "semantic_role": "data", "fuzzable": True},
            {"port_id": 4, "emitted_name": "result_opaque", "direction": "output", "width": 1, "semantic_role": "response", "fuzzable": False},
        ],
        "coverage_universe": [],
    }


def frontend_manifest() -> dict[str, object]:
    return {
        "modules": [
            {
                "name": "generated_top",
                "origName": "generated_top",
                "top": True,
                "ports": [
                    {"name": "wire_17", "direction": "input", "width": 1},
                    {"name": "data_3", "direction": "input", "width": 1},
                    {"name": "payload_opaque", "direction": "input", "width": 8},
                    {"name": "result_opaque", "direction": "output", "width": 1},
                ],
            }
        ]
    }


def instrumentation_manifest() -> dict[str, object]:
    return {
        "coverage_port": "__vi_coverage",
        "coverage_point_count": 1,
        "coverage": [{"module": "generated_top", "signal": "branch_0", "kind": "branch", "subtype": "hit", "file": "top.sv", "line": 1, "column": 1}],
    }


class FlowIntegrationTest(unittest.TestCase):
    def test_opaque_control_names_are_selected_only_by_manifest_roles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "flow.toml"
            write_toml(
                frontend_manifest(),
                instrumentation_manifest(),
                "generated_top",
                output,
                candidate_manifest=candidate_manifest(),
            )
            text = output.read_text()
        self.assertIn('name = "payload_opaque"', text)
        self.assertNotIn('name = "wire_17"', text)
        self.assertNotIn('name = "data_3"', text)

    def test_missing_control_declaration_and_reset_metadata_fail(self) -> None:
        missing = candidate_manifest()
        missing["top_port_abi"][0].pop("semantic_role")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                write_toml(frontend_manifest(), instrumentation_manifest(), "generated_top", Path(directory) / "x.toml", candidate_manifest=missing)

        contradictory = candidate_manifest()
        contradictory["top_port_abi"][1]["active_level"] = 1
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                write_toml(frontend_manifest(), instrumentation_manifest(), "generated_top", Path(directory) / "x.toml", candidate_manifest=contradictory)

    def test_combinational_manifest_does_not_require_controls(self) -> None:
        manifest = candidate_manifest()
        manifest["combinational_design"] = True
        manifest["top_port_abi"] = [port for port in manifest["top_port_abi"] if port["semantic_role"] not in {"clock", "reset"}]
        frontend = copy.deepcopy(frontend_manifest())
        frontend["modules"][0]["ports"] = [port for port in frontend["modules"][0]["ports"] if port["name"] not in {"wire_17", "data_3"}]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "flow.toml"
            write_toml(frontend, instrumentation_manifest(), "generated_top", output, candidate_manifest=manifest)
            text = output.read_text()
        self.assertIn('name = "payload_opaque"', text)

    def test_flow_cli_forwards_manifest_and_candidate_mode(self) -> None:
        argv = ["run_design_flow.py", "--config", "config.json", "--manifest", "candidate.json", "--candidate-mode", "candidate_depaware"]
        with patch.object(sys, "argv", argv):
            args = run_design_flow.parse_args()
        self.assertEqual("candidate.json", args.manifest)
        self.assertEqual("candidate_depaware", args.candidate_mode)

        with patch.object(sys, "argv", ["run_design_flow.py", "--config", "config.json"]):
            defaults = run_design_flow.parse_args()
        self.assertIsNone(defaults.candidate_mode)
        self.assertEqual("candidate_direct", run_design_flow.select_candidate_mode(None, {}))
        self.assertEqual("flat_direct", run_design_flow.select_candidate_mode(None, {"candidate_mode": "flat_direct"}))
        self.assertEqual("candidate_depaware", run_design_flow.select_candidate_mode("candidate_depaware", {"candidate_mode": "flat_direct"}))

    def test_flow_cli_accepts_adapter_seed_and_cycle_bounds(self) -> None:
        argv = [
            "run_design_flow.py",
            "--config",
            "config.json",
            "--stage",
            "fuzz",
            "--seed",
            "19",
            "--max-cycles",
            "1000",
        ]
        with patch.object(sys, "argv", argv):
            args = run_design_flow.parse_args()

        self.assertEqual(19, args.seed)
        self.assertEqual(1000, args.max_cycles)
        self.assertIsNone(args.fuzz_seconds)

    def test_planned_cycle_budget_round_trips_through_driver_argv(self) -> None:
        config = json.loads(
            (ROOT / "configs" / "experiments" / "rvx.json").read_text()
        )
        manifest = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "contracts"
                / "candidate_manifest.v1.valid.json"
            ).read_text()
        )
        planned = plan_experiment(config, [manifest])
        cycle_job = next(job for job in planned.jobs if job.budget_kind == "cycles")

        command = RfuzzAdapter(ROOT).command(cycle_job)
        with patch.object(sys, "argv", [command[1], *command[2:]]):
            args = run_design_flow.parse_args()

        self.assertEqual(config["design_config_path"], args.config)
        self.assertEqual("fuzz", args.stage)
        self.assertEqual("1", args.jobs)
        self.assertEqual(cycle_job.seed, args.seed)
        self.assertEqual(cycle_job.budget_value, args.max_cycles)
        self.assertIsNone(args.fuzz_seconds)

        with tempfile.TemporaryDirectory() as directory:
            execution_root = Path(directory)
            source_config = ROOT / config["design_config_path"]
            runtime_config = execution_root / config["design_config_path"]
            runtime_config.parent.mkdir(parents=True)
            runtime_config.write_text(source_config.read_text())
            with (
                patch.object(run_design_flow, "repo_root", return_value=execution_root),
                patch.object(
                    run_design_flow,
                    "default_frontend_library",
                    return_value=execution_root / "frontend.so",
                ),
                patch.object(
                    run_design_flow,
                    "default_server_verilator",
                    return_value="verilator",
                ),
                patch.object(run_design_flow, "stage_fuzz") as fuzz_stage,
                patch.object(sys, "argv", [command[1], *command[2:]]),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(0, run_design_flow.main())

        driver_config = fuzz_stage.call_args.args[1]
        self.assertEqual(cycle_job.seed, driver_config["fuzz"]["seed"])
        self.assertEqual(cycle_job.budget_value, driver_config["fuzz"]["max_cycles"])
        self.assertIsNone(fuzz_stage.call_args.args[4])

    def test_cycle_only_fuzz_has_no_wall_clock_deadline(self) -> None:
        paths = {"out_dir": Path("run")}
        with (
            patch.object(run_design_flow, "build_fuzzer", return_value=Path("kfuzz")),
            patch.object(
                run_design_flow,
                "run_fuzz_attempt",
                return_value=("ok", 0, 0, None),
            ) as attempt,
        ):
            run_design_flow.stage_fuzz(
                Path("."),
                {"fuzz": {"max_cycles": 1000}},
                Path("config.json"),
                paths,
                None,
            )

        self.assertIsNone(attempt.call_args.args[5])

    def test_stage_harness_materializes_all_modes_and_propagates_abi(self) -> None:
        captured: dict[str, dict] = {}

        def generate_harness_files(conf, ports, top, out_dir, harness_cfg):
            del conf, ports, top
            captured[harness_cfg["candidate_mode"]] = dict(harness_cfg)
            augmented = Path(out_dir) / f"{harness_cfg['candidate_mode']}.rfuzz.toml"
            augmented.write_text("[general]\n")
            return Path(harness_cfg["manual_harness"]), augmented

        api = (
            generate_harness_files,
            lambda path: {"source": str(path)},
            lambda frontend, top: frontend["modules"][0]["ports"],
            lambda *args: None,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "harness": root / "harness",
                "toml": root / "input.toml",
                "instrumented": root / "instrumented",
            }
            paths["toml"].write_text("[general]\n")
            artifacts = {}
            with patch.object(run_design_flow, "rfuzz_harness_api", return_value=api):
                for mode in ("flat_direct", "candidate_direct", "candidate_depaware"):
                    artifacts[mode] = run_design_flow.stage_harness(
                        root,
                        {"top": "generated_top", "harness": {"validate": False}},
                        paths,
                        "verilator",
                        frontend_manifest(),
                        candidate_manifest(),
                        mode,
                    )

            for mode, artifact in artifacts.items():
                source = paths["harness"] / f"{mode}.sv"
                abi = paths["harness"] / f"{mode}.abi.json"
                fragment = json.loads(abi.read_text())
                self.assertEqual(artifact.source_text, source.read_text())
                self.assertEqual(mode, fragment["mode"])
                self.assertEqual(artifact.abi.abi_hash, fragment["abi_hash"])
                self.assertEqual(artifact.raw_width, fragment["raw_width"])
                self.assertEqual(source.resolve().as_posix(), captured[mode]["manual_harness"])
                self.assertEqual(abi.resolve().as_posix(), captured[mode]["raw_abi_manifest"])
            self.assertEqual({8}, {artifact.raw_width for artifact in artifacts.values()})

    def test_toml_stage_uses_materialized_raw_abi_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {"harness": root / "harness", "toml": root / "flow.toml"}
            run_design_flow.stage_toml(
                root,
                {"top": "generated_top"},
                paths,
                frontend_manifest(),
                instrumentation_manifest(),
                candidate_manifest(),
                "candidate_depaware",
            )
            text = paths["toml"].read_text()
            fragment = json.loads((paths["harness"] / "candidate_depaware.abi.json").read_text())
        self.assertIn('name = "rfuzz_input_bits"', text)
        self.assertIn("width = 8", text)
        self.assertNotIn('name = "payload_opaque"', text)
        self.assertEqual("candidate_depaware", fragment["mode"])

    def test_toml_stage_rejects_stale_candidate_manifest_before_manual_input(self) -> None:
        manifest = candidate_manifest()
        manifest["top_port_abi"][2]["width"] = 7
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {"harness": root / "harness", "toml": root / "flow.toml"}
            with self.assertRaisesRegex(ValueError, "mapping mismatch"):
                run_design_flow.stage_toml(
                    root,
                    {"top": "generated_top"},
                    paths,
                    frontend_manifest(),
                    instrumentation_manifest(),
                    manifest,
                    "candidate_depaware",
                )
            self.assertFalse(paths["harness"].exists())

    def test_toml_rejects_invalid_fuzz_disposition(self) -> None:
        manifest = candidate_manifest()
        manifest["top_port_abi"][2]["fuzzable"] = "typo"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "invalid fuzz disposition"):
                write_toml(
                    frontend_manifest(),
                    instrumentation_manifest(),
                    "generated_top",
                    Path(directory) / "flow.toml",
                    candidate_manifest=manifest,
                )

    def test_toml_accepts_abi_fuzz_disposition_aliases(self) -> None:
        manifest = candidate_manifest()
        manifest["top_port_abi"][2].pop("fuzzable")
        manifest["top_port_abi"][2]["fuzz_disposition"] = "fuzz"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "flow.toml"
            write_toml(
                frontend_manifest(),
                instrumentation_manifest(),
                "generated_top",
                output,
                candidate_manifest=manifest,
            )
            self.assertIn('name = "payload_opaque"', output.read_text())

    def test_toml_rejects_candidate_top_that_only_matches_missing_requested_top(self) -> None:
        frontend = frontend_manifest()
        frontend["modules"][0]["name"] = "fallback_generated_top"
        frontend["modules"][0]["origName"] = "fallback_original_top"
        manifest = candidate_manifest()
        manifest["top"]["module"] = "requested_but_missing_top"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "selected frontend module"):
                write_toml(
                    frontend,
                    instrumentation_manifest(),
                    "requested_but_missing_top",
                    Path(directory) / "flow.toml",
                    candidate_manifest=manifest,
                )

    def test_toml_rejects_input_without_explicit_fuzz_disposition(self) -> None:
        manifest = candidate_manifest()
        manifest["top_port_abi"][2].pop("fuzzable")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "fuzz disposition must be explicit"):
                write_toml(
                    frontend_manifest(),
                    instrumentation_manifest(),
                    "generated_top",
                    Path(directory) / "flow.toml",
                    candidate_manifest=manifest,
                )

    def test_toml_rejects_output_without_explicit_fuzz_disposition(self) -> None:
        manifest = candidate_manifest()
        manifest["top_port_abi"][3].pop("fuzzable")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "fuzz disposition must be explicit"):
                write_toml(
                    frontend_manifest(),
                    instrumentation_manifest(),
                    "generated_top",
                    Path(directory) / "flow.toml",
                    candidate_manifest=manifest,
                )

    def test_toml_rejects_unbound_non_fuzzable_data_input(self) -> None:
        manifest = candidate_manifest()
        manifest["top_port_abi"][2]["fuzzable"] = False
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "unbound non-fuzzable input"):
                write_toml(
                    frontend_manifest(),
                    instrumentation_manifest(),
                    "generated_top",
                    Path(directory) / "flow.toml",
                    candidate_manifest=manifest,
                )

    def test_toml_emitter_rejects_candidate_mode_option(self) -> None:
        with patch.object(
            sys,
            "argv",
            [
                "frontend_manifest_to_rfuzz_toml.py",
                "--frontend",
                "frontend.json",
                "--instrumentation",
                "instrumentation.json",
                "--top",
                "generated_top",
                "--out",
                "flow.toml",
                "--manifest",
                "candidate.json",
                "--candidate-mode",
                "candidate_direct",
            ],
        ):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    frontend_manifest_to_rfuzz_toml.parse_args()

    def test_stage_harness_rejects_wrong_candidate_schema_before_rfuzz(self) -> None:
        manifest = candidate_manifest()
        manifest["schema_version"] = "candidate_manifest.v2"
        with tempfile.TemporaryDirectory() as directory:
            paths = {"harness": Path(directory) / "harness", "toml": Path(directory) / "x.toml"}
            with patch.object(run_design_flow, "rfuzz_harness_api", side_effect=AssertionError("rfuzz should not load")):
                with self.assertRaisesRegex(ValueError, "schema_version"):
                    run_design_flow.stage_harness(
                        Path(directory),
                        {"top": "generated_top"},
                        paths,
                        "verilator",
                        frontend_manifest(),
                        manifest,
                        "candidate_direct",
                    )

    def test_stage_harness_rejects_candidate_mapping_mismatch_before_materialization(self) -> None:
        manifest = candidate_manifest()
        manifest["top_port_abi"][2]["width"] = 7
        with tempfile.TemporaryDirectory() as directory:
            paths = {"harness": Path(directory) / "harness", "toml": Path(directory) / "x.toml"}
            with patch.object(run_design_flow, "rfuzz_harness_api", side_effect=AssertionError("rfuzz should not load")):
                with self.assertRaisesRegex(ValueError, "mapping mismatch"):
                    run_design_flow.stage_harness(
                        Path(directory),
                        {"top": "generated_top"},
                        paths,
                        "verilator",
                        frontend_manifest(),
                        manifest,
                        "candidate_direct",
                    )
            self.assertFalse(paths["harness"].exists())

    def test_stage_harness_rejects_candidate_top_mismatch_before_materialization(self) -> None:
        manifest = candidate_manifest()
        manifest["top"]["module"] = "other_top"
        with tempfile.TemporaryDirectory() as directory:
            paths = {"harness": Path(directory) / "harness", "toml": Path(directory) / "x.toml"}
            with patch.object(run_design_flow, "rfuzz_harness_api", side_effect=AssertionError("rfuzz should not load")):
                with self.assertRaisesRegex(ValueError, "selected frontend module"):
                    run_design_flow.stage_harness(
                        Path(directory),
                        {"top": "generated_top"},
                        paths,
                        "verilator",
                        frontend_manifest(),
                        manifest,
                        "candidate_direct",
                    )
            self.assertFalse(paths["harness"].exists())

    def test_flow_has_no_identifier_role_tables(self) -> None:
        source = (SCRIPT_DIR / "frontend_manifest_to_rfuzz_toml.py").read_text()
        self.assertNotIn("CLOCK_NAMES", source)
        self.assertNotIn("RESET_NAMES", source)
        self.assertNotIn("ACTIVE_LOW_RESET_NAMES", source)


if __name__ == "__main__":
    unittest.main()
