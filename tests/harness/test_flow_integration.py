from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parents[2] / "src" / "myfuzz" / "scripts"
if SCRIPT_DIR.as_posix() not in sys.path:
    sys.path.insert(0, SCRIPT_DIR.as_posix())

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

    def test_flow_has_no_identifier_role_tables(self) -> None:
        source = (SCRIPT_DIR / "frontend_manifest_to_rfuzz_toml.py").read_text()
        self.assertNotIn("CLOCK_NAMES", source)
        self.assertNotIn("RESET_NAMES", source)
        self.assertNotIn("ACTIVE_LOW_RESET_NAMES", source)


if __name__ == "__main__":
    unittest.main()
