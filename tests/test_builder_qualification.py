import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    InputValidationError, compute_oracle_digest, evaluate_acceptance,
    load_qualification_oracle,
)
from myfuzz.builder.qualification import _sha256  # noqa: E402


SEMANTICS = (
    "clock", "reset", "awvalid", "awready", "awaddr", "wvalid", "wready", "wdata",
    "wstrb", "bvalid", "bready", "bresp", "arvalid", "arready", "araddr", "rvalid",
    "rready", "rdata", "rresp",
)


def _interface(prefix):
    return {semantic: f"{prefix}_{semantic}" for semantic in SEMANTICS}


def _module_source(identifier, kind, width):
    cpu_inputs = {
        "clock", "reset", "awready", "wready", "bvalid", "bresp", "arready", "rvalid",
        "rdata", "rresp",
    }
    widths = {
        "clock": 1, "reset": 1, "awvalid": 1, "awready": 1, "awaddr": 32,
        "wvalid": 1, "wready": 1, "wdata": width, "wstrb": width // 8,
        "bvalid": 1, "bready": 1, "bresp": 2, "arvalid": 1, "arready": 1,
        "araddr": 32, "rvalid": 1, "rready": 1, "rdata": width, "rresp": 2,
    }
    inputs = cpu_inputs if kind == "cpu" else set(SEMANTICS) - cpu_inputs
    inputs.update(("clock", "reset"))
    declarations = []
    for semantic in SEMANTICS:
        direction = "input" if semantic in inputs else "output"
        packed = "" if widths[semantic] == 1 else f" [{widths[semantic] - 1}:0]"
        declarations.append(f"    {direction} logic{packed} {identifier}_{semantic}")
    return f"module {identifier}(\n" + ",\n".join(declarations) + "\n);\nendmodule\n"


class QualificationTest(unittest.TestCase):
    def _oracle(self, root):
        license_path = root / "LICENSE"
        license_path.write_text("MIT\n")
        candidates = []
        for identifier, kind, width, split in (
            ("cpu32", "cpu", 32, "development"),
            ("cpu64", "cpu", 64, "holdout"),
            ("ip32a", "ip", 32, "development"),
            ("ip32b", "ip", 32, "development"),
            ("ip64a", "ip", 64, "holdout"),
            ("ip64b", "ip", 64, "holdout"),
        ):
            source = root / f"{identifier}.sv"
            source.write_text(_module_source(identifier, kind, width))
            filelist = root / f"{identifier}.f"
            filelist.write_text(source.name + "\n")
            candidates.append({
                "id": identifier, "kind": kind, "module": identifier,
                "family": ({"cpu64": "holdout_cpu", "ip64a": "holdout_ip",
                            "ip64b": "holdout_ip"}.get(identifier, identifier)),
                "split": split, "status": "qualified",
                "reason": "fixture", "protocol": "axi_lite", "data_width": width,
                "address_width": 32, "filelist": filelist.name,
                "parameters": {},
                "filelist_sha256": _sha256(filelist.read_bytes()),
                "sources": [{"path": source.name, "sha256": _sha256(source.read_bytes()),
                             "size": source.stat().st_size}],
                "dependencies": [],
                "licenses": [{"spdx": "MIT", "path": license_path.name,
                              "sha256": _sha256(license_path.read_bytes()),
                              "redistribution": True, "applies_to": [source.name]}],
                "provenance": {"upstreams": [{"source": "fixture", "revision": "r1",
                                               "archive_sha256": "a" * 64,
                                               "submodules": []}], "patches": []},
                "interface": _interface(identifier),
            })
        for index in range(5):
            rejected = dict(candidates[2])
            rejected.update({
                "id": f"rejected_{index}", "family": f"rejected_{index}",
                "status": "rejected", "reason": "frozen rejected fixture", "interface": {},
            })
            candidates.append(rejected)
        compatibility = []
        for cpu in ("cpu32", "cpu64"):
            for ip in ("ip32a", "ip32b", "ip64a", "ip64b"):
                candidate_by_id = {candidate["id"]: candidate for candidate in candidates}
                compatible = (
                    ("32" in cpu) == ("32" in ip)
                    and candidate_by_id[cpu]["split"] == candidate_by_id[ip]["split"]
                )
                compatibility.append({"cpu": cpu, "ip": ip, "compatible": compatible,
                                      "reason": "equal data width" if compatible else "width mismatch"})
        cases = [
            {"id": "development_case", "split": "development", "cpu": "cpu32",
             "ips": ["ip32a", "ip32b"], "manifest_hash": "b" * 64,
             "expected_artifact_bytes": 100000,
             "resource_budget": {"compile_seconds": 60, "run_seconds": 30, "max_bytes": 1000000}},
            {"id": "holdout_case", "split": "holdout", "cpu": "cpu64",
             "ips": ["ip64a", "ip64b"], "manifest_hash": "c" * 64,
             "expected_artifact_bytes": 100000,
             "resource_budget": {"compile_seconds": 60, "run_seconds": 30, "max_bytes": 1000000}},
        ]
        oracle = {
            "schema": "myfuzz.qualification-oracle/v1", "oracle_version": "1",
            "oracle_implementation_sha256": _sha256(
                (ROOT / "src/myfuzz/builder/qualification.py").read_bytes()
            ),
            "frozen_revision": "fixture-revision", "protocol": "axi_lite",
            "oracle_digest": "",
            "dataset": {
                "split_unit": "source_family", "policy": "frozen_family_assignments_v1",
                "development_percent": 80, "holdout_percent": 20,
                "family_assignments": [
                    {"family": family, "split": split}
                    for family, split in dict.fromkeys(
                        (candidate["family"], candidate["split"]) for candidate in candidates
                    )
                ],
            },
            "candidates": candidates, "compatibility": compatibility,
            "cases": cases,
            "experiment": {
                "seeds": [1, 2], "cycles": 100, "timeout_seconds": 30, "early_cycle": 20,
                "entropy_matched": True, "coverage_reset": "fresh_process_per_run",
                "merge": "point_id_union", "censoring": "timeouts_are_failures",
                "confidence_interval": "paired_bootstrap_95_percent",
                "confidence_level": 0.95, "bootstrap_resamples": 1000, "bootstrap_seed": 9,
                "determinism_check": "repeat_first_seed_byte_identical",
            },
        }
        oracle["oracle_digest"] = compute_oracle_digest(oracle)
        path = root / "oracle.json"
        path.write_text(json.dumps(oracle, indent=2, sort_keys=True) + "\n")
        return path, oracle

    def test_frozen_oracle_checks_split_matrix_and_acceptance_denominator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, raw = self._oracle(root)
            oracle = load_qualification_oracle(path, materials_root=root)
            self.assertEqual(oracle.digest, raw["oracle_digest"])
            self.assertEqual(len(oracle.qualified), 6)
            case_results = [{"case_id": case["id"], "status": "passed"} for case in raw["cases"]]
            runs = []
            for case in raw["cases"]:
                for seed in raw["experiment"]["seeds"]:
                    for mode in ("raw", "constrained"):
                        runs.append({
                            "case_id": case["id"], "seed": seed, "mode": mode,
                            "status": "passed", "bit_budget": 100,
                            "coverage_cleared": True, "first_new_coverage_cycle": 5,
                            "early_coverage": 3 if mode == "constrained" else 2,
                            "longest_plateau": 2 if mode == "constrained" else 4,
                            "final_coverage": 10,
                        })
            result = evaluate_acceptance(oracle, case_results, runs)
            self.assertEqual(result["pass_rate"], 1.0)
            self.assertTrue(result["constrained_reduces_plateau"])
            self.assertEqual(result["run_count"], 8)
            self.assertEqual(result["paired_delta_intervals"]["early_coverage"]["estimate"], 1)

    def test_qualified_interfaces_are_proved_by_shared_ast_frontend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _ = self._oracle(root)
            oracle = load_qualification_oracle(path, materials_root=root, verify_elaboration=True)
            self.assertEqual(len(oracle.qualified), 6)

    def test_wrong_material_and_missing_denominator_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, raw = self._oracle(root)
            raw["candidates"][2]["interface"].pop("rresp")
            raw["oracle_digest"] = compute_oracle_digest(raw)
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(InputValidationError, "complete AXI-Lite"):
                load_qualification_oracle(path, materials_root=root)

            path, raw = self._oracle(root)
            oracle = load_qualification_oracle(path, materials_root=root)
            with self.assertRaisesRegex(InputValidationError, "case results"):
                evaluate_acceptance(oracle, [], [])

    def test_rejected_candidate_may_record_incomplete_interface(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, raw = self._oracle(root)
            rejected = dict(raw["candidates"][2])
            rejected.update({"id": "private_bus", "family": "rejected_0", "status": "rejected",
                             "reason": "not AXI-Lite", "interface": {}})
            raw["candidates"].append(rejected)
            raw["oracle_digest"] = compute_oracle_digest(raw)
            path.write_text(json.dumps(raw))
            oracle = load_qualification_oracle(path, materials_root=root)
            self.assertEqual(len(oracle.qualified), 6)

    def test_transitive_dependency_and_family_ratio_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, raw = self._oracle(root)
            dependency = root / "defs.svh"
            dependency.write_text("`define VALUE 1\n")
            raw["candidates"][0]["dependencies"] = [{
                "path": dependency.name, "sha256": _sha256(dependency.read_bytes()),
                "size": dependency.stat().st_size,
            }]
            raw["candidates"][0]["licenses"][0]["applies_to"].append(dependency.name)
            raw["oracle_digest"] = compute_oracle_digest(raw)
            path.write_text(json.dumps(raw))
            dependency.write_text("`define VALUE 2\n")
            with self.assertRaisesRegex(InputValidationError, "dependency content mismatch"):
                load_qualification_oracle(path, materials_root=root)

            path, raw = self._oracle(root)
            raw["dataset"]["family_assignments"][0]["split"] = "holdout"
            raw["oracle_digest"] = compute_oracle_digest(raw)
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(InputValidationError, "assignments"):
                load_qualification_oracle(path, materials_root=root)

    def test_checked_in_oracle_is_reproducible_and_all_qualified_ports_elaborate(self):
        oracle_path = ROOT / "materials/qualification/axi_lite/oracle.json"
        oracle = load_qualification_oracle(
            oracle_path, materials_root=ROOT / "materials", verify_elaboration=True,
        )
        self.assertEqual(len(oracle.data["candidates"]), 12)
        self.assertEqual(len(oracle.qualified), 6)
        self.assertEqual(len(oracle.data["dataset"]["family_assignments"]), 10)


if __name__ == "__main__":
    unittest.main()
