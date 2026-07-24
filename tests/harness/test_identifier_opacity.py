from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.contracts import content_hash
from myfuzz.experiments import prepare_candidate_runtime
from tests.runtime_fixtures import load_runtime_documents


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = ROOT / "src" / "myfuzz"
CONFIG = ROOT / "configs" / "experiments" / "ibex_opentitan.json"
OWNED_AREAS = ("protocols", "dependency", "harness", "experiments")
EMISSION_ALLOWLIST = {Path("harness/direct.py")}
FORBIDDEN_KEYS = {
    "module_name",
    "instance_name",
    "port_name",
    "net_name",
    "file_name",
    "directory_name",
    "target_name",
}
FORBIDDEN_LABELS = {"rvx", "ibex", "opentitan", "uart", "gpio", "rv_timer"}


def _constant_strings(node: ast.AST) -> set[str]:
    return {
        child.value.casefold()
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    }


def _job_behavior(runtime: object) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            job.harness,
            job.seed,
            job.budget_name,
            job.budget_kind,
            job.budget_value,
            job.estimated_rss_bytes,
            job.requested_mib,
            job.worker_limit,
            job.raw_width,
            job.instrumented_rtl_hash,
            job.coverage_universe,
            job.coverage_metadata_hash,
        )
        for job in runtime.experiment_plan.jobs
    )


class IdentifierOpacityTest(unittest.TestCase):
    def test_terminal_b_source_does_not_read_diagnostic_names_or_branch_on_targets(self) -> None:
        violations: list[str] = []
        for area in OWNED_AREAS:
            for source in sorted((SOURCE_ROOT / area).rglob("*.py")):
                relative = source.relative_to(SOURCE_ROOT)
                tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(relative))
                for node in ast.walk(tree):
                    if relative not in EMISSION_ALLOWLIST:
                        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_KEYS:
                            violations.append(f"{relative}:{node.lineno}: attribute {node.attr}")
                        if isinstance(node, ast.Subscript):
                            key = node.slice.value if isinstance(node.slice, ast.Constant) else None
                            if key in FORBIDDEN_KEYS:
                                violations.append(f"{relative}:{node.lineno}: subscript {key}")
                        if (
                            isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Attribute)
                            and node.func.attr in {"get", "pop", "setdefault"}
                            and node.args
                            and isinstance(node.args[0], ast.Constant)
                            and node.args[0].value in FORBIDDEN_KEYS
                        ):
                            violations.append(f"{relative}:{node.lineno}: lookup {node.args[0].value}")
                    if isinstance(node, ast.Compare):
                        labels = _constant_strings(node)
                        for label in sorted(labels & FORBIDDEN_LABELS):
                            violations.append(f"{relative}:{node.lineno}: comparison {label}")
        self.assertEqual([], violations, "\n".join(violations))

    def test_diagnostic_identifier_renames_do_not_change_runtime_semantics(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
        renamed = copy.deepcopy((facts, composition, manifest, config))
        renamed_facts, renamed_composition, renamed_manifest, renamed_config = renamed

        renamed_facts["modules"][0]["module_name"] = "rvx"
        renamed_facts["ports"][0]["port_name"] = "uart"
        renamed_facts["ports"][1]["port_name"] = "gpio"
        renamed_composition["components"][0]["instance_name"] = "opentitan"
        renamed_composition["endpoint_bindings"][0]["net_name"] = "rv_timer"
        renamed_manifest["top"]["module"] = "renamed_top"
        renamed_manifest["top"]["source"] = "renamed_source.sv"
        renamed_manifest["top_port_abi"][0]["emitted_name"] = "renamed_port"
        renamed_facts["source_symbols"][0]["name"] = "renamed_top"
        renamed_facts["source_symbols"][1]["name"] = "renamed_port"
        renamed_port = renamed_manifest["top_port_abi"][0]
        actual_port = renamed_facts["ports"][0]
        renamed_port["validation_evidence_id"] = content_hash(
            {
                "top_module_id": renamed_facts["modules"][0]["id"],
                "logical_port_id": renamed_port["port_id"],
                "actual": {
                    "actual_port_id": renamed_port["actual_port_id"],
                    "emitted_name": renamed_port["emitted_name"],
                    "direction": actual_port["direction"],
                    "width": actual_port["width"],
                    "signed": actual_port["signed"],
                    "declared_role": actual_port["declared_role"],
                },
            }
        )
        renamed_config["target"]["display"] = "renamed target"
        renamed_manifest["composition_ir_hash"] = content_hash(renamed_composition)
        facts_hash = content_hash(renamed_facts)
        renamed_manifest["hdl_facts"]["content_hash"] = facts_hash
        renamed_manifest["validation"]["evidence"]["reparse"][
            "hdl_facts_content_hash"
        ] = facts_hash

        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            baseline = prepare_candidate_runtime(facts, composition, manifest, config, Path(first))
            changed = prepare_candidate_runtime(*renamed, Path(second))

        self.assertEqual(baseline.harness_bundle.protocol_ids, changed.harness_bundle.protocol_ids)
        self.assertEqual(baseline.harness_bundle.dependency_graph, changed.harness_bundle.dependency_graph)
        self.assertEqual(
            baseline.harness_bundle.candidate_direct.abi,
            changed.harness_bundle.candidate_direct.abi,
        )
        self.assertEqual(
            baseline.harness_bundle.candidate_depaware.abi,
            changed.harness_bundle.candidate_depaware.abi,
        )
        self.assertEqual(_job_behavior(baseline), _job_behavior(changed))
        self.assertNotEqual(
            baseline.harness_bundle.candidate_direct.source_text,
            changed.harness_bundle.candidate_direct.source_text,
        )


if __name__ == "__main__":
    unittest.main()
