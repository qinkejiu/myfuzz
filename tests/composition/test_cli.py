#!/usr/bin/env python3
"""Composition CLI orchestration and generated-top reparse tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from myfuzz.composition import compose_topk, load_declarations, normalize_facts
from myfuzz.contracts import content_hash, validate_contract
from myfuzz.scripts.frontend_api import FrontendLibrary, default_frontend_library


ROOT = Path(__file__).resolve().parents[2]


def _protocol() -> dict[str, object]:
    return {
        "schema_version": "protocol.v1",
        "protocol_id": "opaque-bus",
        "plugin_version": "1.0.0",
        "capability_profile": {"max_outstanding": 1, "reorders_ids": False},
        "endpoint_roles": ["initiator", "target"],
        "channels": [
            {
                "id": 1,
                "role": "request",
                "fields": [
                    {
                        "id": 10,
                        "role": "request.data",
                        "direction": "initiator_to_target",
                        "width": {"min": 8, "max": 8},
                        "required": True,
                    }
                ],
            }
        ],
        "temporal_rules": [],
        "dependency_edges": [],
        "legal_adapters": [],
        "projection_actions": [],
        "capability_limits": {
            "supports_bursts": False,
            "supports_source_id_reorder": False,
        },
    }


def _write_inputs(workdir: Path) -> tuple[Path, Path]:
    source = workdir / "opaque.sv"
    source.write_text(
        "module m0(output logic [7:0] p0, input logic p1);\n"
        "  assign p0 = {8{p1}};\n"
        "endmodule\n"
        "module m1(input logic [7:0] p2, input logic p3, output logic p4);\n"
        "  assign p4 = ^p2 ^ p3;\n"
        "endmodule\n"
        "module catalog(input logic p5, output logic [7:0] p6, output logic p7);\n"
        "  m0 i0(.p0(p6), .p1(p5));\n"
        "  m1 i1(.p2(p6), .p3(p5), .p4(p7));\n"
        "endmodule\n",
        encoding="ascii",
    )
    library = default_frontend_library(ROOT)
    verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
    with patch.dict(
        os.environ,
        {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
    ):
        facts = FrontendLibrary(library).facts(
            ["--lint-only", "-Wno-fatal", "--top-module", "catalog", "opaque.sv"],
            workdir,
        )
    facts_path = workdir / "hdl_facts.json"
    facts_path.write_text(json.dumps(facts, sort_keys=True) + "\n", encoding="utf-8")

    symbol_by_id = {
        int(symbol["entity_id"]): str(symbol["name"])
        for symbol in facts["source_symbols"]
    }
    module_by_name = {
        symbol_by_id[int(module["id"])]: int(module["id"])
        for module in facts["modules"]
    }
    ports_by_module = {
        module_id: {
            symbol_by_id[int(port["id"])]: int(port["id"])
            for port in facts["ports"]
            if int(port["module_id"]) == module_id
        }
        for module_id in module_by_name.values()
    }
    m0 = module_by_name["m0"]
    m1 = module_by_name["m1"]
    declarations = {
        "schema_version": "composition_declarations.v1",
        "source_root": ".",
        "sources": ["opaque.sv"],
        "verilator_args": ["-Wno-fatal", "--top-module", "catalog"],
        "protocols": [_protocol()],
        "components": [
            {
                "id": "component-0",
                "module_id": m0,
                "role": "initiator",
                "ports": [
                    {"port_id": ports_by_module[m0]["p0"], "role": "request.data", "required": True},
                    {"port_id": ports_by_module[m0]["p1"], "role": "clock", "required": True},
                ],
                "protocol_bindings": [
                    {
                        "id": "endpoint-0",
                        "protocol_id": "opaque-bus",
                        "side": "initiator",
                        "fields": [
                            {"field_role": "request.data", "port_id": ports_by_module[m0]["p0"]}
                        ],
                    }
                ],
                "clock_reset": [
                    {
                        "port_id": ports_by_module[m0]["p1"],
                        "kind": "clock",
                        "domain_id": "domain-0",
                        "active_level": "high",
                        "synchronous": False,
                    }
                ],
            },
            {
                "id": "component-1",
                "module_id": m1,
                "role": "target",
                "ports": [
                    {"port_id": ports_by_module[m1]["p2"], "role": "request.data", "required": True},
                    {"port_id": ports_by_module[m1]["p3"], "role": "clock", "required": True},
                    {
                        "port_id": ports_by_module[m1]["p4"],
                        "role": "uninterpreted_external",
                        "required": False,
                    },
                ],
                "protocol_bindings": [
                    {
                        "id": "endpoint-1",
                        "protocol_id": "opaque-bus",
                        "side": "target",
                        "fields": [
                            {"field_role": "request.data", "port_id": ports_by_module[m1]["p2"]}
                        ],
                    }
                ],
                "clock_reset": [
                    {
                        "port_id": ports_by_module[m1]["p3"],
                        "kind": "clock",
                        "domain_id": "domain-0",
                        "active_level": "high",
                        "synchronous": False,
                    }
                ],
            },
        ],
    }
    config_path = workdir / "declarations.json"
    config_path.write_text(json.dumps(declarations, indent=2) + "\n", encoding="utf-8")
    return config_path, facts_path


def _refresh_facts(workdir: Path, facts_path: Path) -> None:
    library = default_frontend_library(ROOT)
    verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
    with patch.dict(
        os.environ,
        {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
    ):
        facts = FrontendLibrary(library).facts(
            ["--lint-only", "-Wno-fatal", "--top-module", "catalog", "opaque.sv"],
            workdir,
        )
    facts_path.write_text(json.dumps(facts, sort_keys=True) + "\n", encoding="utf-8")


class CompositionCliTests(unittest.TestCase):
    def test_write_composition_facts_materializes_matching_hdl_facts(self) -> None:
        from myfuzz.scripts.composition_api import write_composition_facts

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, expected_facts_path = _write_inputs(workdir)
            expected_facts = json.loads(expected_facts_path.read_text())
            output = workdir / "generated" / "hdl_facts.json"

            actual = write_composition_facts(config, output)

            self.assertEqual(actual, json.loads(output.read_text()))
            self.assertEqual(actual["schema_version"], "hdl_facts.v2")
            self.assertEqual(
                actual["tool"]["input_hash"],
                expected_facts["tool"]["input_hash"],
            )

    def test_protocol_loader_allows_multiple_versions_of_one_id(self) -> None:
        from myfuzz.scripts.composition_api import _protocols

        version_one = _protocol()
        version_two = json.loads(json.dumps(version_one))
        version_two["plugin_version"] = "2.0.0"

        loaded = _protocols({"protocols": [version_two, version_one]})

        self.assertEqual(
            [(item["protocol_id"], item["plugin_version"]) for item in loaded],
            [("opaque-bus", "1.0.0"), ("opaque-bus", "2.0.0")],
        )
        with self.assertRaisesRegex(ValueError, "protocol_id:duplicate"):
            _protocols({"protocols": [version_one, version_one]})

    def test_validation_evidence_hash_matches_persisted_facts(self) -> None:
        from myfuzz.scripts.composition_api import generate_compositions

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts = _write_inputs(workdir)
            summary = generate_compositions(config, facts, 1, workdir / "out")
            candidate_dir = workdir / "out" / summary["candidates"][0]["directory"]
            manifest = json.loads((candidate_dir / "candidate_manifest.json").read_text())
            reparsed = json.loads((candidate_dir / "hdl_facts.json").read_text())
            facts_by_id = {int(port["id"]): port for port in reparsed["ports"]}
            top_module_id = int(manifest["hdl_facts"]["top_module_id"])

            for port in manifest["top_port_abi"]:
                fact = facts_by_id[int(port["actual_port_id"])]
                expected = content_hash(
                    {
                        "top_module_id": top_module_id,
                        "logical_port_id": int(port["port_id"]),
                        "actual": {
                            "actual_port_id": int(port["actual_port_id"]),
                            "emitted_name": port["emitted_name"],
                            "direction": fact["direction"],
                            "width": fact["width"],
                            "signed": fact["signed"],
                            "declared_role": fact["declared_role"],
                        },
                    }
                )
                self.assertEqual(port["validation_evidence_id"], expected)

    def test_signed_external_ports_survive_emit_and_reparse(self) -> None:
        from myfuzz.scripts.composition_api import generate_compositions

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts_path = _write_inputs(workdir)
            source = workdir / "opaque.sv"
            source.write_text(
                source.read_text()
                .replace("input logic p1", "input logic signed p1")
                .replace("input logic p3", "input logic signed p3")
                .replace("output logic p4", "output logic signed p4")
            )
            _refresh_facts(workdir, facts_path)

            summary = generate_compositions(config, facts_path, 1, workdir / "out")
            candidate_dir = workdir / "out" / summary["candidates"][0]["directory"]
            ir = json.loads((candidate_dir / "composition_ir.json").read_text())
            manifest = json.loads((candidate_dir / "candidate_manifest.json").read_text())
            reparsed = json.loads((candidate_dir / "hdl_facts.json").read_text())
            fact_ports = {int(port["id"]): port for port in reparsed["ports"]}
            manifest_ports = {
                int(port["port_id"]): port for port in manifest["top_port_abi"]
            }
            signed_ports = [port for port in ir["external_ports"] if port["signed"]]

            self.assertEqual(summary["status"], "complete")
            self.assertEqual(len(signed_ports), 3)
            self.assertIn("signed", (candidate_dir / "generated_top.sv").read_text())
            for port in signed_ports:
                manifest_port = manifest_ports[int(port["port_id"])]
                self.assertTrue(manifest_port["signed"])
                self.assertTrue(fact_ports[int(manifest_port["actual_port_id"])]["signed"])

    def test_reparse_rejects_signedness_loss_in_generated_top(self) -> None:
        from myfuzz.scripts.composition_api import generate_compositions

        original_composition = FrontendLibrary.composition

        def emit_unsigned(
            frontend: FrontendLibrary,
            document: object,
            source_symbols: object,
        ) -> dict:
            result = original_composition(frontend, document, source_symbols)
            if not str(document.get("candidate_id", "")).startswith("flat-baseline-"):
                result["source_text"] = str(result["source_text"]).replace(" signed", "")
            return result

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts_path = _write_inputs(workdir)
            source = workdir / "opaque.sv"
            source.write_text(
                source.read_text()
                .replace("input logic p1", "input logic signed p1")
                .replace("input logic p3", "input logic signed p3")
                .replace("output logic p4", "output logic signed p4")
            )
            _refresh_facts(workdir, facts_path)

            with patch.object(
                FrontendLibrary,
                "composition",
                autospec=True,
                side_effect=emit_unsigned,
            ):
                summary = generate_compositions(config, facts_path, 1, workdir / "out")

            self.assertEqual(summary["candidate_count"], 0)
            self.assertEqual(summary["rejected_candidates"][0]["stage"], "top-abi")
            self.assertTrue(
                any(
                    issue["reason"] == "signed-mismatch"
                    for issue in summary["rejected_candidates"][0]["diagnostics"]["issues"]
                )
            )

    def test_generates_deterministic_reparse_valid_candidate(self) -> None:
        from myfuzz.scripts.composition_api import generate_compositions

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts = _write_inputs(workdir)
            first = generate_compositions(config, facts, 3, workdir / "out-a")
            second = generate_compositions(config, facts, 3, workdir / "out-b")

            self.assertEqual(first, second)
            self.assertEqual(first["candidate_count"], 1)
            self.assertEqual(first["requested_top_k"], 3)
            self.assertFalse(first["complete"])
            self.assertEqual(first["status"], "incomplete")
            candidate_name = first["candidates"][0]["directory"]
            first_dir = workdir / "out-a" / candidate_name
            second_dir = workdir / "out-b" / candidate_name
            for name in (
                "composition_ir.json",
                "generated_top.sv",
                "flat_top.sv",
                "candidate_manifest.json",
                "hdl_facts.json",
                "flat_baseline.json",
                "diagnostics.json",
                "graph_hash.txt",
            ):
                self.assertEqual((first_dir / name).read_bytes(), (second_dir / name).read_bytes())

            ir = json.loads((first_dir / "composition_ir.json").read_text())
            manifest = json.loads((first_dir / "candidate_manifest.json").read_text())
            reparsed = json.loads((first_dir / "hdl_facts.json").read_text())
            baseline = json.loads((first_dir / "flat_baseline.json").read_text())
            validate_contract(ir, "composition_ir.v1")
            validate_contract(manifest, "candidate_manifest.v1")
            validate_contract(reparsed, "hdl_facts.v2")
            self.assertEqual((first_dir / "graph_hash.txt").read_text().strip(), ir["graph_hash"])
            self.assertEqual(manifest["lifecycle"], "top_validated")
            self.assertEqual(manifest["validation"]["parse"], "passed")
            self.assertEqual(manifest["validation"]["elaboration"], "passed")
            self.assertEqual(manifest["validation"]["link"], "passed")
            self.assertEqual(manifest["validation"]["width"], "passed")
            self.assertEqual(manifest["hdl_facts"]["source"], "hdl_facts.json")
            self.assertEqual(manifest["hdl_facts"]["content_hash"], content_hash(reparsed))
            self.assertEqual(
                manifest["build_cache_inputs"]["schema_versions"],
                {
                    "candidate_manifest": "candidate_manifest.v1",
                    "composition_build_result": "composition_build_result.v1",
                    "composition_ir": "composition_ir.v1",
                    "hdl_facts": "hdl_facts.v2",
                },
            )
            self.assertEqual(manifest["build_cache_inputs"]["instrumentation"], {})
            self.assertEqual(
                manifest["build_cache_inputs"]["compile_args"],
                [
                    "--lint-only",
                    "-Wno-fatal",
                    "-Wno-fatal",
                    "--top-module",
                    "catalog",
                    "--top-module",
                    "composition_top",
                ],
            )
            self.assertEqual(
                manifest["build_cache_inputs"]["tool_versions"]["verilator_revision"],
                reparsed["tool"]["verilator_revision"],
            )
            self.assertEqual(manifest["flat_baseline"], baseline)
            self.assertNotEqual(baseline["baseline_id"], manifest["candidate_id"])
            self.assertNotEqual(baseline["top"]["content_hash"], manifest["top"]["content_hash"])
            self.assertNotEqual(
                content_hash(baseline["coverage_universe"]),
                content_hash(manifest["coverage_universe"]),
            )
            self.assertTrue(all("semantic_role" in port for port in manifest["top_port_abi"]))
            self.assertTrue(all("fuzzable" in port for port in manifest["top_port_abi"]))
            self.assertTrue(all("actual_port_id" in port for port in manifest["top_port_abi"]))
            fact_ports = {int(port["id"]): port for port in reparsed["ports"]}
            manifest_ports = {
                int(port["port_id"]): port for port in manifest["top_port_abi"]
            }
            top_module = next(module for module in reparsed["modules"] if module.get("top") is True)
            symbol_by_entity = {
                (str(symbol["kind"]), int(symbol["entity_id"])): symbol
                for symbol in reparsed["source_symbols"]
            }
            self.assertEqual(
                symbol_by_entity[("module", int(top_module["id"]))]["name"],
                "composition_top",
            )
            self.assertEqual(
                reparsed["declared_role_provenance"],
                "composition_ir.external_ports",
            )
            for port in ir["external_ports"]:
                port_id = int(port["port_id"])
                manifest_port = manifest_ports[port_id]
                actual_port_id = int(manifest_port["actual_port_id"])
                self.assertIn(actual_port_id, top_module["ports"])
                actual_fact = fact_ports[actual_port_id]
                self.assertEqual(actual_fact["declared_role"], port["semantic_role"])
                self.assertIn("declared_role_evidence_id", actual_fact)
                self.assertEqual(actual_fact["signed"], port["signed"])
                self.assertEqual(manifest_port["signed"], port["signed"])
                self.assertEqual(
                    symbol_by_entity[("port", actual_port_id)]["name"],
                    manifest_port["emitted_name"],
                )
                self.assertEqual(manifest_port["semantic_role"], port["semantic_role"])

    def test_flat_baseline_emits_every_component_as_an_independent_instance(self) -> None:
        from myfuzz.scripts.composition_api import generate_compositions

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts = _write_inputs(workdir)
            summary = generate_compositions(config, facts, 1, workdir / "out")

            candidate_dir = workdir / "out" / summary["candidates"][0]["directory"]
            flat_source = (candidate_dir / "flat_top.sv").read_text(encoding="utf-8")
            baseline = json.loads((candidate_dir / "flat_baseline.json").read_text())
            declarations = json.loads(config.read_text())
            declared_port_ids = {
                int(port["port_id"])
                for component in declarations["components"]
                for port in component["ports"]
            }

            self.assertEqual(baseline["top"]["module"], "composition_top")
            self.assertEqual(baseline["top"]["source"], "flat_top.sv")
            self.assertEqual(
                {int(port["port_id"]) for port in baseline["top_port_abi"]},
                declared_port_ids,
            )
            self.assertIn("m0 instance_", flat_source)
            self.assertIn("m1 instance_", flat_source)
            self.assertNotIn("catalog instance_", flat_source)
            self.assertNotIn(" net_", flat_source)

    def test_flat_and_candidate_coverage_share_stable_source_ids(self) -> None:
        from myfuzz.scripts.composition_api import generate_compositions

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts = _write_inputs(workdir)
            summary = generate_compositions(config, facts, 1, workdir / "out")

            candidate_dir = workdir / "out" / summary["candidates"][0]["directory"]
            baseline = json.loads((candidate_dir / "flat_baseline.json").read_text())
            manifest = json.loads((candidate_dir / "candidate_manifest.json").read_text())
            flat_ids = {
                point["stable_source_id"] for point in baseline["coverage_universe"]
            }
            candidate_ids = {
                point["stable_source_id"] for point in manifest["coverage_universe"]
            }

            self.assertTrue(flat_ids & candidate_ids)

    def test_rejects_supplied_facts_when_current_dut_hash_differs(self) -> None:
        from myfuzz.scripts.composition_api import generate_compositions

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts = _write_inputs(workdir)
            source = workdir / "opaque.sv"
            source.write_text(
                source.read_text().replace(
                    "assign p4 = ^p2 ^ p3;",
                    "assign p4 = ^p2 ^ p3 ^ 1'b1;",
                )
            )
            output = workdir / "out"

            with self.assertRaisesRegex(ValueError, r"frontend\.tool\.input_hash:mismatch"):
                generate_compositions(config, facts, 1, output)
            self.assertFalse(output.exists())

    def test_reparse_rejects_a_generated_top_with_the_wrong_actual_abi(self) -> None:
        from myfuzz.scripts.composition_api import generate_compositions

        original_composition = FrontendLibrary.composition
        build_result = {
            "source_text": "module composition_top; endmodule\n",
            "diagnostics": {"errors": [], "warnings": [], "unsupported": []},
            "validation": {
                "dtype": True,
                "link": True,
                "pin": True,
                "width": True,
                "unknown_width_ports": [],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts = _write_inputs(workdir)
            def replace_candidate_build(
                frontend: FrontendLibrary,
                document: object,
                source_symbols: object,
            ) -> dict:
                if str(document.get("candidate_id", "")).startswith("flat-baseline-"):
                    return original_composition(frontend, document, source_symbols)
                return build_result

            with patch.object(
                FrontendLibrary,
                "composition",
                autospec=True,
                side_effect=replace_candidate_build,
            ):
                summary = generate_compositions(config, facts, 1, workdir / "out")

            self.assertEqual(summary["candidate_count"], 0)
            self.assertEqual(summary["status"], "incomplete")
            self.assertEqual(summary["rejected_candidates"][0]["stage"], "top-abi")
            self.assertIn("expected", summary["rejected_candidates"][0]["diagnostics"])
            self.assertIn("actual", summary["rejected_candidates"][0]["diagnostics"])

    def test_builder_rejection_preserves_structured_diagnostics(self) -> None:
        from myfuzz.scripts.composition_api import generate_compositions

        original_composition = FrontendLibrary.composition
        diagnostic = {
            "code": "undeclared-port",
            "path": "external_ports[0]",
            "message": "port is missing",
            "related_ids": [7],
        }
        build_result = {
            "source_text": "",
            "diagnostics": {"errors": [diagnostic], "warnings": [], "unsupported": []},
            "validation": {
                "dtype": False,
                "link": False,
                "pin": False,
                "width": False,
                "unknown_width_ports": [7],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts = _write_inputs(workdir)
            def replace_candidate_build(
                frontend: FrontendLibrary,
                document: object,
                source_symbols: object,
            ) -> dict:
                if str(document.get("candidate_id", "")).startswith("flat-baseline-"):
                    return original_composition(frontend, document, source_symbols)
                return build_result

            with patch.object(
                FrontendLibrary,
                "composition",
                autospec=True,
                side_effect=replace_candidate_build,
            ):
                summary = generate_compositions(config, facts, 1, workdir / "out")

            rejection = summary["rejected_candidates"][0]
            self.assertEqual(rejection["stage"], "builder")
            self.assertEqual(rejection["diagnostics"]["errors"], [diagnostic])
            self.assertEqual(rejection["validation"]["unknown_width_ports"], [7])

    def test_rejected_candidate_is_backfilled_from_the_remaining_search_space(self) -> None:
        from myfuzz.scripts import composition_api

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts_path = _write_inputs(workdir)
            raw_facts = json.loads(facts_path.read_text())
            base = next(
                compose_topk(
                    normalize_facts(raw_facts),
                    load_declarations(config),
                    (_protocol(),),
                    1,
                )
            )
            bad = replace(
                base,
                candidate_id="candidate-bad",
                graph_hash="sha256:" + "a" * 64,
            )
            good = replace(
                base,
                candidate_id="candidate-good",
                graph_hash="sha256:" + "b" * 64,
            )
            calls: list[frozenset[str]] = []

            def search(*args: object, **kwargs: object) -> object:
                excluded = frozenset(kwargs.get("excluded_graph_hashes", ()))
                calls.append(excluded)
                return iter((good,)) if bad.graph_hash in excluded else iter((bad,))

            original_composition = FrontendLibrary.composition

            def build(frontend: FrontendLibrary, ir: object, symbols: object) -> object:
                if isinstance(ir, dict) and ir.get("candidate_id") == bad.candidate_id:
                    return {
                        "source_text": "",
                        "diagnostics": {
                            "errors": [{"code": "rejected"}],
                            "warnings": [],
                            "unsupported": [],
                        },
                        "validation": {
                            "dtype": False,
                            "link": False,
                            "pin": False,
                            "width": False,
                            "unknown_width_ports": [],
                        },
                    }
                return original_composition(frontend, ir, symbols)

            with patch.object(composition_api, "compose_topk", side_effect=search), patch.object(
                FrontendLibrary,
                "composition",
                autospec=True,
                side_effect=build,
            ):
                summary = composition_api.generate_compositions(
                    config,
                    facts_path,
                    1,
                    workdir / "out",
                )

            self.assertEqual(summary["candidate_count"], 1)
            self.assertEqual(summary["candidates"][0]["candidate_id"], good.candidate_id)
            self.assertEqual(len(calls), 2)
            self.assertIn(bad.graph_hash, calls[1])

    def test_post_reparse_exceptions_are_rejected_and_backfilled(self) -> None:
        from myfuzz.scripts import composition_api

        for expected_stage in (
            "reparse",
            "post-reparse",
            "top-abi",
            "role-validation",
            "coverage",
            "manifest",
        ):
            with self.subTest(stage=expected_stage), tempfile.TemporaryDirectory() as tmp:
                workdir = Path(tmp)
                config, facts_path = _write_inputs(workdir)
                raw_facts = json.loads(facts_path.read_text())
                base = next(
                    compose_topk(
                        normalize_facts(raw_facts),
                        load_declarations(config),
                        (_protocol(),),
                        1,
                    )
                )
                bad = replace(
                    base,
                    candidate_id="candidate-bad",
                    graph_hash="sha256:" + "a" * 64,
                )
                good = replace(
                    base,
                    candidate_id="candidate-good",
                    graph_hash="sha256:" + "b" * 64,
                )

                def search(*args: object, **kwargs: object) -> object:
                    excluded = frozenset(kwargs.get("excluded_graph_hashes", ()))
                    return iter((good,)) if bad.graph_hash in excluded else iter((bad,))

                failed = False
                if expected_stage == "reparse":
                    original = composition_api.FrontendLibrary.facts

                    def fail_stage(
                        frontend: FrontendLibrary,
                        args: list[str],
                        cwd: Path,
                    ) -> object:
                        nonlocal failed
                        if any(str(item).endswith("generated_top.sv") for item in args) and not failed:
                            failed = True
                            raise OSError("injected-reparse")
                        return original(frontend, args, cwd)

                    target = "facts"
                elif expected_stage == "post-reparse":
                    original = composition_api._diagnostics
                    reparse_calls = 0

                    def fail_stage(*args: object, **kwargs: object) -> object:
                        nonlocal failed, reparse_calls
                        if len(args) > 1 and args[1] == "reparse":
                            reparse_calls += 1
                            if reparse_calls == 2:
                                failed = True
                                raise ValueError("injected-post-reparse")
                        return original(*args, **kwargs)

                    target = "_diagnostics"
                elif expected_stage == "top-abi":
                    original = composition_api._actual_top_port_abi

                    def fail_stage(*args: object, **kwargs: object) -> object:
                        nonlocal failed
                        ir = args[1]
                        if isinstance(ir, dict) and ir.get("candidate_id") == bad.candidate_id:
                            failed = True
                            raise ValueError("injected-top-abi")
                        return original(*args, **kwargs)

                    target = "_actual_top_port_abi"
                elif expected_stage == "role-validation":
                    original = composition_api._facts_with_declared_roles

                    def fail_stage(*args: object, **kwargs: object) -> object:
                        nonlocal failed
                        document = args[0]
                        generated = isinstance(document, dict) and any(
                            isinstance(location, dict)
                            and str(location.get("file", "")).endswith("generated_top.sv")
                            for location in document.get("source_locations", [])
                        )
                        if generated and not failed:
                            failed = True
                            raise ValueError("injected-role-validation")
                        return original(*args, **kwargs)

                    target = "_facts_with_declared_roles"
                elif expected_stage == "coverage":
                    original = composition_api._coverage_universe

                    def fail_stage(*args: object, **kwargs: object) -> object:
                        nonlocal failed
                        if len(args) > 2 and args[2] == "candidate" and not failed:
                            failed = True
                            raise ValueError("injected-coverage")
                        return original(*args, **kwargs)

                    target = "_coverage_universe"
                else:
                    original = composition_api.candidate_manifest

                    def fail_stage(*args: object, **kwargs: object) -> object:
                        nonlocal failed
                        candidate = args[0]
                        if candidate.candidate_id == bad.candidate_id:
                            failed = True
                            raise ValueError("injected-manifest")
                        return original(*args, **kwargs)

                    target = "candidate_manifest"

                if expected_stage == "reparse":
                    stage_patch = patch.object(
                        composition_api.FrontendLibrary,
                        target,
                        autospec=True,
                        side_effect=fail_stage,
                    )
                else:
                    stage_patch = patch.object(
                        composition_api,
                        target,
                        side_effect=fail_stage,
                    )
                with patch.object(
                    composition_api,
                    "compose_topk",
                    side_effect=search,
                ), stage_patch:
                    summary = composition_api.generate_compositions(
                        config,
                        facts_path,
                        1,
                        workdir / "out",
                    )

                self.assertTrue(failed)
                self.assertEqual(summary["candidate_count"], 1)
                self.assertEqual(summary["candidates"][0]["candidate_id"], good.candidate_id)
                rejection = summary["rejected_candidates"][0]
                self.assertEqual(rejection["stage"], expected_stage)
                self.assertIn("injected-", rejection["diagnostics"]["exception"])

    def test_atomic_publication_never_replaces_an_existing_directory(self) -> None:
        from myfuzz.scripts.composition_api import _publish_directory_no_replace

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            staging = workdir / "staging"
            destination = workdir / "destination"
            staging.mkdir()
            destination.mkdir()
            (staging / "new").write_text("new")
            (destination / "existing").write_text("existing")

            with self.assertRaises(FileExistsError):
                _publish_directory_no_replace(staging, destination)

            self.assertEqual((destination / "existing").read_text(), "existing")
            self.assertFalse((destination / "new").exists())
            self.assertTrue((staging / "new").is_file())

    def test_missing_explicit_role_fails_without_candidate_output(self) -> None:
        from myfuzz.composition import DeclarationError
        from myfuzz.scripts.composition_api import generate_compositions

        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts = _write_inputs(workdir)
            document = json.loads(config.read_text())
            del document["components"][0]["role"]
            config.write_text(json.dumps(document) + "\n")
            output = workdir / "out"

            with self.assertRaises(DeclarationError):
                generate_compositions(config, facts, 3, output)
            self.assertFalse(output.exists())

    def test_command_line_entrypoint_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            config, facts = _write_inputs(workdir)
            output = workdir / "out"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "generate_composition.py"),
                    "--config",
                    str(config),
                    "--frontend",
                    str(facts),
                    "--top-k",
                    "3",
                    "--out-dir",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["candidate_count"], 1)
            self.assertEqual(result["status"], "incomplete")
            self.assertTrue((output / "generation_summary.json").is_file())


if __name__ == "__main__":
    unittest.main()
