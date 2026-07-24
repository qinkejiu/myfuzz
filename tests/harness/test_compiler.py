from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.contracts import content_hash
from myfuzz.dependency import ActiveDependencyView
from myfuzz.dependency.graph import DependencyNode
from myfuzz.harness import (
    ProjectionState,
    compile_harness_bundle,
    project_sample,
    write_harness_bundle,
)
from myfuzz.harness.abi import content_hash as abi_content_hash
from myfuzz.harness import compiler as compiler_module
from myfuzz.harness.compiler import _compiled_protocols
from myfuzz.protocols import load_builtin_protocol
from tests.runtime_fixtures import load_runtime_documents


def protocols() -> dict[str, object]:
    plugin = load_builtin_protocol("ready-valid-mmio", "1")
    return {plugin.protocol_id: plugin}


def _refresh_runtime_evidence(
    facts: dict[str, object],
    manifest: dict[str, object],
) -> None:
    descriptor = manifest["hdl_facts"]
    validation = manifest["validation"]
    assert isinstance(descriptor, dict)
    assert isinstance(validation, dict)
    evidence = validation["evidence"]
    assert isinstance(evidence, dict)
    reparse = evidence["reparse"]
    assert isinstance(reparse, dict)
    tool = facts["tool"]
    assert isinstance(tool, dict)
    facts_hash = content_hash(facts)
    descriptor["content_hash"] = facts_hash
    descriptor["input_hash"] = tool["input_hash"]
    reparse["hdl_facts_content_hash"] = facts_hash
    reparse["hdl_facts_input_hash"] = tool["input_hash"]
    reparse["top_module_id"] = descriptor["top_module_id"]


def _reverse_array(record: object, key: str) -> None:
    if isinstance(record, dict) and isinstance(record.get(key), list):
        record[key] = list(reversed(record[key]))


def _reverse_reorderable_arrays(
    facts: dict[str, object],
    composition: dict[str, object],
    manifest: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    reversed_facts = copy.deepcopy(facts)
    reversed_composition = copy.deepcopy(composition)
    reversed_manifest = copy.deepcopy(manifest)

    for key in (
        "modules",
        "parameters",
        "ports",
        "instances",
        "pin_bindings",
        "expressions",
        "dataflow_edges",
        "control_edges",
        "adapter_edges",
        "external_endpoint_port_ids",
        "clock_reset_checks",
        "local_address_facts",
        "source_locations",
        "source_symbols",
    ):
        _reverse_array(reversed_facts, key)
    for module in reversed_facts.get("modules", []):  # type: ignore[union-attr]
        _reverse_array(module, "ports")
        _reverse_array(module, "instances")
    facts_diagnostics = reversed_facts.get("diagnostics")
    for key in ("errors", "warnings", "unsupported"):
        _reverse_array(facts_diagnostics, key)

    for key in (
        "components",
        "instances",
        "nets",
        "endpoint_bindings",
        "adapters",
        "address_regions",
        "clock_domains",
        "reset_domains",
        "external_ports",
        "external_endpoint_port_ids",
        "unresolved_optional_endpoints",
        "evidence",
        "assumptions",
        "rejected_alternatives",
    ):
        _reverse_array(reversed_composition, key)
    for binding in reversed_composition.get("endpoint_bindings", []):  # type: ignore[union-attr]
        _reverse_array(binding, "fields")
    composition_diagnostics = reversed_composition.get("diagnostics")
    for key in ("errors", "warnings"):
        _reverse_array(composition_diagnostics, key)

    flat_baseline = reversed_manifest.get("flat_baseline")
    for key in ("source_composition", "top_port_abi", "coverage_universe"):
        _reverse_array(flat_baseline, key)
    harnesses = reversed_manifest.get("harnesses")
    if isinstance(harnesses, dict):
        for key in harnesses:
            _reverse_array(harnesses, key)
    mappings = reversed_manifest.get("raw_bit_mappings")
    if isinstance(mappings, dict):
        for key in mappings:
            _reverse_array(mappings, key)
    for key in (
        "top_port_abi",
        "address_map",
        "coverage_universe",
        "source_map",
        "evidence",
        "assumptions",
        "rejected_alternatives",
    ):
        _reverse_array(reversed_manifest, key)
    manifest_diagnostics = reversed_manifest.get("diagnostics")
    for key in ("errors", "warnings"):
        _reverse_array(manifest_diagnostics, key)

    reversed_manifest["composition_ir_hash"] = content_hash(reversed_composition)
    _refresh_runtime_evidence(reversed_facts, reversed_manifest)
    return reversed_facts, reversed_composition, reversed_manifest


class HarnessCompilerTest(unittest.TestCase):
    def test_reversing_all_reorderable_arrays_preserves_bundle_and_plan(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        reversed_documents = _reverse_reorderable_arrays(facts, composition, manifest)

        original = compile_harness_bundle(facts, composition, manifest, protocols())
        reordered = compile_harness_bundle(*reversed_documents, protocols())

        self.assertEqual(original, reordered)
        self.assertEqual(
            original.candidate_depaware.projection_plan,
            reordered.candidate_depaware.projection_plan,
        )
        self.assertNotEqual(original.input_manifest_hash, reordered.input_manifest_hash)
        self.assertNotEqual(original.composition_ir_hash, reordered.composition_ir_hash)

    def test_preserves_explicit_versions_when_selecting_apb3_and_apb4(self) -> None:
        apb3 = load_builtin_protocol("apb", "3")
        apb4 = load_builtin_protocol("apb", "4")
        next_port_id = 100
        fact_ports: list[dict[str, object]] = []
        bindings: list[dict[str, object]] = []
        for endpoint_id, plugin in ((3, apb3), (4, apb4)):
            fields: list[dict[str, object]] = []
            parameters = {"address_width": 16, "data_width": 32}
            for field in plugin.fields:
                if not field.required:
                    continue
                width = (
                    16
                    if field.field_id == "paddr"
                    else 32
                    if field.field_id in {"pwdata", "prdata"}
                    else 4
                    if field.field_id == "pstrb"
                    else 1
                )
                fact_ports.append(
                    {
                        "id": next_port_id,
                        "direction": (
                            "input" if field.direction == "host_to_device" else "output"
                        ),
                        "width": width,
                        "signed": False,
                    }
                )
                fields.append(
                    {
                        "field_role": field.field_id,
                        "port_id": next_port_id,
                        "direction": (
                            "input" if field.direction == "host_to_device" else "output"
                        ),
                        "width": width,
                        "signed": False,
                    }
                )
                next_port_id += 1
            bindings.append(
                {
                    "endpoint_id": endpoint_id,
                    "protocol_id": "apb",
                    "version": plugin.version,
                    "side": "target",
                    "parameters": parameters,
                    "fields": fields,
                }
            )

        compiled = _compiled_protocols(
            {"ports": fact_ports},
            {"endpoint_bindings": bindings},
            {"apb@3": apb3, "apb@4": apb4},
        )

        self.assertEqual(
            (("apb", "3"), ("apb", "4")),
            tuple((protocol.protocol_id, protocol.version) for protocol in compiled),
        )

    def test_protocol_binding_direction_is_side_aware(self) -> None:
        plugin = load_builtin_protocol("ready-valid-mmio", "1")
        bindings: list[dict[str, object]] = []
        fact_ports: list[dict[str, object]] = []
        port_id = 100
        for endpoint_id, side in ((1, "initiator"), (2, "target")):
            fields: list[dict[str, object]] = []
            for specification in plugin.fields:
                width = 8 if specification.field_id in {"addr", "wdata", "rdata"} else 1
                host_to_device = specification.direction == "host_to_device"
                direction = (
                    "output" if host_to_device else "input"
                ) if side == "initiator" else (
                    "input" if host_to_device else "output"
                )
                fields.append(
                    {
                        "field_role": specification.field_id,
                        "port_id": port_id,
                        "direction": direction,
                        "width": width,
                        "signed": False,
                    }
                )
                fact_ports.append(
                    {
                        "id": port_id,
                        "direction": direction,
                        "width": width,
                        "signed": False,
                    }
                )
                port_id += 1
            bindings.append(
                {
                    "endpoint_id": endpoint_id,
                    "protocol_id": plugin.protocol_id,
                    "version": plugin.version,
                    "side": side,
                    "parameters": {"address_width": 8, "data_width": 8},
                    "fields": fields,
                }
            )

        compiled = _compiled_protocols(
            {"ports": fact_ports},
            {"endpoint_bindings": bindings},
            {plugin.protocol_id: plugin},
        )

        self.assertEqual(2, len(compiled))

    def test_protocol_bindings_require_matching_internal_and_external_hdl_facts(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        top_map = {
            port["actual_port_id"]: port["port_id"]
            for port in manifest["top_port_abi"]
        }
        external_ports = [
            copy.deepcopy(port)
            for port in facts["ports"]
            if port["id"] in top_map and top_map[port["id"]] >= 10
        ]
        internal_ports = []
        for fact in external_ports:
            logical = copy.deepcopy(fact)
            logical["id"] = top_map[fact["id"]]
            internal_ports.append(logical)

        sources = (
            ("internal", internal_ports, {port["id"]: port["id"] for port in internal_ports}),
            ("external", external_ports, top_map),
        )
        for scope, source_ports, port_id_map in sources:
            for field, changed_value, message in (
                ("missing", None, "HDL fact"),
                ("direction", "output", "direction"),
                ("width", 7, "width"),
                ("signed", True, "signed"),
            ):
                current_ports = copy.deepcopy(source_ports)
                if field == "missing":
                    current_ports.pop(0)
                else:
                    current_ports[0][field] = changed_value
                with self.subTest(scope=scope, field=field):
                    try:
                        with self.assertRaisesRegex(ValueError, message):
                            _compiled_protocols(
                                {"ports": current_ports},
                                composition,
                                protocols(),
                                port_id_map=port_id_map,
                            )
                    except TypeError as error:
                        self.fail(f"protocol fact mapping is unsupported: {error}")

    def test_rejects_missing_duplicate_and_mismatched_actual_port_mapping(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        cases: list[tuple[str, dict[str, object], dict[str, object]]] = []

        missing = copy.deepcopy(manifest)
        missing["top_port_abi"][2].pop("actual_port_id")  # type: ignore[index]
        cases.append(("actual_port_id", facts, missing))

        duplicate = copy.deepcopy(manifest)
        duplicate["top_port_abi"][3]["actual_port_id"] = 110  # type: ignore[index]
        cases.append(("duplicate actual_port_id", facts, duplicate))

        unknown = copy.deepcopy(manifest)
        unknown["top_port_abi"][2]["actual_port_id"] = 999  # type: ignore[index]
        cases.append(("actual_port_id", facts, unknown))

        wrong_name = copy.deepcopy(manifest)
        wrong_name["top_port_abi"][2]["emitted_name"] = "wrong"  # type: ignore[index]
        cases.append(("emitted_name", facts, wrong_name))

        wrong_signed = copy.deepcopy(manifest)
        wrong_signed["top_port_abi"][2]["signed"] = True  # type: ignore[index]
        cases.append(("signed", facts, wrong_signed))

        wrong_evidence = copy.deepcopy(manifest)
        wrong_evidence["top_port_abi"][2]["validation_evidence_id"] = "sha256:" + "0" * 64  # type: ignore[index]
        cases.append(("validation_evidence_id", facts, wrong_evidence))

        outside_top = copy.deepcopy(facts)
        outside_top["modules"][0]["ports"].remove(110)  # type: ignore[index]
        outside_manifest = copy.deepcopy(manifest)
        _refresh_runtime_evidence(outside_top, outside_manifest)
        cases.append(("top module", outside_top, outside_manifest))

        for message, current_facts, current_manifest in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    compile_harness_bundle(
                        copy.deepcopy(current_facts),
                        composition,
                        copy.deepcopy(current_manifest),
                        protocols(),
                    )

    def test_validation_evidence_uses_final_fact_role_not_frontend_role(self) -> None:
        facts, _, manifest = load_runtime_documents()
        helper = getattr(compiler_module, "_validation_evidence_id", None)
        self.assertIsNotNone(helper, "compiler must expose one canonical evidence formula")
        descriptor = manifest["hdl_facts"]
        manifest_port = manifest["top_port_abi"][0]
        actual_port_id = manifest_port["actual_port_id"]
        fact = next(port for port in facts["ports"] if port["id"] == actual_port_id)

        evidence_id = helper(
            descriptor["top_module_id"],
            manifest_port["port_id"],
            manifest_port,
            fact,
        )
        changed_frontend = copy.deepcopy(fact)
        changed_frontend["frontend_declared_role"] = "diagnostic-only-role"

        self.assertEqual(manifest_port["validation_evidence_id"], evidence_id)
        self.assertEqual(
            evidence_id,
            helper(
                descriptor["top_module_id"],
                manifest_port["port_id"],
                manifest_port,
                changed_frontend,
            ),
        )

    def test_accepts_top_validated_input_and_emits_pending_runtime_fragment(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        manifest["lifecycle"] = "top_validated"
        manifest["validation"]["compile"] = "pending"  # type: ignore[index]
        manifest["validation"]["smoke"] = "pending"  # type: ignore[index]
        input_manifest_hash = content_hash(manifest)

        fragment = compile_harness_bundle(
            facts,
            composition,
            manifest,
            protocols(),
        ).manifest_fragment()

        self.assertEqual(manifest["candidate_id"], fragment["candidate_id"])
        self.assertEqual(manifest["composition_ir_hash"], fragment["composition_ir_hash"])
        self.assertEqual(input_manifest_hash, fragment["input_manifest_hash"])
        self.assertEqual(
            {
                "status": "pending",
                "input_lifecycle": "top_validated",
                "build_cache_key": manifest["build_cache_key"],
                "peak_rss_bytes": None,
                "validation": {
                    "status": "pending",
                    "contracts": "passed",
                    "candidate_abi": "passed",
                    "protocols": "passed",
                    "dependency_graph": "passed",
                    "harnesses": "passed",
                    "compile": "pending",
                    "smoke": "pending",
                },
            },
            fragment["runtime"],
        )

    def test_numeric_hdl_facts_top_module_id_is_authoritative(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        facts["modules"].append(  # type: ignore[union-attr]
            {"id": 901, "ports": [], "instances": [], "top": False}
        )
        facts["source_symbols"].append(  # type: ignore[union-attr]
            {
                "id": 99,
                "kind": "module",
                "entity_id": 901,
                "name": manifest["top"]["module"],  # type: ignore[index]
                "original_name": "decoy",
            }
        )
        _refresh_runtime_evidence(facts, manifest)

        try:
            bundle = compile_harness_bundle(facts, composition, manifest, protocols())
        except ValueError as error:
            self.fail(f"numeric top descriptor was not authoritative: {error}")

        self.assertEqual(manifest["candidate_id"], bundle.candidate_id)

    def test_rejects_stale_numeric_top_descriptor(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        manifest["hdl_facts"]["top_module_id"] = 901  # type: ignore[index]
        manifest["validation"]["evidence"]["reparse"]["top_module_id"] = 901  # type: ignore[index]

        with self.assertRaisesRegex(ValueError, "top_module_id"):
            compile_harness_bundle(facts, composition, manifest, protocols())

    def test_rejects_missing_elaboration_unsupported_facts_and_stale_reparse_evidence(
        self,
    ) -> None:
        facts, composition, manifest = load_runtime_documents()
        cases: list[tuple[str, dict[str, object], dict[str, object]]] = []

        missing_elaboration = copy.deepcopy(manifest)
        missing_elaboration["validation"].pop("elaboration")  # type: ignore[union-attr]
        cases.append(("elaboration", facts, missing_elaboration))

        unsupported_facts = copy.deepcopy(facts)
        unsupported_facts["diagnostics"]["unsupported"] = ["construct"]  # type: ignore[index]
        unsupported_manifest = copy.deepcopy(manifest)
        _refresh_runtime_evidence(unsupported_facts, unsupported_manifest)
        cases.append(("unsupported", unsupported_facts, unsupported_manifest))

        stale_descriptor = copy.deepcopy(manifest)
        stale_descriptor["hdl_facts"]["content_hash"] = "sha256:" + "0" * 64  # type: ignore[index]
        cases.append(("content_hash", facts, stale_descriptor))

        stale_input = copy.deepcopy(manifest)
        stale_input["hdl_facts"]["input_hash"] = "sha256:" + "0" * 64  # type: ignore[index]
        cases.append(("input_hash", facts, stale_input))

        stale_reparse = copy.deepcopy(manifest)
        stale_reparse["validation"]["evidence"]["reparse"][  # type: ignore[index]
            "hdl_facts_content_hash"
        ] = "sha256:" + "0" * 64
        cases.append(("reparse.*content_hash", facts, stale_reparse))

        for message, current_facts, current_manifest in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    compile_harness_bundle(
                        current_facts,
                        composition,
                        current_manifest,
                        protocols(),
                    )

    def test_rejects_extra_actual_top_ports(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        facts["modules"][0]["ports"].append(999)  # type: ignore[index]
        facts["ports"].append(  # type: ignore[union-attr]
            {
                "id": 999,
                "module_id": 900,
                "direction": "input",
                "width": 1,
                "signed": False,
                "declared_role": "uninterpreted_external",
            }
        )
        facts["source_symbols"].append(  # type: ignore[union-attr]
            {
                "id": 99,
                "kind": "port",
                "entity_id": 999,
                "name": "unexpected_actual_port",
                "original_name": "unexpected_actual_port",
            }
        )
        _refresh_runtime_evidence(facts, manifest)

        with self.assertRaisesRegex(ValueError, "unexpected actual top port"):
            compile_harness_bundle(facts, composition, manifest, protocols())

    def test_maps_declared_internal_fact_ids_and_rejects_unmapped_reparse_ids(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        facts["modules"].append(  # type: ignore[union-attr]
            {"id": 901, "ports": [10, 11], "instances": [], "top": False}
        )
        facts["ports"].extend(  # type: ignore[union-attr]
            (
                {
                    "id": 10,
                    "module_id": 901,
                    "direction": "input",
                    "width": 8,
                    "signed": False,
                    "declared_role": "protocol",
                },
                {
                    "id": 11,
                    "module_id": 901,
                    "direction": "input",
                    "width": 1,
                    "signed": False,
                    "declared_role": "protocol",
                },
            )
        )
        facts["dataflow_edges"].append(  # type: ignore[union-attr]
            {"source_port_id": 10, "target_port_id": 11, "evidence_id": "internal-edge"}
        )
        _refresh_runtime_evidence(facts, manifest)

        bundle = compile_harness_bundle(facts, composition, manifest, protocols())

        self.assertIn(DependencyNode("port", ("10",)), bundle.dependency_graph.node_ids)
        self.assertIn(DependencyNode("port", ("11",)), bundle.dependency_graph.node_ids)

        unmapped_facts = copy.deepcopy(facts)
        unmapped_manifest = copy.deepcopy(manifest)
        for port in unmapped_facts["ports"]:  # type: ignore[union-attr]
            if port["module_id"] == 901:
                port["id"] += 200
        unmapped_facts["modules"][1]["ports"] = [210, 211]  # type: ignore[index]
        unmapped_facts["dataflow_edges"][-1]["source_port_id"] = 210  # type: ignore[index]
        unmapped_facts["dataflow_edges"][-1]["target_port_id"] = 211  # type: ignore[index]
        _refresh_runtime_evidence(unmapped_facts, unmapped_manifest)

        with self.assertRaisesRegex(ValueError, "unmapped actual port ID"):
            compile_harness_bundle(
                unmapped_facts,
                composition,
                unmapped_manifest,
                protocols(),
            )

    def test_rejects_runtime_ready_input_before_integration_finalization(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        manifest["lifecycle"] = "runtime_ready"

        with self.assertRaisesRegex(ValueError, "top_validated"):
            compile_harness_bundle(facts, composition, manifest, protocols())

    def test_rejects_failed_producer_validation_phases(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        manifest["lifecycle"] = "top_validated"
        manifest["validation"]["compile"] = "pending"  # type: ignore[index]
        manifest["validation"]["smoke"] = "pending"  # type: ignore[index]

        for phase in ("link", "width", "compile", "smoke"):
            with self.subTest(phase=phase):
                failed = copy.deepcopy(manifest)
                failed["validation"][phase] = "failed"  # type: ignore[index]
                with self.assertRaisesRegex(ValueError, phase):
                    compile_harness_bundle(facts, composition, failed, protocols())

    def test_rejects_semantic_control_and_fuzz_disposition_abi_mismatches(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        cases: list[tuple[str, dict[str, object], dict[str, object], dict[str, object]]] = []

        fact_role = copy.deepcopy(facts)
        fact_role["ports"][2]["declared_role"] = "response"  # type: ignore[index]
        cases.append(("ABI semantic_role", fact_role, composition, manifest))

        ir_role = copy.deepcopy(composition)
        ir_role["external_ports"][2]["semantic_role"] = "response"  # type: ignore[index]
        ir_role_manifest = copy.deepcopy(manifest)
        ir_role_manifest["composition_ir_hash"] = content_hash(ir_role)
        cases.append(("ABI semantic_role", facts, ir_role, ir_role_manifest))

        manifest_role = copy.deepcopy(manifest)
        manifest_role["top_port_abi"][2]["semantic_role"] = "response"  # type: ignore[index]
        cases.append(("ABI semantic_role", facts, composition, manifest_role))

        missing_role = copy.deepcopy(manifest)
        missing_role["top_port_abi"][2].pop("semantic_role")  # type: ignore[index]
        cases.append(("ABI semantic_role", facts, composition, missing_role))

        ir_control = copy.deepcopy(composition)
        ir_control["reset_domains"][0]["active_level"] = "high"  # type: ignore[index]
        ir_control_manifest = copy.deepcopy(manifest)
        ir_control_manifest["composition_ir_hash"] = content_hash(ir_control)
        cases.append(("ABI control", facts, ir_control, ir_control_manifest))

        manifest_control = copy.deepcopy(manifest)
        manifest_control["top_port_abi"][1]["synchronous"] = True  # type: ignore[index]
        cases.append(("ABI control", facts, composition, manifest_control))

        fact_control = copy.deepcopy(facts)
        fact_control["clock_reset_checks"][0]["domain_id"] = 9  # type: ignore[index]
        cases.append(("ABI control", fact_control, composition, manifest))

        missing_fuzzable = copy.deepcopy(manifest)
        missing_fuzzable["top_port_abi"][2].pop("fuzzable")  # type: ignore[index]
        cases.append(("ABI fuzz disposition", facts, composition, missing_fuzzable))

        input_not_fuzzable = copy.deepcopy(manifest)
        input_not_fuzzable["top_port_abi"][2]["fuzzable"] = False  # type: ignore[index]
        cases.append(("ABI fuzz disposition", facts, composition, input_not_fuzzable))

        output_fuzzable = copy.deepcopy(manifest)
        output_fuzzable["top_port_abi"][6]["fuzzable"] = True  # type: ignore[index]
        cases.append(("ABI fuzz disposition", facts, composition, output_fuzzable))

        contradictory_disposition = copy.deepcopy(manifest)
        contradictory_disposition["top_port_abi"][2]["fuzz_disposition"] = "observe"  # type: ignore[index]
        cases.append(("ABI fuzz disposition", facts, composition, contradictory_disposition))

        for message, current_facts, current_composition, current_manifest in cases:
            with self.subTest(message=message):
                checked_facts = copy.deepcopy(current_facts)
                checked_manifest = copy.deepcopy(current_manifest)
                _refresh_runtime_evidence(checked_facts, checked_manifest)
                with self.assertRaisesRegex(ValueError, message):
                    compile_harness_bundle(
                        checked_facts,
                        copy.deepcopy(current_composition),
                        checked_manifest,
                        protocols(),
                    )

    def test_compiles_three_genuinely_distinct_runtime_modes(self) -> None:
        facts, composition, manifest = load_runtime_documents()

        bundle = compile_harness_bundle(facts, composition, manifest, protocols())

        self.assertEqual(18, bundle.candidate_direct.raw_width)
        self.assertEqual(bundle.candidate_direct.raw_width, bundle.candidate_depaware.raw_width)
        self.assertIn("flat_runtime_top", bundle.flat_direct.source_text)
        self.assertNotIn("candidate_runtime_top", bundle.flat_direct.source_text)
        self.assertIn("candidate_runtime_top", bundle.candidate_direct.source_text)
        self.assertIn("projection_state", bundle.candidate_depaware.source_text)
        self.assertIn("always_ff", bundle.candidate_depaware.source_text)
        self.assertIn("timeout_count", bundle.candidate_depaware.source_text)
        self.assertIn("correction_protocol_legality", bundle.candidate_depaware.source_text)
        self.assertNotEqual(bundle.candidate_direct.source_text, bundle.candidate_depaware.source_text)
        self.assertIsNotNone(bundle.candidate_depaware.projection_plan)
        self.assertGreater(bundle.candidate_depaware.projection_plan.max_state_bits, 0)
        self.assertEqual(
            [
                (use.raw_lo, use.raw_hi, use.destination_id, use.destination_lo)
                for use in bundle.candidate_direct.abi.uses
            ],
            [
                (use.raw_lo, use.raw_hi, use.destination_id, use.destination_lo)
                for use in bundle.candidate_depaware.abi.uses
            ],
        )
        self.assertEqual(
            {
                "projection_rate",
                "protocol_event_count",
                "timeout_count",
                "violation_count",
                "no_progress_count",
            },
            set(bundle.candidate_depaware.counters) & {
                "projection_rate",
                "protocol_event_count",
                "timeout_count",
                "violation_count",
                "no_progress_count",
            },
        )

        edge_kinds = set(bundle.dependency_graph.edge_kinds)
        self.assertIn("adapter:adapter-fact", edge_kinds)
        self.assertIn("adapter:adapter-composition", edge_kinds)
        self.assertNotIn("15", {component for node in bundle.dependency_graph.node_ids for component in node.components})
        self.assertEqual(("15",), bundle.dependency_graph.external_endpoint_port_ids)
        self.assertEqual(
            (
                ("10", "12", "adapter-fact", "fact-adapter-1"),
                ("12", "13", "adapter-composition", "composition-adapter-1"),
            ),
            bundle.dependency_graph.adapter_edges,
        )
        fragment = bundle.manifest_fragment()
        self.assertEqual(
            [{"protocol_id": "ready-valid-mmio", "version": "1"}],
            fragment["protocols"],
        )
        self.assertEqual(
            fragment["coverage_metadata_hash"],
            fragment["harnesses"]["candidate-direct"]["coverage_universe"],
        )
        self.assertEqual(
            fragment["harnesses"]["candidate-direct"]["coverage_universe"],
            fragment["harnesses"]["candidate-depaware"]["coverage_universe"],
        )
        self.assertNotEqual(
            fragment["harnesses"]["flat-direct"]["instrumented_rtl_hash"],
            fragment["harnesses"]["candidate-direct"]["instrumented_rtl_hash"],
        )

    def test_active_view_changes_priority_without_changing_raw_geometry(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        baseline = compile_harness_bundle(facts, composition, manifest, protocols())
        graph = baseline.dependency_graph
        node_index = {node: index for index, node in enumerate(graph.node_ids)}
        addr_edge = (
            node_index[DependencyNode("field_group", ("1000", "addr"))],
            node_index[DependencyNode("port", ("10",))],
        )
        all_active = ActiveDependencyView.all_active(graph, epoch=6)
        self.assertIn(addr_edge, all_active.active_edges)
        active_view = ActiveDependencyView(
            graph,
            all_active.active_edges - {addr_edge},
            epoch=7,
        )

        changed = compile_harness_bundle(
            facts,
            composition,
            manifest,
            protocols(),
            active_view=active_view,
        )
        baseline_plan = baseline.candidate_depaware.projection_plan
        changed_plan = changed.candidate_depaware.projection_plan
        assert baseline_plan is not None and changed_plan is not None
        addr_destination = next(
            destination.destination_id
            for destination in changed_plan.raw_abi.destinations
            if destination.port_id == 10
        )
        self.assertNotEqual(baseline_plan.plan_hash, changed_plan.plan_hash)
        self.assertEqual(addr_destination, changed_plan.field_order[-1])
        addr_actions = [
            action
            for action in changed_plan.actions
            if action.destination_id == addr_destination
        ]
        self.assertTrue(addr_actions)
        self.assertTrue(all(not action.active for action in addr_actions))
        self.assertEqual(
            [
                (use.raw_lo, use.raw_hi, use.destination_id, use.destination_lo)
                for use in baseline_plan.raw_abi.uses
            ],
            [
                (use.raw_lo, use.raw_hi, use.destination_id, use.destination_lo)
                for use in changed_plan.raw_abi.uses
            ],
        )
        projected = project_sample(
            changed_plan,
            (1 << changed_plan.raw_abi.raw_width) - 1,
            ProjectionState.initial(changed_plan),
        )
        self.assertEqual(set(changed_plan.field_order), dict(projected.driven_fields).keys())
        self.assertEqual(addr_destination, projected.driven_fields[-1][0])

        foreign = copy.deepcopy(graph)
        object.__setattr__(foreign, "diagnostics", ("foreign",))
        with self.assertRaisesRegex(ValueError, "does not belong"):
            compile_harness_bundle(
                facts,
                composition,
                manifest,
                protocols(),
                active_view=ActiveDependencyView.all_active(foreign),
            )

    def test_writes_exact_atomic_bundle_files_with_verifiable_hashes(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        bundle = compile_harness_bundle(facts, composition, manifest, protocols())

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            paths = write_harness_bundle(bundle, output)
            self.assertEqual(
                {
                    "flat-direct.sv",
                    "candidate-direct.sv",
                    "candidate-depaware.sv",
                    "dependency_graph.v1.json",
                    "harness_manifest_fragment.json",
                },
                set(paths),
            )
            self.assertEqual(set(paths), {path.name for path in output.iterdir()})
            fragment = json.loads(paths["harness_manifest_fragment.json"].read_text())
            graph = json.loads(paths["dependency_graph.v1.json"].read_text())
            self.assertEqual(
                bundle.dependency_graph_hash,
                content_hash(graph),
            )
            for name, artifact in (
                ("flat-direct", bundle.flat_direct),
                ("candidate-direct", bundle.candidate_direct),
                ("candidate-depaware", bundle.candidate_depaware),
            ):
                source = paths[f"{name}.sv"].read_text()
                self.assertEqual(artifact.content_hash, abi_content_hash({"source_text": source}))
                self.assertEqual(f"{name}.sv", fragment["harnesses"][name]["source"])
            self.assertNotIn(directory, json.dumps(fragment, sort_keys=True))

    def test_rejects_missing_baseline_and_incomplete_runtime_evidence(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        cases: list[tuple[str, dict[str, object], dict[str, object], dict[str, object]]] = []

        no_baseline = copy.deepcopy(manifest)
        no_baseline.pop("flat_baseline")
        cases.append(("flat_baseline", facts, composition, no_baseline))

        bad_validation = copy.deepcopy(manifest)
        bad_validation["validation"]["elaboration"] = "pending"  # type: ignore[index]
        cases.append(("elaboration", facts, composition, bad_validation))

        bad_parse = copy.deepcopy(manifest)
        bad_parse["validation"]["parse"] = "pending"  # type: ignore[index]
        cases.append(("parse", facts, composition, bad_parse))

        bad_status = copy.deepcopy(manifest)
        bad_status["validation"]["status"] = "invalid"  # type: ignore[index]
        cases.append(("status", facts, composition, bad_status))

        diagnostics = copy.deepcopy(manifest)
        diagnostics["diagnostics"]["errors"] = ["fatal"]  # type: ignore[index]
        cases.append(("diagnostics", facts, composition, diagnostics))

        facts_diagnostics = copy.deepcopy(facts)
        facts_diagnostics["diagnostics"]["errors"] = ["fatal"]  # type: ignore[index]
        cases.append(("hdl_facts.diagnostics", facts_diagnostics, composition, manifest))

        composition_diagnostics = copy.deepcopy(composition)
        composition_diagnostics["diagnostics"]["errors"] = ["fatal"]  # type: ignore[index]
        changed_manifest = copy.deepcopy(manifest)
        changed_manifest["composition_ir_hash"] = content_hash(composition_diagnostics)
        cases.append(
            ("composition_ir.diagnostics", facts, composition_diagnostics, changed_manifest)
        )

        abi_mismatch = copy.deepcopy(manifest)
        abi_mismatch["top_port_abi"][2]["width"] = 7  # type: ignore[index]
        cases.append(("ABI", facts, composition, abi_mismatch))

        composition_abi = copy.deepcopy(composition)
        composition_abi["external_ports"][2]["direction"] = "output"  # type: ignore[index]
        changed_manifest = copy.deepcopy(manifest)
        changed_manifest["composition_ir_hash"] = content_hash(composition_abi)
        cases.append(("ABI", facts, composition_abi, changed_manifest))

        candidate_baseline = copy.deepcopy(manifest)
        candidate_baseline["flat_baseline"]["top"] = copy.deepcopy(manifest["top"])  # type: ignore[index]
        candidate_baseline["flat_baseline"]["source_composition"] = [  # type: ignore[index]
            copy.deepcopy(manifest["top"])
        ]
        cases.append(("standalone", facts, composition, candidate_baseline))

        content_alias = copy.deepcopy(manifest)
        content_alias["flat_baseline"]["top"]["content_hash"] = manifest["top"][  # type: ignore[index]
            "content_hash"
        ]
        content_alias["flat_baseline"]["source_composition"][0][  # type: ignore[index]
            "content_hash"
        ] = manifest["top"]["content_hash"]  # type: ignore[index]
        cases.append(("standalone", facts, composition, content_alias))

        shared_coverage = copy.deepcopy(manifest)
        shared_coverage["flat_baseline"]["coverage_universe"] = copy.deepcopy(  # type: ignore[index]
            manifest["coverage_universe"]
        )
        cases.append(("distinct coverage", facts, composition, shared_coverage))

        for message, current_facts, current_composition, current_manifest in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    compile_harness_bundle(
                        copy.deepcopy(current_facts),
                        copy.deepcopy(current_composition),
                        copy.deepcopy(current_manifest),
                        protocols(),
                    )

    def test_rejects_unknown_missing_direction_and_width_protocol_fields(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        cases: list[tuple[str, dict[str, object], dict[str, object]]] = []

        unknown = copy.deepcopy(composition)
        unknown["endpoint_bindings"][0]["fields"][0]["field_role"] = "unknown"  # type: ignore[index]
        cases.append(("unknown", facts, unknown))

        missing = copy.deepcopy(composition)
        missing["endpoint_bindings"][0]["fields"].pop()  # type: ignore[index]
        cases.append(("missing", facts, missing))

        aliased = copy.deepcopy(composition)
        aliased["endpoint_bindings"][0]["fields"][3]["port_id"] = 11  # type: ignore[index]
        cases.append(("duplicate protocol port", facts, aliased))

        direction_facts = copy.deepcopy(facts)
        direction_facts["ports"][4]["direction"] = "output"  # type: ignore[index]
        cases.append(("direction", direction_facts, composition))

        width_facts = copy.deepcopy(facts)
        width_facts["ports"][2]["width"] = 7  # type: ignore[index]
        cases.append(("width", width_facts, composition))

        missing_direction = copy.deepcopy(composition)
        missing_direction["endpoint_bindings"][0]["fields"][0].pop("direction")  # type: ignore[index]
        cases.append(("direction", facts, missing_direction))

        wrong_field_width = copy.deepcopy(composition)
        wrong_field_width["endpoint_bindings"][0]["fields"][0]["width"] = 7  # type: ignore[index]
        cases.append(("width", facts, wrong_field_width))

        wrong_side = copy.deepcopy(composition)
        wrong_side["endpoint_bindings"][0]["side"] = "observer"  # type: ignore[index]
        cases.append(("side", facts, wrong_side))

        for message, current_facts, current_composition in cases:
            with self.subTest(message=message):
                changed_manifest = copy.deepcopy(manifest)
                changed_manifest["composition_ir_hash"] = content_hash(current_composition)
                checked_facts = copy.deepcopy(current_facts)
                _refresh_runtime_evidence(checked_facts, changed_manifest)
                with self.assertRaisesRegex(ValueError, message):
                    compile_harness_bundle(
                        checked_facts,
                        copy.deepcopy(current_composition),
                        changed_manifest,
                        protocols(),
                    )


if __name__ == "__main__":
    unittest.main()
