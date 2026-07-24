from __future__ import annotations

import unittest
from dataclasses import replace

from myfuzz.composition.ir import composition_ir
from myfuzz.composition.manifest import candidate_manifest
from myfuzz.composition.search import compose_topk
from myfuzz.composition.facts import HdlFacts
from myfuzz.contracts import content_hash, validate_contract
from tests.composition.test_constraints import (
    _declarations as constraint_declarations,
    _facts as constraint_facts,
    _protocol as constraint_protocol,
)
from tests.composition.test_search import design


class CompositionIrTests(unittest.TestCase):
    def test_ir_preserves_evidence_assumptions_and_rejected_alternatives(self) -> None:
        facts, declarations, protocols = design(2)
        candidate = next(compose_topk(facts, declarations, protocols, 1))
        document = composition_ir(candidate)

        validate_contract(document, "composition_ir.v1")
        self.assertTrue(document["evidence"])
        self.assertTrue(all(item["provenance"] == "rtl" for item in document["evidence"]))
        self.assertTrue(document["rejected_alternatives"])
        self.assertEqual(document["graph_hash"], candidate.graph_hash)
        self.assertEqual(document, composition_ir(candidate))

    def test_optional_externalization_is_recorded_as_assumption(self) -> None:
        facts, declarations, protocols = design(1)
        components = list(declarations.components)
        target = components[-1]
        target_port = target.ports[0]
        components[-1] = type(target)(target.id, target.module_id, target.role, (type(target_port)(target_port.port_id, target_port.role, False),), target.protocol_bindings, target.clock_reset)
        candidate = next(compose_topk(facts, type(declarations)(tuple(components)), protocols, 1))
        document = composition_ir(candidate)
        self.assertTrue(any(item["provenance"] == "assumed" for item in document["assumptions"]))

    def test_allocated_address_base_is_inferred_not_rtl(self) -> None:
        facts, declarations, protocols = design(1)
        address_fact = (("address_field_port_id", 101), ("size", 4), ("fixed_base", 16))
        facts = HdlFacts(facts.modules, facts.ports, facts.structural_sections + (("local_address_facts", (address_fact,)),))

        document = composition_ir(next(compose_topk(facts, declarations, protocols, 1)))

        self.assertEqual(document["address_regions"][0]["provenance"], "inferred")
        self.assertTrue(any(item["kind"] == "local_address_facts" for item in document["evidence"]))
        self.assertTrue(any(item["kind"] == "address_base" and item["provenance"] == "inferred" for item in document["assumptions"]))

    def test_reordered_local_address_evidence_has_canonical_ordinals_and_semantic_hash(self) -> None:
        facts, declarations, protocols = design(1)
        records = (
            (("address_field_port_id", 101), ("size", 4), ("fixed_base", 32), ("region_id", 2)),
            (("address_field_port_id", 101), ("size", 4), ("fixed_base", 16), ("region_id", 1)),
            (("address_field_port_id", 101), ("size", 4), ("fixed_base", 16), ("region_id", 1)),
        )
        first_facts = HdlFacts(facts.modules, facts.ports, facts.structural_sections + (("local_address_facts", records),))
        second_facts = HdlFacts(facts.modules, facts.ports, facts.structural_sections + (("local_address_facts", tuple(reversed(records))),))

        first = next(compose_topk(first_facts, declarations, protocols, 1))
        second = next(compose_topk(second_facts, declarations, protocols, 1))
        first_ir = composition_ir(first)
        second_ir = composition_ir(second)

        self.assertEqual(first.parent_input_hash, second.parent_input_hash)
        self.assertEqual(first_ir, second_ir)
        local_evidence = [item for item in first_ir["evidence"] if item["kind"] == "local_address_facts"]
        self.assertEqual([item["ordinal"] for item in local_evidence], [0, 1, 2])
        self.assertEqual(content_hash(first_ir), content_hash(second_ir))

    def test_ir_has_concrete_instances_and_canonical_edge_order(self) -> None:
        facts, declarations, protocols = design(2)
        candidate = next(compose_topk(facts, declarations, protocols, 1))
        reversed_candidate = replace(candidate, edges=tuple(reversed(candidate.edges)))

        document = composition_ir(candidate)

        self.assertEqual(
            document["instances"],
            [
                {"id": component.id, "component_id": component.id, "module_id": component.module_id, "role": component.role}
                for component in declarations.components
            ],
        )
        self.assertEqual(document, composition_ir(reversed_candidate))

    def test_ir_carries_explicit_protocol_version_parameters_and_adapter_ids(self) -> None:
        candidate = next(
            compose_topk(
                constraint_facts(width_b=16),
                constraint_declarations(),
                {"bus": constraint_protocol(adapter=["width-adapter"])},
                1,
            )
        )

        document = composition_ir(candidate)

        self.assertTrue(document["endpoint_bindings"])
        for binding in document["endpoint_bindings"]:
            self.assertEqual(binding["version"], "1")
            self.assertEqual(binding["parameters"], {})
        self.assertEqual(len(document["adapters"]), 1)
        adapter = document["adapters"][0]
        self.assertIsInstance(adapter["adapter_id"], str)
        self.assertEqual(adapter["source_port_id"], 11)
        self.assertEqual(adapter["target_port_id"], 21)
        self.assertIsInstance(adapter["evidence_id"], str)

    def test_manifest_rejects_host_specific_metadata_in_all_emitted_sections(self) -> None:
        facts, declarations, protocols = design(1)
        candidate = next(compose_topk(facts, declarations, protocols, 1))
        emitted = {
            "source_text": "module generated_top; endmodule\n",
            "top_port_abi": [{"port_id": 1, "emitted_name": "input_1", "direction": "input", "width": 1, "debug_path": "/private/build/top.sv"}],
            "diagnostics": {"warnings": ["built 2026-07-23T10:11:12Z"]},
            "validation": {"parse": "object at 0x7ffd1234"},
        }

        with self.assertRaisesRegex(ValueError, r"^emitted.metadata:host-specific"):
            candidate_manifest(candidate, emitted)

    def test_manifest_rejects_embedded_absolute_host_paths(self) -> None:
        facts, declarations, protocols = design(1)
        candidate = next(compose_topk(facts, declarations, protocols, 1))
        emitted_values = (
            {"top_port_abi": [{"port_id": 1, "emitted_name": "input_1", "direction": "input", "width": 1, "debug_path": "debug_path=/private/build/top.sv"}]},
            {"diagnostics": {"warnings": ["cache:/tmp/output"]}},
        )

        for emitted_fields in emitted_values:
            with self.subTest(emitted_fields=emitted_fields), self.assertRaisesRegex(ValueError, r"^emitted.metadata:host-specific"):
                candidate_manifest(candidate, {"source_text": "module generated_top; endmodule\n", **emitted_fields})

    def test_manifest_rejects_absolute_paths_embedded_in_source_text_before_hashing(self) -> None:
        facts, declarations, protocols = design(1)
        candidate = next(compose_topk(facts, declarations, protocols, 1))

        with self.assertRaisesRegex(ValueError, r"^emitted.source_text:host-specific"):
            candidate_manifest(
                candidate,
                {"source_text": 'module generated_top; string source = "/tmp/build/generated_top.sv"; endmodule\n'},
            )

    def test_manifest_rejects_delimiter_embedded_absolute_source_path_before_hashing(self) -> None:
        facts, declarations, protocols = design(1)
        candidate = next(compose_topk(facts, declarations, protocols, 1))

        with self.assertRaisesRegex(ValueError, r"^emitted.source_text:host-specific"):
            candidate_manifest(
                candidate,
                {"source_text": 'module generated_top; string source = "debug_path_/tmp/build/generated_top.sv"; endmodule\n'},
            )

    def test_manifest_accepts_verilog_division_but_rejects_host_path_literals(self) -> None:
        facts, declarations, protocols = design(1)
        candidate = next(compose_topk(facts, declarations, protocols, 1))

        for source_text in (
            "module generated_top; wire q = a/b; endmodule\n",
            "module generated_top; wire q = a /b; endmodule\n",
        ):
            with self.subTest(source_text=source_text):
                manifest = candidate_manifest(candidate, {"source_text": source_text})
                self.assertEqual(manifest["top"]["content_hash"], content_hash({"source_text": source_text}))
        with self.assertRaisesRegex(ValueError, r"^emitted.source_text:host-specific"):
            candidate_manifest(candidate, {"source_text": 'module generated_top; string source = "/tmp/build/generated_top.sv"; endmodule\n'})

    def test_manifest_uses_semantic_ir_hash_and_sanitizes_source_path(self) -> None:
        facts, declarations, protocols = design(1)
        candidate = next(compose_topk(facts, declarations, protocols, 1))
        emitted = {
            "module": "generated_top",
            "source": "/tmp/process-123/generated_top.sv",
            "source_text": "module generated_top; endmodule\n",
            "top_port_abi": [],
            "diagnostics": {"errors": [], "warnings": []},
        }
        manifest = candidate_manifest(candidate, emitted)

        validate_contract(manifest, "candidate_manifest.v1")
        self.assertEqual(manifest["composition_ir_hash"], content_hash(composition_ir(candidate)))
        self.assertEqual(manifest["top"]["source"], "generated_top.sv")
        self.assertNotIn("/tmp", manifest["build_cache_key"])
        self.assertEqual(manifest, candidate_manifest(candidate, emitted))

    def test_manifest_cache_key_is_bound_to_the_current_dut_input_hash(self) -> None:
        facts, declarations, protocols = design(1)
        candidate = next(compose_topk(facts, declarations, protocols, 1))
        first_hash = "sha256:" + "1" * 64
        second_hash = "sha256:" + "2" * 64

        first = candidate_manifest(
            candidate,
            {"source_text": "module generated_top; endmodule\n", "dut_input_hash": first_hash},
        )
        second = candidate_manifest(
            candidate,
            {"source_text": "module generated_top; endmodule\n", "dut_input_hash": second_hash},
        )

        self.assertEqual(first["dut_input_hash"], first_hash)
        self.assertEqual(second["dut_input_hash"], second_hash)
        self.assertNotEqual(first["build_cache_key"], second["build_cache_key"])

    def test_manifest_cache_key_covers_build_environment_deterministically(self) -> None:
        facts, declarations, protocols = design(1)
        candidate = next(compose_topk(facts, declarations, protocols, 1))
        base = {
            "source_text": "module generated_top; endmodule\n",
            "tool_versions": {"frontend": "myfuzz-1", "verilator": "v5"},
            "schema_versions": {
                "candidate_manifest": "candidate_manifest.v1",
                "composition_ir": "composition_ir.v1",
            },
            "instrumentation": {"coverage": "branch", "counter_width": 8},
            "compile_args": ["--cc", "-O2"],
        }
        first = candidate_manifest(candidate, base)
        reordered = candidate_manifest(
            candidate,
            {
                **base,
                "tool_versions": {"verilator": "v5", "frontend": "myfuzz-1"},
                "instrumentation": {"counter_width": 8, "coverage": "branch"},
            },
        )

        self.assertEqual(first["build_cache_key"], reordered["build_cache_key"])
        self.assertEqual(
            first["build_cache_inputs"],
            {
                "compile_args": ["--cc", "-O2"],
                "instrumentation": {"counter_width": 8, "coverage": "branch"},
                "schema_versions": {
                    "candidate_manifest": "candidate_manifest.v1",
                    "composition_ir": "composition_ir.v1",
                },
                "tool_versions": {"frontend": "myfuzz-1", "verilator": "v5"},
            },
        )
        for field, changed_value in (
            ("tool_versions", {"frontend": "myfuzz-2", "verilator": "v5"}),
            ("schema_versions", {"composition_ir": "composition_ir.v2"}),
            ("instrumentation", {"coverage": "toggle", "counter_width": 8}),
            ("compile_args", ["--cc", "-O3"]),
        ):
            with self.subTest(field=field):
                changed = candidate_manifest(candidate, {**base, field: changed_value})
                self.assertNotEqual(first["build_cache_key"], changed["build_cache_key"])

    def test_manifest_preserves_rejected_alternatives_and_validates_contract(self) -> None:
        facts, declarations, protocols = design(2)
        candidate = next(compose_topk(facts, declarations, protocols, 1))

        manifest = candidate_manifest(
            candidate,
            {"source_text": "module generated_top; endmodule\n"},
        )

        validate_contract(manifest, "candidate_manifest.v1")
        self.assertEqual(
            manifest["rejected_alternatives"],
            composition_ir(candidate)["rejected_alternatives"],
        )


if __name__ == "__main__":
    unittest.main()
