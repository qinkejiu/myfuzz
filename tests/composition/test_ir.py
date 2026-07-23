from __future__ import annotations

import unittest
from dataclasses import replace

from myfuzz.composition.ir import composition_ir
from myfuzz.composition.manifest import candidate_manifest
from myfuzz.composition.search import compose_topk
from myfuzz.composition.facts import HdlFacts
from myfuzz.contracts import content_hash, validate_contract
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


if __name__ == "__main__":
    unittest.main()
