from __future__ import annotations

import unittest

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

    def test_address_fact_provenance_uses_contract_vocabulary(self) -> None:
        facts, declarations, protocols = design(1)
        address_fact = (("address_field_port_id", 101), ("size", 4), ("fixed_base", 16))
        facts = HdlFacts(facts.modules, facts.ports, facts.structural_sections + (("local_address_facts", (address_fact,)),))

        document = composition_ir(next(compose_topk(facts, declarations, protocols, 1)))

        self.assertEqual(document["address_regions"][0]["provenance"], "rtl")
        self.assertTrue(any(item["kind"] == "local_address_facts" for item in document["evidence"]))

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
