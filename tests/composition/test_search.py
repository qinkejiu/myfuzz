from __future__ import annotations

import unittest
from unittest.mock import patch

from myfuzz.composition.constraints import EdgeCandidate, FieldConnection
from myfuzz.contracts import content_hash
from myfuzz.composition.declarations import ComponentDecl, DeclarationSet, PortDecl, ProtocolBinding, ProtocolFieldBinding
from myfuzz.composition.facts import HdlFacts, HdlModule, HdlPort
from myfuzz.composition.search import compose_topk


def protocol() -> dict[str, object]:
    return {
        "schema_version": "protocol.v1",
        "protocol_id": "bus",
        "plugin_version": "1",
        "capability_profile": {},
        "endpoint_roles": ["initiator", "target"],
        "channels": [{"id": 1, "role": "request", "fields": [{"id": 10, "role": "request.data", "direction": "initiator_to_target", "width": 8, "required": True}]}],
        "temporal_rules": [],
        "dependency_edges": [],
        "legal_adapters": [],
        "projection_actions": [],
        "capability_limits": {},
    }


def design(count: int = 2, *, bad_target_direction: bool = False) -> tuple[HdlFacts, DeclarationSet, dict[str, object]]:
    modules: list[HdlModule] = []
    ports: list[HdlPort] = []
    components: list[ComponentDecl] = []
    for index in range(count):
        module_id = index + 1
        port_id = 100 + module_id
        endpoint_id = 1000 + module_id
        component_id = 10000 + module_id
        modules.append(HdlModule(module_id, (port_id,), ()))
        ports.append(HdlPort(port_id, module_id, "output", 8, False, "request.data"))
        components.append(ComponentDecl(component_id, module_id, "initiator", (PortDecl(port_id, "request.data", True),), (ProtocolBinding(endpoint_id, "bus", "initiator", (ProtocolFieldBinding("request.data", port_id),)),), ()))
    for index in range(count):
        module_id = count + index + 1
        port_id = 100 + module_id
        endpoint_id = 1000 + module_id
        component_id = 10000 + module_id
        modules.append(HdlModule(module_id, (port_id,), ()))
        direction = "output" if bad_target_direction else "input"
        ports.append(HdlPort(port_id, module_id, direction, 8, False, "request.data"))
        components.append(ComponentDecl(component_id, module_id, "target", (PortDecl(port_id, "request.data", True),), (ProtocolBinding(endpoint_id, "bus", "target", (ProtocolFieldBinding("request.data", port_id),)),), ()))
    evidence_record = (("from_port_id", 101), ("to_port_id", 100 + count + 1))
    facts = HdlFacts(tuple(modules), tuple(ports), (("dataflow_edges", (evidence_record,)),))
    return facts, DeclarationSet(tuple(components)), {"bus": protocol()}


class CompositionSearchTests(unittest.TestCase):
    def test_limit_and_fewer_than_k(self) -> None:
        facts, declarations, protocols = design(2)
        self.assertEqual(len(list(compose_topk(facts, declarations, protocols, 1))), 1)
        self.assertEqual(len(list(compose_topk(facts, declarations, protocols, 8))), 2)

    def test_repeated_runs_have_byte_identical_order(self) -> None:
        facts, declarations, protocols = design(2)
        first = [(item.graph_hash, item.score_vector) for item in compose_topk(facts, declarations, protocols, 2)]
        second = [(item.graph_hash, item.score_vector) for item in compose_topk(facts, declarations, protocols, 2)]
        self.assertEqual(first, second)

    def test_final_score_tie_break_uses_only_selected_edge_ids(self) -> None:
        facts, declarations, protocols = design(2)

        for candidate in compose_topk(facts, declarations, protocols, 2):
            self.assertEqual(candidate.score_vector[7:], tuple(sorted(edge.id for edge in candidate.edges)))

    def test_parent_hash_rejects_host_specific_evidence_before_hashing(self) -> None:
        facts, declarations, protocols = design(1)
        path_evidence = (("debug_path", "debug_path_/tmp/build/input.json"),)
        contaminated = HdlFacts(
            facts.modules,
            facts.ports,
            facts.structural_sections + (("dataflow_edges", (path_evidence,)),),
        )

        with self.assertRaisesRegex(ValueError, r"^composition.parent_input:host-specific"):
            list(compose_topk(contaminated, declarations, protocols, 1))

    def test_normalized_graph_hash_deduplicates_semantic_edges(self) -> None:
        facts, declarations, protocols = design(1)

        from myfuzz.composition import search

        real_candidate_edges = search.candidate_edges

        def duplicate_edges(graph: object):
            edges = list(real_candidate_edges(graph))
            yield from edges
            for edge in edges:
                yield EdgeCandidate(edge.id + 1, edge.kind, edge.source_endpoint_id, edge.target_endpoint_id, edge.fields, edge.adapter, edge.evidence)

        with patch("myfuzz.composition.search.candidate_edges", duplicate_edges):
            candidates = list(compose_topk(facts, declarations, protocols, 4))
        self.assertEqual(len(candidates), 1)

    def test_graph_hash_and_rejected_edges_are_canonical_under_edge_permutation(self) -> None:
        facts, declarations, protocols = design(2)
        from myfuzz.composition import search

        real_candidate_edges = search.candidate_edges

        with patch("myfuzz.composition.search.candidate_edges", lambda graph: reversed(tuple(real_candidate_edges(graph)))):
            reversed_order = list(compose_topk(facts, declarations, protocols, 2))
        normal_order = list(compose_topk(facts, declarations, protocols, 2))

        self.assertEqual(
            [(item.graph_hash, item.rejected_alternatives) for item in normal_order],
            [(item.graph_hash, item.rejected_alternatives) for item in reversed_order],
        )

    def test_normalized_graph_hash_ignores_field_permutation(self) -> None:
        from myfuzz.composition.search import _graph_document

        fields = (
            FieldConnection("request.data", 101, 102, 8, 8),
            FieldConnection("request.mask", 103, 104, 4, 4),
        )
        edge = EdgeCandidate(1, "connection", 1001, 1002, fields, None, ())
        permuted = EdgeCandidate(2, "connection", 1001, 1002, tuple(reversed(fields)), None, ())

        self.assertEqual(content_hash(_graph_document((edge,), (), ())), content_hash(_graph_document((permuted,), (), ())))

    def test_score_tier_four_counts_only_unvalidated_declared_clock_reset_associations(self) -> None:
        facts, declarations, protocols = design(1)
        from myfuzz.composition.declarations import ClockResetDecl

        clock_port_ids = {component.module_id: 501 + index for index, component in enumerate(declarations.components)}
        clock_declarations = DeclarationSet(
            tuple(
                ComponentDecl(
                    component.id,
                    component.module_id,
                    component.role,
                    component.ports + (PortDecl(clock_port_ids[component.module_id], "clock", True),),
                    component.protocol_bindings,
                    (ClockResetDecl(clock_port_ids[component.module_id], "clock", 77, "high", False),),
                )
                for component in declarations.components
            )
        )
        modules = tuple(type(module)(module.id, module.port_ids + (clock_port_ids[module.id],), module.instance_ids) for module in facts.modules)
        clock_facts = HdlFacts(
            modules,
            facts.ports + tuple(type(facts.ports[0])(port_id, module_id, "input", 1, False, "clock") for module_id, port_id in clock_port_ids.items()),
            facts.structural_sections,
        )

        unvalidated = next(compose_topk(clock_facts, clock_declarations, protocols, 1))
        generic_validated_facts = HdlFacts(
            clock_facts.modules,
            clock_facts.ports,
            clock_facts.structural_sections + (("clock_reset_checks", tuple((("port_id", port_id), ("kind", "clock"), ("validated", True)) for port_id in clock_port_ids.values())),),
        )
        generic_validated = next(compose_topk(generic_validated_facts, clock_declarations, protocols, 1))
        validated_facts = HdlFacts(
            clock_facts.modules,
            clock_facts.ports,
            clock_facts.structural_sections + (("clock_reset_checks", tuple((("component_id", component.id), ("port_id", clock_port_ids[component.module_id]), ("kind", "clock"), ("domain_id", 77), ("structurally_validated", True)) for component in clock_declarations.components)),),
        )
        validated = next(compose_topk(validated_facts, clock_declarations, protocols, 1))

        self.assertEqual(unvalidated.score_vector[3], 2)
        self.assertEqual(generic_validated.score_vector[3], 2)
        self.assertEqual(validated.score_vector[3], 0)

    def test_invalid_limit_and_hard_conflict_rejection(self) -> None:
        facts, declarations, protocols = design(1)
        for invalid in (0, -1, True, 1.5):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                list(compose_topk(facts, declarations, protocols, invalid))

        bad_facts, bad_declarations, bad_protocols = design(1, bad_target_direction=True)
        self.assertEqual(list(compose_topk(bad_facts, bad_declarations, bad_protocols, 3)), [])


if __name__ == "__main__":
    unittest.main()
