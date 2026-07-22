from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from myfuzz.composition.constraints import (
    ConstraintGraphError,
    ForbiddenEdge,
    build_constraint_graph,
    candidate_edges,
    reject_hard_conflicts,
)
from myfuzz.composition.declarations import (
    ClockResetDecl,
    ComponentDecl,
    DeclarationSet,
    PortDecl,
    ProtocolBinding,
    ProtocolFieldBinding,
)
from myfuzz.composition.facts import HdlFacts, HdlModule, HdlPort, normalize_facts


def _protocol(protocol_id: str = "bus", *, adapter: list[str] | None = None) -> dict[str, object]:
    return {
        "schema_version": "protocol.v1",
        "protocol_id": protocol_id,
        "plugin_version": "1",
        "capability_profile": {},
        "endpoint_roles": ["initiator", "target"],
        "channels": [
            {
                "id": 1,
                "role": "request",
                "fields": [
                    {"id": 10, "role": "request.data", "direction": "initiator_to_target", "width": {"min": 1, "max": 64}, "required": True},
                ],
            }
        ],
        "temporal_rules": [],
        "dependency_edges": [],
        "legal_adapters": adapter or [],
        "projection_actions": [],
        "capability_limits": {},
    }


def _facts(*, width_a: int = 32, width_b: int = 32, direction_b: str = "input", domains: tuple[int, int] | None = None) -> HdlFacts:
    ports = [
        HdlPort(11, 1, "output", width_a, False, "request.data"),
        HdlPort(21, 2, direction_b, width_b, False, "request.data"),
    ]
    modules = [HdlModule(1, (11,), ()), HdlModule(2, (21,), ())]
    sections = (
        ("dataflow_edges", ((("from_port_id", 11), ("to_port_id", 21)),)),
        ("control_edges", ((("from_port_id", 11), ("to_port_id", 21)),)),
    )
    if domains is not None:
        ports.extend(
            [
                HdlPort(12, 1, "input", 1, False, "clock"),
                HdlPort(22, 2, "input", 1, False, "clock"),
            ]
        )
        modules = [HdlModule(1, (11, 12), ()), HdlModule(2, (21, 22), ())]
    return HdlFacts(tuple(modules), tuple(ports), sections)


def _declarations(*, required_a: bool = True, required_b: bool = True, protocol_b: str = "bus", clock_domains: tuple[int, int] | None = None) -> DeclarationSet:
    ports_a = [PortDecl(11, "request.data", required_a)]
    ports_b = [PortDecl(21, "request.data", required_b)]
    clocks_a: tuple[ClockResetDecl, ...] = ()
    clocks_b: tuple[ClockResetDecl, ...] = ()
    if clock_domains is not None:
        ports_a.append(PortDecl(12, "clock", True))
        ports_b.append(PortDecl(22, "clock", True))
        clocks_a = (ClockResetDecl(12, "clock", clock_domains[0], "high", True),)
        clocks_b = (ClockResetDecl(22, "clock", clock_domains[1], "high", True),)
    return DeclarationSet(
        (
            ComponentDecl(101, 1, "initiator", tuple(ports_a), (ProtocolBinding(1001, "bus", "initiator", (ProtocolFieldBinding("request.data", 11),)),), clocks_a),
            ComponentDecl(202, 2, "target", tuple(ports_b), (ProtocolBinding(2002, protocol_b, "target", (ProtocolFieldBinding("request.data", 21),)),), clocks_b),
        )
    )


class ConstraintGraphTests(unittest.TestCase):
    def test_compatible_edge_preserves_rtl_evidence_and_is_deterministic(self) -> None:
        graph = build_constraint_graph(_facts(), _declarations(), {"bus": _protocol()})
        edges = list(candidate_edges(graph))

        self.assertEqual(len(edges), 1)
        self.assertEqual((edges[0].source_endpoint_id, edges[0].target_endpoint_id), (1001, 2002))
        self.assertEqual(edges[0].adapter, None)
        self.assertEqual([item.kind for item in edges[0].evidence], ["dataflow_edges", "control_edges"])
        self.assertEqual(reject_hard_conflicts(graph), [])
        self.assertEqual(edges, list(candidate_edges(graph)))

    def test_direction_mismatch_is_a_hard_conflict(self) -> None:
        graph = build_constraint_graph(_facts(direction_b="output"), _declarations(), {"bus": _protocol()})
        conflicts = reject_hard_conflicts(graph)

        self.assertTrue(any(conflict.kind == "direction" for conflict in conflicts))
        self.assertEqual(list(candidate_edges(graph)), [])

    def test_width_mismatch_is_rejected_without_declared_adapter(self) -> None:
        graph = build_constraint_graph(_facts(width_b=16), _declarations(), {"bus": _protocol()})
        conflicts = reject_hard_conflicts(graph)

        self.assertTrue(any(conflict.kind == "width" for conflict in conflicts))
        self.assertEqual(list(candidate_edges(graph)), [])

    def test_declared_width_adapter_is_the_only_way_to_cross_widths(self) -> None:
        graph = build_constraint_graph(_facts(width_b=16), _declarations(), {"bus": _protocol(adapter=["width-adapter"])})
        edges = list(candidate_edges(graph))

        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].adapter, "width-adapter")
        self.assertEqual(reject_hard_conflicts(graph), [])

    def test_required_endpoint_cardinality_and_optional_external_endpoint(self) -> None:
        required_graph = build_constraint_graph(_facts(), _declarations(required_b=False), {"bus": _protocol()})
        self.assertFalse(any(conflict.kind == "required_cardinality" for conflict in reject_hard_conflicts(required_graph)))

        external_graph = build_constraint_graph(_facts(), _declarations(required_a=False, required_b=False), {"bus": _protocol()})
        edges = list(candidate_edges(external_graph))
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].kind, "connection")

        orphan_facts = HdlFacts((HdlModule(1, (11,), ()),), (HdlPort(11, 1, "output", 32, False, "request.data"),), ())
        orphan_declarations = DeclarationSet((ComponentDecl(101, 1, "initiator", (PortDecl(11, "request.data", False),), (ProtocolBinding(1001, "bus", "initiator", (ProtocolFieldBinding("request.data", 11),)),), ()),))
        orphan_graph = build_constraint_graph(orphan_facts, orphan_declarations, {"bus": _protocol()})
        external_edges = list(candidate_edges(orphan_graph))
        self.assertEqual(len(external_edges), 1)
        self.assertEqual(external_edges[0].kind, "external")
        self.assertEqual(reject_hard_conflicts(orphan_graph), [])

        required_orphan_declarations = DeclarationSet((ComponentDecl(101, 1, "initiator", (PortDecl(11, "request.data", True),), (ProtocolBinding(1001, "bus", "initiator", (ProtocolFieldBinding("request.data", 11),)),), ()),))
        required_orphan = build_constraint_graph(orphan_facts, required_orphan_declarations, {"bus": _protocol()})
        self.assertTrue(any(conflict.kind == "required_cardinality" for conflict in reject_hard_conflicts(required_orphan)))

    def test_domain_and_protocol_mismatch_are_forbidden(self) -> None:
        domain_graph = build_constraint_graph(_facts(domains=(1, 2)), _declarations(clock_domains=(1, 2)), {"bus": _protocol()})
        self.assertTrue(any(conflict.kind == "domain" for conflict in reject_hard_conflicts(domain_graph)))

        protocol_graph = build_constraint_graph(_facts(), _declarations(protocol_b="other"), {"bus": _protocol(), "other": _protocol("other")})
        self.assertTrue(any(conflict.kind == "protocol" for conflict in reject_hard_conflicts(protocol_graph)))

    def test_unknown_clock_domain_is_not_connected_without_explicit_cdc(self) -> None:
        facts = HdlFacts(
            (HdlModule(1, (11, 12), ()), HdlModule(2, (21,), ())),
            (HdlPort(11, 1, "output", 32, False, "request.data"), HdlPort(12, 1, "input", 1, False, "clock"), HdlPort(21, 2, "input", 32, False, "request.data")),
            (),
        )
        declarations = DeclarationSet(
            (
                ComponentDecl(101, 1, "initiator", (PortDecl(11, "request.data", True), PortDecl(12, "clock", True)), (ProtocolBinding(1001, "bus", "initiator", (ProtocolFieldBinding("request.data", 11),)),), (ClockResetDecl(12, "clock", 7, "high", True),)),
                ComponentDecl(202, 2, "target", (PortDecl(21, "request.data", True),), (ProtocolBinding(2002, "bus", "target", (ProtocolFieldBinding("request.data", 21),)),), ()),
            )
        )
        graph = build_constraint_graph(facts, declarations, {"bus": _protocol()})
        self.assertTrue(any(conflict.kind == "domain" for conflict in reject_hard_conflicts(graph)))
        self.assertEqual(list(candidate_edges(graph)), [])

    def test_candidate_edges_preserve_all_legal_endpoint_pairs(self) -> None:
        facts = HdlFacts(
            (HdlModule(1, (11,), ()), HdlModule(2, (21,), ()), HdlModule(3, (31,), ())),
            (HdlPort(11, 1, "output", 32, False, "request.data"), HdlPort(21, 2, "output", 32, False, "request.data"), HdlPort(31, 3, "input", 32, False, "request.data")),
            (),
        )
        binding = lambda endpoint_id, port_id, side: ProtocolBinding(endpoint_id, "bus", side, (ProtocolFieldBinding("request.data", port_id),))
        declarations = DeclarationSet(
            (
                ComponentDecl(101, 1, "initiator", (PortDecl(11, "request.data", True),), (binding(1001, 11, "initiator"),), ()),
                ComponentDecl(202, 2, "initiator", (PortDecl(21, "request.data", True),), (binding(2002, 21, "initiator"),), ()),
                ComponentDecl(303, 3, "target", (PortDecl(31, "request.data", True),), (binding(3003, 31, "target"),), ()),
            )
        )
        graph = build_constraint_graph(facts, declarations, {"bus": _protocol()})
        edges = list(candidate_edges(graph))
        self.assertEqual(
            [(edge.source_endpoint_id, edge.target_endpoint_id) for edge in edges],
            [(1001, 3003), (2002, 3003)],
        )
        self.assertTrue(any(conflict.kind == "required_cardinality" for conflict in reject_hard_conflicts(graph)))

    def test_required_matching_handles_s1_to_t1_t2_and_s2_to_t1(self) -> None:
        facts = HdlFacts(
            (HdlModule(1, (11,), ()), HdlModule(2, (21,), ()), HdlModule(3, (31,), ()), HdlModule(4, (41,), ())),
            (
                HdlPort(11, 1, "output", 32, False, "request.data"),
                HdlPort(21, 2, "output", 32, False, "request.data"),
                HdlPort(31, 3, "input", 32, False, "request.data"),
                HdlPort(41, 4, "input", 32, False, "request.data"),
            ),
            (),
        )
        binding = lambda endpoint_id, port_id, side: ProtocolBinding(endpoint_id, "bus", side, (ProtocolFieldBinding("request.data", port_id),))
        declarations = DeclarationSet(
            (
                ComponentDecl(101, 1, "initiator", (PortDecl(11, "request.data", True),), (binding(1001, 11, "initiator"),), ()),
                ComponentDecl(202, 2, "initiator", (PortDecl(21, "request.data", True),), (binding(2002, 21, "initiator"),), ()),
                ComponentDecl(303, 3, "target", (PortDecl(31, "request.data", True),), (binding(3003, 31, "target"),), ()),
                ComponentDecl(404, 4, "target", (PortDecl(41, "request.data", True),), (binding(4004, 41, "target"),), ()),
            )
        )
        graph = build_constraint_graph(facts, declarations, {"bus": _protocol()})
        graph = replace(
            graph,
            forbidden_edges=tuple(
                sorted(
                    (*graph.forbidden_edges, ForbiddenEdge(2002, 4004, ("test_forbidden",))),
                    key=lambda edge: (edge.source_endpoint_id, edge.target_endpoint_id),
                )
            ),
        )
        edges = list(candidate_edges(graph))
        self.assertEqual(
            [(edge.source_endpoint_id, edge.target_endpoint_id) for edge in edges],
            [(1001, 3003), (1001, 4004), (2002, 3003)],
        )
        self.assertEqual(reject_hard_conflicts(graph), [])

    def test_reverse_cross_protocol_adapter_is_not_legal(self) -> None:
        reverse_adapter = {"kind": "other-to-bus", "source_protocol_id": "other", "target_protocol_id": "bus", "allows_width_mismatch": True}
        graph = build_constraint_graph(_facts(), _declarations(protocol_b="other"), {"bus": _protocol(adapter=[reverse_adapter]), "other": _protocol("other")})
        self.assertTrue(any(conflict.kind == "protocol" for conflict in reject_hard_conflicts(graph)))

    def test_missing_protocol_binding_is_an_input_error(self) -> None:
        declarations = _declarations()
        component = declarations.components[0]
        missing = DeclarationSet((ComponentDecl(component.id, component.module_id, component.role, component.ports, (), component.clock_reset), declarations.components[1]))
        with self.assertRaises(ConstraintGraphError):
            build_constraint_graph(_facts(), missing, {"bus": _protocol()})

    def test_neutral_identifier_renames_produce_isomorphic_graphs(self) -> None:
        raw = {
            "schema_version": "hdl_facts.v2",
            "tool": {"frontend": "test", "verilator_revision": "test", "input_hash": "sha256:" + "0" * 64},
            "modules": [{"id": 1, "ports": [11], "instances": []}, {"id": 2, "ports": [21], "instances": []}],
            "parameters": [], "ports": [
                {"id": 11, "module_id": 1, "direction": "output", "width": 32, "signed": False, "declared_role": "request.data", "name": "plain"},
                {"id": 21, "module_id": 2, "direction": "input", "width": 32, "signed": False, "declared_role": "request.data", "name": "plain2"},
            ],
            "instances": [], "pin_bindings": [], "expressions": [], "dataflow_edges": [{"from_port_id": 11, "to_port_id": 21}], "control_edges": [], "clock_reset_checks": [], "local_address_facts": [], "source_locations": [], "source_symbols": [], "diagnostics": {"errors": [], "warnings": [], "unsupported": []},
        }
        renamed = copy.deepcopy(raw)
        renamed["ports"][0]["name"] = "misleading_target_name"  # type: ignore[index]
        renamed["ports"][1]["name"] = "other_name"  # type: ignore[index]
        left = build_constraint_graph(normalize_facts(raw), _declarations(), {"bus": _protocol()})
        right = build_constraint_graph(normalize_facts(renamed), _declarations(), {"bus": _protocol()})
        self.assertEqual(left, right)


if __name__ == "__main__":
    unittest.main()
