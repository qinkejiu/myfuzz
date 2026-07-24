from __future__ import annotations

import unittest

from myfuzz.dependency.csr import to_csr
from myfuzz.dependency.graph import DependencyEdge, DependencyGraph, field_group_node, port_node


class CsrGraphTest(unittest.TestCase):
    def test_csr_orders_nodes_and_adjacency_deterministically(self) -> None:
        graph = DependencyGraph(
            node_ids=(port_node("z"), field_group_node("b", "field"), port_node("a"), field_group_node("a", "field")),
            group_ids=(field_group_node("b", "field"), field_group_node("a", "field")),
            edges=(
                DependencyEdge(port_node("z"), field_group_node("b", "field"), "rtl_dataflow", "fact-2"),
                DependencyEdge(field_group_node("a", "field"), port_node("z"), "declared_field", "fact-1"),
                DependencyEdge(field_group_node("a", "field"), port_node("a"), "declared_field", "fact-3"),
            ),
            diagnostics=(),
        )

        csr = to_csr(graph)

        self.assertEqual((field_group_node("a", "field"), field_group_node("b", "field"), port_node("a"), port_node("z")), csr.node_ids)
        self.assertEqual((0, 2, 2, 2, 3), csr.indptr)
        self.assertEqual((2, 3, 1), csr.indices)
        self.assertEqual(("declared_field", "declared_field", "rtl_dataflow"), csr.edge_kinds)
        self.assertEqual(("fact-3", "fact-1", "fact-2"), csr.evidence_ids)

    def test_csr_rejects_edge_to_undeclared_node(self) -> None:
        graph = DependencyGraph(
            node_ids=(field_group_node("a", "field"),), group_ids=(field_group_node("a", "field"),),
            edges=(DependencyEdge(field_group_node("a", "field"), port_node("missing"), "declared_field", "fact"),), diagnostics=(),
        )

        with self.assertRaisesRegex(ValueError, "unknown dependency node"):
            to_csr(graph)


if __name__ == "__main__":
    unittest.main()
