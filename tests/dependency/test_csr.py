from __future__ import annotations

import unittest

from myfuzz.dependency.csr import to_csr
from myfuzz.dependency.graph import DependencyEdge, DependencyGraph


class CsrGraphTest(unittest.TestCase):
    def test_csr_orders_nodes_and_adjacency_deterministically(self) -> None:
        graph = DependencyGraph(
            node_ids=("port:z", "group:b", "port:a", "group:a"),
            group_ids=("group:b", "group:a"),
            edges=(
                DependencyEdge("port:z", "group:b", "rtl_dataflow", "fact-2"),
                DependencyEdge("group:a", "port:z", "declared_field", "fact-1"),
                DependencyEdge("group:a", "port:a", "declared_field", "fact-3"),
            ),
            diagnostics=(),
        )

        csr = to_csr(graph)

        self.assertEqual(("group:a", "group:b", "port:a", "port:z"), csr.node_ids)
        self.assertEqual((0, 2, 2, 2, 3), csr.indptr)
        self.assertEqual((2, 3, 1), csr.indices)
        self.assertEqual(("declared_field", "declared_field", "rtl_dataflow"), csr.edge_kinds)
        self.assertEqual(("fact-3", "fact-1", "fact-2"), csr.evidence_ids)

    def test_csr_rejects_edge_to_undeclared_node(self) -> None:
        graph = DependencyGraph(
            node_ids=("group:a",), group_ids=("group:a",),
            edges=(DependencyEdge("group:a", "port:missing", "declared_field", "fact"),), diagnostics=(),
        )

        with self.assertRaisesRegex(ValueError, "unknown dependency node"):
            to_csr(graph)


if __name__ == "__main__":
    unittest.main()
