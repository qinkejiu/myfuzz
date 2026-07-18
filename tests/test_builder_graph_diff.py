import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    ConnectionKind, ConnectionRequest, EdgeEquivalence, EndpointRef, InputValidationError,
    PortDirection, SignalEndpoint, build_system_graph, compare_planned_realized,
)


def graph(source="a", target="b"):
    endpoints = [
        SignalEndpoint(EndpointRef(source, "o"), PortDirection.OUTPUT, 8, "data"),
        SignalEndpoint(EndpointRef(target, "i"), PortDirection.INPUT, 8, "data"),
    ]
    return build_system_graph(endpoints, [ConnectionRequest(
        EndpointRef(source, "o"), EndpointRef(target, "i"), ConnectionKind.DATA,
        "planned edge", "ast", "proven",
    )])


class GraphDiffTest(unittest.TestCase):
    def test_identical_graph_is_equivalent(self):
        result = compare_planned_realized(graph(), graph())
        self.assertTrue(result.equivalent)

    def test_unlisted_edge_change_fails_closed(self):
        result = compare_planned_realized(graph(), graph("a", "c"))
        self.assertFalse(result.equivalent)
        self.assertTrue(result.unexpected_edges)

    def test_explicit_equivalence_requires_matching_semantics_and_evidence(self):
        planned = graph()
        realized = graph("a", "c")
        result = compare_planned_realized(
            planned, realized,
            (EdgeEquivalence(
                (EndpointRef("a", "o"), EndpointRef("b", "i")),
                (EndpointRef("a", "o"), EndpointRef("c", "i")),
                "generate_replication", "frontend source-to-realized mapping",
            ),),
        )
        self.assertTrue(result.equivalent)
        with self.assertRaisesRegex(InputValidationError, "absent"):
            compare_planned_realized(planned, realized, (EdgeEquivalence(
                (EndpointRef("missing", "o"), EndpointRef("b", "i")),
                (EndpointRef("a", "o"), EndpointRef("c", "i")), "x", "y",
            ),))


if __name__ == "__main__":
    unittest.main()
