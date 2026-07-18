import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (
    ConnectionKind,
    ConnectionRequest,
    ConstraintKind,
    EndpointRef,
    InputValidationError,
    PortDirection,
    SignalConstraint,
    SignalEndpoint,
    build_system_graph,
)


def endpoint(module, port, direction, width=1, semantic=None):
    return SignalEndpoint(EndpointRef(module, port), PortDirection(direction), width, semantic)


def connection(source, target, kind=ConnectionKind.DATA):
    return ConnectionRequest(
        EndpointRef(*source), EndpointRef(*target), kind,
        reason="explicit integration rule", evidence_source="user", confidence="declared",
    )


class SystemGraphTest(unittest.TestCase):
    def test_connections_have_stable_semantic_order(self):
        endpoints = [
            endpoint("clock", "clk_o", "output", semantic="clock"),
            endpoint("cpu", "clk_i", "input", semantic="clock"),
            endpoint("cpu", "req_o", "output", semantic="bus.req"),
            endpoint("ram", "req_i", "input", semantic="bus.req"),
        ]
        requests = [
            connection(("cpu", "req_o"), ("ram", "req_i"), ConnectionKind.PROTOCOL),
            connection(("clock", "clk_o"), ("cpu", "clk_i"), ConnectionKind.CLOCK_RESET),
        ]
        graph = build_system_graph(endpoints, reversed(requests))
        self.assertEqual([edge.kind for edge in graph.connections], [
            ConnectionKind.CLOCK_RESET, ConnectionKind.PROTOCOL,
        ])
        self.assertEqual([edge.order for edge in graph.connections], [0, 1])

    def test_width_mismatch_fails(self):
        with self.assertRaisesRegex(InputValidationError, "width mismatch"):
            build_system_graph(
                [endpoint("a", "out", "output", 8), endpoint("b", "in", "input", 4)],
                [connection(("a", "out"), ("b", "in"))],
            )

    def test_direction_mismatch_fails(self):
        with self.assertRaisesRegex(InputValidationError, "source.*not an output"):
            build_system_graph(
                [endpoint("a", "in", "input"), endpoint("b", "in", "input")],
                [connection(("a", "in"), ("b", "in"))],
            )

    def test_multiple_drivers_fail(self):
        endpoints = [
            endpoint("a", "out", "output"), endpoint("b", "out", "output"),
            endpoint("c", "in", "input"),
        ]
        with self.assertRaisesRegex(InputValidationError, "multiple drivers"):
            build_system_graph(endpoints, [
                connection(("a", "out"), ("c", "in")),
                connection(("b", "out"), ("c", "in")),
            ])

    def test_constraint_is_explicit_and_reportable(self):
        target = EndpointRef("unit", "test_mode")
        constraint = SignalConstraint(
            target=target,
            kind=ConstraintKind.CONSTANT,
            expression="value == 0",
            reason="documented inactive test mode",
            evidence_source="user",
            confidence="declared",
        )
        graph = build_system_graph([endpoint("unit", "test_mode", "input")], [], [constraint])
        self.assertEqual(graph.constraints, (constraint,))

    def test_connection_and_constraint_cannot_both_drive_input(self):
        target = EndpointRef("b", "in")
        constraint = SignalConstraint(
            target, ConstraintKind.CONSTANT, "value == 0", "tieoff", "profile", "profile",
        )
        with self.assertRaisesRegex(InputValidationError, "both a connection and a constraint"):
            build_system_graph(
                [endpoint("a", "out", "output"), endpoint("b", "in", "input")],
                [connection(("a", "out"), ("b", "in"))],
                [constraint],
            )

    def test_connected_input_may_have_non_driving_handshake_constraint(self):
        target = EndpointRef("b", "in")
        constraint = SignalConstraint(
            target, ConstraintKind.HANDSHAKE, "stable while valid", "protocol", "profile", "profile",
        )
        graph = build_system_graph(
            [endpoint("a", "out", "output"), endpoint("b", "in", "input")],
            [connection(("a", "out"), ("b", "in"))], [constraint],
        )
        self.assertEqual(graph.constraints, (constraint,))


if __name__ == "__main__":
    unittest.main()
