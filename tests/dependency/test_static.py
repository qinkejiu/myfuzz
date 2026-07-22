from __future__ import annotations

import unittest

from myfuzz.dependency.static import build_static_graph
from myfuzz.protocols.model import CompiledField, CompiledProtocol


def compiled(binding_id: str, fields: tuple[CompiledField, ...]) -> CompiledProtocol:
    return CompiledProtocol(binding_id, "declared-protocol", "1", fields)


class StaticGraphTest(unittest.TestCase):
    def test_includes_declared_groups_dataflow_and_adapter_edges(self) -> None:
        protocols = (
            compiled("endpoint-a", (
                CompiledField("request", "host_to_device", 1, "port-1", 0),
                CompiledField("response", "device_to_host", 1, "port-4", 0),
            )),
            compiled("endpoint-b", (
                CompiledField("payload", "host_to_device", 8, "port-3", 0),
            )),
        )
        facts = {
            "dataflow_edges": [{"source_port_id": "port-1", "target_port_id": "port-2"}],
            "control_edges": [{"source_port_id": "port-2", "target_port_id": "port-4"}],
            "adapter_edges": [{"adapter_id": "adapter-1", "source_port_id": "port-2", "target_port_id": "port-3"}],
        }

        graph = build_static_graph(facts, protocols)

        self.assertEqual(("group:endpoint-a:request", "group:endpoint-b:payload"), graph.group_ids)
        edges = {(edge.source_id, edge.target_id, edge.kind) for edge in graph.edges}
        self.assertIn(("group:endpoint-a:request", "port:port-1", "declared_field"), edges)
        self.assertIn(("port:port-1", "port:port-2", "rtl_dataflow"), edges)
        self.assertIn(("port:port-2", "port:port-4", "rtl_control"), edges)
        self.assertIn(("port:port-2", "port:port-3", "adapter:adapter-1"), edges)

    def test_excludes_explicit_clock_reset_and_external_endpoint_ports(self) -> None:
        protocols = (compiled("endpoint-a", (
            CompiledField("request", "host_to_device", 1, "port-1", 0),
        )),)
        facts = {
            "clock_port_ids": ["port-2"],
            "reset_port_ids": ["port-3"],
            "external_endpoint_port_ids": ["port-4"],
            "dataflow_edges": [
                {"source_port_id": "port-1", "target_port_id": "port-2"},
                {"source_port_id": "port-1", "target_port_id": "port-3"},
                {"source_port_id": "port-1", "target_port_id": "port-4"},
            ],
        }

        graph = build_static_graph(facts, protocols)

        self.assertEqual({"port:port-1", "group:endpoint-a:request"}, set(graph.node_ids))
        self.assertEqual({("group:endpoint-a:request", "port:port-1")}, {(edge.source_id, edge.target_id) for edge in graph.edges})

    def test_coalesces_more_than_sixty_four_groups_with_deterministic_diagnostic(self) -> None:
        fields = tuple(CompiledField(f"field-{index:02d}", "host_to_device", 1, f"port-{index:02d}", 0) for index in range(65))

        graph = build_static_graph({}, (compiled("endpoint-a", fields),))

        self.assertEqual(64, len(graph.group_ids))
        self.assertEqual("group:coalesced:000", graph.group_ids[-1])
        self.assertEqual(("coalesced dependency groups from 65 to 64",), graph.diagnostics)


if __name__ == "__main__":
    unittest.main()
