from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.dependency.csr import to_csr
from myfuzz.dependency.static import build_static_graph
from myfuzz.harness.abi import RawBitAbi, RawBitUse, RawDestination, content_hash
from myfuzz.harness.compiler import _projection_plan
from myfuzz.harness.projection import ProjectionState, project_sample
from myfuzz.protocols.catalog import load_protocol_catalog
from myfuzz.protocols.compiler import compile_protocol
from myfuzz.protocols.model import ProtocolDefinitionError


PLUGIN_DIR = Path(__file__).resolve().parents[2] / "src" / "myfuzz" / "protocols" / "plugins"


class AdditionalProtocolCatalogTest(unittest.TestCase):
    def test_all_eight_declared_protocol_versions_load(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)

        self.assertEqual(
            {(plugin.protocol_id, plugin.version) for plugin in catalog.plugins},
            {
                ("apb", "3"),
                ("apb", "4"),
                ("axi4-lite", "1"),
                ("axi4", "1"),
                ("tl-ul", "1"),
                ("obi", "1"),
                ("wishbone", "classic"),
                ("ready-valid-mmio", "1"),
            },
        )

    def test_axi4_declares_complete_single_beat_channel_contract(self) -> None:
        plugin = load_protocol_catalog(PLUGIN_DIR).require("axi4", "1")
        fields = {field.field_id: field for field in plugin.fields}

        expected = {
            "awid": ("host_to_device", "id_width"),
            "awaddr": ("host_to_device", "address_width"),
            "awlen": ("host_to_device", "8"),
            "awsize": ("host_to_device", "3"),
            "awburst": ("host_to_device", "2"),
            "awvalid": ("host_to_device", "1"),
            "awready": ("device_to_host", "1"),
            "wdata": ("host_to_device", "data_width"),
            "wstrb": ("host_to_device", "data_width / 8"),
            "wlast": ("host_to_device", "1"),
            "wvalid": ("host_to_device", "1"),
            "wready": ("device_to_host", "1"),
            "bid": ("device_to_host", "id_width"),
            "bresp": ("device_to_host", "2"),
            "bvalid": ("device_to_host", "1"),
            "bready": ("host_to_device", "1"),
            "arid": ("host_to_device", "id_width"),
            "araddr": ("host_to_device", "address_width"),
            "arlen": ("host_to_device", "8"),
            "arsize": ("host_to_device", "3"),
            "arburst": ("host_to_device", "2"),
            "arvalid": ("host_to_device", "1"),
            "arready": ("device_to_host", "1"),
            "rid": ("device_to_host", "id_width"),
            "rdata": ("device_to_host", "data_width"),
            "rresp": ("device_to_host", "2"),
            "rlast": ("device_to_host", "1"),
            "rvalid": ("device_to_host", "1"),
            "rready": ("host_to_device", "1"),
        }
        self.assertEqual(
            {field_id: (field.direction, field.width_expression) for field_id, field in fields.items()},
            expected,
        )
        self.assertTrue(all(field.required for field in fields.values()))
        self.assertEqual(
            {action.kind for action in plugin.projection_actions},
            {"mask", "gate", "fold_xor", "constant"},
        )
        self.assertTrue(
            all(
                action.category != "unsupported_burst"
                and action.category != "unsupported_id"
                and action.category != "unsupported_ordering"
                for action in plugin.projection_actions
            )
        )
        self.assertTrue(any(rule.kind == "write_response_after_write" for rule in plugin.temporal_rules))
        self.assertTrue(any(rule.kind == "read_response_after_read" for rule in plugin.temporal_rules))

    def test_wishbone_classic_declares_cycle_strobe_and_response_contract(self) -> None:
        plugin = load_protocol_catalog(PLUGIN_DIR).require("wishbone", "classic")
        fields = {field.field_id: field for field in plugin.fields}

        self.assertEqual(
            {field_id: (field.direction, field.width_expression) for field_id, field in fields.items()},
            {
                "cyc": ("host_to_device", "1"),
                "stb": ("host_to_device", "1"),
                "we": ("host_to_device", "1"),
                "adr": ("host_to_device", "address_width"),
                "dat_w": ("host_to_device", "data_width"),
                "sel": ("host_to_device", "data_width / 8"),
                "ack": ("device_to_host", "1"),
                "err": ("device_to_host", "1"),
                "stall": ("device_to_host", "1"),
                "dat_r": ("device_to_host", "data_width"),
            },
        )
        self.assertTrue(all(field.required for field in fields.values()))
        self.assertEqual(plugin.legal_adapters, ("width-adapter",))
        self.assertTrue(any(rule.kind == "ack_or_error_after_strobe" for rule in plugin.temporal_rules))

    def test_protocol_documents_declare_channel_relations_and_capability_limits(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        axi4 = catalog.require("axi4", "1")
        wishbone = catalog.require("wishbone", "classic")

        self.assertEqual(
            {relation.kind for relation in axi4.channel_relations},
            {"write_address_and_data_before_response", "read_address_before_response"},
        )
        self.assertEqual(
            dict(axi4.capability_limits),
            {
                "max_outstanding": 1,
                "single_beat_only": True,
                "supported_burst_length": 0,
                "supported_id_value": 0,
                "ordering": "in_order_single_id",
                "splitter_required_for_bursts": True,
                "bursts": "reject_non_single_beat",
                "ids": "reject_nonzero",
                "byte_enable": True,
                "partial_write": True,
            },
        )
        self.assertEqual(
            {relation.kind for relation in wishbone.channel_relations},
            {"cycle_strobe_held_until_completion"},
        )
        self.assertEqual(
            dict(wishbone.capability_limits),
            {
                "max_outstanding": 1,
                "single_beat_only": True,
                "stall_supported": True,
                "completion": "ack_or_err",
                "max_wait_cycles": 16,
                "byte_enable": True,
                "partial_write": True,
            },
        )

    def test_every_runtime_profile_preserves_channel_and_byte_enable_contracts(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        expected = {
            ("apb", "3"): (False, False),
            ("apb", "4"): (True, True),
            ("axi4-lite", "1"): (True, True),
            ("axi4", "1"): (True, True),
            ("tl-ul", "1"): (True, True),
            ("obi", "1"): (False, False),
            ("wishbone", "classic"): (True, True),
            ("ready-valid-mmio", "1"): (False, False),
        }
        for identity, (byte_enable, partial_write) in expected.items():
            with self.subTest(protocol=identity):
                plugin = catalog.require(*identity)
                self.assertTrue(plugin.channel_relations)
                self.assertEqual(dict(plugin.capability_limits)["byte_enable"], byte_enable)
                self.assertEqual(dict(plugin.capability_limits)["partial_write"], partial_write)
                if not partial_write:
                    self.assertTrue(
                        any(
                            action.kind == "fold_xor"
                            and action.category == "dependency_consistency"
                            for action in plugin.projection_actions
                        )
                    )

    def test_axi4_constant_constraints_compile_through_projection_pipeline(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        plugin = catalog.require("axi4", "1")
        width_expressions = {
            "address_width": 32,
            "data_width": 32,
            "data_width / 8": 4,
            "id_width": 4,
        }
        widths = {
            field.field_id: (
                width_expressions[field.width_expression]
                if field.width_expression in width_expressions
                else int(field.width_expression)
            )
            for field in plugin.fields
        }
        ports = {field.field_id: str(index + 1) for index, field in enumerate(plugin.fields)}
        compiled = compile_protocol(
            {
                "binding_id": "axi4-binding",
                "protocol_id": "axi4",
                "version": "1",
                "ports": ports,
                "parameters": {"address_width": 32, "data_width": 32, "id_width": 4},
            },
            {"port_widths": {ports[field_id]: width for field_id, width in widths.items()}},
            catalog,
            require_runtime=True,
        )
        inputs = tuple(field for field in compiled.fields if field.direction == "host_to_device")
        destinations = tuple(
            RawDestination(index, None, int(field.port_id), field.width)
            for index, field in enumerate(inputs)
        )
        cursor = 0
        uses = []
        for destination in destinations:
            uses.append(RawBitUse(cursor, cursor + destination.width - 1, destination.destination_id, 0, "direct", "direct"))
            cursor += destination.width
        raw_abi = RawBitAbi(
            cursor,
            destinations,
            tuple(uses),
            content_hash({"fixture": "axi4-projection", "width": cursor}),
        )
        graph = to_csr(build_static_graph({}, (compiled,)))

        plan = _projection_plan(raw_abi, (compiled,), {"axi4": plugin}, graph, None)
        driven = dict(project_sample(plan, (1 << cursor) - 1, ProjectionState.initial(plan)).driven_fields)
        destination_for = {field.field_id: index for index, field in enumerate(inputs)}

        self.assertEqual(driven[destination_for["awlen"]], 0)
        self.assertEqual(driven[destination_for["arlen"]], 0)
        self.assertEqual(driven[destination_for["awid"]], 0)
        self.assertEqual(driven[destination_for["arid"]], 0)
        self.assertEqual(driven[destination_for["wlast"]], 1)

    def test_catalog_rejects_dangling_references_duplicate_fields_and_invalid_widths(self) -> None:
        document = {
            "protocol_id": "example",
            "version": "1",
            "legal_adapters": ["width-adapter"],
            "fields": [
                {
                    "field_id": "request",
                    "direction": "host_to_device",
                    "width": "address_width",
                    "required": True,
                    "reset_value": 0,
                },
                {
                    "field_id": "response",
                    "direction": "device_to_host",
                    "width": "1",
                    "required": True,
                    "reset_value": 0,
                },
            ],
            "projection_actions": [
                {
                    "action_id": 1,
                    "field_ids": ["request"],
                    "kind": "gate",
                    "category": "protocol_legality",
                    "max_cycles": 16,
                }
            ],
            "temporal_rules": [
                {
                    "rule_id": 1,
                    "kind": "response_after_request",
                    "antecedent_field_id": "request",
                    "consequent_field_id": "response",
                    "max_cycles": 16,
                }
            ],
        }
        invalid_documents = {
            "dangling_action": {**document, "projection_actions": [{**document["projection_actions"][0], "field_ids": ["missing"]}]},
            "dangling_rule": {**document, "temporal_rules": [{**document["temporal_rules"][0], "consequent_field_id": "missing"}]},
            "duplicate_field": {**document, "fields": [*document["fields"], document["fields"][0]]},
            "invalid_width": {**document, "fields": [{**document["fields"][0], "width": "address_width +"}, document["fields"][1]]},
            "zero_divisor": {**document, "fields": [{**document["fields"][0], "width": "address_width / 0"}, document["fields"][1]]},
            "dangling_channel_relation": {
                **document,
                "channel_relations": [{"relation_id": 1, "kind": "request_response", "field_ids": ["missing"]}],
            },
            "duplicate_channel_relation": {
                **document,
                "channel_relations": [
                    {"relation_id": 1, "kind": "request_response", "field_ids": ["request", "response"]},
                    {"relation_id": 1, "kind": "request_response", "field_ids": ["request", "response"]},
                ],
            },
            "invalid_capability_value": {**document, "capability_limits": {"partial_write": 1.5}},
            "unsupported_projection_kind": {
                **document,
                "projection_actions": [
                    {**document["projection_actions"][0], "kind": "reject"}
                ],
            },
        }

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            for label, invalid_document in invalid_documents.items():
                with self.subTest(case=label):
                    (directory / "example.json").write_text(json.dumps(invalid_document), encoding="utf-8")
                    with self.assertRaises(ProtocolDefinitionError):
                        load_protocol_catalog(directory)


if __name__ == "__main__":
    unittest.main()
