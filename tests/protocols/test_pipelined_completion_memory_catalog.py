from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.protocols.catalog import load_protocol_catalog
from myfuzz.protocols.compiler import compile_runtime_protocol
from myfuzz.protocols.model import ProtocolDefinitionError


PLUGIN_DIR = Path(__file__).resolve().parents[2] / "src" / "myfuzz" / "protocols" / "plugins"
PLUGIN_PATH = PLUGIN_DIR / "pipelined_completion_memory.json"


class PipelinedCompletionMemoryCatalogTest(unittest.TestCase):
    def test_declares_all_physical_roles_with_rvx_widths_and_directions(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        plugin = catalog.require("pipelined-completion-memory", "1")
        expected = {
            "addr": ("host_to_device", "address_width", None, 32),
            "read_request": ("host_to_device", "1", None, 1),
            "read_response": ("device_to_host", "1", None, 1),
            "read_data": ("device_to_host", "data_width", "data", 32),
            "write_request": ("host_to_device", "1", None, 1),
            "write_response": ("device_to_host", "1", None, 1),
            "write_data": ("host_to_device", "data_width", "data", 32),
            "write_strobe": ("host_to_device", "data_width / 8", "byte_enable", 4),
        }

        self.assertEqual(
            {
                field.field_id: (field.direction, field.width_expression, field.semantic_role)
                for field in plugin.fields
            },
            {field_id: values[:3] for field_id, values in expected.items()},
        )
        self.assertTrue(all(field.required and field.reset_value == 0 for field in plugin.fields))
        ports = {field_id: f"port-{field_id}" for field_id in expected}
        compiled = compile_runtime_protocol(
            {
                "binding_id": "rvx-memory",
                "protocol_id": plugin.protocol_id,
                "version": plugin.version,
                "ports": ports,
                "parameters": {"address_width": 32, "data_width": 32},
            },
            {"port_widths": {ports[field_id]: values[3] for field_id, values in expected.items()}},
            catalog,
        )
        self.assertEqual(
            {field.field_id: (field.direction, field.width, field.semantic_role) for field in compiled.fields},
            {field_id: (values[0], values[3], values[2]) for field_id, values in expected.items()},
        )

    def test_declares_separate_completions_and_completion_edge_acceptance(self) -> None:
        plugin = load_protocol_catalog(PLUGIN_DIR).require("pipelined-completion-memory", "1")
        self.assertEqual(
            {(relation.kind, relation.field_ids) for relation in plugin.channel_relations},
            {
                ("read_address_before_response", ("read_request", "addr", "read_response", "read_data")),
                (
                    "write_address_and_data_before_response",
                    ("write_request", "addr", "write_data", "write_strobe", "write_response"),
                ),
            },
        )
        self.assertEqual(
            {
                (rule.kind, rule.antecedent_field_id, rule.consequent_field_id, rule.max_cycles)
                for rule in plugin.temporal_rules
            },
            {
                ("response_after_request", "read_request", "read_response", 16),
                ("response_after_request", "write_request", "write_response", 16),
            },
        )
        self.assertEqual(
            dict(plugin.capability_limits),
            {
                "max_outstanding": 1,
                "byte_enable": True,
                "partial_write": True,
                "stall_supported": True,
                "max_wait_cycles": 16,
                "x-address-unit": "byte",
                "x-completion-edge-next-request": True,
                "x-held-request-single-transaction": True,
                "x-read-data-frozen-on-accept": True,
            },
        )
        self.assertEqual(plugin.legal_adapters, ())

    def test_catalog_rejects_malformed_relation_and_unsupported_temporal_rule(self) -> None:
        self.assertTrue(PLUGIN_PATH.is_file(), "pipelined completion protocol plugin is absent")
        declaration = json.loads(PLUGIN_PATH.read_text(encoding="utf-8"))
        malformed = (
            (
                "relation",
                {
                    **declaration,
                    "channel_relations": [
                        {**declaration["channel_relations"][0], "field_ids": ["read_request", "missing"]}
                    ],
                },
                "channel relation fields",
            ),
            (
                "rule",
                {
                    **declaration,
                    "temporal_rules": [
                        {**declaration["temporal_rules"][0], "kind": "completion_without_request"}
                    ],
                },
                "unsupported temporal rule 0.kind",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / PLUGIN_PATH.name
            for label, document, message in malformed:
                with self.subTest(label=label):
                    source.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaisesRegex(ProtocolDefinitionError, message):
                        load_protocol_catalog(source.parent)
