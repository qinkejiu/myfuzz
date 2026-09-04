from __future__ import annotations

import json
import unittest
from pathlib import Path

from myfuzz.protocols.catalog import load_protocol_catalog
from myfuzz.protocols.compiler import (
    ProtocolCompilationError,
    compile_protocol,
    compile_runtime_protocol,
    protocol_input_fields,
)


PLUGIN_DIR = Path(__file__).resolve().parents[2] / "src" / "myfuzz" / "protocols" / "plugins"
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "protocol.v1.schema.json"


class ProtocolCatalogTest(unittest.TestCase):
    def test_runtime_protocols_expose_complete_field_sets(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        cases = (
            (
                "apb",
                "4",
                {"paddr", "pprot", "psel", "penable", "pwrite", "pwdata", "pstrb", "pready", "prdata", "pslverr"},
            ),
            (
                "axi4-lite",
                "1",
                {
                    "awaddr", "awprot", "awvalid", "awready", "wdata", "wstrb", "wvalid", "wready",
                    "bresp", "bvalid", "bready", "araddr", "arprot", "arvalid", "arready", "rdata",
                    "rresp", "rvalid", "rready",
                },
            ),
            (
                "tl-ul",
                "1",
                {
                    "a_valid", "a_ready", "a_opcode", "a_param", "a_size", "a_source", "a_address",
                    "a_mask", "a_data", "a_corrupt", "d_valid", "d_ready", "d_opcode", "d_param",
                    "d_size", "d_source", "d_sink", "d_denied", "d_data", "d_corrupt",
                },
            ),
        )
        for protocol_id, version, expected_fields in cases:
            with self.subTest(protocol_id=protocol_id, version=version):
                plugin = catalog.require(protocol_id, version)
                runtime_fields = {
                    field.field_id for field in plugin.fields if field.required or field.runtime_required
                }
                self.assertEqual(runtime_fields, expected_fields)

    def test_runtime_required_defaults_to_false(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        plugin = catalog.require("ready-valid-mmio", "1")

        self.assertTrue(all(not field.runtime_required for field in plugin.fields))

    def test_abstract_apb4_binding_can_omit_runtime_only_pprot(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        port_fields = {
            "paddr": ("port-paddr", 32),
            "psel": ("port-psel", 1),
            "penable": ("port-penable", 1),
            "pwrite": ("port-pwrite", 1),
            "pwdata": ("port-pwdata", 32),
            "pstrb": ("port-pstrb", 4),
            "pready": ("port-pready", 1),
            "prdata": ("port-prdata", 32),
            "pslverr": ("port-pslverr", 1),
        }
        binding = {
            "binding_id": "apb4-abstract",
            "protocol_id": "apb",
            "version": "4",
            "ports": {field_id: value[0] for field_id, value in port_fields.items()},
            "parameters": {"address_width": 32, "data_width": 32},
        }
        facts = {"port_widths": {port_id: width for port_id, width in port_fields.values()}}

        compiled = compile_protocol(binding, facts, catalog)
        self.assertNotIn("pprot", {field.field_id for field in compiled.fields})
        with self.assertRaisesRegex(ProtocolCompilationError, "missing declared port binding.*pprot"):
            compile_runtime_protocol(binding, facts, catalog)

    def test_protocol_schema_declares_runtime_required_as_boolean(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

        runtime_required = schema["properties"]["channels"]["items"]["properties"]["fields"]["items"]["properties"]["runtime_required"]
        self.assertEqual(runtime_required, {"type": "boolean"})

    def test_catalog_exposes_required_declared_fields(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        cases = (
            ("ready-valid-mmio", "1", {"addr", "write", "wdata", "valid", "ready", "rdata"}),
            ("apb", "3", {"paddr", "psel", "penable", "pwrite", "pwdata", "prdata"}),
            ("apb", "4", {"paddr", "psel", "penable", "pwrite", "pwdata", "pstrb", "prdata"}),
            ("axi4-lite", "1", {"awaddr", "awvalid", "awready", "wdata", "wvalid", "bvalid", "araddr", "rdata"}),
            ("obi", "1", {"req", "gnt", "addr", "we", "wdata", "rvalid", "rdata"}),
            ("tl-ul", "1", {"a_valid", "a_opcode", "a_address", "d_valid", "d_opcode", "d_data"}),
        )
        for protocol_id, version, required_fields in cases:
            with self.subTest(protocol_id=protocol_id, version=version):
                plugin = catalog.require(protocol_id, version)
                self.assertTrue(required_fields <= {field.field_id for field in plugin.fields})
                self.assertTrue(all(field.direction in {"host_to_device", "device_to_host"} for field in plugin.fields))
                self.assertTrue(all(field.reset_value is not None for field in plugin.fields))

    def test_every_builtin_has_nonempty_bounded_dependency_aware_policy(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        for protocol_id, version in (
            ("ready-valid-mmio", "1"),
            ("apb", "3"),
            ("apb", "4"),
            ("axi4-lite", "1"),
            ("obi", "1"),
            ("tl-ul", "1"),
        ):
            with self.subTest(protocol_id=protocol_id, version=version):
                plugin = catalog.require(protocol_id, version)
                self.assertTrue(plugin.projection_actions)
                self.assertTrue(plugin.temporal_rules)
                self.assertTrue(
                    all(
                        action.max_cycles is not None
                        for action in plugin.projection_actions
                        if action.kind in {"gate", "delay_select"}
                    )
                )
                self.assertTrue(all(1 <= rule.max_cycles <= 65_535 for rule in plugin.temporal_rules))

    def test_compile_uses_only_explicit_port_ids_and_width_facts(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        binding = {
            "binding_id": "binding-7", "protocol_id": "ready-valid-mmio", "version": "1",
            "ports": {"addr": "port-17", "write": "port-18", "wdata": "port-19", "valid": "port-20", "ready": "port-21", "rdata": "port-22"},
            "parameters": {"address_width": 19, "data_width": 64},
        }
        facts = {"port_widths": {"port-17": 19, "port-18": 1, "port-19": 64, "port-20": 1, "port-21": 1, "port-22": 64}}

        compiled = compile_protocol(binding, facts, catalog)

        self.assertEqual(compiled.binding_id, "binding-7")
        self.assertEqual(compiled.port_for("addr"), "port-17")
        self.assertEqual(compiled.field_for("wdata").width, 64)
        self.assertEqual([field.field_id for field in protocol_input_fields(compiled)], ["addr", "write", "wdata", "valid"])

    def test_compile_rejects_missing_explicit_binding(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        binding = {
            "binding_id": "binding-8", "protocol_id": "obi", "version": "1",
            "ports": {"req": "port-1", "gnt": "port-2", "addr": "port-3", "we": "port-4", "wdata": "port-5", "rvalid": "port-6"},
            "parameters": {"address_width": 32, "data_width": 32},
        }
        facts = {"port_widths": {f"port-{index}": 32 for index in range(1, 9)}}

        with self.assertRaisesRegex(ProtocolCompilationError, "missing declared port binding.*rdata"):
            compile_protocol(binding, facts, catalog)

    def test_compile_rejects_unsupported_protocol_version(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        binding = {"binding_id": "binding-9", "protocol_id": "apb", "version": "5", "ports": {}, "parameters": {}}

        with self.assertRaisesRegex(ProtocolCompilationError, "unsupported protocol version: apb@5"):
            compile_protocol(binding, {}, catalog)


if __name__ == "__main__":
    unittest.main()
