from __future__ import annotations

import unittest
from pathlib import Path

from myfuzz.protocols.catalog import load_protocol_catalog
from myfuzz.protocols.compiler import (
    ProtocolCompilationError,
    compile_protocol,
    protocol_input_fields,
)


PLUGIN_DIR = Path(__file__).resolve().parents[2] / "src" / "myfuzz" / "protocols" / "plugins"


class ProtocolCatalogTest(unittest.TestCase):
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
