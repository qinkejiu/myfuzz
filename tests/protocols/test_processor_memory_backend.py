from __future__ import annotations

import unittest
from pathlib import Path

from myfuzz.composition.endpoint_capabilities import normalize_annotations
from myfuzz.composition.processor_boundary import build_processor_boundary
from myfuzz.protocols.catalog import load_builtin_protocol, load_protocol_catalog
from myfuzz.protocols.compiler import compile_runtime_protocol
from myfuzz.protocols.widths import compile_width_expression


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = ROOT / "src/myfuzz/protocols/plugins"


class ProcessorMemoryBackendTests(unittest.TestCase):
    def test_backend_declares_complete_beat_request_and_response(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        plugin = catalog.require("processor-memory-beat", "1")

        self.assertEqual(
            {
                "req_valid", "req_ready", "write", "addr", "wdata", "be",
                "rsp_valid", "rsp_ready", "rdata", "error",
            },
            {field.field_id for field in plugin.fields},
        )
        self.assertTrue(all(field.required for field in plugin.fields))
        self.assertEqual(
            {
                "max_outstanding": 1,
                "byte_enable": True,
                "partial_write": True,
                "stall_supported": True,
                "completion": "ack_or_err",
                "max_wait_cycles": 16,
                "ordering": "in_order_single_id",
            },
            dict(plugin.capability_limits),
        )

    def test_backend_compiles_for_32_and_64_bit_data(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        plugin = catalog.require("processor-memory-beat", "1")
        for data_width in (32, 64):
            with self.subTest(data_width=data_width):
                parameters = {"address_width": 64, "data_width": data_width}
                ports = {field.field_id: "port_" + field.field_id for field in plugin.fields}
                widths = {
                    ports[field.field_id]: compile_width_expression(
                        field.width_expression, parameters
                    )
                    for field in plugin.fields
                }
                compiled = compile_runtime_protocol(
                    {
                        "binding_id": "backend",
                        "protocol_id": "processor-memory-beat",
                        "version": "1",
                        "ports": ports,
                        "parameters": parameters,
                    },
                    {"port_widths": widths},
                    catalog,
                )
                self.assertEqual(data_width // 8, compiled.field_for("be").width)
                self.assertEqual(64, compiled.field_for("addr").width)

    def test_backend_forms_a_generic_processor_memory_boundary(self) -> None:
        catalog = load_protocol_catalog(PLUGIN_DIR)
        plugin = catalog.require("processor-memory-beat", "1")
        parameters = {"address_width": 32, "data_width": 32}
        fields = []
        for line, field in enumerate(plugin.fields, 1):
            fields.append({
                "role": field.field_id,
                "port": "opaque_" + field.field_id,
                "direction": "output" if field.direction == "host_to_device" else "input",
                "width": compile_width_expression(field.width_expression, parameters),
                "signed": False,
                "source": {"file": "rtl/renamed.sv", "line": line, "column": 1},
                "evidence": ["hdl_declaration"],
            })
        annotations = {
            "schema_version": "interface_annotations.v1",
            "endpoints": [
                {
                    "endpoint_id": "opaque.memory",
                    "function": "memory_master",
                    "side": "initiator",
                    "protocol": ["processor-memory-beat", "1"],
                    "fields": fields,
                },
                {
                    "endpoint_id": "opaque.clock", "function": "clock",
                    "fields": [{
                        "role": "clock", "port": "opaque_clk", "direction": "input",
                        "width": 1, "signed": False,
                        "source": {"file": "rtl/renamed.sv", "line": 20, "column": 1},
                        "evidence": ["hdl_declaration"],
                    }],
                },
                {
                    "endpoint_id": "opaque.reset", "function": "reset",
                    "fields": [{
                        "role": "reset", "port": "opaque_rst", "direction": "input",
                        "width": 1, "signed": False,
                        "source": {"file": "rtl/renamed.sv", "line": 21, "column": 1},
                        "evidence": ["hdl_declaration"],
                    }],
                },
            ],
        }

        boundary = build_processor_boundary(
            normalize_annotations(annotations), protocol_catalog=catalog
        )
        self.assertEqual(("processor-memory-beat", "1"), boundary.memories[0].protocol)
        self.assertEqual((), boundary.memories[0].extension_fields)

    def test_existing_ready_valid_contract_remains_unambiguous(self) -> None:
        plugin = load_builtin_protocol("ready-valid-mmio")
        self.assertEqual("1", plugin.version)
        self.assertEqual(
            {"addr", "write", "wdata", "valid", "ready", "rdata"},
            {field.field_id for field in plugin.fields},
        )


if __name__ == "__main__":
    unittest.main()
