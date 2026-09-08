from __future__ import annotations

import unittest
from pathlib import Path

from myfuzz.composition.endpoint_capabilities import EndpointFieldFact
from myfuzz.composition.processor_adapters import (
    ProcessorAdapterError,
    resolve_processor_adapter,
)
from myfuzz.composition.processor_boundary import ProcessorMemoryBinding
from myfuzz.protocols.catalog import load_protocol_catalog


ROOT = Path(__file__).resolve().parents[2]


def _field(role: str, direction: str, width: int = 1) -> EndpointFieldFact:
    return EndpointFieldFact(role, "opaque_" + role, direction, width, False)


def _axi_memory(*extra: EndpointFieldFact) -> ProcessorMemoryBinding:
    fields = (
        _field("awvalid", "output"), _field("awready", "input"),
        _field("wvalid", "output"), _field("wready", "input"),
        _field("bvalid", "input"), _field("bready", "output"),
        _field("arvalid", "output"), _field("arready", "input"),
        _field("rvalid", "input"), _field("rready", "output"),
        *extra,
    )
    return ProcessorMemoryBinding(
        "memory", "memory_master", ("axi4", "1"), fields, tuple(extra)
    )


def _obi_memory(*optional: EndpointFieldFact) -> ProcessorMemoryBinding:
    fields = (
        _field("req", "output"), _field("gnt", "input"),
        _field("addr", "output", 32), _field("rvalid", "input"),
        _field("rdata", "input", 32), *optional,
    )
    extensions = tuple(field for field in optional if field.role in {"be", "error"})
    return ProcessorMemoryBinding(
        "memory", "instruction_memory_master", ("obi", "1"), fields, extensions
    )


def _tl_memory() -> ProcessorMemoryBinding:
    roles = (
        ("a_valid", "output", 1), ("a_ready", "input", 1),
        ("a_opcode", "output", 3), ("a_param", "output", 3),
        ("a_size", "output", 3), ("a_source", "output", 1),
        ("a_address", "output", 32), ("a_mask", "output", 4),
        ("a_data", "output", 32), ("a_corrupt", "output", 1),
        ("d_valid", "input", 1), ("d_ready", "output", 1),
        ("d_opcode", "input", 3), ("d_param", "input", 3),
        ("d_size", "input", 3), ("d_source", "input", 1),
        ("d_sink", "input", 1), ("d_denied", "input", 1),
        ("d_data", "input", 32), ("d_corrupt", "input", 1),
    )
    fields = tuple(_field(*item) for item in roles)
    return ProcessorMemoryBinding(
        "memory", "memory_master", ("tl-ul", "1"), fields, ()
    )


def _ready_valid_memory(*extra: EndpointFieldFact) -> ProcessorMemoryBinding:
    fields = (
        _field("valid", "output"), _field("ready", "input"),
        _field("addr", "output", 32), _field("wdata", "output", 32),
        _field("wstrb", "output", 4), _field("rdata", "input", 32),
        *extra,
    )
    return ProcessorMemoryBinding(
        "memory", "memory_master", ("ready-valid-memory", "1"), fields, tuple(extra)
    )


class ProcessorAdapterTests(unittest.TestCase):
    def test_axi_adapter_selection_uses_protocol_and_explicit_extension_policy(self) -> None:
        extras = tuple(
            _field(role, direction, width)
            for role, direction, width in (
                ("awlock", "output", 1), ("awcache", "output", 4), ("awprot", "output", 3),
                ("awqos", "output", 4), ("awregion", "output", 4), ("awatop", "output", 6),
                ("awuser", "output", 64), ("wuser", "output", 64), ("buser", "input", 64),
                ("arlock", "output", 1), ("arcache", "output", 4), ("arprot", "output", 3),
                ("arqos", "output", 4), ("arregion", "output", 4), ("aruser", "output", 64),
                ("ruser", "input", 64),
            )
        )
        adapter = resolve_processor_adapter(_axi_memory(*extras))
        policies = {item.role: item.action for item in adapter.extension_policies}

        self.assertEqual("axi4-to-processor-memory-beat", adapter.adapter_id)
        self.assertEqual(("processor-memory-beat", "1"), adapter.target_protocol)
        self.assertEqual(
            "src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv",
            adapter.rtl_source,
        )
        self.assertEqual("reject-with-axi-completion", policies["awatop"])
        self.assertEqual("reject-nonzero", policies["awlock"])
        self.assertEqual("reject-nonzero", policies["arlock"])
        self.assertEqual("drive-zero", policies["buser"])
        self.assertEqual("drive-zero", policies["ruser"])
        self.assertEqual("accept-ignore", policies["awcache"])
        self.assertNotIn("cva6", repr(adapter).lower())

    def test_unknown_extension_and_wrong_direction_fail_closed(self) -> None:
        with self.assertRaisesRegex(ProcessorAdapterError, "unsupported-extension:mystery"):
            resolve_processor_adapter(_axi_memory(_field("mystery", "output")))
        with self.assertRaisesRegex(ProcessorAdapterError, "extension-direction:buser"):
            resolve_processor_adapter(_axi_memory(_field("buser", "output")))
        with self.assertRaisesRegex(ProcessorAdapterError, "extension-width:awatop"):
            resolve_processor_adapter(_axi_memory(_field("awatop", "output", 5)))
        with self.assertRaisesRegex(ProcessorAdapterError, "extension-width-group:user"):
            resolve_processor_adapter(_axi_memory(
                _field("awuser", "output", 8), _field("buser", "input", 4)
            ))

    def test_protocol_without_implemented_adapter_is_explicitly_rejected(self) -> None:
        memory = ProcessorMemoryBinding(
            "memory", "memory_master", ("tilelink", "1"), (), ()
        )
        with self.assertRaisesRegex(
            ProcessorAdapterError, "unsupported-processor-adapter:tilelink@1"
        ):
            resolve_processor_adapter(memory)

    def test_tl_ul_adapter_selection_uses_protocol_fields_only(self) -> None:
        adapter = resolve_processor_adapter(_tl_memory())
        self.assertEqual("tl-ul-to-processor-memory-beat", adapter.adapter_id)
        self.assertEqual("tl_ul_processor_memory_adapter", adapter.rtl_module)
        self.assertEqual(("processor-memory-beat", "1"), adapter.target_protocol)
        self.assertEqual((), adapter.extension_policies)
        self.assertNotIn("boom", repr(adapter).lower())

    def test_ready_valid_memory_adapter_maps_pico_style_fields(self) -> None:
        adapter = resolve_processor_adapter(_ready_valid_memory())
        self.assertEqual("ready-valid-to-processor-memory-beat", adapter.adapter_id)
        self.assertEqual(("processor-memory-beat", "1"), adapter.target_protocol)
        self.assertIn("partial-write", adapter.features)

    def test_ready_valid_memory_unknown_extension_fails_closed(self) -> None:
        with self.assertRaisesRegex(ProcessorAdapterError, "unsupported-extension:mystery"):
            resolve_processor_adapter(_ready_valid_memory(_field("mystery", "output")))

    def test_obi_adapter_is_derived_from_read_write_and_optional_signals(self) -> None:
        read_only = resolve_processor_adapter(_obi_memory(_field("error", "input")))
        read_write = resolve_processor_adapter(_obi_memory(
            _field("we", "output"), _field("wdata", "output", 32),
            _field("be", "output", 4), _field("error", "input"),
        ))

        self.assertEqual("obi-to-processor-memory-beat", read_only.adapter_id)
        self.assertEqual(("processor-memory-beat", "1"), read_only.target_protocol)
        self.assertEqual((("READ_ONLY", 1), ("HAS_BE", 0), ("HAS_ERROR", 1)),
                         read_only.parameter_values)
        self.assertEqual((("READ_ONLY", 0), ("HAS_BE", 1), ("HAS_ERROR", 1)),
                         read_write.parameter_values)
        self.assertNotIn("ibex", repr(read_write).lower())

        with self.assertRaisesRegex(ProcessorAdapterError, "obi-write-fields"):
            resolve_processor_adapter(_obi_memory(_field("we", "output")))
        with self.assertRaisesRegex(ProcessorAdapterError, "extension-width:be"):
            resolve_processor_adapter(_obi_memory(
                _field("we", "output"), _field("wdata", "output", 32),
                _field("be", "output", 3), _field("error", "input"),
            ))
        with self.assertRaisesRegex(ProcessorAdapterError, "obi-error-field"):
            resolve_processor_adapter(_obi_memory())
        with self.assertRaisesRegex(
            ProcessorAdapterError, "obi-byte-enable-without-write"
        ):
            resolve_processor_adapter(_obi_memory(
                _field("be", "output", 4), _field("error", "input")
            ))

    def test_axi_rtl_ports_cover_protocol_and_extension_contracts(self) -> None:
        catalog = load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins")
        adapter = resolve_processor_adapter(_axi_memory())
        rtl = (ROOT / adapter.rtl_source).read_text(encoding="utf-8")
        for field in catalog.require("axi4", "1").fields:
            suffix = "_i" if field.direction == "host_to_device" else "_o"
            self.assertIn(field.field_id + suffix, rtl)
        for policy in adapter.extension_policies:
            suffix = "_i" if policy.direction == "output" else "_o"
            self.assertIn(policy.role + suffix, rtl)
        for field in catalog.require("processor-memory-beat", "1").fields:
            suffix = "_o" if field.direction == "host_to_device" else "_i"
            self.assertIn(field.field_id + suffix, rtl)

    def test_obi_rtl_ports_cover_protocol_extensions_and_backend(self) -> None:
        catalog = load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins")
        adapter = resolve_processor_adapter(_obi_memory(_field("error", "input")))
        rtl = (ROOT / adapter.rtl_source).read_text(encoding="utf-8")
        for field in catalog.require("obi", "1").fields:
            suffix = "_i" if field.direction == "host_to_device" else "_o"
            self.assertIn(field.field_id + suffix, rtl)
        for policy in adapter.extension_policies:
            suffix = "_i" if policy.direction == "output" else "_o"
            self.assertIn(policy.role + suffix, rtl)
        for field in catalog.require("processor-memory-beat", "1").fields:
            suffix = "_o" if field.direction == "host_to_device" else "_i"
            self.assertIn(field.field_id + suffix, rtl)

    def test_tl_ul_rtl_ports_cover_protocol_and_backend(self) -> None:
        catalog = load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins")
        adapter = resolve_processor_adapter(_tl_memory())
        rtl = (ROOT / adapter.rtl_source).read_text(encoding="utf-8")
        for field in catalog.require("tl-ul", "1").fields:
            suffix = "_i" if field.direction == "host_to_device" else "_o"
            self.assertIn(field.field_id + suffix, rtl)
        for field in catalog.require("processor-memory-beat", "1").fields:
            suffix = "_o" if field.direction == "host_to_device" else "_i"
            self.assertIn(field.field_id + suffix, rtl)


if __name__ == "__main__":
    unittest.main()
