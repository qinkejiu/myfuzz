"""Check dynamic layouts against RFuzz's MSB-first, 64-bit padded transport."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest

from myfuzz.composition.input_layout import InputLayout, LayoutField
from myfuzz.composition import rfuzz_transport


def layout(width):
    return InputLayout("input_layout.v1", width,
                       (LayoutField("x", "endpoint", "data", width, 0, width - 1, "raw", {}),), "layout-id")


class RfuzzTransportTests(unittest.TestCase):
    def test_generic_publication_emits_transport_bound_to_layout(self):
        from myfuzz.composition import GenericCompositionRequest, plan_generic_composition, write_generic_composition
        from tests.composition.test_generic_auto import synthetic_description
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            description = synthetic_description(root, "arbitrary_source", ("clk", "rst", "fuzz", "seen"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            result = write_generic_composition(plan, root / "out", base_dir=root)
            manifest = root / "out" / "rfuzz_input_transport.json"
            self.assertTrue(manifest.is_file(), "generic publisher must emit the layout-derived transport")
            document = json.loads(manifest.read_text())
            self.assertEqual(document, rfuzz_transport.build_rfuzz_transport(plan.layout).document())
            self.assertEqual(result["transport_hash"], document["transport_hash"])
            self.assertEqual((root / "out" / "rfuzz_input_transport.sv").read_text(),
                             rfuzz_transport.build_rfuzz_transport(plan.layout).render_systemverilog())

    def test_395_bit_record_uses_56_bytes_with_trailing_padding(self):
        transport = rfuzz_transport.build_rfuzz_transport(layout(395))
        self.assertEqual((transport.byte_count, transport.padding_bits), (56, 53))
        value = (1 << 394) | 1
        record = transport.pack(value)
        self.assertEqual(record, (value << 53).to_bytes(56, "big"))
        self.assertEqual(transport.unpack(record), value)

    def test_generic_widths_roundtrip_and_ignore_mutated_padding(self):
        for width in (1, 7, 13, 64, 65, 128, 2049):
            with self.subTest(width=width):
                transport = rfuzz_transport.build_rfuzz_transport(layout(width))
                self.assertEqual(transport.byte_count, ((width + 63) // 64) * 8)
                for value in (0, 1, (1 << width) - 1):
                    self.assertEqual(transport.unpack(transport.pack(value)), value)
                record = bytearray(transport.pack(1))
                if transport.padding_bits:
                    record[-1] |= 1
                    self.assertEqual(transport.unpack(bytes(record)), 1)
                    with self.assertRaises(ValueError):
                        transport.unpack(bytes(record), strict_padding=True)

    def test_bad_records_and_layouts_are_rejected(self):
        transport = rfuzz_transport.build_rfuzz_transport(layout(13))
        for value in (-1, 8192, True, "1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                transport.pack(value)
        for record in (b"", b"\0" * 7, b"\0" * 9, "00000000"):
            with self.subTest(record=record), self.assertRaises(ValueError):
                transport.unpack(record)
        with self.assertRaises(ValueError):
            rfuzz_transport.build_rfuzz_transport(InputLayout("input_layout.v1", 13, (), "id"))

    def test_manifest_binds_layout_and_transport_order(self):
        transport = rfuzz_transport.build_rfuzz_transport(layout(13))
        document = transport.document()
        self.assertEqual(document["layout_hash"], "layout-id")
        self.assertEqual(document["raw_width"], 13)
        self.assertEqual(document["byte_order"], "big")
        self.assertEqual(document["payload_position"], "most_significant_bits")
        self.assertEqual(document["padding_bits"], 51)
        self.assertNotEqual(document["transport_hash"], rfuzz_transport.build_rfuzz_transport(layout(14)).document()["transport_hash"])

    def test_unpack_records_returns_complete_cycles_and_truncated_tail(self):
        transport = rfuzz_transport.build_rfuzz_transport(layout(13))
        payload = transport.pack(7) + transport.pack(8) + b"tail"

        records, truncated_bytes = transport.unpack_records(payload)

        self.assertEqual(records, (7, 8))
        self.assertEqual(truncated_bytes, 4)
        self.assertEqual(transport.unpack_records(payload, max_records=1), ((7,), 4))

    def test_transport_preserves_multi_component_raw_slices(self):
        fields = (LayoutField("a", "peripheral.a", "control", 4, 0, 3, "raw", {}),
                  LayoutField("b", "peripheral.b", "data", 9, 4, 12, "raw", {}))
        transport = rfuzz_transport.build_rfuzz_transport(InputLayout("input_layout.v1", 13, fields, "two-components"))
        raw = (0x123 << 4) | 0xA
        decoded = transport.unpack(transport.pack(raw))
        self.assertEqual(decoded & 0xF, 0xA)
        self.assertEqual((decoded >> 4) & 0x1FF, 0x123)
        self.assertNotEqual(transport.document()["transport_hash"],
                            rfuzz_transport.build_rfuzz_transport(layout(13)).document()["transport_hash"])

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
    def test_generated_rtl_matches_python_record_packing(self):
        for width in (13, 64, 65, 395):
            with self.subTest(width=width), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                transport = rfuzz_transport.build_rfuzz_transport(layout(width))
                value = (1 << (width - 1)) | 1
                record = transport.pack(value)
                connections = [f".io_input_bytes_{i}(8'h{byte:02x})" for i, byte in enumerate(record)]
                connections.append(".rfuzz_input_bits(bits)")
                source = root / "test.sv"
                source.write_text(transport.render_systemverilog() +
                    f"module tb; wire [{width-1}:0] bits; myfuzz_rfuzz_transport dut(" + ",".join(connections) +
                    f"); initial begin #1; if(bits !== {width}'h{value:x}) $fatal(1,\"packing\"); $finish; end endmodule")
                binary = root / "sim"
                result = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(binary), str(source)], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run(["vvp", str(binary)], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
