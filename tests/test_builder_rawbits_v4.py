import dataclasses
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.artifact_inventory import (  # noqa: E402
    ArtifactInventory, ArtifactInventoryEntry, artifact_inventory_from_dict,
    build_artifact_inventory, verify_artifact_inventory, write_artifact_inventory,
)
from myfuzz.builder.input_model import InputValidationError  # noqa: E402
from myfuzz.builder.rawbits_v4 import (  # noqa: E402
    RAWBITS_V4_FLAG_CONTINUATION, RAWBITS_V4_HEADER_BYTES,
    OpaqueRawBitsV4Envelope, RawBitsV4Lane, RawBitsV4Limits,
    RawBitsV4Submode, build_rawbits_v4_layout, decode_rawbits_v4_testcase,
    encode_rawbits_v4_testcase, envelope_legacy_rawbits_v4,
    opaque_v4_envelope_from_dict, rawbits_v4_header_schema,
    rawbits_v4_layout_from_dict,
    unwrap_legacy_rawbits_v4,
)


def fixture_layout():
    field = lambda name, width, used=True, submodes=None: {  # noqa: E731
        "name": name,
        "width": width,
        "source": "controller",
        "consumer": "verification_frontend",
        "used": used,
        **({"submodes": submodes} if submodes is not None else {}),
        "default_interpretation": "literal",
        "provenance": {"source": "fixture"},
    }
    return build_rawbits_v4_layout({
        RawBitsV4Lane.RAW_ESCAPE: (field("raw", 13),),
        RawBitsV4Lane.PROTOCOL_WAVEFORM: (
            field("awvalid", 1, submodes=["LITERAL_TRACE"]),
            field("awaddr", 8), field("reserved", 3, False),
        ),
        RawBitsV4Lane.ADVERSARIAL_MUTATION: (field("mutation", 17),),
    })


class RawBitsV4LayoutTest(unittest.TestCase):
    def test_layout_is_canonical_aligned_and_digest_gated(self):
        layout = fixture_layout()
        self.assertEqual(layout.record_width_bits, 17)
        self.assertEqual(layout.record_width_bytes, 8)
        self.assertEqual([lane.lane for lane in layout.lanes], [
            "RAW_ESCAPE", "PROTOCOL_WAVEFORM", "ADVERSARIAL_MUTATION",
        ])
        self.assertEqual(layout, fixture_layout())
        with self.assertRaisesRegex(InputValidationError, "digest mismatch"):
            dataclasses.replace(layout, digest="0" * 64)

    def test_header_schema_is_exactly_64_bytes_and_nonoverlapping(self):
        schema = rawbits_v4_header_schema()
        self.assertEqual(schema["header_bytes"], RAWBITS_V4_HEADER_BYTES)
        cursor = 0
        for field in schema["fields"]:
            self.assertEqual(field["offset_bytes"], cursor)
            cursor += field["size_bytes"]
        self.assertEqual(cursor, 64)

    def test_serialized_layout_is_reconstructed_instead_of_trusted(self):
        layout = fixture_layout()
        serialized = json.loads(json.dumps(layout.to_dict()))
        self.assertEqual(rawbits_v4_layout_from_dict(serialized), layout)
        serialized["lanes"][0]["used_mask"] ^= 1
        with self.assertRaisesRegex(InputValidationError, "reconstructed form"):
            rawbits_v4_layout_from_dict(serialized)


class RawBitsV4TransportTest(unittest.TestCase):
    def test_multichunk_round_trip_validates_complete_testcase_before_return(self):
        layout = fixture_layout()
        records = tuple(range(8))
        encoded = encode_rawbits_v4_testcase(
            layout, lane=RawBitsV4Lane.RAW_ESCAPE,
            submode=RawBitsV4Submode.RAW_LITERAL, logical_testcase_id=17,
            records=records, records_per_chunk=3,
        )
        decoded = decode_rawbits_v4_testcase(layout, encoded)
        self.assertEqual(decoded.records, records)
        self.assertEqual(decoded.chunk_count, 3)
        self.assertEqual(decoded.logical_testcase_id, 17)

    def test_missing_final_chunk_and_trailing_after_final_fail_closed(self):
        layout = fixture_layout()
        encoded = encode_rawbits_v4_testcase(
            layout, lane="RAW_ESCAPE", submode=RawBitsV4Submode.RAW_LITERAL,
            logical_testcase_id=1, records=(1, 2, 3), records_per_chunk=2,
        )
        first_chunk_bytes = RAWBITS_V4_HEADER_BYTES + 2 * layout.record_width_bytes
        with self.assertRaisesRegex(InputValidationError, "missing a final chunk"):
            decode_rawbits_v4_testcase(layout, encoded[:first_chunk_bytes])
        with self.assertRaisesRegex(InputValidationError, "final chunk"):
            decode_rawbits_v4_testcase(layout, encoded + encoded[-(RAWBITS_V4_HEADER_BYTES + 8):])

    def test_crc_digest_geometry_and_padding_corruption_fail_closed(self):
        layout = fixture_layout()
        encoded = bytearray(encode_rawbits_v4_testcase(
            layout, lane="PROTOCOL_WAVEFORM", submode=RawBitsV4Submode.LITERAL_TRACE,
            logical_testcase_id=2, records=(1,),
        ))
        encoded[5] ^= 1
        with self.assertRaisesRegex(InputValidationError, "magic/version|CRC"):
            decode_rawbits_v4_testcase(layout, bytes(encoded))

        encoded = bytearray(encode_rawbits_v4_testcase(
            layout, lane="PROTOCOL_WAVEFORM", submode=RawBitsV4Submode.LITERAL_TRACE,
            logical_testcase_id=2, records=(1,),
        ))
        encoded[RAWBITS_V4_HEADER_BYTES + 7] = 1
        with self.assertRaisesRegex(InputValidationError, "unused or padding"):
            decode_rawbits_v4_testcase(layout, bytes(encoded))

    def test_lane_submode_and_manifest_limits_are_enforced(self):
        layout = fixture_layout()
        with self.assertRaisesRegex(InputValidationError, "invalid for lane"):
            encode_rawbits_v4_testcase(
                layout, lane="RAW_ESCAPE", submode=RawBitsV4Submode.MUTATION,
                logical_testcase_id=3, records=(0,),
            )
        with self.assertRaisesRegex(InputValidationError, "record count"):
            encode_rawbits_v4_testcase(
                layout, lane="RAW_ESCAPE", submode=RawBitsV4Submode.RAW_LITERAL,
                logical_testcase_id=3, records=(0, 1),
                limits=RawBitsV4Limits(max_logical_records=1),
            )

    def test_unused_named_field_bits_are_rejected(self):
        layout = fixture_layout()
        lane = layout.lane_layout("PROTOCOL_WAVEFORM")
        reserved = next(field for field in lane.fields if field.name == "reserved")
        with self.assertRaisesRegex(InputValidationError, "unused or padding"):
            encode_rawbits_v4_testcase(
                layout, lane="PROTOCOL_WAVEFORM", submode=RawBitsV4Submode.LITERAL_TRACE,
                logical_testcase_id=4, records=(1 << reserved.offset,),
            )
        awvalid = next(field for field in lane.fields if field.name == "awvalid")
        with self.assertRaisesRegex(InputValidationError, "unused or padding"):
            encode_rawbits_v4_testcase(
                layout, lane="PROTOCOL_WAVEFORM",
                submode=RawBitsV4Submode.GUARDED_INTENT,
                logical_testcase_id=5, records=(1 << awvalid.offset,),
            )


class RawBitsV4CompatibilityTest(unittest.TestCase):
    def test_v2_and_v3_payloads_round_trip_opaquely(self):
        for schema in ("myfuzz.rawbits/v2", "myfuzz.rawbits-layout/v3"):
            payload = b"\x00\xfflegacy"
            envelope = envelope_legacy_rawbits_v4(
                payload, legacy_schema=schema, provenance={"fixture": schema},
            )
            self.assertEqual(unwrap_legacy_rawbits_v4(envelope), payload)
            parsed = opaque_v4_envelope_from_dict(envelope.to_dict())
            self.assertEqual(unwrap_legacy_rawbits_v4(parsed), payload)
            with self.assertRaisesRegex(InputValidationError, "digest mismatch"):
                OpaqueRawBitsV4Envelope(**dict(
                    envelope.to_dict(), digest="0" * 64, schema=envelope.schema,
                ))


class ArtifactInventoryTest(unittest.TestCase):
    def test_inventory_is_sorted_content_addressed_and_written_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            (root / "b.bin").write_bytes(b"b")
            (root / "nested/a.bin").write_bytes(b"aa")
            inventory = build_artifact_inventory(root, ("nested", "b.bin"), label="legacy")
            self.assertEqual([entry.path for entry in inventory.entries], ["b.bin", "nested/a.bin"])
            self.assertEqual(inventory.total_bytes, 3)
            output = write_artifact_inventory(inventory, root / "inventory.json")
            self.assertEqual(json.loads(output.read_text())["digest"], inventory.digest)

    def test_frozen_inventory_self_verifies_and_detects_content_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"frozen")
            inventory = build_artifact_inventory(root, (artifact,), label="baseline")
            parsed = artifact_inventory_from_dict(inventory.to_dict())
            verify_artifact_inventory(parsed, root)
            artifact.write_bytes(b"changed")
            with self.assertRaisesRegex(InputValidationError, "size drift|SHA-256 drift"):
                verify_artifact_inventory(parsed, root)

    def test_frozen_inventory_parser_rejects_unknown_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"frozen")
            serialized = build_artifact_inventory(
                root, (artifact,), label="baseline"
            ).to_dict()
            serialized["unknown"] = True
            with self.assertRaisesRegex(InputValidationError, "fields do not match schema"):
                artifact_inventory_from_dict(serialized)

    def test_inventory_cli_checks_frozen_entries_without_original_path_list(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.bin"
            output = root / "inventory.json"
            artifact.write_bytes(b"frozen")
            script = ROOT / "src/myfuzz/scripts/freeze_artifact_inventory.py"
            generated = subprocess.run(
                [sys.executable, str(script), "--root", str(root), "--label", "baseline",
                 "--output", str(output), "artifact.bin"],
                capture_output=True, text=True,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            checked = subprocess.run(
                [sys.executable, str(script), "--root", str(root), "--label", "baseline",
                 "--output", str(output), "--check"],
                capture_output=True, text=True,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertIn("verified 1 files, 6 bytes", checked.stdout)

    def test_inventory_rejects_paths_outside_root(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            path = Path(outside) / "escape.bin"
            path.write_bytes(b"x")
            with self.assertRaisesRegex(InputValidationError, "escapes root"):
                build_artifact_inventory(root, (path,), label="legacy")

    def test_inventory_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "selected").mkdir()
            (root / "outside.bin").write_bytes(b"outside")
            link = root / "selected/link.bin"
            try:
                os.symlink(root / "outside.bin", link)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links are unavailable")
            with self.assertRaisesRegex(InputValidationError, "symlink"):
                build_artifact_inventory(root, ("selected",), label="legacy")

    def test_inventory_validates_entry_metadata(self):
        with self.assertRaisesRegex(InputValidationError, "invalid artifact inventory path"):
            ArtifactInventory(
                label="forged",
                root="/tmp",
                entries=(ArtifactInventoryEntry("../escape", 1, "0" * 64),),
                total_bytes=1,
            )


if __name__ == "__main__":
    unittest.main()
