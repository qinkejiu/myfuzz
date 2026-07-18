import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.contracts import (  # noqa: E402
    CONTRACT_SCHEMAS, ControlPlaneIRV1, ExperimentManifestV2, RegisterModelIRV1,
    SoCIRV2, TemporalConstraintIRV2, seal_contract, validate_contract,
)
from myfuzz.builder.input_model import InputValidationError  # noqa: E402
from myfuzz.builder.rawbits_v3 import (  # noqa: E402
    build_rawbits_v3_layout, envelope_rawbits_v2, opaque_envelope_from_dict, unwrap_rawbits_v2,
)


def _soc():
    return SoCIRV2(
        "demo", ({"id": "cpu", "source_digest": "a" * 64},), (), (), (), (), (), (), (), (), (), (), (), (),
        {"source": "manifest", "version": 1},
    )


class VersionedContractsTest(unittest.TestCase):
    def test_sealed_contract_is_order_independent_and_validates(self):
        first = seal_contract(_soc())
        second = seal_contract(SoCIRV2(
            "demo", ({"source_digest": "a" * 64, "id": "cpu"},), (), (), (), (), (), (), (), (), (), (), (), (),
            {"version": 1, "source": "manifest"},
        ))
        self.assertEqual(first.digest, second.digest)
        validate_contract(first.to_dict(), "soc_ir_v2")
        with self.assertRaisesRegex(InputValidationError, "unknown field"):
            value = first.to_dict(); value["unexpected"] = True
            validate_contract(value, "soc_ir_v2")

    def test_all_new_schema_documents_are_registered(self):
        schema_dir = ROOT / "src" / "myfuzz" / "builder" / "contracts" / "schemas"
        ids = {json.loads(path.read_text(encoding="utf-8"))["$id"] for path in schema_dir.glob("*.json")}
        self.assertEqual(ids, {value["schema"] for value in CONTRACT_SCHEMAS.values()})

    def test_digest_tampering_and_version_mismatch_fail_closed(self):
        value = seal_contract(_soc()).to_dict()
        value["digest"] = "0" * 64
        with self.assertRaisesRegex(InputValidationError, "digest mismatch"):
            SoCIRV2(**{key: item for key, item in value.items() if key != "schema"})
        value["schema"] = "myfuzz.soc-ir/v1"
        with self.assertRaisesRegex(InputValidationError, "expected.*v2"):
            validate_contract(value, "soc_ir_v2")

    def test_other_contracts_require_content_digests(self):
        digest = "1" * 64
        model = seal_contract(RegisterModelIRV1("ip", (), {"source": "fixture"}))
        control = seal_contract(ControlPlaneIRV1(digest, digest, (), (), (), {"source": "fixture"}))
        temporal = seal_contract(TemporalConstraintIRV2(digest, digest, digest, (), {"source": "fixture"}))
        manifest = seal_contract(ExperimentManifestV2("exp", digest, digest, digest, digest, digest, digest, digest, (), (), {"source": "fixture"}))
        for item, name in ((model, "register_model_ir_v1"), (control, "control_plane_ir_v1"),
                           (temporal, "temporal_constraint_ir_v2"), (manifest, "experiment_manifest_v2")):
            validate_contract(item.to_dict(), name)


class RawBitsMigrationTest(unittest.TestCase):
    def test_v2_payload_round_trips_byte_for_byte(self):
        payload = bytes(range(32))
        envelope = envelope_rawbits_v2(payload, provenance={"fixture": "legacy"})
        self.assertEqual(unwrap_rawbits_v2(envelope), payload)
        self.assertEqual(envelope.legacy_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(envelope.digest, envelope.digest)
        self.assertEqual(unwrap_rawbits_v2(opaque_envelope_from_dict(envelope.to_dict())), payload)

    def test_native_v3_layout_is_deterministic_and_bit_accounted(self):
        layout = build_rawbits_v3_layout((
            {"name": "opcode", "width": 3, "source": "fuzz", "consumer": "control",
             "minimum": 0, "maximum": 5, "default": 0, "provenance": {"rule": "profile"}},
            {"name": "target", "width": 4, "source": "fuzz", "consumer": "control",
             "minimum": 0, "maximum": 15, "default": 0, "provenance": {"rule": "soc"}},
        ))
        self.assertEqual(layout.cycle_width, 7)
        self.assertEqual(layout.bytes_per_cycle, 1)
        self.assertEqual(layout.fields[0].offset, 0)
        self.assertEqual(layout.fields[1].offset, 3)
        reordered = build_rawbits_v3_layout(tuple(reversed((
            {"name": "opcode", "width": 3, "source": "fuzz", "consumer": "control", "minimum": 0, "maximum": 5, "default": 0, "provenance": {"rule": "profile"}},
            {"name": "target", "width": 4, "source": "fuzz", "consumer": "control", "minimum": 0, "maximum": 15, "default": 0, "provenance": {"rule": "soc"}},
        ))))
        self.assertEqual(layout.digest, reordered.digest)


if __name__ == "__main__":
    unittest.main()
