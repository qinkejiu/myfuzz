from __future__ import annotations

import copy
import unittest

from myfuzz.composition import InputLayoutError, build_input_layout, input_layout_document
from myfuzz.contracts import validate_contract
from myfuzz.isa.constraints import IsaContract


def _field(role: str, port: str, width: int, *, signed: bool = False, source_file: str = "rtl/device.sv", line: int = 10) -> dict[str, object]:
    return {"role": role, "port": port, "direction": "input", "width": width, "signed": signed,
            "source": {"file": source_file, "line": line, "column": 1}, "evidence": ["explicit_alias"], "confidence": "high"}


def _annotations(*, address_width: int = 32, data_width: int = 32, include_optional: bool = True) -> dict[str, object]:
    fields = [_field("address", "opaque_address", address_width, line=10), _field("valid", "opaque_valid", 1, line=11),
              _field("byte_enable", "opaque_be", data_width // 8, line=12), _field("ready", "opaque_ready", 1, line=13),
              _field("data", "opaque_data", data_width, line=14), _field("instruction", "opaque_instruction", 32, line=15)]
    if include_optional:
        optional = _field("debug_hint", "opaque_hint", 4, line=16)
        optional["optional"] = True
        fields.append(optional)
    return {"schema_version": "interface_annotations.v1", "source": {"revision": "sha256:" + "a" * 64,
            "content_hash": "sha256:" + "b" * 64, "files": ["rtl/device.sv"], "modules": ["device"]},
            "endpoints": [{"endpoint_id": "device.alpha", "function": "memory", "module": "device", "fields": fields,
                           "clock": "clk", "reset": "rst", "timing": [],
                           "protocol_candidates": [{"id": "apb", "version": "4", "status": "consistent", "orientation": "host", "evidence": "declared"}],
                           "evidence": ["explicit_module"], "confidence": "high", "diagnostics": []}], "diagnostics": []}


class InputLayoutTest(unittest.TestCase):
    def test_real_annotation_endpoint_preserves_binding_and_path_independent_hash(self) -> None:
        left = _annotations()
        validate_contract(left, "interface_annotations.v1")
        right = copy.deepcopy(left)
        right["endpoints"][0]["fields"].reverse()  # type: ignore[index]
        right["source"]["files"] = ["relocated/device.sv"]  # type: ignore[index]
        for field in right["endpoints"][0]["fields"]:  # type: ignore[index]
            field["source"] = {"file": "relocated/device.sv", "line": 100, "column": 9}
        first = build_input_layout(left, component_constraints=(
            {"owner": "device.alpha", "role": "address", "range": [0, 4092], "dependency_group": "mmio"},
            {"owner": "device.alpha", "role": "data", "dependency_group": "mmio"}))
        second = build_input_layout(right, component_constraints=(
            {"dependency_group": "mmio", "role": "data", "owner": "device.alpha"},
            {"range": [0, 4092], "role": "address", "dependency_group": "mmio", "owner": "device.alpha"}))
        self.assertEqual(first.layout_hash, second.layout_hash)
        address = next(field for field in first.fields if field.role == "address")
        self.assertEqual(address.constraint["alignment"], 4)
        self.assertEqual(address.port, "opaque_address")
        self.assertFalse(address.signed)
        document = input_layout_document(first)
        address_document = next(field for field in document["fields"] if field["role"] == "address")
        self.assertEqual(address_document["binding"], {"port": "opaque_address", "direction": "input", "signed": False})
        self.assertEqual(address_document["provenance"], {"file": "rtl/device.sv", "line": 10, "column": 1})
        self.assertEqual(address_document.get("evidence"), ["explicit_alias"])

    def test_field_evidence_is_preserved_and_changes_canonical_layout_hash(self) -> None:
        left = _annotations(include_optional=False)
        right = copy.deepcopy(left)
        address = next(field for field in right["endpoints"][0]["fields"] if field["role"] == "address")  # type: ignore[index]
        address["evidence"] = ["hdl_declaration"]
        first = build_input_layout(left)
        second = build_input_layout(right)
        self.assertNotEqual(first.layout_hash, second.layout_hash)
        first_address = next(field for field in input_layout_document(first)["fields"] if field["role"] == "address")
        self.assertEqual(first_address["evidence"], ["explicit_alias"])

    def test_byte_enable_uses_same_endpoint_data_width_not_address_width(self) -> None:
        layout = build_input_layout(_annotations(address_width=64, data_width=32, include_optional=False))
        byte_enable = next(field for field in layout.fields if field.role == "byte_enable")
        self.assertEqual(byte_enable.width, 4)
        self.assertEqual(byte_enable.constraint["byte_enable_width"], 4)

    def test_address_width_and_optional_fields_do_not_reidentify_required_fields(self) -> None:
        base = build_input_layout(_annotations(include_optional=False))
        wide = build_input_layout(_annotations(address_width=64, include_optional=False))
        optional = build_input_layout(_annotations())
        self.assertEqual(wide.raw_width - base.raw_width, 32)
        self.assertEqual([(item.field_id, item.raw_lo) for item in base.fields], [(item.field_id, item.raw_lo) for item in optional.fields[:len(base.fields)]])

    def test_constraints_fail_closed_for_unknown_overflow_alignment_and_invalid_relationships(self) -> None:
        cases = (({"owner": "device.alpha", "role": "address", "unknown": 1}, "unknown constraint"),
                 ({"owner": "device.alpha", "role": "address", "range": [0, 1 << 32]}, "outside field width"),
                 ({"owner": "device.alpha", "role": "address", "alignment": 4, "range": [0, 4095]}, "contradictory"),
                 ({"owner": "device.alpha", "role": "valid", "gated_by": "device.alpha:valid"}, "cannot gate itself"),
                 ({"owner": "device.alpha", "role": "data", "gated_by": "device.alpha:missing"}, "unknown gated_by"),
                 ({"owner": "device.alpha", "role": "address", "dependency_group": "orphan"}, "dependency_group"))
        for constraint, message in cases:
            with self.subTest(constraint=constraint):
                with self.assertRaisesRegex(InputLayoutError, message):
                    build_input_layout(_annotations(), component_constraints=(constraint,))

    def test_signed_ranges_must_fit_field_and_default_ready_gates_valid(self) -> None:
        annotations = _annotations()
        next(field for field in annotations["endpoints"][0]["fields"] if field["role"] == "data")["signed"] = True  # type: ignore[index]
        layout = build_input_layout(annotations, component_constraints=({"owner": "device.alpha", "role": "data", "range": [-(1 << 31), (1 << 31) - 1]},))
        self.assertEqual(next(field for field in layout.fields if field.role == "ready").constraint["gated_by"], "device.alpha:valid")
        with self.assertRaisesRegex(InputLayoutError, "outside field width"):
            build_input_layout(annotations, component_constraints=({"owner": "device.alpha", "role": "data", "range": [-(1 << 31) - 1, 0]},))

    def test_empty_layout_and_bad_data_binding_fail_closed(self) -> None:
        with self.assertRaisesRegex(InputLayoutError, "empty"):
            build_input_layout({"schema_version": "interface_annotations.v1", "endpoints": []})
        annotations = _annotations(address_width=64, data_width=32)
        next(field for field in annotations["endpoints"][0]["fields"] if field["role"] == "byte_enable")["width"] = 8  # type: ignore[index]
        with self.assertRaisesRegex(InputLayoutError, "byte_enable"):
            build_input_layout(annotations)

    def test_raw_abi_hash_covers_complete_layout_geometry(self) -> None:
        narrow_layout = build_input_layout(_annotations(address_width=32, include_optional=False))
        narrow = narrow_layout.to_raw_abi()
        wide = build_input_layout(_annotations(address_width=64, include_optional=False)).to_raw_abi()
        self.assertNotEqual(narrow.abi_hash, wide.abi_hash)
        self.assertEqual([(use.raw_lo, use.raw_hi) for use in narrow.uses], [(field.raw_lo, field.raw_hi) for field in narrow_layout.fields])

    def test_non_instruction_fields_do_not_construct_isa_provider(self) -> None:
        annotations = _annotations()
        annotations["endpoints"][0]["fields"] = [field for field in annotations["endpoints"][0]["fields"] if field["role"] != "instruction"]  # type: ignore[index]
        layout = build_input_layout(annotations, isa=IsaContract(32, ("I",)))
        self.assertNotIn("instruction", [field.role for field in layout.fields])

    def test_unsupported_isa_extension_uses_explicit_raw_instruction_mode(self) -> None:
        layout = build_input_layout(_annotations(), isa=IsaContract(64, ("I", "Zba")))
        self.assertEqual(next(field for field in layout.fields if field.role == "instruction").encoding, "raw_instruction")


if __name__ == "__main__":
    unittest.main()
