from __future__ import annotations

import copy
import unittest

from myfuzz.composition.input_layout import InputLayoutError, build_input_layout, input_layout_document
from myfuzz.isa.constraints import IsaContract


def _annotations(*, address_width: int = 32, include_optional: bool = True) -> dict[str, object]:
    fields: list[dict[str, object]] = [
        {"role": "address", "port": "opaque_address", "direction": "input", "width": address_width, "signed": False},
        {"role": "valid", "port": "opaque_valid", "direction": "input", "width": 1, "signed": False},
        {"role": "byte_enable", "port": "opaque_be", "direction": "input", "width": address_width // 8, "signed": False},
        {"role": "ready", "port": "opaque_ready", "direction": "input", "width": 1, "signed": False},
        {"role": "instruction", "port": "opaque_instruction", "direction": "input", "width": 32, "signed": False},
    ]
    if include_optional:
        fields.append({"role": "debug_hint", "port": "opaque_hint", "direction": "input", "width": 4, "signed": False, "optional": True})
    return {
        "schema_version": "interface_annotations.v1",
        "endpoints": [{
            "endpoint_id": "device.alpha",
            "function": "memory",
            "side": "target",
            "protocol": ["apb", "3"],
            "fields": fields,
            "clock": "clk",
            "reset": "rst",
            "timing": [],
        }],
    }


class InputLayoutTest(unittest.TestCase):
    def test_semantic_order_hash_and_intervals_ignore_json_order(self) -> None:
        left = _annotations()
        right = copy.deepcopy(left)
        right["endpoints"][0]["fields"].reverse()  # type: ignore[index]

        first = build_input_layout(left, component_constraints=({"owner": "device.alpha", "role": "address", "range": [0, 4095], "dependency_group": "mmio"},))
        second = build_input_layout(right, component_constraints=({"dependency_group": "mmio", "range": [0, 4095], "role": "address", "owner": "device.alpha"},))

        self.assertEqual(first.layout_hash, second.layout_hash)
        self.assertEqual(input_layout_document(first), input_layout_document(second))
        self.assertEqual([(field.raw_lo, field.raw_hi) for field in first.fields], [(0, 31), (32, 35), (36, 36), (37, 37), (38, 69), (70, 73)])
        address = next(field for field in first.fields if field.role == "address")
        self.assertEqual(address.constraint["alignment"], 4)
        self.assertEqual(address.constraint["range"], [0, 4095])
        self.assertEqual(address.dependency_group, "mmio")
        self.assertEqual(next(field for field in first.fields if field.role == "byte_enable").constraint["byte_enable_width"], 4)
        self.assertEqual(next(field for field in first.fields if field.role == "ready").constraint["gated_by"], "device.alpha:valid")

    def test_address_width_and_optional_fields_do_not_reidentify_required_fields(self) -> None:
        base = build_input_layout(_annotations(include_optional=False))
        wide = build_input_layout(_annotations(address_width=64, include_optional=False))
        optional = build_input_layout(_annotations())

        self.assertEqual(wide.raw_width - base.raw_width, 36)
        self.assertEqual([(item.field_id, item.raw_lo) for item in base.fields], [(item.field_id, item.raw_lo) for item in optional.fields[: len(base.fields)]])

    def test_rejects_invalid_unbounded_and_contradictory_constraints(self) -> None:
        invalid = _annotations()
        invalid["endpoints"][0]["fields"][0]["width"] = 0  # type: ignore[index]
        cases = (
            (invalid, (), "width"),
            (_annotations(), ({"owner": "device.alpha", "role": "address", "range": [0, None]},), "unbounded"),
            (_annotations(), ({"owner": "device.alpha", "role": "address", "alignment": 8, "range": [2, 31]},), "contradictory"),
        )
        for annotations, constraints, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(InputLayoutError, message):
                    build_input_layout(annotations, component_constraints=constraints)

    def test_non_instruction_fields_do_not_construct_isa_provider(self) -> None:
        annotations = _annotations()
        annotations["endpoints"][0]["fields"] = [  # type: ignore[index]
            field for field in annotations["endpoints"][0]["fields"] if field["role"] != "instruction"  # type: ignore[index]
        ]
        layout = build_input_layout(annotations, isa=IsaContract(32, ("I",)))
        self.assertNotIn("instruction", [field.role for field in layout.fields])

    def test_unsupported_isa_extension_uses_explicit_raw_instruction_mode(self) -> None:
        layout = build_input_layout(_annotations(), isa=IsaContract(64, ("I", "F")))
        instruction = next(field for field in layout.fields if field.role == "instruction")
        self.assertEqual(instruction.encoding, "raw_instruction")


if __name__ == "__main__":
    unittest.main()
