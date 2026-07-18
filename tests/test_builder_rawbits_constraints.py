import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    ConstraintInterpreter, InputValidationError, build_constraint_ir,
    build_rawbits_layout, decode_rawbits_testcase, load_rawbits_testcase,
    pack_rawbits_cycles, write_rawbits_testcase,
)


def fixture_layout():
    return build_rawbits_layout((
        {"target": "direct", "width": 3, "purpose": "data", "provenance": "user"},
        {"target": "tie", "width": 1, "purpose": "mode", "provenance": "profile"},
        {"target": "mask", "width": 4, "purpose": "masked", "provenance": "profile"},
        {"target": "range", "width": 4, "purpose": "range", "provenance": "profile"},
        {"target": "enum", "width": 2, "purpose": "enum", "provenance": "profile"},
        {"target": "onehot", "raw_width": 2, "value_width": 4, "purpose": "onehot", "provenance": "profile"},
        {"target": "pulse", "raw_width": 3, "value_width": 1, "purpose": "pulse", "provenance": "profile"},
        {"target": "hold", "raw_width": 4, "value_width": 3, "purpose": "hold", "provenance": "profile"},
        {"target": "dependency", "width": 3, "purpose": "dependent", "provenance": "profile"},
        {"target": "reset", "width": 1, "purpose": "reset", "provenance": "profile"},
    ))


def fixture_constraints(layout):
    return build_constraint_ir(layout, (
        {"target": "direct", "primitive": "DIRECT", "provenance": "user", "idle_value": 0},
        {"target": "tie", "primitive": "TIEOFF", "value": 1, "provenance": "profile", "idle_value": 1},
        {"target": "mask", "primitive": "MASK", "mask": 0b0101, "provenance": "profile", "idle_value": 0},
        {"target": "range", "primitive": "RANGE", "minimum": 3, "maximum": 7, "provenance": "profile", "idle_value": 3},
        {"target": "enum", "primitive": "ENUM", "values": [0, 2, 3], "provenance": "profile", "idle_value": 0},
        {"target": "onehot", "primitive": "ONEHOT", "provenance": "profile", "idle_value": 1},
        {"target": "pulse", "primitive": "PULSE", "max_cycles": 3, "provenance": "profile", "idle_value": 0},
        {"target": "hold", "primitive": "HOLD", "provenance": "profile"},
        {"target": "dependency", "primitive": "DEPENDENCY", "source": "tie", "equals": 1,
         "fallback": 0, "provenance": "profile", "idle_value": 0},
        {"target": "reset", "primitive": "RESET_SEQUENCE", "assert_cycles": 2,
         "active_value": 0, "inactive_value": 1, "provenance": "profile", "idle_value": 1},
    ))


def raw_cycle(layout, values):
    result = 0
    for entry in layout.entries:
        result |= int(values.get(entry.target, 0)) << entry.offset
    return result


class RawBitsConstraintTest(unittest.TestCase):
    def test_layout_and_testcase_are_deterministic_and_digest_gated(self):
        layout = fixture_layout()
        self.assertEqual(layout, fixture_layout())
        cycles = (0, (1 << layout.cycle_width) - 1, 7)
        data, metadata = pack_rawbits_cycles(layout, cycles)
        self.assertEqual(decode_rawbits_testcase(layout, data, metadata).cycles, cycles)
        broken = dict(metadata, layout_digest="0" * 64)
        with self.assertRaisesRegex(InputValidationError, "layout_digest"):
            decode_rawbits_testcase(layout, data, broken)
        with self.assertRaisesRegex(InputValidationError, "byte length"):
            decode_rawbits_testcase(layout, data[:-1], metadata)

    def test_writer_and_loader_reject_nonzero_padding_bits(self):
        layout = build_rawbits_layout((
            {"target": "pin", "width": 3, "purpose": "data", "provenance": "user"},
        ))
        with tempfile.TemporaryDirectory() as directory:
            paths = write_rawbits_testcase(layout, (1, 7), directory, name="seed")
            loaded = load_rawbits_testcase(layout, paths["rawbits"], paths["metadata"])
            self.assertEqual(loaded.cycles, (1, 7))
            Path(paths["rawbits"]).write_bytes(bytes((1, 0x87)))
            with self.assertRaisesRegex(InputValidationError, "high bits"):
                load_rawbits_testcase(layout, paths["rawbits"], paths["metadata"])

    def test_all_constraint_primitives_have_cycle_exact_golden_behavior(self):
        layout = fixture_layout()
        interpreter = ConstraintInterpreter(layout, fixture_constraints(layout))
        first = interpreter.step(raw_cycle(layout, {
            "direct": 5, "tie": 0, "mask": 0b1111, "range": 9, "enum": 2,
            "onehot": 2, "pulse": 0b101, "hold": 0b1_101, "dependency": 6,
            "reset": 1,
        }), constrained=True)
        self.assertEqual(first, {
            "dependency": 6, "direct": 5, "enum": 3, "hold": 5, "mask": 5,
            "onehot": 4, "pulse": 1, "range": 7, "reset": 0, "tie": 1,
        })
        second = interpreter.step(raw_cycle(layout, {"hold": 0b0_010}), constrained=True)
        self.assertEqual(second["hold"], 5)
        self.assertEqual(second["pulse"], 1)
        self.assertEqual(second["reset"], 0)
        third = interpreter.step(0, constrained=True)
        self.assertEqual(third["pulse"], 1)
        self.assertEqual(third["reset"], 1)
        self.assertEqual(interpreter.drain()["hold"], 5)

    def test_raw_mode_bypasses_constraints_except_tieoff(self):
        layout = fixture_layout()
        interpreter = ConstraintInterpreter(layout, fixture_constraints(layout))
        result = interpreter.step(raw_cycle(layout, {
            "tie": 0, "mask": 15, "range": 12, "onehot": 3, "reset": 1,
        }), constrained=False)
        self.assertEqual(result["tie"], 1)
        self.assertEqual(result["mask"], 15)
        self.assertEqual(result["range"], 12)
        self.assertEqual(result["onehot"], 3)
        self.assertEqual(result["reset"], 1)

    def test_constraint_ir_rejects_missing_targets_and_bad_temporal_shapes(self):
        layout = build_rawbits_layout((
            {"target": "pulse", "width": 1, "purpose": "pulse", "provenance": "profile"},
        ))
        with self.assertRaisesRegex(InputValidationError, "at least two raw bits"):
            build_constraint_ir(layout, ({
                "target": "pulse", "primitive": "PULSE", "max_cycles": 2,
                "provenance": "profile",
            },))
        with self.assertRaisesRegex(InputValidationError, "missing constraint"):
            build_constraint_ir(layout, ())

    def test_dependency_requires_an_earlier_source_and_schema_is_bounded(self):
        layout = build_rawbits_layout((
            {"target": "dependent", "width": 2, "purpose": "data", "provenance": "profile"},
            {"target": "source", "width": 1, "purpose": "enable", "provenance": "profile"},
        ))
        dependency = {"target": "dependent", "primitive": "DEPENDENCY", "source": "source",
                      "equals": 1, "fallback": 0, "provenance": "profile"}
        direct = {"target": "source", "primitive": "DIRECT", "provenance": "profile"}
        with self.assertRaisesRegex(InputValidationError, "must be defined earlier"):
            build_constraint_ir(layout, (dependency, direct))
        constraint_ir = build_constraint_ir(layout, (direct, dependency))
        self.assertEqual(constraint_ir.constraints[1]["source"], "source")
        with self.assertRaisesRegex(InputValidationError, "unsupported field"):
            build_constraint_ir(layout, (dict(direct, arbitrary_verilog="assign x = y"), dependency))


if __name__ == "__main__":
    unittest.main()
