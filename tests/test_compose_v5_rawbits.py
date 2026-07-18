import dataclasses
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.input_model import InputValidationError  # noqa: E402
from myfuzz.builder.rawbits_v5 import (  # noqa: E402
    RAWBITS_V5_MAX_STEPS, build_rawbits_v5_layout, decode_rawbits_v5_record,
    decode_rawbits_v5_testcase, encode_rawbits_v5_records, rawbits_v5_layout_from_dict,
    run_rawbits_v5_reference,
)


def fixture_layout():
    return build_rawbits_v5_layout((
        {"name": "data", "component": "ip", "owner": "ip.data", "kind": "external_input",
         "width": 5},
        {"name": "rst", "component": "soc", "owner": "soc.rst", "kind": "reset",
         "width": 1},
        {"name": "clk", "component": "soc", "owner": "soc.clk", "kind": "clock",
         "width": 1},
    ))


class StableModel:
    created = 0

    def __init__(self):
        StableModel.created += 1
        self.values = {}
        self.state = b""

    def drive_inputs(self, values):
        self.values = dict(values)

    def eval(self):
        self.state = json.dumps(self.values, sort_keys=True).encode()

    def wire_state(self):
        return self.state

    def coverage_state(self):
        return bytes([sum(self.values.values()) & 0xff])


class OscillatingModel(StableModel):
    def __init__(self):
        super().__init__()
        self.phase = False

    def eval(self):
        self.phase = not self.phase
        self.state = bytes([self.phase])


class ComposeV5RawBitsTest(unittest.TestCase):
    def test_layout_is_canonical_minimally_packed_and_digest_gated(self):
        layout = fixture_layout()
        self.assertEqual([field.owner for field in layout.fields], ["ip.data", "soc.clk", "soc.rst"])
        self.assertEqual(layout.record_width_bits, 7)
        self.assertEqual(layout.record_width_bytes, 1)
        self.assertEqual(layout.max_steps, RAWBITS_V5_MAX_STEPS)
        self.assertEqual(layout, fixture_layout())
        self.assertEqual(rawbits_v5_layout_from_dict(layout.to_dict()), layout)
        with self.assertRaisesRegex(InputValidationError, "digest mismatch"):
            dataclasses.replace(layout, digest="0" * 64)

    def test_records_round_trip_and_partial_final_record_is_zero_padded(self):
        layout = fixture_layout()
        encoded = encode_rawbits_v5_records(layout, (0x01, 0x7f))
        testcase = decode_rawbits_v5_testcase(layout, encoded)
        self.assertEqual(testcase.records, (0x01, 0x7f))
        wide = build_rawbits_v5_layout((
            {"name": "wide", "component": "x", "owner": "x.wide",
             "kind": "external_input", "width": 12},
        ))
        partial = decode_rawbits_v5_testcase(wide, b"\xbc")
        self.assertEqual(partial.records, (0x0bc,))
        self.assertEqual(partial.padded_final_bytes, 1)

    def test_length_and_record_limits_fail_closed(self):
        layout = fixture_layout()
        with self.assertRaisesRegex(InputValidationError, "1 MiB"):
            decode_rawbits_v5_testcase(layout, b"\x00" * ((1 << 20) + 1))
        with self.assertRaisesRegex(InputValidationError, "step count"):
            decode_rawbits_v5_testcase(layout, b"\x00" * (RAWBITS_V5_MAX_STEPS + 1))
        with self.assertRaisesRegex(InputValidationError, "does not fit"):
            encode_rawbits_v5_records(layout, (1 << layout.record_width_bits,))

    def test_duplicate_owners_fail_closed(self):
        with self.assertRaisesRegex(InputValidationError, "owners"):
            build_rawbits_v5_layout((
                {"name": "a", "component": "x", "owner": "shared", "kind": "clock",
                 "width": 1},
                {"name": "b", "component": "y", "owner": "shared", "kind": "reset",
                 "width": 1},
            ))

    def test_reference_runner_counts_real_edges_uses_fresh_state_and_does_not_drain(self):
        layout = fixture_layout()
        owners = {field.owner: field for field in layout.fields}
        records = []
        for clk, rst, data in ((0, 1, 1), (1, 1, 2), (1, 0, 3), (0, 0, 4)):
            record = 0
            for owner, value in (("soc.clk", clk), ("soc.rst", rst), ("ip.data", data)):
                record |= value << owners[owner].offset
            records.append(record)
        payload = encode_rawbits_v5_records(layout, tuple(records))
        before = StableModel.created
        first = run_rawbits_v5_reference(layout, payload, StableModel)
        second = run_rawbits_v5_reference(layout, payload, StableModel)
        self.assertEqual(StableModel.created - before, 2)
        self.assertTrue(first.settled)
        self.assertEqual(first.steps, 4)
        self.assertEqual(first.eval_count, 8)
        self.assertEqual(first.rising_edges, {"soc.clk": 1})
        self.assertEqual(first.falling_edges, {"soc.clk": 1})
        self.assertEqual(first.wire_digest, second.wire_digest)
        self.assertEqual(first.coverage_digest, second.coverage_digest)

    def test_non_settling_step_is_an_execution_failure(self):
        result = run_rawbits_v5_reference(fixture_layout(), b"\x01", OscillatingModel,
                                          max_settle_evals=4)
        self.assertFalse(result.settled)
        self.assertEqual(result.failure, "settle_limit")
        self.assertEqual(result.eval_count, 4)

    def test_record_decoding_is_bit_exact(self):
        layout = fixture_layout()
        values = decode_rawbits_v5_record(layout, 0b1010111)
        self.assertEqual(values, {"ip.data": 0b10111, "soc.clk": 0, "soc.rst": 1})


if __name__ == "__main__":
    unittest.main()
