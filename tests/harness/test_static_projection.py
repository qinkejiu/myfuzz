from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from myfuzz.harness.abi import RawBitAbi, RawBitUse, RawDestination, content_hash
from myfuzz.harness.static_policy import StaticPolicyParameters, compile_static_policy
from myfuzz.harness.static_projection import emit_static_projection, project_static_sample


POLICY = StaticPolicyParameters(2, 4, 2, "one_hot")


def raw_abi() -> RawBitAbi:
    destinations = (
        RawDestination(10, 100, 10, 4),
        RawDestination(20, 100, 20, 3),
        RawDestination(30, 100, 30, 1),
        RawDestination(40, 100, 40, 1),
        RawDestination(50, 100, 50, 1),
    )
    uses = (
        RawBitUse(0, 3, 10, 0, "direct", "direct"),
        RawBitUse(4, 6, 20, 0, "direct", "direct"),
        RawBitUse(7, 7, 30, 0, "direct", "direct"),
        RawBitUse(8, 8, 40, 0, "direct", "direct"),
        RawBitUse(9, 9, 50, 0, "direct", "direct"),
    )
    return RawBitAbi(
        10,
        destinations,
        uses,
        content_hash({"fixture": "static-projection", "raw_width": 10}),
    )


def declarations() -> dict[str, object]:
    return {
        "mask_align": [{"action_id": 20, "destination_id": 10, "alignment": 4}],
        "legal_set": [{"action_id": 10, "destination_id": 20, "values": [1, 3, 5]}],
        "dependency_gate": [{"action_id": 30, "destination_id": 30, "gate_bit": 0}],
        "mutual_exclusion": [{"action_id": 40, "destination_id": 40, "peer_ids": [30]}],
        "rarity_fold": [{"action_id": 50, "destination_id": 50, "fold_bits": [8, 9]}],
    }


def manifest() -> dict[str, object]:
    return {
        "combinational_design": True,
        "candidate_id": "static-fixture",
        "coverage_universe": [{"point_id": 1}],
        "top": {"module": "static_projection_fixture", "content_hash": "fixture-top"},
        "top_port_abi": [
            {"port_id": 10, "emitted_name": "data_a", "direction": "input", "width": 4, "semantic_role": "data", "fuzzable": True},
            {"port_id": 20, "emitted_name": "opcode", "direction": "input", "width": 3, "semantic_role": "data", "fuzzable": True},
            {"port_id": 30, "emitted_name": "enable", "direction": "input", "width": 1, "semantic_role": "data", "fuzzable": True},
            {"port_id": 40, "emitted_name": "event", "direction": "input", "width": 1, "semantic_role": "data", "fuzzable": True},
            {"port_id": 50, "emitted_name": "rare", "direction": "input", "width": 1, "semantic_role": "data", "fuzzable": True},
        ],
        "dependency_groups": [],
    }


def property_samples(width: int) -> range:
    return range(1 << width)


class StaticProjectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = compile_static_policy(raw_abi(), declarations(), POLICY)
        self.manifest = manifest()
        self.destination_ids = {item.destination_id for item in self.plan.raw_abi.destinations}
        self.opcode_id = 20
        self.legal_opcodes = {1, 3, 5}

    def test_projection_outputs_have_declared_width_and_legal_membership(self) -> None:
        for raw in property_samples(self.plan.raw_abi.raw_width):
            values = project_static_sample(self.plan, raw)
            self.assertEqual(set(values), self.destination_ids)
            raw_opcode = (raw >> 4) & 0b111
            if raw_opcode % POLICY.direct_ratio:
                self.assertIn(values[self.opcode_id], self.legal_opcodes)
            else:
                self.assertEqual(values[self.opcode_id], raw_opcode)
            for destination in self.plan.raw_abi.destinations:
                self.assertLess(values[destination.destination_id], 1 << destination.width)

    def test_emitted_rtl_is_combinational_and_retains_direct_samples(self) -> None:
        rtl = emit_static_projection(self.manifest, self.plan)

        self.assertNotIn("always_ff", rtl)
        self.assertNotIn("projection_state", rtl)
        self.assertNotRegex(rtl, r"dut\s*\.")
        self.assertIn("rfuzz_input_bits", rtl)
        self.assertIn("direct sample", rtl)

    def test_entropy_mix_selects_between_projected_and_direct_values(self) -> None:
        # Destination 10 is aligned to four.  An even raw value selects the
        # direct branch, while an odd raw value keeps the aligned projection.
        self.assertEqual(project_static_sample(self.plan, 0b0010)[10], 0b0010)
        self.assertEqual(project_static_sample(self.plan, 0b0011)[10], 0)

        rtl = emit_static_projection(self.manifest, self.plan)
        self.assertIn("? (rfuzz_input_bits[3:0]) :", rtl)
        self.assertNotIn("? (rfuzz_input_bits[3:0]) : (rfuzz_input_bits[3:0])", rtl)

    def test_generated_fixture_passes_verilator_lint(self) -> None:
        if shutil.which("verilator") is None:
            self.skipTest("verilator is not installed")
        rtl = emit_static_projection(self.manifest, self.plan)
        fixture = """
module static_projection_fixture (
    input logic [3:0] data_a,
    input logic [2:0] opcode,
    input logic enable,
    input logic event,
    input logic rare
);
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "static_projection.sv"
            source.write_text(f"{fixture}\n{rtl}")
            result = subprocess.run(
                ["verilator", "--lint-only", "--timing", str(source)],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
