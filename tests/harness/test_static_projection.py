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
        RawBitUse(0, 1, 10, 0, "direct", "direct"),
        RawBitUse(2, 3, 10, 2, "direct", "direct"),
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
        "rarity_fold": [{"action_id": 50, "destination_id": 50, "fold_bits": [0, 1, 9]}],
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


def fixture_source() -> str:
    return r"""
module static_projection_fixture (
    input logic [3:0] data_a,
    input logic [2:0] opcode,
    input logic enable,
    input logic \event ,
    input logic rare
);
endmodule
"""


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
        self.assertIn("? ({{2{1'b0}}, rfuzz_input_bits[1:0]} |", rtl)

    def test_evaluator_primitives_have_exact_results(self) -> None:
        self.assertEqual(project_static_sample(self.plan, 0b0011)[10], 0)
        self.assertEqual(project_static_sample(self.plan, 1 << 4)[20], 1)
        self.assertEqual(project_static_sample(self.plan, 1 << 7)[30], 0)
        self.assertEqual(project_static_sample(self.plan, (1 << 7) | 1)[30], 1)
        self.assertEqual(project_static_sample(self.plan, 1 << 8)[40], 1)
        self.assertEqual(project_static_sample(self.plan, (1 << 8) | (1 << 7) | 1)[40], 0)
        self.assertEqual(project_static_sample(self.plan, 1 << 9)[50], 1)
        self.assertEqual(project_static_sample(self.plan, (1 << 9) | 1)[50], 0)

    def test_priority_mutual_exclusion_uses_stable_destination_ids(self) -> None:
        priority_plan = compile_static_policy(
            raw_abi(),
            {
                "mutual_exclusion": [
                    {"action_id": 40, "destination_id": 40, "peer_ids": [30]},
                ],
            },
            StaticPolicyParameters(2, 4, 2, "priority"),
        )

        projected = project_static_sample(priority_plan, (1 << 8) | (1 << 7))

        self.assertEqual(projected[30], 1)
        self.assertEqual(projected[40], 0)

    def test_legal_set_strength_changes_the_mapping(self) -> None:
        semantic = {
            "legal_set": [
                {"action_id": 10, "destination_id": 20, "values": [1, 3, 5]},
            ],
        }
        weak = compile_static_policy(
            raw_abi(),
            semantic,
            StaticPolicyParameters(2, 4, 1, "none"),
        )
        strong = compile_static_policy(
            raw_abi(),
            semantic,
            StaticPolicyParameters(2, 4, 2, "none"),
        )

        self.assertEqual(project_static_sample(weak, 1 << 4)[20], 3)
        self.assertEqual(project_static_sample(strong, 1 << 4)[20], 1)

    def test_generated_fixture_passes_verilator_lint(self) -> None:
        if shutil.which("verilator") is None:
            self.skipTest("verilator is not installed")
        rtl = emit_static_projection(self.manifest, self.plan)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "static_projection.sv"
            source.write_text(f"{fixture_source()}\n{rtl}")
            result = subprocess.run(
                ["verilator", "--lint-only", "--timing", str(source)],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_emitted_rtl_matches_evaluator_for_every_fixture_sample(self) -> None:
        compiler = shutil.which("iverilog")
        runtime = shutil.which("vvp")
        if compiler is None or runtime is None:
            self.skipTest("iverilog and vvp are required for behavioral equivalence")

        rtl = emit_static_projection(self.manifest, self.plan)
        wrapper = f"myfuzz_candidate_static_{self.plan.plan_hash[:12]}"
        testbench = f"""
module testbench;
    logic [{self.plan.raw_abi.raw_width - 1}:0] raw;
    integer sample;
    {wrapper} wrapper (.rfuzz_input_bits(raw));
    initial begin
        for (sample = 0; sample < {1 << self.plan.raw_abi.raw_width}; sample = sample + 1) begin
            raw = sample;
            #1;
            $display("%0d %0d %0d %0d %0d %0d", sample,
                wrapper.port_10, wrapper.port_20, wrapper.port_30,
                wrapper.port_40, wrapper.port_50);
        end
        $finish;
    end
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "static_projection.sv"
            executable = Path(directory) / "static_projection.vvp"
            source.write_text(f"{fixture_source()}\n{rtl}\n{testbench}")
            compiled = subprocess.run(
                [compiler, "-g2012", "-s", "testbench", "-o", str(executable), str(source)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            simulated = subprocess.run(
                [runtime, str(executable)],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(simulated.returncode, 0, simulated.stderr)
        observed: dict[int, dict[int, int]] = {}
        for line in simulated.stdout.splitlines():
            fields = line.split()
            if len(fields) != 6 or any(not field.isdecimal() for field in fields):
                continue
            values = tuple(int(field) for field in fields)
            observed[values[0]] = dict(zip((10, 20, 30, 40, 50), values[1:]))
        expected = {
            raw: project_static_sample(self.plan, raw)
            for raw in property_samples(self.plan.raw_abi.raw_width)
        }
        self.assertEqual(observed, expected)


if __name__ == "__main__":
    unittest.main()
