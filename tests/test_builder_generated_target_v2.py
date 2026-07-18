import json
import subprocess
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    EmittedSocIRV2, InputValidationError, SocExternalPort, build_control_plane,
    build_generated_verilator_target_v2, emit_generated_harness_v2,
    replay_generated_variant, run_generated_bcd_seed, synthesize_temporal_constraints,
)
from myfuzz.builder.contracts import (  # noqa: E402
    CoverageABIV2, SoCIRV2, build_elaboration_manifest, seal_contract,
)
from myfuzz.builder.rfuzz_campaign import RFuzzInputTest, RFuzzTargetServer  # noqa: E402


def _soc_ir():
    return seal_contract(SoCIRV2(
        "target_fixture", (), (), (), (), (),
        ({"instance_id": "target", "global_base": 0x1000, "size": 0x100,
          "local_address_width": 8, "provenance": {"source": "fixture"}},),
        (), (), (), (), (), (), (),
        {"source": "fixture"},
    ))


class GeneratedTargetV2Test(unittest.TestCase):
    def _fixture(self, root):
        ir = _soc_ir()
        control = build_control_plane(ir, cpu_profile_digest="a" * 64)
        constraints = synthesize_temporal_constraints(ir, control, operation_timeout_limit=32)
        coverage = CoverageABIV2(
            "b" * 64, "__vi_coverage", 2, 4,
            (
                {"point_id": "stub.branch.0", "included": True, "offset": 0, "source_offset": 0},
                {"point_id": "stub.branch.2", "included": True, "offset": 1, "source_offset": 2},
            ),
            transport_width=3,
        )
        specs = (
            SocExternalPort("control_raw_bits", "input", control.layout.cycle_width, "control"),
            SocExternalPort("control_start", "input", 1, "control"),
            SocExternalPort("control_accepted", "output", 1, "control"),
            SocExternalPort("control_done", "output", 1, "control"),
            SocExternalPort("control_active", "output", 1, "control"),
            SocExternalPort("control_status", "output", 32, "control"),
            SocExternalPort("control_result", "output", 32, "control"),
        )
        source_root = root / "instrumented"
        source_root.mkdir()
        source = source_root / "coverage_soc_stub.sv"
        source.write_text(f"""module coverage_soc_stub #(parameter BOOT_ROM_HEX_FILE="") (
          input logic clk,input logic resetn,input logic [3:0] coverage_epoch_i,
          output logic [2:0] __vi_coverage,
          input logic [{control.layout.cycle_width - 1}:0] control_raw_bits,input logic control_start,
          output logic control_accepted,output logic control_done,output logic control_active,
          output logic [31:0] control_status,output logic [31:0] control_result);
          always_ff @(posedge clk or negedge resetn) begin
            if(!resetn) begin __vi_coverage<=0;control_accepted<=0;control_done<=0;
              control_active<=0;control_status<=0;control_result<=0;end
            else begin
              __vi_coverage<=__vi_coverage+1;control_accepted<=0;control_done<=0;
              if(control_start&&!control_active) begin control_active<=1;control_accepted<=1;end
              else if(control_active) begin control_active<=0;control_done<=1;end
            end
          end
        endmodule
        """, encoding="utf-8")
        manifest = build_elaboration_manifest(
            top_module="coverage_soc_stub", rtl_files=(source,), allow_roots=(source_root,),
        )
        soc = EmittedSocIRV2(
            "coverage_soc_stub", "", (), (), tuple(port.name for port in specs), ir.digest, specs,
        )
        harness = emit_generated_harness_v2(
            soc, control, constraints, module_name="generated_target_harness",
            reset_cycles=1, drain_cycles=3, coverage_abi=coverage, embed_soc_rtl=False,
        )
        return manifest, source_root, control, constraints, coverage, harness

    def test_build_and_run_uses_exact_measured_cycle_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, source_root, control, constraints, coverage, harness = self._fixture(root)
            built = build_generated_verilator_target_v2(
                root / "targets", manifest=manifest, source_root=source_root, harness=harness,
                layout=control.layout, temporal_ir=constraints.ir, coverage_abi=coverage,
            )
            cached = build_generated_verilator_target_v2(
                root / "targets", manifest=manifest, source_root=source_root, harness=harness,
                layout=control.layout, temporal_ir=constraints.ir, coverage_abi=coverage,
            )
            self.assertTrue(cached.cached)
            completion = json.loads(Path(built.completion_manifest).read_text(encoding="utf-8"))
            self.assertEqual(completion["runner_schema"], "myfuzz.generated-target-runner/v2")
            cycles = 9
            raw = root / "input.rawbits"
            raw.write_bytes(bytes(cycles * control.layout.bytes_per_cycle))
            coverage_path = root / "coverage.bin"
            trace_path = root / "trace.bin"
            metrics_path = root / "metrics.json"
            result = subprocess.run(
                [Path(built.path) / "bin/myfuzz_target", raw, str(cycles), "0",
                 coverage_path, trace_path, metrics_path],
                cwd=built.path, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            trace = trace_path.read_bytes()
            self.assertEqual(len(trace), cycles)
            self.assertEqual(coverage_path.read_bytes(), trace[-1:])
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            self.assertEqual(metrics["measured_cycles"], cycles)
            self.assertEqual(
                metrics["accepted_records"] + metrics["unconsumed_records"], cycles,
            )
            self.assertEqual(len(metrics["acceptance_cycles"]), metrics["accepted_records"])

            event_log = root / "events.jsonl"
            server = RFuzzTargetServer(
                built.path, mode="generated_raw", server_id="generated-target-test",
                log_path=event_log, testcase_timeout_seconds=30,
            )
            work = root / "server-work"
            work.mkdir()
            server._run_test(RFuzzInputTest(cycles, raw.read_bytes(), 0), work)
            event = json.loads(event_log.read_text(encoding="utf-8"))
            self.assertEqual(event["accepted_records"], metrics["accepted_records"])
            self.assertEqual(event["stall_cycles"], metrics["stall_cycles"])
            self.assertEqual(event["unconsumed_records"], metrics["unconsumed_records"])
            tail = raw.read_bytes()[
                metrics["accepted_records"] * control.layout.bytes_per_cycle:
            ]
            self.assertEqual(event["unconsumed_tail_sha256"], __import__("hashlib").sha256(tail).hexdigest())

            paired = run_generated_bcd_seed(
                built.path, root / "paired", seed=17, cycles=cycles,
                checkpoints=(3, 6, 9), timeout_seconds=30,
            )
            self.assertTrue(paired.report["shared_binary"])
            self.assertTrue(paired.report["shared_ordered_input_bytes"])
            self.assertEqual(
                [item["mode"] for item in paired.report["variants"]],
                ["B_GENERATED_RAW", "C_PROTOCOL_SAFE", "D_SCENARIO_CONSTRAINED"],
            )
            self.assertEqual(
                {item["coverage_curve"][-1]["cycle"] for item in paired.report["variants"]},
                {cycles},
            )
            replay = replay_generated_variant(
                paired.report["variants"][2]["replay_bundle"], root / "replay",
            )
            self.assertEqual(replay["status"], "reproduced")

    def test_contract_digest_mismatch_fails_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, source_root, control, constraints, coverage, harness = self._fixture(root)
            broken = type(harness)(
                harness.module_name, harness.rtl, "0" * 64, harness.soc_digest,
                harness.constraint_digest, harness.protocol_safe_degenerate,
                harness.boundary_ports, harness.coverage_abi_digest,
            )
            with self.assertRaisesRegex(InputValidationError, "layout digests differ"):
                build_generated_verilator_target_v2(
                    root / "targets", manifest=manifest, source_root=source_root,
                    harness=broken, layout=control.layout, temporal_ir=constraints.ir,
                    coverage_abi=coverage,
                )


if __name__ == "__main__":
    unittest.main()
