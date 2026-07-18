import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    EmittedSocIRV2, SocExternalPort, build_control_plane, build_generated_pipeline_v2,
    run_generated_bcd_seed, synthesize_temporal_constraints,
)
from myfuzz.builder.contracts import SoCIRV2, build_elaboration_manifest, seal_contract  # noqa: E402


def _soc_ir():
    return seal_contract(SoCIRV2(
        "pipeline_fixture", (), (), (), (), (),
        ({"instance_id": "target", "global_base": 0x1000, "size": 0x100,
          "local_address_width": 8, "provenance": {"source": "fixture"}},),
        (), (), (), (), (), (), (), {"source": "fixture"},
    ))


class GeneratedPipelineV2Test(unittest.TestCase):
    def test_builds_instruments_and_runs_one_shared_bcd_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            source_root.mkdir()
            leaf = source_root / "leaf_cpu.sv"
            leaf.write_text(
                "module leaf_cpu(input logic clk,input logic resetn,input logic sel,"
                "output logic hit);\n"
                "always_ff @(posedge clk or negedge resetn) begin\n"
                " if(!resetn) hit<=0; else if(sel) hit<=1; else hit<=0;\n"
                "end\nendmodule\n",
                encoding="utf-8",
            )
            source_manifest = build_elaboration_manifest(
                top_module="leaf_cpu", rtl_files=(leaf,), allow_roots=(source_root,),
                parameters={"LEAF_ONLY_PARAMETER": 7},
            )
            ir = _soc_ir()
            control = build_control_plane(ir, cpu_profile_digest="a" * 64)
            constraints = synthesize_temporal_constraints(ir, control, operation_timeout_limit=32)
            specs = (
                SocExternalPort("control_raw_bits", "input", control.layout.cycle_width, "control"),
                SocExternalPort("control_start", "input", 1, "control"),
                SocExternalPort("control_accepted", "output", 1, "control"),
                SocExternalPort("control_done", "output", 1, "control"),
                SocExternalPort("control_active", "output", 1, "control"),
                SocExternalPort("control_status", "output", 32, "control"),
                SocExternalPort("control_result", "output", 32, "control"),
            )
            rtl = f"""module pipeline_soc #(parameter BOOT_ROM_HEX_FILE=\"\") (
              input logic clk,input logic resetn,
              input logic [{control.layout.cycle_width - 1}:0] control_raw_bits,
              input logic control_start,output logic control_accepted,
              output logic control_done,output logic control_active,
              output logic [31:0] control_status,output logic [31:0] control_result);
              logic cpu_hit;
              leaf_cpu cpu0(.clk(clk),.resetn(resetn),.sel(control_raw_bits[0]),.hit(cpu_hit));
              always_ff @(posedge clk or negedge resetn) begin
                if(!resetn) begin control_accepted<=0;control_done<=0;control_active<=0;
                  control_status<=0;control_result<=0;end
                else begin control_accepted<=0;control_done<=0;control_result<={{31'b0,cpu_hit}};
                  if(control_start&&!control_active) begin control_active<=1;control_accepted<=1;end
                  else if(control_active) begin control_active<=0;control_done<=1;end
                end
              end
            endmodule
            """
            soc = EmittedSocIRV2(
                "pipeline_soc", rtl, (), (), tuple(port.name for port in specs), ir.digest, specs,
            )
            built = build_generated_pipeline_v2(
                root / "pipeline",
                source_manifest=source_manifest,
                source_root=source_root,
                soc=soc,
                control=control,
                constraints=constraints,
                hierarchy_component_roots={"cpu.main": ("pipeline_soc.cpu0",)},
                required_modules=("leaf_cpu",),
                coverage_epoch_width=4,
                reset_cycles=1,
                drain_cycles=3,
            )
            self.assertEqual(built.instrumented_manifest.parameters, ())
            included = [point for point in built.coverage_abi.points if point["included"]]
            self.assertTrue(included)
            self.assertEqual({point["component_id"] for point in included}, {"cpu.main"})
            report = json.loads(Path(built.report_path).read_text(encoding="utf-8"))
            self.assertFalse(report["baseline_a_affected"])
            run = run_generated_bcd_seed(
                built.target.path, root / "run", seed=17, cycles=8,
            )
            variants = run.report["variants"]
            self.assertEqual(
                tuple(item["mode"] for item in variants),
                ("B_GENERATED_RAW", "C_PROTOCOL_SAFE", "D_SCENARIO_CONSTRAINED"),
            )
            self.assertTrue(run.report["shared_ordered_input_bytes"])


if __name__ == "__main__":
    unittest.main()
