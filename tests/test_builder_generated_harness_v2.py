import subprocess
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    EmittedSocIRV2, SocExternalPort, build_control_plane,
    emit_generated_harness_v2, synthesize_temporal_constraints,
)
from myfuzz.builder.contracts import CoverageABIV2, SoCIRV2, seal_contract  # noqa: E402


def _soc_ir():
    return seal_contract(SoCIRV2(
        "harness_fixture", (), (), (), (), (),
        ({"instance_id": "target", "global_base": 0x1000, "size": 0x100,
          "local_address_width": 8, "provenance": {"source": "fixture"}},),
        (), (), (), (), (), (), (),
        {"source": "fixture"},
    ))


def _control_specs(width):
    return (
        SocExternalPort("control_raw_bits", "input", width, "control"),
        SocExternalPort("control_start", "input", 1, "control"),
        SocExternalPort("control_accepted", "output", 1, "control"),
        SocExternalPort("control_done", "output", 1, "control"),
        SocExternalPort("control_active", "output", 1, "control"),
        SocExternalPort("control_status", "output", 32, "control"),
        SocExternalPort("control_result", "output", 32, "control"),
    )


class GeneratedHarnessV2Test(unittest.TestCase):
    def test_coverage_v2_is_projected_and_frozen_before_drain(self):
        ir = _soc_ir()
        control = build_control_plane(ir, cpu_profile_digest="a" * 64)
        constraints = synthesize_temporal_constraints(ir, control)
        coverage = CoverageABIV2(
            "b" * 64, "__vi_coverage", 2, 4,
            (
                {"included": True, "offset": 0, "source_offset": 0},
                {"included": True, "offset": 1, "source_offset": 2},
            ),
            transport_width=3,
        )
        stub = f"""module coverage_soc_stub #(parameter BOOT_ROM_HEX_FILE="") (
          input logic clk,input logic resetn,input logic [3:0] coverage_epoch_i,
          output logic [2:0] __vi_coverage,
          input logic [{control.layout.cycle_width - 1}:0] control_raw_bits,input logic control_start,
          output logic control_accepted,output logic control_done,output logic control_active,
          output logic [31:0] control_status,output logic [31:0] control_result);
          always_ff @(posedge clk or negedge resetn) begin
            if(!resetn) begin __vi_coverage<=0;control_accepted<=0;control_done<=0;
              control_active<=0;control_status<=0;control_result<=0;end
            else begin __vi_coverage<=__vi_coverage+1;control_accepted<=0;control_done<=0;end
          end
        endmodule
        """
        specs = _control_specs(control.layout.cycle_width)
        soc = EmittedSocIRV2(
            "coverage_soc_stub", stub, (), (), tuple(port.name for port in specs), ir.digest, specs,
        )
        emitted = emit_generated_harness_v2(
            soc, control, constraints, module_name="coverage_harness", reset_cycles=1,
            drain_cycles=3, coverage_abi=coverage,
        )
        testbench = f"""module tb;
          logic clk=0,resetn=0,start=0,end_i=0;logic [1:0] mode=0;logic ready,done;
          logic [1:0] coverage_value,expected;logic coverage_valid;
          always #1 clk=~clk;
          initial begin #100 $display("watchdog state=%0d ready=%0d done=%0d format=%0d runtime=%0d",
            dut.state,ready,done,dut.format_error_o,dut.runtime_error_o);$fatal(1,"watchdog");end
          coverage_harness dut(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),.mode_i(mode),
            .format_version_i(3),.layout_digest_i(256'h{control.layout.digest}),
            .soc_digest_i(256'h{ir.digest}),.constraint_digest_i(256'h{constraints.ir.digest}),
            .raw_bits_i('0),.raw_bits_valid_i(0),.end_i(end_i),.coverage_epoch_i(4'd1),
            .coverage_abi_digest_i(256'h{coverage.manifest_digest}),.coverage_o(coverage_value),
            .coverage_valid_o(coverage_valid),.raw_bits_ready_o(ready),.done_o(done));
          initial begin
            #2 resetn=1;start=1;#2 start=0;wait(ready);@(negedge clk);
            expected=dut.coverage_live;end_i=1;@(posedge clk);#1;end_i=0;wait(done);#1;
            if(!coverage_valid || coverage_value!==expected)$fatal(1,"coverage snapshot mismatch");
            repeat(4) @(posedge clk);#1;
            if(coverage_value!==expected)$fatal(1,"drain changed frozen coverage");
            $finish;
          end
        endmodule
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "coverage.sv"; executable = root / "coverage.out"
            source.write_text(emitted.rtl + testbench, encoding="utf-8")
            compile_result = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(executable), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                ["vvp", str(executable)], capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr + run_result.stdout)

    def test_same_binary_latches_b_c_d_mode_and_dispatches_after_temporal_step(self):
        ir = _soc_ir()
        control = build_control_plane(ir, cpu_profile_digest="a" * 64)
        constraints = synthesize_temporal_constraints(ir, control, operation_timeout_limit=32)
        opcode = next(field for field in control.layout.fields if field.name == "opcode")
        sequence = next(field for field in control.layout.fields if field.name == "sequence_control")
        stub = f"""module harness_soc_stub #(parameter BOOT_ROM_HEX_FILE="") (
          input logic clk,input logic resetn,
          input logic [{control.layout.cycle_width - 1}:0] control_raw_bits,input logic control_start,
          output logic control_accepted,output logic control_done,output logic control_active,
          output logic [31:0] control_status,output logic [31:0] control_result);
          always_ff @(posedge clk or negedge resetn) begin
            if (!resetn) begin control_accepted<=0;control_done<=0;control_active<=0;
              control_status<=0;control_result<=0; end
            else begin
              control_accepted<=0;control_done<=0;
              if (control_start&&!control_active) begin
                control_active<=1;control_accepted<=1;
                control_result<=control_raw_bits[{opcode.offset} +: {opcode.width}];
              end else if (control_active) begin control_active<=0;control_done<=1; end
            end
          end
        endmodule
        """
        specs = _control_specs(control.layout.cycle_width)
        soc = EmittedSocIRV2(
            "harness_soc_stub", stub, (), (), tuple(port.name for port in specs), ir.digest, specs,
        )
        emitted = emit_generated_harness_v2(
            soc, control, constraints, module_name="harness_under_test", reset_cycles=1, drain_cycles=4,
        )
        wait_cycles = next(field for field in control.layout.fields if field.name == "wait_cycles")
        target_region = next(field for field in control.layout.fields if field.name == "target_region")
        self.assertIn(
            f"if (mode_latched==MODE_D) selected_record[{wait_cycles.offset} +: {wait_cycles.width}]=scenario_wait_cycles;",
            emitted.rtl,
        )
        self.assertIn(
            f"if (mode_latched==MODE_D) selected_record[{target_region.offset} +: {target_region.width}]=scenario_target_region;",
            emitted.rtl,
        )
        weighted_rule = next(
            rule for rule in constraints.ir.constraints if rule["id"] == "scenario_opcode_weight"
        )
        raw_opcode = 15
        bucket = raw_opcode * sum(weighted_rule["integer_weights"]) // (1 << opcode.width)
        upper = 0
        expected_d = None
        for choice, weight in zip(weighted_rule["choices"], weighted_rule["integer_weights"]):
            upper += weight
            if bucket < upper:
                expected_d = choice
                break
        raw = (raw_opcode << opcode.offset) | (1 << sequence.offset)
        for mode, expected in ((0, raw_opcode), (1, raw_opcode), (2, expected_d)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "harness.sv"
                executable = root / "harness.out"
                testbench = f"""module tb;
                  logic clk=0,resetn=0,start=0; logic [1:0] mode={mode};
                  logic [15:0] version=3; logic [255:0] layout=256'h{control.layout.digest};
                  logic [255:0] soc=256'h{ir.digest},constraint_value=256'h{constraints.ir.digest};
                  logic [{control.layout.cycle_width - 1}:0] raw={control.layout.cycle_width}'h{raw:x};
                  logic valid=0,end_i=0,ready,consumed,done,format_error,runtime_error;
                  logic [1:0] latched; logic accepted,control_done;
                  logic [31:0] status,result;
                  always #1 clk=~clk;
                  harness_under_test dut(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),
                    .mode_i(mode),.format_version_i(version),.layout_digest_i(layout),
                    .soc_digest_i(soc),.constraint_digest_i(constraint_value),.raw_bits_i(raw),
                    .raw_bits_valid_i(valid),.end_i(end_i),.raw_bits_ready_o(ready),
                    .raw_bits_consumed_o(consumed),.done_o(done),.format_error_o(format_error),
                    .runtime_error_o(runtime_error),.latched_mode_o(latched),
                    .control_accepted_o(accepted),.control_done_o(control_done),
                    .control_status_o(status),.control_result_o(result));
                  initial begin
                    #2 resetn=1; start=1; #2 start=0;
                    wait(ready); valid=1; #0;
                    if (!consumed) $fatal(1,"record was not consumed");
                    @(posedge clk); #1; valid=0; end_i=1; wait(control_done); #1;
                    if (result!={expected}) $fatal(1,"mode %0d result %0d",mode,result);
                    if (latched!={mode} || format_error || runtime_error) $fatal(1,"bad terminal flags");
                    wait(done); #2; $finish;
                  end
                endmodule
                """
                source.write_text(emitted.rtl + testbench, encoding="utf-8")
                compile_result = subprocess.run(
                    ["iverilog", "-g2012", "-s", "tb", "-o", str(executable), str(source)],
                    capture_output=True, text=True,
                )
                self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
                run_result = subprocess.run(
                    ["vvp", str(executable)], capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(run_result.returncode, 0, run_result.stderr + run_result.stdout)

    def test_rejects_mode_change_during_testcase(self):
        ir = _soc_ir()
        control = build_control_plane(ir, cpu_profile_digest="a" * 64)
        constraints = synthesize_temporal_constraints(ir, control)
        specs = _control_specs(control.layout.cycle_width)
        soc = EmittedSocIRV2("stub", "", (), (), tuple(port.name for port in specs), ir.digest, specs)
        emitted = emit_generated_harness_v2(soc, control, constraints)
        self.assertIn("mode_i!=mode_latched", emitted.rtl)
        self.assertIn("format_error_o<=1", emitted.rtl)
        self.assertNotIn(
            "temporal_error || operation_timeout_fired || reset_domain_error_value",
            emitted.rtl,
        )

    def test_external_input_is_operation_driven_while_output_is_observed(self):
        base = _soc_ir()
        ir = seal_contract(SoCIRV2(
            base.name, base.logical_modules, base.instances, base.endpoints, base.port_bindings,
            base.protocol_edges, base.address_views, base.clock_domains, base.reset_domains,
            base.interrupt_edges,
            (
                {"boundary_id": "pins.drive", "instance_id": "pins", "port": "drive",
                 "direction": "input", "width": 4, "action": "external_input",
                 "provenance": {"source": "fixture"}},
                {"boundary_id": "pins.observe", "instance_id": "pins", "port": "observe",
                 "direction": "output", "width": 4, "action": "observe",
                 "provenance": {"source": "fixture"}},
            ),
            base.service_nodes, base.adapters, base.unknown_port_decisions, base.provenance,
        ))
        control = build_control_plane(ir, cpu_profile_digest="a" * 64)
        constraints = synthesize_temporal_constraints(ir, control)
        fields = {field.name: field for field in control.layout.fields}
        specs = (
            SocExternalPort("ext_pins_drive", "input", 4, "boundary", 0, "external_input"),
            SocExternalPort("obs_pins_observe", "output", 4, "boundary", None, "observe"),
        ) + _control_specs(control.layout.cycle_width)
        stub = f"""module external_soc_stub #(parameter BOOT_ROM_HEX_FILE="") (
          input logic clk,input logic resetn,input logic [3:0] ext_pins_drive,
          output logic [3:0] obs_pins_observe,
          input logic [{control.layout.cycle_width - 1}:0] control_raw_bits,input logic control_start,
          output logic control_accepted,output logic control_done,output logic control_active,
          output logic [31:0] control_status,output logic [31:0] control_result);
          assign obs_pins_observe=ext_pins_drive;
          always_ff @(posedge clk or negedge resetn) begin
            if (!resetn) begin control_accepted<=0;control_done<=0;control_active<=0;
              control_status<=0;control_result<=0; end
            else begin control_accepted<=0;control_done<=0;
              if (control_start&&!control_active) begin control_active<=1;control_accepted<=1; end
              else if (control_active) begin control_active<=0;control_done<=1; end
            end
          end
        endmodule
        """
        soc = EmittedSocIRV2(
            "external_soc_stub", stub, (), (), tuple(port.name for port in specs), ir.digest, specs,
        )
        emitted = emit_generated_harness_v2(soc, control, constraints, module_name="external_harness")
        self.assertNotRegex(emitted.rtl.split(");", 1)[0], r"input logic \\[3:0\\] ext_pins_drive")
        self.assertIn("output logic [3:0] obs_pins_observe", emitted.rtl.split(");", 1)[0])
        raw = (
            (10 << fields["opcode"].offset)
            | (0 << fields["external_select"].offset)
            | (0xA << fields["external_value"].offset)
        )
        pulse_raw = (
            (11 << fields["opcode"].offset)
            | (0 << fields["external_select"].offset)
            | (0x3 << fields["external_value"].offset)
            | (2 << fields["wait_cycles"].offset)
        )
        testbench = f"""module tb;
          logic clk=0,resetn=0,start=0;logic [1:0] mode=0;logic valid=0,end_i=0;
          logic ready,consumed,done,format_error,runtime_error,accepted,control_done;
          logic [1:0] latched;logic [31:0] status,result;logic [3:0] observed;
          logic [{control.layout.cycle_width - 1}:0] raw={control.layout.cycle_width}'h{raw:x};
          always #1 clk=~clk;
          external_harness dut(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),.mode_i(mode),
            .format_version_i(3),.layout_digest_i(256'h{control.layout.digest}),
            .soc_digest_i(256'h{ir.digest}),.constraint_digest_i(256'h{constraints.ir.digest}),
            .raw_bits_i(raw),.raw_bits_valid_i(valid),.end_i(end_i),.raw_bits_ready_o(ready),
            .raw_bits_consumed_o(consumed),.done_o(done),.format_error_o(format_error),
            .runtime_error_o(runtime_error),.latched_mode_o(latched),.control_accepted_o(accepted),
            .control_done_o(control_done),.control_status_o(status),.control_result_o(result),
            .obs_pins_observe(observed));
          initial begin
            #2 resetn=1;start=1;#2 start=0;wait(ready);valid=1;@(posedge clk);#1;valid=0;
            wait(accepted);@(posedge clk);#1;
            if(observed!==4'ha)$fatal(1,"SET_EXTERNAL did not drive selected input");
            wait(control_done);wait(ready);raw={control.layout.cycle_width}'h{pulse_raw:x};
            valid=1;@(posedge clk);#1;valid=0;wait(accepted);@(posedge clk);#1;
            if(observed!==4'h3)$fatal(1,"PULSE_EXTERNAL did not drive selected input");
            repeat(2) @(posedge clk);#1;
            if(observed!==4'h0)$fatal(1,"PULSE_EXTERNAL did not return to idle");
            end_i=1;wait(done);#2;$finish;
          end
        endmodule
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "external.sv"; executable = root / "external.out"
            source.write_text(emitted.rtl + testbench, encoding="utf-8")
            compile_result = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(executable), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(["vvp", str(executable)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run_result.returncode, 0, run_result.stderr + run_result.stdout)


if __name__ == "__main__":
    unittest.main()
