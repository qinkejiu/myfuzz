import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    ConstraintInterpreter, HarnessPort, InputValidationError, PortDirection, build_constraint_ir,
    build_rawbits_layout, emit_dual_mode_harness,
)
from myfuzz.builder.contracts import CoverageABI  # noqa: E402
from myfuzz.instrumentation.source_branch_instrumenter import instrument_project  # noqa: E402


class HarnessTest(unittest.TestCase):
    def _run_iverilog(self, fixture):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "harness.sv"
            source.write_text(fixture)
            compile_result = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(root / "a.out"), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            simulation = subprocess.run(["vvp", str(root / "a.out")], capture_output=True, text=True)
            self.assertEqual(simulation.returncode, 0, simulation.stderr + simulation.stdout)
            return simulation.stdout

    def test_dual_mode_harness_checks_digest_resets_drains_and_matches_golden(self):
        layout = build_rawbits_layout((
            {"target": "direct_i", "width": 3, "purpose": "data", "provenance": "user"},
            {"target": "tie_i", "width": 1, "purpose": "mode", "provenance": "profile"},
            {"target": "mask_i", "width": 3, "purpose": "mask", "provenance": "profile"},
            {"target": "hold_i", "raw_width": 4, "value_width": 3, "purpose": "hold", "provenance": "profile"},
            {"target": "pulse_i", "raw_width": 3, "value_width": 1, "purpose": "pulse", "provenance": "profile"},
        ))
        constraints = build_constraint_ir(layout, (
            {"target": "direct_i", "primitive": "DIRECT", "provenance": "user", "idle_value": 0},
            {"target": "tie_i", "primitive": "TIEOFF", "value": 1, "provenance": "profile", "idle_value": 1},
            {"target": "mask_i", "primitive": "MASK", "mask": 5, "provenance": "profile", "idle_value": 0},
            {"target": "hold_i", "primitive": "HOLD", "provenance": "profile"},
            {"target": "pulse_i", "primitive": "PULSE", "max_cycles": 3, "provenance": "profile", "idle_value": 0},
        ))
        ports = (
            HarnessPort("clk", PortDirection.INPUT, 1, "clock"),
            HarnessPort("resetn", PortDirection.INPUT, 1, "reset", True),
            HarnessPort("direct_i", PortDirection.INPUT, 3),
            HarnessPort("tie_i", PortDirection.INPUT, 1),
            HarnessPort("mask_i", PortDirection.INPUT, 3),
            HarnessPort("hold_i", PortDirection.INPUT, 3),
            HarnessPort("pulse_i", PortDirection.INPUT, 1),
            HarnessPort("seen_o", PortDirection.OUTPUT, 11),
        )
        constrained = emit_dual_mode_harness(
            "dummy_soc", layout, constraints, ports, module_name="harness_constrained",
            reset_cycles=2, drain_cycles=2,
        )
        raw = emit_dual_mode_harness(
            "dummy_soc", layout, constraints, ports, module_name="harness_raw",
            reset_cycles=2, drain_cycles=2,
        )
        self.assertEqual(constrained.rtl, emit_dual_mode_harness(
            "dummy_soc", layout, constraints, ports, module_name="harness_constrained",
            reset_cycles=2, drain_cycles=2,
        ).rtl)
        values = {"direct_i": 5, "tie_i": 0, "mask_i": 7, "hold_i": 0b1_101, "pulse_i": 0b101}
        raw_cycle = sum(values[entry.target] << entry.offset for entry in layout.entries)
        fixture = f"""
module dummy_soc(input logic clk, input logic resetn, input logic [2:0] direct_i,
 input logic tie_i, input logic [2:0] mask_i, input logic [2:0] hold_i,
 input logic pulse_i, output logic [10:0] seen_o);
 assign seen_o={{pulse_i,hold_i,mask_i,tie_i,direct_i}};
endmodule
{constrained.rtl}
{raw.rtl}
module tb;
 logic clk=0, resetn=0, start=0, valid=0, finish=0;
 logic [{layout.cycle_width - 1}:0] bits={layout.cycle_width}'d{raw_cycle};
 logic ready_c, done_c, error_c, ready_r, done_r, error_r;
 logic [10:0] seen_c, seen_r;
 always #5 clk=~clk;
 harness_constrained hc(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),
  .mode_constrained_i(1'b1),.format_version_i(16'd2),.layout_digest_i(256'h{layout.digest}),
  .raw_bits_i(bits),.raw_bits_valid_i(valid),.end_i(finish),.raw_bits_ready_o(ready_c),
  .done_o(done_c),.format_error_o(error_c),.observe__seen_o(seen_c));
 harness_raw hr(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),
  .mode_constrained_i(1'b0),.format_version_i(16'd2),.layout_digest_i(256'h{layout.digest}),
  .raw_bits_i(bits),.raw_bits_valid_i(valid),.end_i(finish),.raw_bits_ready_o(ready_r),
 .done_o(done_r),.format_error_o(error_r),.observe__seen_o(seen_r));
 initial begin
  repeat(2) @(posedge clk); @(negedge clk); resetn=1; start=1;
  @(negedge clk); start=0;
  wait(ready_c && ready_r); @(negedge clk); valid=1; @(negedge clk); valid=0; #1;
  if(seen_c !== 11'h6dd) $fatal(1,"constrained mismatch %h",seen_c);
  if(seen_r !== 11'h6fd) $fatal(1,"raw mismatch %h",seen_r);
  finish=1; @(negedge clk); finish=0; wait(done_c && done_r);
  if(error_c || error_r) $fatal(1,"format error");
  $display("HARNESS_PASS"); $finish;
 end
endmodule
"""
        self.assertIn("HARNESS_PASS", self._run_iverilog(fixture))

    def test_all_primitives_match_interpreter_cycle_by_cycle(self):
        specs = (
            {"target": "direct", "width": 3, "purpose": "data", "provenance": "user"},
            {"target": "tie", "width": 1, "purpose": "mode", "provenance": "profile"},
            {"target": "mask", "width": 4, "purpose": "mask", "provenance": "profile"},
            {"target": "range", "width": 4, "purpose": "range", "provenance": "profile"},
            {"target": "enum_value", "width": 2, "purpose": "enum", "provenance": "profile"},
            {"target": "onehot", "raw_width": 2, "value_width": 4, "purpose": "onehot", "provenance": "profile"},
            {"target": "pulse", "raw_width": 3, "value_width": 1, "purpose": "pulse", "provenance": "profile"},
            {"target": "hold", "raw_width": 4, "value_width": 3, "purpose": "hold", "provenance": "profile"},
            {"target": "dependency", "width": 3, "purpose": "dependent", "provenance": "profile"},
            {"target": "reset_seq", "width": 1, "purpose": "reset sequence", "provenance": "profile"},
        )
        layout = build_rawbits_layout(specs)
        constraints = build_constraint_ir(layout, (
            {"target": "tie", "primitive": "TIEOFF", "value": 1, "provenance": "profile"},
            {"target": "direct", "primitive": "DIRECT", "provenance": "user"},
            {"target": "mask", "primitive": "MASK", "mask": 5, "provenance": "profile"},
            {"target": "range", "primitive": "RANGE", "minimum": 3, "maximum": 7, "provenance": "profile"},
            {"target": "enum_value", "primitive": "ENUM", "values": [0, 2, 3], "provenance": "profile"},
            {"target": "onehot", "primitive": "ONEHOT", "provenance": "profile"},
            {"target": "pulse", "primitive": "PULSE", "max_cycles": 3, "provenance": "profile"},
            {"target": "hold", "primitive": "HOLD", "provenance": "profile"},
            {"target": "dependency", "primitive": "DEPENDENCY", "source": "tie", "equals": 1,
             "fallback": 0, "provenance": "profile"},
            {"target": "reset_seq", "primitive": "RESET_SEQUENCE", "assert_cycles": 2,
             "active_value": 0, "inactive_value": 1, "provenance": "profile"},
        ))
        widths = {entry.target: entry.value_width for entry in layout.entries}
        input_order = tuple(reversed([entry.target for entry in layout.entries]))
        ports = (
            HarnessPort("clk", PortDirection.INPUT, 1, "clock"),
            HarnessPort("resetn", PortDirection.INPUT, 1, "reset"),
            *(HarnessPort(name, PortDirection.INPUT, widths[name]) for name in input_order),
            HarnessPort("seen", PortDirection.OUTPUT, 26),
        )
        emitted = emit_dual_mode_harness(
            "primitive_soc", layout, constraints, ports, module_name="primitive_harness",
            reset_cycles=1, drain_cycles=1,
        )
        values_by_cycle = (
            {"direct": 5, "mask": 15, "range": 9, "enum_value": 2, "onehot": 2,
             "pulse": 5, "hold": 13, "dependency": 6, "reset_seq": 1},
            {"direct": 1, "mask": 10, "range": 0, "enum_value": 1, "onehot": 3,
             "pulse": 0, "hold": 2, "dependency": 3, "reset_seq": 1},
            {"direct": 7, "mask": 3, "range": 15, "enum_value": 0, "onehot": 0,
             "pulse": 0, "hold": 11, "dependency": 2, "reset_seq": 0},
        )
        raw_cycles = []
        for values in values_by_cycle:
            raw_cycles.append(sum(int(values.get(entry.target, 0)) << entry.offset for entry in layout.entries))
        interpreter = ConstraintInterpreter(layout, constraints)
        expected = [interpreter.step(bits, constrained=True) for bits in raw_cycles]
        packed_order = ("reset_seq", "dependency", "hold", "pulse", "onehot", "enum_value", "range", "mask", "tie", "direct")
        def pack(values):
            result = 0
            for name in packed_order:
                result = (result << widths[name]) | values[name]
            return result
        expected_packed = [pack(value) for value in expected]
        soc_inputs = ", ".join(
            f"input logic {'' if widths[name] == 1 else f'[{widths[name] - 1}:0] '}{name}"
            for name in input_order
        )
        concatenation = ",".join(packed_order)
        fixture = f"""
module primitive_soc(input logic clk, input logic resetn, {soc_inputs}, output logic [25:0] seen);
 assign seen={{{concatenation}}};
endmodule
{emitted.rtl}
module tb;
 logic clk=0, resetn=0, start=0, valid=0, finish=0;
 logic [{layout.cycle_width - 1}:0] bits; logic ready, done, error; logic [25:0] seen;
 always #5 clk=~clk;
 primitive_harness dut(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),
  .mode_constrained_i(1'b1),.format_version_i(16'd2),.layout_digest_i(256'h{layout.digest}),
  .raw_bits_i(bits),.raw_bits_valid_i(valid),.end_i(finish),.raw_bits_ready_o(ready),
  .done_o(done),.format_error_o(error),.observe__seen(seen));
 task send(input [{layout.cycle_width - 1}:0] value, input [25:0] expected);
  begin @(negedge clk); bits=value; valid=1; @(negedge clk); valid=0; #1;
   if(seen !== expected) $fatal(1,"trace mismatch got=%h expected=%h",seen,expected);
  end
 endtask
 initial begin
  repeat(2) @(posedge clk); @(negedge clk); resetn=1; start=1; @(negedge clk); start=0;
  wait(ready);
  send({layout.cycle_width}'d{raw_cycles[0]},26'd{expected_packed[0]});
  send({layout.cycle_width}'d{raw_cycles[1]},26'd{expected_packed[1]});
  send({layout.cycle_width}'d{raw_cycles[2]},26'd{expected_packed[2]});
  finish=1; @(negedge clk); finish=0; wait(done);
  if(error) $fatal(1,"format error"); $display("PRIMITIVES_PASS"); $finish;
 end
endmodule
"""
        self.assertIn("PRIMITIVES_PASS", self._run_iverilog(fixture))

    def test_harness_rejects_bad_version_and_digest_before_consuming_bits(self):
        layout = build_rawbits_layout((
            {"target": "pin", "width": 1, "purpose": "data", "provenance": "user"},
        ))
        constraints = build_constraint_ir(layout, ({
            "target": "pin", "primitive": "DIRECT", "provenance": "user",
        },))
        ports = (
            HarnessPort("clk", PortDirection.INPUT, 1, "clock"),
            HarnessPort("resetn", PortDirection.INPUT, 1, "reset"),
            HarnessPort("pin", PortDirection.INPUT, 1),
            HarnessPort("seen", PortDirection.OUTPUT, 1),
        )
        emitted = emit_dual_mode_harness("gate_soc", layout, constraints, ports, module_name="gate_harness")
        fixture = f"""
module gate_soc(input logic clk, input logic resetn, input logic pin, output logic seen); assign seen=pin; endmodule
{emitted.rtl}
module tb;
 logic clk=0, resetn=0, start=0; logic ready_v,done_v,error_v,ready_d,done_d,error_d;
 always #5 clk=~clk;
 gate_harness bad_version(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),.mode_constrained_i(1'b0),
  .format_version_i(16'd1),.layout_digest_i(256'h{layout.digest}),.raw_bits_i(1'b1),
  .raw_bits_valid_i(1'b1),.end_i(1'b0),.raw_bits_ready_o(ready_v),.done_o(done_v),
  .format_error_o(error_v),.observe__seen());
 gate_harness bad_digest(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),.mode_constrained_i(1'b0),
  .format_version_i(16'd2),.layout_digest_i(256'h0),.raw_bits_i(1'b1),
  .raw_bits_valid_i(1'b1),.end_i(1'b0),.raw_bits_ready_o(ready_d),.done_o(done_d),
  .format_error_o(error_d),.observe__seen());
 initial begin
  repeat(2) @(posedge clk); @(negedge clk); resetn=1; start=1; @(negedge clk); start=0;
  wait(done_v && done_d); #1;
  if(!error_v || !error_d || ready_v || ready_d) $fatal(1,"format gate failed");
  $display("FORMAT_GATE_PASS"); $finish;
 end
endmodule
"""
        self.assertIn("FORMAT_GATE_PASS", self._run_iverilog(fixture))

    def test_harness_exports_only_instrumented_soc_coverage_with_abi_handshake(self):
        layout = build_rawbits_layout((
            {"target": "pin", "width": 1, "purpose": "data", "provenance": "user"},
        ))
        constraints = build_constraint_ir(layout, ({
            "target": "pin", "primitive": "DIRECT", "provenance": "user",
        },))
        ports = (
            HarnessPort("clk", PortDirection.INPUT, 1, "clock"),
            HarnessPort("resetn", PortDirection.INPUT, 1, "reset"),
            HarnessPort("pin", PortDirection.INPUT, 1),
            HarnessPort("seen", PortDirection.OUTPUT, 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            (project / "soc.sv").write_text("""
module coverage_soc(input logic clk, input logic resetn, input logic pin, output logic seen);
 always_ff @(posedge clk or negedge resetn) begin
  if(!resetn) seen<=0; else if(pin) seen<=1; else seen<=0;
 end
endmodule
""")
            manifest = instrument_project(
                project, root / "instrumented", top_module="coverage_soc",
                required_modules={"coverage_soc"},
            )
            value = manifest["coverage_abi"]
            abi = CoverageABI(
                value["manifest_digest"], value["port_name"], value["width"],
                tuple(value["points"]),
            )
            emitted = emit_dual_mode_harness(
                "coverage_soc", layout, constraints, ports, module_name="coverage_harness",
                reset_cycles=1, drain_cycles=1, coverage_abi=abi,
            )
            fixture = (root / "instrumented/soc.sv").read_text() + emitted.rtl + f"""
module tb;
 logic clk=0, resetn=0, start=0, valid=0, finish=0;
 logic ready,done,error,coverage_valid,seen; logic [{abi.width - 1}:0] coverage;
 always #5 clk=~clk;
 coverage_harness dut(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),
  .mode_constrained_i(1'b0),.format_version_i(16'd2),.layout_digest_i(256'h{layout.digest}),
  .coverage_abi_digest_i(256'h{abi.manifest_digest}),.raw_bits_i(1'b1),
  .raw_bits_valid_i(valid),.end_i(finish),.raw_bits_ready_o(ready),.done_o(done),
  .format_error_o(error),.observe__seen(seen),.coverage_o(coverage),
  .coverage_valid_o(coverage_valid));
 initial begin
  repeat(2) @(posedge clk); @(negedge clk); resetn=1; start=1; @(negedge clk); start=0;
  wait(ready); valid=1; @(negedge clk); valid=0; repeat(2) @(negedge clk);
  finish=1; @(negedge clk); finish=0; wait(done); #1;
  if(error || !coverage_valid || coverage==='0) $fatal(1,"coverage handshake failed");
  $display("COVERAGE_PASS"); $finish;
 end
endmodule
"""
            self.assertIn("COVERAGE_PASS", self._run_iverilog(fixture))

    def test_harness_rejects_unmapped_inputs_and_inout(self):
        layout = build_rawbits_layout((
            {"target": "pin", "width": 1, "purpose": "data", "provenance": "user"},
        ))
        constraints = build_constraint_ir(layout, ({
            "target": "pin", "primitive": "DIRECT", "provenance": "user",
        },))
        base = (
            HarnessPort("clk", PortDirection.INPUT, 1, "clock"),
            HarnessPort("resetn", PortDirection.INPUT, 1, "reset"),
            HarnessPort("pin", PortDirection.INPUT, 1),
        )
        with self.assertRaisesRegex(InputValidationError, "cover every"):
            emit_dual_mode_harness("soc", layout, constraints, base + (
                HarnessPort("extra", PortDirection.INPUT, 1),
            ))
        with self.assertRaisesRegex(InputValidationError, "inout"):
            emit_dual_mode_harness("soc", layout, constraints, base + (
                HarnessPort("pad", PortDirection.INOUT, 1),
            ))


if __name__ == "__main__":
    unittest.main()
