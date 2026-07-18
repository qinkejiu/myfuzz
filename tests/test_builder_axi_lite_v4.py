import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.axi_lite_v4 import (  # noqa: E402
    AxiLiteGuardedIntent, AxiLiteMasterSignals, AxiLiteSlaveFeedback,
    AxiLiteV4Capability, AxiLiteV4Frontend, AxiLiteV4Monitor,
    axi_lite_v4_profile_registry, build_axi_lite_protocol_layout,
    pack_axi_lite_protocol_record,
    unpack_axi_lite_protocol_record, emit_axi_lite_v4_frontend_rtl,
    emit_axi_lite_v4_monitor_rtl,
)
from myfuzz.builder.builtin_profiles import builtin_profile_registry  # noqa: E402
from myfuzz.builder.input_model import InputValidationError  # noqa: E402
from myfuzz.builder.rawbits_v4 import RawBitsV4Submode  # noqa: E402


class AxiLiteV4ProfileTest(unittest.TestCase):
    def test_optional_protection_signals_are_structural_profile_facts(self):
        profile = axi_lite_v4_profile_registry().query("axi_lite", "initiator")[0]
        rules = {rule.semantic: rule for rule in profile.ports}
        self.assertFalse(rules["axi_lite.awprot"].required)
        self.assertFalse(rules["axi_lite.arprot"].required)
        self.assertEqual(rules["axi_lite.awprot"].direction.value, "output")

        legacy = builtin_profile_registry().query("axi_lite", "initiator")[0]
        legacy_semantics = {rule.semantic for rule in legacy.ports}
        self.assertNotIn("axi_lite.awprot", legacy_semantics)
        self.assertNotIn("axi_lite.arprot", legacy_semantics)

    def test_layout_has_distinct_literal_and_guarded_masks(self):
        layout = build_axi_lite_protocol_layout(AxiLiteV4Capability(
            address_width=20, awprot_present=True, arprot_present=True,
        ))
        lane = layout.lane_layout("PROTOCOL_WAVEFORM")
        literal = lane.used_mask_for(RawBitsV4Submode.LITERAL_TRACE)
        guarded = lane.used_mask_for(RawBitsV4Submode.GUARDED_INTENT)
        self.assertNotEqual(literal, guarded)
        self.assertEqual(literal & guarded, 0)
        self.assertEqual(layout.record_width_bytes % 8, 0)

    def test_record_pack_unpack_is_lossless_and_strict(self):
        layout = build_axi_lite_protocol_layout(AxiLiteV4Capability(
            address_width=7, awprot_present=True, arprot_present=True,
        ))
        lane = layout.lane_layout("PROTOCOL_WAVEFORM")
        values = {
            field.name: (1 << field.width) - 1
            for field in lane.fields
            if RawBitsV4Submode.LITERAL_TRACE.name in field.submodes
        }
        record = pack_axi_lite_protocol_record(
            layout, RawBitsV4Submode.LITERAL_TRACE, values,
        )
        self.assertEqual(
            unpack_axi_lite_protocol_record(
                layout, RawBitsV4Submode.LITERAL_TRACE, record,
            ),
            values,
        )
        with self.assertRaisesRegex(InputValidationError, "unknown field"):
            pack_axi_lite_protocol_record(
                layout, RawBitsV4Submode.LITERAL_TRACE,
                dict(values, hidden_repair_bit=1),
            )


class AxiLiteV4FrontendTest(unittest.TestCase):
    def test_emitted_frontend_compiles_for_optional_protection_variants(self):
        for present in (False, True):
            emitted = emit_axi_lite_v4_frontend_rtl(AxiLiteV4Capability(
                address_width=13, awprot_present=present, arprot_present=present,
            ))
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "frontend.sv"
                output = Path(directory) / "frontend.out"
                source.write_text(emitted.rtl, encoding="ascii")
                result = subprocess.run(
                    ["iverilog", "-g2012", "-s", emitted.module_name, "-o", output, source],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_emitted_frontend_literal_and_guarded_cycle_behavior(self):
        capability = AxiLiteV4Capability(address_width=8)
        emitted = emit_axi_lite_v4_frontend_rtl(capability, module_name="dut")
        literal_values = {
            field.name: 0
            for field in emitted.layout.lane_layout("PROTOCOL_WAVEFORM").fields
            if RawBitsV4Submode.LITERAL_TRACE.name in field.submodes
        }
        literal_values.update({
            "literal_awvalid": 1, "literal_awaddr": 0xA5,
            "literal_wvalid": 1, "literal_wdata": 0xDEADBEEF,
            "literal_wstrb": 0, "literal_bready": 1,
            "literal_arvalid": 1, "literal_araddr": 0xFF,
            "literal_rready": 1,
        })
        guarded_values = {
            field.name: 0
            for field in emitted.layout.lane_layout("PROTOCOL_WAVEFORM").fields
            if RawBitsV4Submode.GUARDED_INTENT.name in field.submodes
        }
        guarded_values.update({"guarded_aw_start": 1, "guarded_awaddr": 0x12})
        literal = pack_axi_lite_protocol_record(
            emitted.layout, RawBitsV4Submode.LITERAL_TRACE, literal_values,
        )
        guarded = pack_axi_lite_protocol_record(
            emitted.layout, RawBitsV4Submode.GUARDED_INTENT, guarded_values,
        )
        width = emitted.layout.record_width_bytes * 8
        testbench = f"""
module tb;
  logic clk=0,resetn=1;always #5 clk=~clk;
  logic [7:0] submode;logic [{width-1}:0] record;logic valid;
  logic awready=0,wready=0,bvalid=0,arready=0,rvalid=0;
  wire consumed,error,dut_reset,awvalid,wvalid,bready,arvalid,rready;
  wire [7:0] awaddr,araddr;wire [31:0] wdata;wire [3:0] wstrb;wire [31:0] ignored;
  dut u(.clk_i(clk),.resetn_i(resetn),.submode_i(submode),.record_i(record),
    .record_valid_i(valid),.record_consumed_o(consumed),.decoder_error_o(error),
    .dut_reset_event_o(dut_reset),.m_awvalid_o(awvalid),.m_awready_i(awready),
    .m_awaddr_o(awaddr),.m_wvalid_o(wvalid),.m_wready_i(wready),.m_wdata_o(wdata),
    .m_wstrb_o(wstrb),.m_bvalid_i(bvalid),.m_bready_o(bready),.m_bresp_i(2'b0),
    .m_arvalid_o(arvalid),.m_arready_i(arready),.m_araddr_o(araddr),
    .m_rvalid_i(rvalid),.m_rready_o(rready),.m_rdata_i(32'b0),.m_rresp_i(2'b0),
    .ignored_intents_o(ignored));
  initial begin
    submode=8'd3;record={width}'h{literal:x};valid=1;#1;
    if (!consumed||error||!awvalid||awaddr!=8'hA5||!wvalid||wdata!=32'hDEADBEEF||
        wstrb!=0||!bready||!arvalid||araddr!=8'hFF||!rready) $fatal(1,"literal");
    submode=8'd2;record={width}'h{guarded:x};
    @(posedge clk);#1;valid=0;
    if (!awvalid||awaddr!=8'h12) $fatal(1,"guarded launch");
    @(posedge clk);#1;
    if (!awvalid||awaddr!=8'h12) $fatal(1,"guarded stall");
    awready=1;@(posedge clk);#1;
    if (awvalid) $fatal(1,"guarded handshake");
    $finish;
  end
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "test.sv"
            output = Path(directory) / "test.out"
            source.write_text(emitted.rtl + testbench, encoding="ascii")
            compile_result = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", output, source],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                ["vvp", output], capture_output=True, text=True, check=False,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stdout + run_result.stderr)

    def test_literal_trace_is_not_repaired_or_filtered(self):
        frontend = AxiLiteV4Frontend(AxiLiteV4Capability(address_width=32))
        trace = AxiLiteMasterSignals(
            awvalid=True, awaddr=0xDEADBEEF, wvalid=True, wdata=0xFFFFFFFF,
            wstrb=0, bready=True, arvalid=True, araddr=0xFFFFFFFF, rready=True,
        )
        self.assertIs(frontend.step_literal(trace), trace)

    def test_guarded_channels_advance_independently_and_hold_payload(self):
        frontend = AxiLiteV4Frontend(AxiLiteV4Capability(address_width=16))
        first = frontend.step_guarded(AxiLiteGuardedIntent(
            aw_start=True, awaddr=0x1234, w_start=True, wdata=0xA5A5A5A5,
            wstrb=0b0101, ar_start=True, araddr=0x88,
        ), AxiLiteSlaveFeedback())
        self.assertFalse(first.awvalid)
        stalled = frontend.step_guarded(
            AxiLiteGuardedIntent(bready=True, rready=True),
            AxiLiteSlaveFeedback(wready=True, arready=True),
        )
        self.assertTrue(stalled.awvalid)
        self.assertEqual(stalled.awaddr, 0x1234)
        self.assertTrue(stalled.wvalid)
        self.assertTrue(stalled.arvalid)
        after = frontend.step_guarded(
            AxiLiteGuardedIntent(), AxiLiteSlaveFeedback(awready=False),
        )
        self.assertTrue(after.awvalid)
        self.assertFalse(after.wvalid)
        self.assertFalse(after.arvalid)


class AxiLiteV4MonitorTest(unittest.TestCase):
    def test_emitted_monitor_compiles_for_optional_protection_variants(self):
        for present in (False, True):
            emitted = emit_axi_lite_v4_monitor_rtl(AxiLiteV4Capability(
                address_width=13, awprot_present=present, arprot_present=present,
            ))
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "monitor.sv"
                output = Path(directory) / "monitor.out"
                source.write_text(emitted.rtl, encoding="ascii")
                result = subprocess.run(
                    ["iverilog", "-g2012", "-s", emitted.module_name, "-o", output, source],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_emitted_monitor_latches_first_violation_and_cycle(self):
        emitted = emit_axi_lite_v4_monitor_rtl(
            AxiLiteV4Capability(address_width=8), module_name="dut",
        )
        testbench = """
module tb;
  logic clk=0,monitor_resetn=0,bus_resetn=1;always #5 clk=~clk;
  logic awvalid=0,awready=0,wvalid=0,wready=0,bvalid=0,bready=0;
  logic arvalid=0,arready=0,rvalid=0,rready=0;logic [7:0] awaddr=0,araddr=0;
  wire violation;wire [7:0] rule;wire [63:0] cycle;wire [255:0] snapshot;
  dut u(.clk_i(clk),.monitor_resetn_i(monitor_resetn),.bus_resetn_i(bus_resetn),
    .m_awvalid_i(awvalid),.m_awready_i(awready),.m_awaddr_i(awaddr),
    .m_wvalid_i(wvalid),.m_wready_i(wready),.m_wdata_i(32'b0),.m_wstrb_i(4'b0),
    .m_bvalid_i(bvalid),.m_bready_i(bready),.m_bresp_i(2'b0),
    .m_arvalid_i(arvalid),.m_arready_i(arready),.m_araddr_i(araddr),
    .m_rvalid_i(rvalid),.m_rready_i(rready),.m_rdata_i(32'b0),.m_rresp_i(2'b0),
    .violation_valid_o(violation),.violation_rule_o(rule),.violation_cycle_o(cycle),
    .violation_snapshot_o(snapshot));
  initial begin
    #1 monitor_resetn=1;awvalid=1;awaddr=8'h11;
    @(posedge clk);#1;awaddr=8'h22;
    @(posedge clk);#1;
    if (!violation||rule!=8'd2||cycle!=64'd1) $fatal(1,"monitor first violation");
    awvalid=0;bvalid=1;bready=1;@(posedge clk);#1;
    if (rule!=8'd2||cycle!=64'd1) $fatal(1,"monitor overwrite");
    $finish;
  end
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "test.sv"
            output = Path(directory) / "test.out"
            source.write_text(emitted.rtl + testbench, encoding="ascii")
            compile_result = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", output, source],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                ["vvp", output], capture_output=True, text=True, check=False,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stdout + run_result.stderr)

    def test_aw_w_any_order_and_parallel_read_are_valid(self):
        monitor = AxiLiteV4Monitor(AxiLiteV4Capability(
            address_width=16, max_write_outstanding=2, max_read_outstanding=2,
        ))
        trace = (
            (AxiLiteMasterSignals(wvalid=True, wdata=1, wstrb=0xF), AxiLiteSlaveFeedback(wready=True)),
            (AxiLiteMasterSignals(awvalid=True, awaddr=0xFFF0, arvalid=True, araddr=3),
             AxiLiteSlaveFeedback(awready=True, arready=True)),
            (AxiLiteMasterSignals(bready=True, rready=True),
             AxiLiteSlaveFeedback(bvalid=True, bresp=3, rvalid=True, rresp=2, rdata=7)),
        )
        for master, feedback in trace:
            monitor.observe(master, feedback)
        self.assertTrue(monitor.protocol_valid)

    def test_literal_violation_is_classified_but_observation_continues(self):
        monitor = AxiLiteV4Monitor(AxiLiteV4Capability(address_width=16))
        monitor.observe(
            AxiLiteMasterSignals(awvalid=True, awaddr=1),
            AxiLiteSlaveFeedback(awready=False),
        )
        monitor.observe(
            AxiLiteMasterSignals(awvalid=True, awaddr=2),
            AxiLiteSlaveFeedback(awready=False),
        )
        monitor.observe(AxiLiteMasterSignals(), AxiLiteSlaveFeedback())
        self.assertEqual(monitor.first_violation.rule_id, "AW_STABLE_UNTIL_READY")
        self.assertEqual(monitor.first_violation.cycle, 1)
        self.assertEqual(monitor.cycle, 3)

    def test_response_without_request_is_invalid(self):
        monitor = AxiLiteV4Monitor(AxiLiteV4Capability(address_width=32))
        monitor.observe(
            AxiLiteMasterSignals(bready=True),
            AxiLiteSlaveFeedback(bvalid=True),
        )
        self.assertEqual(monitor.first_violation.rule_id, "B_WITHOUT_WRITE_REQUEST")


if __name__ == "__main__":
    unittest.main()
