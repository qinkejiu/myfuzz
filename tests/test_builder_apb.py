import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    ApbDecoderConfig, InputValidationError, emit_apb_decoder,
    emit_axi_lite_to_apb_bridge,
)


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "iverilog/vvp required")
class ApbBackendTest(unittest.TestCase):
    def test_validation_is_protocol_not_module_driven(self):
        with self.assertRaisesRegex(InputValidationError, "32-bit"):
            ApbDecoderConfig(16, 64, (0,), (256,))
        with self.assertRaisesRegex(InputValidationError, "overlap"):
            ApbDecoderConfig(16, 32, (0, 128), (256, 256))
        first = emit_apb_decoder(ApbDecoderConfig(16, 32, (0x100, 0x200), (0x100, 0x80)))
        self.assertEqual(first, emit_apb_decoder(ApbDecoderConfig(16, 32, (0x100, 0x200), (0x100, 0x80))))
        self.assertIn("paddr-BASE_1", first)

    def test_two_targets_read_write_wait_and_default_error(self):
        bridge = emit_axi_lite_to_apb_bridge(address_width=16)
        decoder = emit_apb_decoder(ApbDecoderConfig(16, 32, (0x100, 0x200), (0x100, 0x100)))
        tb = bridge + decoder + r"""
module tb;
  logic clk=0, resetn=0;
  logic [15:0] awaddr=0, araddr=0; logic awvalid=0, wvalid=0, bready=0, arvalid=0, rready=0;
  logic [31:0] wdata=0; logic [3:0] wstrb=0; wire awready,wready,bvalid,arready,rvalid;
  wire [1:0] bresp,rresp; wire [31:0] rdata;
  wire psel,penable,pwrite,pready,pslverr; wire [15:0] paddr; wire [31:0] pwdata,prdata; wire [3:0] pstrb;
  wire [1:0] m_psel,m_penable,m_pwrite,m_pready,m_pslverr;
  wire [1:0][15:0] m_paddr; wire [1:0][31:0] m_pwdata,m_prdata; wire [1:0][3:0] m_pstrb;
  logic [1:0] waits=0; logic [15:0] written_address=0; logic [31:0] written_data=0;
  assign m_pready[0]=1'b1;
  assign m_pready[1]=(waits==2);
  assign m_prdata[0]=32'ha0000000 | m_paddr[0];
  assign m_prdata[1]=32'hb0000000 | m_paddr[1];
  assign m_pslverr='0;
  always_ff @(posedge clk) begin
    if (!resetn) waits<=0;
    else if (m_psel[1] && m_penable[1] && !m_pready[1]) waits<=waits+1'b1;
    else waits<=0;
    if (m_psel[0] && m_penable[0] && m_pready[0] && m_pwrite[0]) begin
      written_address<=m_paddr[0]; written_data<=m_pwdata[0];
    end
  end
  myfuzz_axi_lite_to_apb bridge(
    .clk(clk),.resetn(resetn),.s_awaddr(awaddr),.s_awvalid(awvalid),.s_awready(awready),
    .s_wdata(wdata),.s_wstrb(wstrb),.s_wvalid(wvalid),.s_wready(wready),
    .s_bresp(bresp),.s_bvalid(bvalid),.s_bready(bready),.s_araddr(araddr),
    .s_arvalid(arvalid),.s_arready(arready),.s_rdata(rdata),.s_rresp(rresp),
    .s_rvalid(rvalid),.s_rready(rready),.psel(psel),.penable(penable),.pwrite(pwrite),
    .paddr(paddr),.pwdata(pwdata),.pstrb(pstrb),.pready(pready),.prdata(prdata),.pslverr(pslverr));
  myfuzz_apb_decoder decoder(
    .psel(psel),.penable(penable),.pwrite(pwrite),.paddr(paddr),.pwdata(pwdata),.pstrb(pstrb),
    .pready(pready),.prdata(prdata),.pslverr(pslverr),.m_psel(m_psel),.m_penable(m_penable),
    .m_pwrite(m_pwrite),.m_paddr(m_paddr),.m_pwdata(m_pwdata),.m_pstrb(m_pstrb),
    .m_pready(m_pready),.m_prdata(m_prdata),.m_pslverr(m_pslverr));
  task tick; begin #1 clk=1; #1 clk=0; #1; end endtask
  initial begin
    tick; resetn=1;
    awaddr=16'h010c; awvalid=1; araddr=16'h0204; arvalid=1; #1;
    if (!awready || arready) $fatal(1,"write priority/lock failed"); tick;
    awvalid=0; arvalid=0; wdata=32'h12345678; wstrb=4'hf; wvalid=1; tick; wvalid=0;
    repeat (3) tick; if (!bvalid || bresp!=0) $fatal(1,"write response failed");
    if (written_address!=16'h000c || written_data!=32'h12345678) $fatal(1,"local write failed");
    bready=1; tick; bready=0;
    araddr=16'h0204; arvalid=1; tick; arvalid=0;
    repeat (5) tick; if (!rvalid || rresp!=0 || rdata!=32'hb0000004) $fatal(1,"wait/read failed %h",rdata);
    rready=1; tick; rready=0;
    araddr=16'h0800; arvalid=1; tick; arvalid=0;
    repeat (3) tick; if (!rvalid || rresp!=2) $fatal(1,"default error failed");
    $display("APB_BACKEND_PASS"); $finish;
  end
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "tb.sv"; executable = root / "sim.out"
            source.write_text(tb)
            compile_run = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(executable), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(compile_run.returncode, 0, compile_run.stderr)
            run = subprocess.run(["vvp", str(executable)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("APB_BACKEND_PASS", run.stdout)


if __name__ == "__main__":
    unittest.main()
