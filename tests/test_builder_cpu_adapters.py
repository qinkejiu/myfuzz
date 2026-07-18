import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RTL = ROOT / "src/myfuzz/builder/rtl"


@unittest.skipUnless(shutil.which("iverilog"), "iverilog is required")
class CpuAdapterTest(unittest.TestCase):
    def _run_vvp(self, sources, top, directory, *, cwd=None):
        executable = Path(directory) / f"{top}.vvp"
        subprocess.run(["iverilog", "-g2012", "-s", top, "-o", str(executable), *map(str, sources)],
                       cwd=cwd, check=True, capture_output=True, text=True)
        return subprocess.run(["vvp", str(executable)], cwd=cwd, check=True,
                              capture_output=True, text=True).stdout

    def test_picorv32_execution_adapter_elaborates(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([
                "iverilog", "-g2012", "-s", "picorv32_level1_adapter", "-o", str(Path(directory) / "pico.vvp"),
                str(ROOT / "materials/qualification/axi_lite/upstream/picorv32/picorv32.v"),
                str(RTL / "picorv32_level1_adapter.sv"),
            ], check=True, capture_output=True, text=True)

    def test_picorv32_bridge_ignores_stale_opposite_direction_response(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tb = root / "picorv32_bridge_tb.sv"
            tb.write_text('''module picorv32_bridge_tb;
 reg clk=0,resetn=0,mem_valid=0,mem_instr=0;
 reg [31:0] mem_addr=0,mem_wdata=0,m_rdata=32'h12345678;
 reg [3:0] mem_wstrb=0;
 reg m_awready=1,m_wready=1,m_bvalid=0,m_arready=1,m_rvalid=0;
 wire mem_ready,m_awvalid,m_wvalid,m_bready,m_arvalid,m_rready;
 wire [31:0] mem_rdata,m_awaddr,m_wdata,m_araddr; wire [3:0] m_wstrb;
 always #1 clk=~clk;
 myfuzz_picorv32_axi_lite_bridge dut(
  .clk(clk),.resetn(resetn),.mem_valid(mem_valid),.mem_instr(mem_instr),
  .mem_ready(mem_ready),.mem_addr(mem_addr),.mem_wdata(mem_wdata),
  .mem_wstrb(mem_wstrb),.mem_rdata(mem_rdata),.m_awvalid(m_awvalid),
  .m_awready(m_awready),.m_awaddr(m_awaddr),.m_wvalid(m_wvalid),
  .m_wready(m_wready),.m_wdata(m_wdata),.m_wstrb(m_wstrb),
  .m_bvalid(m_bvalid),.m_bready(m_bready),.m_arvalid(m_arvalid),
  .m_arready(m_arready),.m_araddr(m_araddr),.m_rvalid(m_rvalid),
  .m_rready(m_rready),.m_rdata(m_rdata));
 initial begin
  #3 resetn=1;
  mem_valid=1;mem_wstrb=0;m_bvalid=1;m_rvalid=0;force dut.state=3'd4;
  #1; if(mem_ready) $fatal(1,"stale B completed read");
  m_rvalid=1; #1; if(!mem_ready) $fatal(1,"R did not complete read");
  mem_wstrb=4'hf;m_bvalid=0;m_rvalid=1;force dut.state=3'd2;
  #1; if(mem_ready) $fatal(1,"stale R completed write");
  m_bvalid=1; #1; if(!mem_ready) $fatal(1,"B did not complete write");
  release dut.state;
  $display("PICORV32_BRIDGE_PASS"); $finish;
 end
endmodule
''')
            executable = root / "picorv32_bridge_tb.vvp"
            subprocess.run([
                "iverilog", "-g2012", "-s", "picorv32_bridge_tb", "-o", str(executable),
                str(RTL / "picorv32_level1_adapter.sv"), str(tb),
            ], check=True, capture_output=True, text=True)
            run = subprocess.run(["vvp", str(executable)], check=False,
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("PICORV32_BRIDGE_PASS", run.stdout)

    def test_ultra_execution_adapter_elaborates_with_loader_exposed(self):
        cases = ROOT / "materials/qualification/axi_lite/cases"
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([
                "iverilog", "-g2012", "-s", "ultra_riscv_level1_adapter", "-o", str(Path(directory) / "ultra.vvp"),
                "-f", "ultra_riscv_cpu.f", str(RTL / "ultra_riscv_level1_adapter.sv"),
            ], cwd=cases, check=True, capture_output=True, text=True)

    def test_install_backends_elaborate(self):
        with tempfile.TemporaryDirectory() as directory:
            for top, source in (
                ("myfuzz_level1_external_rom", "level1_external_rom.sv"),
                ("myfuzz_level1_tcm_loader", "level1_tcm_loader.sv"),
            ):
                subprocess.run([
                    "iverilog", "-g2012", "-s", top, "-o", str(Path(directory) / f"{top}.vvp"),
                    str(RTL / source),
                ], check=True, capture_output=True, text=True)

    def test_lfsr_adapter_suppresses_unsolicited_read_response(self):
        cases = ROOT / "materials/qualification/axi_lite/cases"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); tb = root / "lfsr_tb.sv"; executable = root / "lfsr.vvp"
            tb.write_text('''module pulp_axi_lite_lfsr_wrapper(
 input clk,resetn,s_awvalid,s_wvalid,s_bready,s_arvalid,s_rready,
 input [31:0] s_awaddr,s_wdata,s_araddr,input [3:0] s_wstrb,
 output s_awready,s_wready,s_bvalid,s_arready,s_rvalid,
 output [1:0] s_bresp,s_rresp,output [31:0] s_rdata);
 assign s_awready=1;assign s_wready=1;assign s_bvalid=0;assign s_bresp=0;
 assign s_arready=1;assign s_rvalid=1;assign s_rresp=0;assign s_rdata=32'h12345678;
endmodule
module lfsr_tb;
 reg clk=0,resetn=0,arvalid=0,rready=1; wire arready,rvalid;
 wire awready,wready,bvalid; wire [1:0] bresp,rresp; wire [31:0] rdata;
 always #1 clk=~clk;
 pulp_axi_lite_lfsr_level1_adapter dut(.clk(clk),.resetn(resetn),
  .s_awvalid(0),.s_awready(awready),.s_awaddr(0),.s_wvalid(0),.s_wready(wready),
  .s_wdata(0),.s_wstrb(0),.s_bvalid(bvalid),.s_bready(1),.s_bresp(bresp),
  .s_arvalid(arvalid),.s_arready(arready),.s_araddr(0),.s_rvalid(rvalid),
  .s_rready(rready),.s_rdata(rdata),.s_rresp(rresp));
 initial begin #3 resetn=1; repeat(3) begin @(negedge clk); if(rvalid) $fatal(1,"unsolicited RVALID"); end
  arvalid=1; @(negedge clk); arvalid=0; wait(rvalid); @(negedge clk);
  if(rvalid) $fatal(1,"response was not consumed"); $display("LFSR_ADAPTER_PASS"); $finish; end
endmodule\n''')
            subprocess.run(["iverilog", "-g2012", "-s", "lfsr_tb", "-o", str(executable),
                            str(RTL / "pulp_axi_lite_lfsr_level1_adapter.sv"), str(tb)],
                           cwd=cases, check=True, capture_output=True, text=True)
            run = subprocess.run(["vvp", str(executable)], cwd=cases, check=False,
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("LFSR_ADAPTER_PASS", run.stdout)

    def test_external_rom_reads_image_and_rejects_split_channel_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "image.hex"
            image.write_text("11223344\na5a55a5a\n")
            tb = root / "rom_tb.sv"
            tb.write_text(f'''module rom_tb;
 reg clk=0, resetn=0, awvalid=0, wvalid=0, bready=1, arvalid=0, rready=1;
 reg [31:0] awaddr=0, wdata=0, araddr=0; reg [3:0] wstrb=0;
 wire awready,wready,bvalid,arready,rvalid; wire [1:0] bresp,rresp; wire [31:0] rdata;
 always #1 clk=~clk;
 myfuzz_level1_external_rom #(.WORDS(2),.HEX_FILE("{image}")) dut(
  .clk(clk),.resetn(resetn),.s_awvalid(awvalid),.s_awready(awready),.s_awaddr(awaddr),
  .s_wvalid(wvalid),.s_wready(wready),.s_wdata(wdata),.s_wstrb(wstrb),
  .s_bvalid(bvalid),.s_bready(bready),.s_bresp(bresp),.s_arvalid(arvalid),
  .s_arready(arready),.s_araddr(araddr),.s_rvalid(rvalid),.s_rready(rready),
  .s_rdata(rdata),.s_rresp(rresp));
 initial begin
  #3 resetn=1; @(negedge clk); araddr=32'h2004; arvalid=1;
  @(negedge clk); arvalid=0; wait(rvalid); if(rdata!==32'ha5a55a5a || rresp!==0) $fatal;
  @(negedge clk); awvalid=1; awaddr=32'h2000; @(negedge clk); awvalid=0;
  @(negedge clk); wvalid=1; wdata=1; wstrb=4'hf; @(negedge clk); wvalid=0;
  wait(bvalid); if(bresp!==2'b10) $fatal; $display("ROM_PASS"); $finish;
 end
endmodule\n''')
            output = self._run_vvp((RTL / "level1_external_rom.sv", tb), "rom_tb", root)
            self.assertIn("ROM_PASS", output)

    def test_ultra_loader_writes_and_reads_back_real_tcm(self):
        cases = ROOT / "materials/qualification/axi_lite/cases"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "image.hex"
            image.write_text("11223344\na5a55a5a\n")
            tb = root / "loader_tb.sv"
            tb.write_text(f'''module loader_tb;
 reg clk=0, reset=1, start=0; wire busy,done,error;
 wire awvalid,awready,wvalid,wready,bvalid,bready,arvalid,arready,rvalid,rready;
 wire [31:0] awaddr,wdata,araddr,rdata; wire [3:0] awid,wstrb,bid,arid,rid;
 wire [7:0] awlen,arlen; wire [1:0] awburst,bresp,arburst,rresp; wire wlast,rlast;
 always #1 clk=~clk;
 myfuzz_level1_tcm_loader #(.WORDS(2),.HEX_FILE("{image}")) loader(
  .clk(clk),.reset(reset),.start(start),.busy(busy),.done(done),.error(error),
  .awvalid(awvalid),.awready(awready),.awaddr(awaddr),.awid(awid),.awlen(awlen),.awburst(awburst),
  .wvalid(wvalid),.wready(wready),.wdata(wdata),.wstrb(wstrb),.wlast(wlast),
  .bvalid(bvalid),.bready(bready),.bresp(bresp),.bid(bid),.arvalid(arvalid),.arready(arready),
  .araddr(araddr),.arid(arid),.arlen(arlen),.arburst(arburst),.rvalid(rvalid),.rready(rready),
  .rdata(rdata),.rresp(rresp),.rid(rid),.rlast(rlast));
 ultra_riscv_level1_adapter cpu(.clk(clk),.reset(reset),.cpu_reset(1'b1),.fuzz_irq(0),
  .m_awready(0),.m_wready(0),.m_bvalid(0),.m_bresp(0),.m_arready(0),.m_rvalid(0),.m_rdata(0),.m_rresp(0),
  .loader_awvalid(awvalid),.loader_awready(awready),.loader_awaddr(awaddr),.loader_awid(awid),
  .loader_awlen(awlen),.loader_awburst(awburst),.loader_wvalid(wvalid),.loader_wready(wready),
  .loader_wdata(wdata),.loader_wstrb(wstrb),.loader_wlast(wlast),.loader_bvalid(bvalid),
  .loader_bready(bready),.loader_bresp(bresp),.loader_bid(bid),.loader_arvalid(arvalid),
  .loader_arready(arready),.loader_araddr(araddr),.loader_arid(arid),.loader_arlen(arlen),
  .loader_arburst(arburst),.loader_rvalid(rvalid),.loader_rready(rready),.loader_rdata(rdata),
  .loader_rresp(rresp),.loader_rid(rid),.loader_rlast(rlast));
 initial begin #4 reset=0; @(posedge clk); start=1; @(posedge clk); start=0;
  fork begin wait(done); if(error) $fatal; $display("LOADER_PASS"); $finish; end
       begin repeat(300) @(posedge clk); $fatal; end join_any
 end
endmodule\n''')
            executable = root / "loader.vvp"
            subprocess.run([
                "iverilog", "-g2012", "-s", "loader_tb", "-o", str(executable),
                "-f", "ultra_riscv_cpu.f", str(RTL / "ultra_riscv_level1_adapter.sv"),
                str(RTL / "level1_tcm_loader.sv"), str(tb),
            ], cwd=cases, check=True, capture_output=True, text=True)
            output = subprocess.run(["vvp", str(executable)], cwd=cases, check=True,
                                    capture_output=True, text=True).stdout
            self.assertIn("LOADER_PASS", output)


if __name__ == "__main__":
    unittest.main()
