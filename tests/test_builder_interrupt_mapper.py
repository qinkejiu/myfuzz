import subprocess
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import emit_interrupt_mapper  # noqa: E402


class InterruptMapperTest(unittest.TestCase):
    def test_pending_claim_complete_and_simultaneous_reassert(self):
        rtl = emit_interrupt_mapper(module_name="irq_dut", width=4)
        testbench = """module tb;
          logic clk=0,resetn=0;logic[3:0]src;logic[3:0]irq;
          logic[31:0]awaddr,wdata,araddr,rdata;logic[3:0]wstrb;
          logic awvalid,awready,wvalid,wready,bvalid,bready,arvalid,arready,rvalid,rready;
          logic[1:0]bresp,rresp;always #1 clk=~clk;
          irq_dut dut(.clk(clk),.resetn(resetn),.irq_sources(src),.cpu_irq(irq),
            .s_awaddr(awaddr),.s_awvalid(awvalid),.s_awready(awready),.s_wdata(wdata),
            .s_wstrb(wstrb),.s_wvalid(wvalid),.s_wready(wready),.s_bresp(bresp),
            .s_bvalid(bvalid),.s_bready(bready),.s_araddr(araddr),.s_arvalid(arvalid),
            .s_arready(arready),.s_rdata(rdata),.s_rresp(rresp),.s_rvalid(rvalid),.s_rready(rready));
          initial begin src=0;awaddr=0;wdata=0;araddr=0;wstrb=15;awvalid=0;wvalid=0;
            bready=1;arvalid=0;rready=1;#2 resetn=1;
            src=4'b1010;@(posedge clk);#1;src=0;if(irq!==4'b1010)$fatal(1,"pending lost");
            araddr=4;arvalid=1;@(posedge clk);#1;arvalid=0;wait(rvalid);
            if(rdata!==2)$fatal(1,"claim priority is not lowest source");
            @(posedge clk);#1;
            awaddr=8;wdata=4'b0010;awvalid=1;wvalid=1;src=4'b0010;
            @(posedge clk);#1;awvalid=0;wvalid=0;src=0;wait(bvalid);@(posedge clk);#1;
            if(irq!==4'b1010)$fatal(1,"simultaneous reassert was cleared");
            awaddr=8;wdata=4'b1010;awvalid=1;wvalid=1;@(posedge clk);#1;
            awvalid=0;wvalid=0;wait(bvalid);@(posedge clk);#1;
            if(irq!==0)$fatal(1,"complete did not clear pending");$finish;
          end
        endmodule
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "irq.sv"; executable = root / "irq.out"
            source.write_text(rtl + testbench, encoding="utf-8")
            compiled = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(executable), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            run = subprocess.run(["vvp", str(executable)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)


if __name__ == "__main__":
    unittest.main()
