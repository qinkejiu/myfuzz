import subprocess
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import emit_reset_controller  # noqa: E402


class ResetControllerTest(unittest.TestCase):
    def test_bounded_reset_epoch_and_protected_domain(self):
        rtl = emit_reset_controller(
            module_name="reset_dut", domain_count=2, protected_mask=1, assert_cycles=2,
        )
        tb = """module tb;
          logic clk=0,resetn=0,start=0,busy,done,error;logic domain;logic[1:0]active;
          logic[31:0]epoch,rdata;logic awready,wready,bvalid,arready,rvalid;
          logic[1:0]bresp,rresp;always #1 clk=~clk;
          reset_dut dut(.clk(clk),.resetn(resetn),.request_start(start),.request_domain(domain),
            .reset_active(active),.request_busy(busy),.request_done(done),.request_error(error),.epoch(epoch),
            .s_awaddr(0),.s_awvalid(0),.s_awready(awready),.s_wdata(0),.s_wstrb(0),
            .s_wvalid(0),.s_wready(wready),.s_bresp(bresp),.s_bvalid(bvalid),.s_bready(1),
            .s_araddr(0),.s_arvalid(0),.s_arready(arready),.s_rdata(rdata),.s_rresp(rresp),
            .s_rvalid(rvalid),.s_rready(1));
          initial begin #2 resetn=1;domain=0;start=1;@(posedge clk);#1;start=0;
            if(!done||!error||busy||active!=0||epoch!=0)$fatal(1,"protected reset accepted");
            @(posedge clk);#1;domain=1;start=1;@(posedge clk);#1;start=0;
            if(!busy||active!=2)$fatal(1,"domain reset did not assert");
            @(posedge clk);#1;if(!busy||active!=2)$fatal(1,"reset too short");
            @(posedge clk);#1;if(busy||active!=0||!done||error||epoch!=1)$fatal(1,"bad completion");
            $finish;end
        endmodule
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "reset.sv"; executable = root / "reset.out"
            source.write_text(rtl + tb, encoding="utf-8")
            compiled = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(executable), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            run = subprocess.run(["vvp", str(executable)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)


if __name__ == "__main__":
    unittest.main()
