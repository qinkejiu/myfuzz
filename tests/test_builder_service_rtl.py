import subprocess
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import emit_system_service_target  # noqa: E402


class SystemServiceRtlTest(unittest.TestCase):
    def test_read_write_partial_write_read_only_and_bounds(self):
        writable = emit_system_service_target(module_name="service_rw", size=16)
        readonly = emit_system_service_target(module_name="service_ro", size=16, read_only=True)
        bench = r"""
module tb;
 logic clk=0, resetn=0; always #5 clk=~clk;
 logic [31:0] s_awaddr,s_wdata,s_araddr,s_rdata; logic [3:0] s_wstrb;
 logic s_awvalid,s_wvalid,s_bready,s_arvalid,s_rready,s_awready,s_wready,s_bvalid,s_arready,s_rvalid; logic [1:0] s_bresp,s_rresp;
 service_rw dut(.*);
 task write(input [31:0] addr,input [31:0] data,input [3:0] strb);
  begin @(negedge clk); s_awaddr=addr;s_wdata=data;s_wstrb=strb;s_awvalid=1;s_wvalid=1;s_bready=1;
   @(negedge clk); s_awvalid=0;s_wvalid=0; wait(s_bvalid); @(negedge clk); end
 endtask
 task read(input [31:0] addr); begin @(negedge clk);s_araddr=addr;s_arvalid=1;s_rready=1;
   @(negedge clk);s_arvalid=0;wait(s_rvalid);@(negedge clk);end endtask
 initial begin s_awaddr=0;s_wdata=0;s_wstrb=0;s_awvalid=0;s_wvalid=0;s_bready=0;s_araddr=0;s_arvalid=0;s_rready=0;
  repeat(2) @(negedge clk);resetn=1;
  write(4,32'h11223344,4'b1111); if(s_bresp!==0)$fatal;
  write(4,32'haabbccdd,4'b0101); read(4); if(s_rdata!==32'h11bb33dd)$fatal;
  read(16); if(s_rresp!==2'b10)$fatal; $display("SERVICE_PASS");$finish;
 end
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "service.sv"
            source.write_text(writable + readonly + bench)
            output = Path(directory) / "service.out"
            compiled = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(output), str(source)],
                                      capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            run = subprocess.run(["vvp", str(output)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("SERVICE_PASS", run.stdout)


if __name__ == "__main__":
    unittest.main()
