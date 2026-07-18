import subprocess
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import build_control_mailbox_abi, emit_control_mailbox  # noqa: E402
from test_builder_control_plane import soc_fixture  # noqa: E402
from myfuzz.builder import build_control_plane  # noqa: E402


class ControlMailboxTest(unittest.TestCase):
    def test_abi_and_rtl_preserve_bit_fields(self):
        generated = build_control_plane(soc_fixture(), cpu_profile_digest="4" * 64)
        abi = build_control_mailbox_abi(generated.control_ir, generated.layout)
        opcode = next(item for item in abi.fields if item.name == "opcode")
        self.assertEqual(opcode.raw_offset, next(item.offset for item in generated.layout.fields if item.name == "opcode"))
        rtl = emit_control_mailbox(abi, module_name="mailbox_dut")
        raw_value = 5 << opcode.raw_offset
        bench = f"""
module tb;
 logic clk=0,resetn=0;always #5 clk=~clk;
 logic [{abi.raw_width-1}:0] raw_bits_i={abi.raw_width}'h{raw_value:x}; logic start_i=0,accepted_o,done_o,active_o;
 logic [31:0] status_o,result_o,s_awaddr=0,s_wdata=0,s_araddr=0,s_rdata;logic [3:0] s_wstrb=0;
 logic s_awvalid=0,s_awready,s_wvalid=0,s_wready,s_bvalid,s_bready=0,s_arvalid=0,s_arready,s_rvalid,s_rready=0;logic [1:0]s_bresp,s_rresp;
 mailbox_dut dut(.*);
 initial begin repeat(2)@(negedge clk);resetn=1;start_i=1;@(negedge clk);start_i=0;if(!accepted_o)$fatal;
  s_araddr=32'h{opcode.register_offset:x};s_arvalid=1;s_rready=1;@(negedge clk);s_arvalid=0;wait(s_rvalid);if(s_rdata!==5)$fatal;
  @(negedge clk);s_awaddr=4;s_wdata=32'h55;s_wstrb=15;s_awvalid=1;s_wvalid=1;s_bready=1;
  @(negedge clk);s_awvalid=0;s_wvalid=0;wait(done_o);if(status_o!==32'h55||active_o)$fatal;
  $display("MAILBOX_PASS");$finish;end
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "mailbox.sv"; output = Path(directory) / "mailbox.out"
            source.write_text(rtl + bench)
            compile_result = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(output), str(source)], capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run = subprocess.run(["vvp", str(output)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("MAILBOX_PASS", run.stdout)


if __name__ == "__main__":
    unittest.main()
