from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
ROOT=Path(__file__).resolve().parents[2]
class NativeCompletionAdapterTests(unittest.TestCase):
    def test_completion_not_acceptance_and_errors_never_complete(self):
        source='''module tb;
logic clk=0,reset=1,valid=0,ready,reqvalid,reqready=0,rspvalid=0,rspready,rsperror=0,fault;
logic [31:0] addr=32'h100,wdata=0,rdata,reqaddr,reqwdata,rspdata=32'h12345678;
logic [3:0] strb=0,be; logic write; logic [1:0] code;
native_completion_memory_adapter #(.MAX_WAIT_CYCLES(4)) dut(
.clk(clk),.reset(reset),.valid_i(valid),.ready_o(ready),.addr_i(addr),.wdata_i(wdata),.wstrb_i(strb),.rdata_o(rdata),
.req_valid_o(reqvalid),.req_ready_i(reqready),.req_write_o(write),.req_addr_o(reqaddr),.req_wdata_o(reqwdata),.req_be_o(be),
.rsp_valid_i(rspvalid),.rsp_ready_o(rspready),.rsp_rdata_i(rspdata),.rsp_error_i(rsperror),.fault_o(fault),.fault_code_o(code));
task tick; #1;clk=1;#1;clk=0;#1;endtask
initial begin
 tick();reset=0;valid=1;#1;if(ready)$fatal(1,"early ready");tick();
 if(!reqvalid||be!=15||write)$fatal(1,"request");reqready=1;tick();reqready=0;
 if(ready||!rspready)$fatal(1,"early response");rspvalid=1;tick();rspvalid=0;
 if(!ready||rdata!=32'h12345678)$fatal(1,"completion data");
 addr=32'h104;#1;if(ready)$fatal(1,"unstable completion success");tick();
 if(!fault||code!=3)$fatal(1,"unstable completion fault");valid=0;addr=32'h100;
 reset=1;tick();reset=0;valid=1;tick();reqready=1;tick();reqready=0;
 rspvalid=1;rsperror=1;tick();rspvalid=0;if(!fault||ready||code!=1)$fatal(1,"error success");
 reset=1;tick();reset=0;valid=1;tick();repeat(4)tick();if(!fault||ready||code!=2)$fatal(1,"timeout success");
 reset=1;tick();reset=0;valid=1;tick();addr=32'h104;tick();if(!fault||ready||code!=3)$fatal(1,"unstable");
 $display("NATIVE_COMPLETION_OK");$finish;end
endmodule'''
        with TemporaryDirectory() as directory:
            directory=Path(directory);tb=directory/'tb.sv';tb.write_text(source)
            result=subprocess.run(['verilator','--binary','--timing','-Wno-fatal','-j','1','--top-module','tb','--Mdir',str(directory/'obj'),str(ROOT/'src/myfuzz/protocols/rtl/native_completion_memory_adapter.sv'),str(tb)],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr[-4000:])
            result=subprocess.run([str(directory/'obj/Vtb')],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('NATIVE_COMPLETION_OK',result.stdout)
