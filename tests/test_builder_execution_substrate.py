import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RTL = ROOT / "src/myfuzz/builder/rtl"


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "iverilog/vvp required")
class ExecutionSubstrateTest(unittest.TestCase):
    def test_mailbox_watchdog_and_monitor_elaborate(self):
        with tempfile.TemporaryDirectory() as directory:
            for module, filename in (
                ("myfuzz_level1_record_owner", "level1_record_owner.sv"),
                ("myfuzz_level1_recovery_controller", "level1_recovery_controller.sv"),
                ("myfuzz_level1_mailbox", "level1_mailbox.sv"),
                ("myfuzz_level1_watchdog", "level1_watchdog.sv"),
                ("myfuzz_level1_transaction_monitor", "level1_transaction_monitor.sv"),
            ):
                subprocess.run(["iverilog", "-g2012", "-s", module, "-o", str(Path(directory) / module),
                                str(RTL / filename)], check=True, capture_output=True, text=True)

    def test_monitor_ignores_fetch_response_then_completes_target_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); tb = root / "monitor_tb.sv"; executable = root / "monitor.vvp"
            tb.write_text('''module monitor_tb;
 reg clk=0,resetn=0,active=0,rw=0,timeout=0;
 reg awv=0,awr=0,wv=0,wr=0,bv=0,br=1,arv=0,arr=0,rv=0,rr=1;
 reg [31:0] awa=0,ara=0; reg [1:0] bp=0,rp=0; wire term,to; wire [31:0] tseq,taddr,cycles;
 wire [7:0] route; wire trw; wire [1:0] response; always #1 clk=~clk;
 myfuzz_level1_transaction_monitor dut(.clk(clk),.resetn(resetn),.record_active(active),
  .record_sequence(32'd7),.record_read_write(rw),.expected_route(8'd2),.expected_address(32'h20000008),
  .watchdog_timeout(timeout),.m_awvalid(awv),.m_awready(awr),.m_awaddr(awa),.m_wvalid(wv),.m_wready(wr),
  .m_bvalid(bv),.m_bready(br),.m_bresp(bp),.m_arvalid(arv),.m_arready(arr),.m_araddr(ara),
  .m_rvalid(rv),.m_rready(rr),.m_rresp(rp),.terminal_valid(term),.terminal_timed_out(to),
  .terminal_sequence(tseq),.terminal_route(route),.terminal_read_write(trw),.terminal_address(taddr),
  .terminal_response(response),.terminal_cycles(cycles));
 initial begin
  #3 resetn=1; @(negedge clk); active=1;
  @(negedge clk); rv=1; rp=0; @(negedge clk); rv=0; if(term) $fatal(1,"fetch terminated record");
  arv=1;arr=1;ara=32'h20000008; @(negedge clk);arv=0;arr=0;
  rv=1;rp=2'b10; @(negedge clk);
  if(!term||to||tseq!=7||route!=2||response!=2)
    $fatal(1,"bad terminal term=%b to=%b seq=%d route=%d response=%d",term,to,tseq,route,response);
  $display("MONITOR_PASS"); $finish;
 end
endmodule\n''')
            subprocess.run(["iverilog", "-g2012", "-s", "monitor_tb", "-o", str(executable),
                            str(RTL / "level1_transaction_monitor.sv"), str(tb)],
                           check=True, capture_output=True, text=True)
            run = subprocess.run(["vvp", str(executable)], check=False,
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("MONITOR_PASS", run.stdout)

    def test_owner_holds_terminal_until_capture_ack_and_consumes_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); tb = root / "owner_tb.sv"; executable = root / "owner.vvp"
            tb.write_text('''module owner_tb;
 reg clk=0,resetn=0,enable=0,rv=0,raw=0,ack=0; reg [31:0] seq=0;
 wire ready,active,tv,error; wire [31:0] aseq,tseq; wire [31:0] ai,ao,ad,ta,tc;
 wire arw,tto,trw; wire [7:0] route; wire [1:0] resp; always #1 clk=~clk;
 myfuzz_level1_record_owner dut(.clk(clk),.resetn(resetn),.accept_enable(enable),
  .record_valid(rv),.record_ready(ready),.record_sequence(seq),.record_ip_select(3),
  .record_read_write(0),.record_offset(4),.record_data(5),.active(active),
  .active_sequence(aseq),.active_ip_select(ai),.active_read_write(arw),.active_offset(ao),.active_data(ad),
  .raw_terminal_valid(raw),.raw_terminal_timed_out(1),.raw_terminal_sequence(seq),
  .raw_terminal_route(3),.raw_terminal_read_write(0),.raw_terminal_address(32'h2000),
  .raw_terminal_response(0),.raw_terminal_cycles(9),.terminal_valid(tv),.terminal_capture_ack(ack),
  .terminal_timed_out(tto),.terminal_sequence(tseq),.terminal_route(route),
  .terminal_read_write(trw),.terminal_address(ta),.terminal_response(resp),.terminal_cycles(tc),
  .protocol_error(error));
 initial begin
  #3 resetn=1; enable=1; seq=7; rv=1; @(negedge clk); rv=0;
  if(!active||ready) $fatal(1,"record not owned");
  raw=1; @(negedge clk); raw=0;
  if(active||!tv||ready||!tto||tseq!=7||tc!=9) $fatal(1,"terminal not held");
  repeat(3) begin @(negedge clk); if(!tv||ready) $fatal(1,"terminal escaped before ack"); end
  ack=1; @(negedge clk); ack=0; if(tv||!ready||error) $fatal(1,"ack did not consume once");
  $display("OWNER_PASS"); $finish;
 end
endmodule\n''')
            subprocess.run(["iverilog", "-g2012", "-s", "owner_tb", "-o", str(executable),
                            str(RTL / "level1_record_owner.sv"), str(tb)],
                           check=True, capture_output=True, text=True)
            run = subprocess.run(["vvp", str(executable)], check=False, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("OWNER_PASS", run.stdout)

    def test_recovery_resets_and_reenters_after_captured_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); tb = root / "recovery_tb.sv"; executable = root / "recovery.vvp"
            tb.write_text('''module recovery_tb;
 reg clk=0,resetn=0,tv=0,to=0,ack=0,quiet=1; wire erun,crun,start,accept,recovering,error;
 wire [31:0] restarts; always #1 clk=~clk;
 myfuzz_level1_recovery_controller #(.RESET_CYCLES(2),.QUIET_CYCLES(2),.QUARANTINE_LIMIT(8)) dut(
  .clk(clk),.resetn(resetn),.terminal_valid(tv),.terminal_timed_out(to),.terminal_capture_ack(ack),
  .bus_quiet(quiet),.loader_done(1),.loader_error(0),.execution_resetn(erun),.cpu_run(crun),
  .loader_start(start),.accept_enable(accept),.recovering(recovering),.restart_count(restarts),
  .recovery_error(error));
 initial begin
  #3 resetn=1; wait(accept); if(!erun||!crun||recovering) $fatal(1,"initial boot failed");
  @(negedge clk); tv=1;to=1;ack=1; @(negedge clk); tv=0;to=0;ack=0;
  if(erun||accept||restarts!=1) $fatal(1,"timeout did not reset domain");
  wait(accept); if(!erun||!crun||restarts!=1||error) $fatal(1,"reentry failed");
  $display("RECOVERY_PASS"); $finish;
 end
endmodule\n''')
            subprocess.run(["iverilog", "-g2012", "-s", "recovery_tb", "-o", str(executable),
                            str(RTL / "level1_recovery_controller.sv"), str(tb)],
                           check=True, capture_output=True, text=True)
            run = subprocess.run(["vvp", str(executable)], check=False, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("RECOVERY_PASS", run.stdout)


if __name__ == "__main__":
    unittest.main()
