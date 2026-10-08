"""Clocked behavior of the passive Ibex IRQ to RVFI serial sideband."""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'src/myfuzz/composition/rtl/ibex_irq_serial_sideband.sv'


class IbexIrqSerialSidebandTests(unittest.TestCase):
    def test_decision_stall_supersession_and_reset(self):
        tb = r'''module tb;
          reg clk=0, rst=0, ext=0, any_irq=0, first=0, id_done=0, wb_done=0;
          reg valid=0, intr=0;
          wire [63:0] decision, retire;
          ibex_irq_serial_sideband dut(.clk_i(clk), .rst_ni(rst),
            .external_decision_i(ext), .any_irq_pc_decision_i(any_irq),
            .instr_first_cycle_id_i(first), .rvfi_id_done_i(id_done),
            .rvfi_wb_done_i(wb_done), .rvfi_valid_i(valid), .rvfi_intr_i(intr),
            .decision_serial_o(decision), .retirement_serial_o(retire));
          task tick; begin #1 clk=1; #1 clk=0; end endtask
          task expect_retire(input [63:0] wanted); begin
            #1; if (retire !== wanted) $fatal(1,"retirement serial %0d != %0d",retire,wanted);
          end endtask
          initial begin
            tick(); rst=1;
            ext=1; any_irq=1; #1;
            if (decision !== 1) $fatal(1,"first decision serial missing");
            tick(); ext=0; any_irq=0;
            tick(); tick();
            first=1; tick(); first=0; // first handler instruction enters ID
            tick(); id_done=1; intr=1; tick(); id_done=0; valid=1;
            expect_retire(1); valid=0; intr=0;
            // An external decision superseded by a different IRQ PC decision
            // must not certify that later handler as the external source.
            ext=1; any_irq=1; tick(); ext=0;
            any_irq=1; tick(); any_irq=0;
            first=1; tick(); first=0; id_done=1; intr=1; tick();
            id_done=0; valid=1; expect_retire(0);
            valid=0; intr=0; rst=0; tick(); rst=1;
            ext=1; any_irq=1; #1;
            if (decision !== 1) $fatal(1,"serial not reset with epoch");
            $display("PASS"); $finish;
          end
        endmodule'''
        with tempfile.TemporaryDirectory() as tmp:
            bench = Path(tmp) / 'tb.sv'
            bench.write_text(tb)
            binary = Path(tmp) / 'tb.out'
            build = subprocess.run(['iverilog', '-g2012', '-s', 'tb', '-o', str(binary),
                                    str(SOURCE), str(bench)], capture_output=True, text=True)
            self.assertEqual(0, build.returncode, build.stderr)
            run = subprocess.run(['vvp', str(binary)], capture_output=True, text=True)
            self.assertEqual(0, run.returncode, run.stdout + run.stderr)
            self.assertIn('PASS', run.stdout)


if __name__ == '__main__':
    unittest.main()
