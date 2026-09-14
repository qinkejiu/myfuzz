from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from myfuzz.integration.interaction_monitor import (
    InteractionEvent,
    InteractionMonitorError,
    diff_replay,
    evaluate_interactions,
)


ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src/myfuzz/protocols/rtl"


def _run_rtl(test: unittest.TestCase, source: Path, bench: str) -> str:
    iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
    test.assertIsNotNone(iverilog, "iverilog is required for SoC interaction RTL tests")
    test.assertIsNotNone(vvp, "vvp is required for SoC interaction RTL tests")
    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory) / "interaction.vvp"
        tb = Path(directory) / "tb.sv"
        tb.write_text(textwrap.dedent(bench), encoding="utf-8")
        compiled = subprocess.run(
            [str(iverilog), "-g2012", "-s", "tb", "-o", str(out), str(source), str(tb)],
            cwd=ROOT, text=True, capture_output=True, timeout=60,
        )
        test.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
        result = subprocess.run([str(vvp), str(out)], cwd=ROOT,
                                text=True, capture_output=True, timeout=60)
        test.assertEqual(0, result.returncode, result.stdout + result.stderr)
        test.assertIn("PASS", result.stdout, result.stdout + result.stderr)
        return result.stdout


class SocPeerRtlTests(unittest.TestCase):
    def test_uart_peer_serializes_explicit_rx_byte_and_counts_busy_drop(self):
        _run_rtl(self, RTL / "fuzz_uart_peer.sv", r"""
          module tb;
            logic clk = 0, reset = 1, offer = 0;
            logic [7:0] data = 0;
            logic rx, ready, busy;
            logic [31:0] drop_count, sent_count;
            always #1 clk = ~clk;
            task tick; @(posedge clk); #1; endtask
            fuzz_uart_peer #(.BAUD_DIV(1)) dut (
              .clk_i(clk), .reset_i(reset), .offer_i(offer), .data_i(data),
              .rx_o(rx), .ready_o(ready), .busy_o(busy),
              .drop_count_o(drop_count), .sent_count_o(sent_count)
            );
            initial begin
              repeat (2) tick(); reset = 0;
              if (!ready || rx !== 1'b1) $fatal(1, "uart idle");
              data = 8'hA5; offer = 1; tick(); offer = 0;
              if (ready || !busy) $fatal(1, "uart accepted byte");
              if (rx !== 1'b0) $fatal(1, "uart start bit");
              offer = 1; tick(); offer = 0;
              if (drop_count != 1) $fatal(1, "uart busy drop");
              if (rx !== 1'b1) $fatal(1, "uart data bit 0");
              tick(); if (rx !== 1'b0) $fatal(1, "uart data bit 1");
              tick(); if (rx !== 1'b1) $fatal(1, "uart data bit 2");
              tick(); if (rx !== 1'b0) $fatal(1, "uart data bit 3");
              tick(); if (rx !== 1'b0) $fatal(1, "uart data bit 4");
              tick(); if (rx !== 1'b1) $fatal(1, "uart data bit 5");
              tick(); if (rx !== 1'b0) $fatal(1, "uart data bit 6");
              tick(); if (rx !== 1'b1) $fatal(1, "uart data bit 7");
              tick(); if (rx !== 1'b1) $fatal(1, "uart stop bit");
              tick();
              if (sent_count != 1 || !ready || rx !== 1'b1) $fatal(1, "uart completion");
              $display("PASS uart");
              $finish;
            end
          endmodule
        """)

    def test_spi_peer_shifts_declared_miso_bits_on_clock_edges(self):
        _run_rtl(self, RTL / "fuzz_spi_peer.sv", r"""
          module tb;
            logic clk = 0, reset = 1, offer = 0, sck = 0, cs = 1;
            logic [7:0] data = 0;
            logic miso, ready, busy;
            logic [31:0] drop_count, sent_count;
            always #1 clk = ~clk;
            task tick; @(posedge clk); #1; endtask
            fuzz_spi_peer #(.BITS(8), .CPOL(0), .CPHA(0)) dut (
              .clk_i(clk), .reset_i(reset), .offer_i(offer), .data_i(data),
              .sck_i(sck), .cs_i(cs), .miso_o(miso), .ready_o(ready),
              .busy_o(busy), .drop_count_o(drop_count), .sent_count_o(sent_count)
            );
            task edge_sck(input logic expected);
              begin sck = 1; tick(); if (miso !== expected) $fatal(1, "spi bit"); sck = 0; tick(); end
            endtask
            initial begin
              repeat (2) tick(); reset = 0; cs = 0; data = 8'b1010_0101;
              offer = 1; tick(); offer = 0;
              if (!busy || ready) $fatal(1, "spi accepted byte");
              edge_sck(1'b1); edge_sck(1'b0); edge_sck(1'b1); edge_sck(0);
              edge_sck(0); edge_sck(1); edge_sck(0); edge_sck(1);
              cs = 1; tick();
              if (sent_count != 1 || !ready) $fatal(1, "spi completion");
              $display("PASS spi");
              $finish;
            end
          endmodule
        """)

    def test_irq_router_captures_edge_level_priority_clear_and_reset(self):
        _run_rtl(self, RTL / "soc_irq_router.sv", r"""
          module tb;
            localparam N = 3;
            logic clk = 0, reset = 1, claim = 0, complete = 0;
            logic [N-1:0] source = 0, enable = 3'b111, edge_mode = 3'b001, clear = 0;
            logic [N*4-1:0] prio = {4'd1, 4'd3, 4'd2};
            logic irq, claim_valid;
            logic [N-1:0] pending, in_service;
            logic [1:0] claim_id;
            always #1 clk = ~clk;
            task tick; @(posedge clk); #1; endtask
            soc_irq_router #(.NUM_SOURCES(N), .SOURCE_ID_WIDTH(2), .PRIORITY_WIDTH(4)) dut (
              .clk_i(clk), .reset_i(reset), .source_i(source), .enable_i(enable),
              .edge_mode_i(edge_mode), .clear_i(clear), .claim_i(claim),
              .complete_i(complete), .priority_i(prio), .irq_o(irq),
              .pending_o(pending), .in_service_o(in_service),
              .claim_valid_o(claim_valid), .claim_id_o(claim_id)
            );
            initial begin
              repeat (2) tick(); reset = 0;
              source[0] = 1; source[1] = 1; tick();
              if (pending !== 3'b011 || !irq) $fatal(1, "irq capture");
              claim = 1; tick(); claim = 0;
              if (!claim_valid || claim_id != 1 || in_service[1] !== 1) $fatal(1, "priority claim");
              clear[0] = 1; tick(); clear = 0;
              if (pending[0]) $fatal(1, "edge clear");
              complete = 1; tick(); complete = 0;
              source[1] = 0; tick();
              if (pending[1]) $fatal(1, "level clear");
              reset = 1; tick(); reset = 0;
              if (pending !== 0 || in_service !== 0) $fatal(1, "irq reset");
              $display("PASS irq");
              $finish;
            end
          endmodule
        """)


class InteractionMonitorTests(unittest.TestCase):
    def _chain(self, *, changed: int = 0):
        return [
            InteractionEvent("t", 4, "fuzz", "gpio", "a", "environment", changed),
            InteractionEvent("t", 7, "gpio", "cpu", "a", "irq", 1),
            InteractionEvent("t", 10, "cpu", "cpu", "a", "cpu_isr", 3),
            InteractionEvent("t", 13, "cpu", "uart", "b", "transaction_accepted", 0x20),
        ]

    def test_bounded_a_irq_isr_b_chain_and_exact_event_schema(self):
        result = evaluate_interactions(self._chain())
        self.assertTrue(result["ok"])
        self.assertEqual(1, len(result["chains"]))
        event = InteractionEvent.from_mapping(result["chains"][0]["events"][0])
        self.assertEqual(("t", 4, "fuzz", "gpio", "a", "environment", 0), event.as_tuple())

    def test_missing_or_wrong_source_fails_without_reordering(self):
        missing = self._chain()[:-1]
        result = evaluate_interactions(missing)
        self.assertFalse(result["ok"])
        self.assertTrue(any(error.startswith("missing:transaction_accepted") for error in result["errors"]))
        wrong = self._chain()
        wrong[1] = InteractionEvent("t", 7, "timer", "cpu", "a", "irq", 1)
        with self.assertRaisesRegex(InteractionMonitorError, "source"):
            evaluate_interactions(wrong, raise_on_error=True)

    def test_latency_bound_and_reset_clear_are_checked(self):
        late = [event for event in self._chain()]
        late[-1] = InteractionEvent("t", 100, "cpu", "uart", "b", "transaction_accepted", 0)
        result = evaluate_interactions(late, max_latency=32)
        self.assertFalse(result["ok"])
        reset = self._chain()[:2] + [
            InteractionEvent("t", 8, "harness", "soc", "r", "reset", 1),
            *self._chain()[2:],
        ]
        self.assertFalse(evaluate_interactions(reset)["ok"])

    def test_simultaneous_chains_and_differential_replay(self):
        events = [
            InteractionEvent("t", 4, "fuzz", "gpio", "a", "environment", 0),
            InteractionEvent("t", 5, "fuzz", "gpio", "c", "environment", 1),
            InteractionEvent("t", 7, "gpio", "cpu", "a", "irq", 1),
            InteractionEvent("t", 8, "gpio", "cpu", "c", "irq", 1),
            InteractionEvent("t", 10, "cpu", "cpu", "a", "cpu_isr", 3),
            InteractionEvent("t", 11, "cpu", "cpu", "c", "cpu_isr", 3),
            InteractionEvent("t", 13, "cpu", "uart", "b", "transaction_accepted", 0x20),
            InteractionEvent("t", 14, "cpu", "spi", "d", "transaction_accepted", 0x40),
        ]
        result = evaluate_interactions(events)
        self.assertTrue(result["ok"])
        self.assertEqual(2, len(result["chains"]))
        replay = diff_replay(self._chain(), self._chain(changed=1))
        self.assertTrue(replay["changed"])
        self.assertTrue(replay["baseline"]["ok"] and replay["variant"]["ok"])

    def test_non_monotonic_cycles_and_malformed_event_rejected(self):
        bad = self._chain()
        bad[2] = InteractionEvent("t", 6, "cpu", "cpu", "a", "cpu_isr", 3)
        with self.assertRaisesRegex(InteractionMonitorError, "cycle"):
            evaluate_interactions(bad, raise_on_error=True)
        with self.assertRaisesRegex(InteractionMonitorError, "event"):
            InteractionEvent.from_mapping({"cycle": 1})


if __name__ == "__main__":
    unittest.main()
