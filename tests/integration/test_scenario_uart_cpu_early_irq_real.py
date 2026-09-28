"""E2E-07: real UART IRQ reaches real Ibex before UART TX_DONE."""

import os
from pathlib import Path
import unittest

from myfuzz.scenario.genome import GenomeCodec, MemoryImage, ScenarioGenome
from myfuzz.scenario.scheduler import DependencyScheduler
from myfuzz.scenario.checker import check_uart_early_irq_chain


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15
            | 2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _image(words: tuple[int, ...]) -> str:
    return b"".join(word.to_bytes(4, "little") for word in words).hex()


def make_uart_early_irq_genome() -> ScenarioGenome:
    main = (
        0x400000b7,             # UART MMIO base in x1
        0x20000137, 0x00110113,  # CTRL.NCO=0x2000, TX=1
        _sw(2, 1, 0x10),
        0x0a500113, _sw(2, 1, 0x1c),  # WDATA=0xA5
        0x00500113, _sw(2, 1, 0x04),  # enable watermark + tx_done
        0x000102b7, 0x10028293, 0x30529073,  # mtvec=0x10100
        0x000012b7, 0x80028293, 0x3042a073,  # MEIE
        0x00800293, 0x3002a073,  # MIE
        0x0000006f,
    )
    isr = (
        0x400000b7, _lw(2, 1, 0),  # real INTR_STATE read
        _sw(2, 0, 0x200),           # record what CPU actually read
        0x00400193, _sw(3, 1, 0x04),  # disable watermark, retain tx_done
        0x30200073,
    )
    return ScenarioGenome(
        testcase_id="uart-early-irq-cpu", direction="CPU_TO_IP_TO_CPU",
        path_id="cpu-uart-early-irq-cpu", schedule_order=("cpu", "uart"),
        max_steps=4000, actions=(), initial_images=(
            MemoryImage("cpu.main", "cpu", 0x10080, _image(main)),
            MemoryImage("cpu.isr", "cpu", 0x10100, _image(isr)),
            MemoryImage("cpu.isr.vector", "cpu", 0x1012c, _image(isr)),
        ))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealUartCpuEarlyIrqTests(unittest.TestCase):
    def test_cpu_observes_real_uart_irq_before_tx_done(self):
        from myfuzz.scenario.uart_example import make_ibex_uart_runner

        genome = make_uart_early_irq_genome()
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(GenomeCodec.encode(genome),
                         (root / "configs/scenario/ibex_opentitan_uart_early_irq.json")
                         .read_bytes().rstrip(b"\n"))
        runner = make_ibex_uart_runner()
        try:
            result = DependencyScheduler().run(runner, genome)
            self.assertEqual("complete", result.status)
            events = runner.events
            early = [event for event in events
                     if event.get("component") == "uart"
                     and event.get("outputs", {}).get("irq") == 1
                     and event["outputs"]["tx_done"] == 0]
            done = [event for event in events
                    if event.get("component") == "uart"
                    and event.get("outputs", {}).get("tx_done") == 1]
            self.assertTrue(early)
            self.assertTrue(done)
            self.assertLess(early[0]["event_id"], done[0]["event_id"])
            self.assertTrue(any(event.get("kind") == "dataflow_delivery"
                                and tuple(event.get("source", ())) == ("uart", "irq")
                                and tuple(event.get("target", ())) == ("cpu", "irq")
                                and event["value"] == 1
                                and early[0]["event_id"] < event["event_id"]
                                < done[0]["event_id"] for event in events))
            self.assertTrue(any(event.get("component") == "cpu"
                                and event.get("outputs", {}).get("irq_taken_pre") == 1
                                and event["event_id"] < done[0]["event_id"]
                                for event in events))
            early_reads = [event for event in events
                           if event.get("kind") == "mmio_delivery"
                           and event.get("device_id") == "uart"
                           and event.get("offset") == 0
                           and not event.get("write")
                           and event["event_id"] < done[0]["event_id"]]
            self.assertTrue(early_reads)
            self.assertEqual(0, early_reads[0]["read_value"] & 0b100)
            self.assertTrue(early_reads[0]["read_value"] & 0b1)
            transaction = early_reads[0]["source_transaction"]
            self.assertTrue(any(event.get("component") == "cpu"
                                and event.get("outputs", {}).get("data_rsp_consumed") == 1
                                and event["outputs"]["data_rsp_source_epoch"] ==
                                transaction["source_epoch"]
                                and event["outputs"]["data_rsp_source_sequence"] ==
                                transaction["source_sequence"]
                                and event["outputs"]["data_rsp_rdata"] ==
                                early_reads[0]["read_value"]
                                and event["event_id"] < done[0]["event_id"]
                                for event in events))
            self.assertTrue(any(event.get("kind") == "memory_write"
                                and event.get("address") == 0x200
                                and event.get("value") == early_reads[0]["read_value"]
                                and event["event_id"] < done[0]["event_id"]
                                for event in events))
            self.assertEqual([], check_uart_early_irq_chain(
                events, runner.final_state_document())["findings"])
        finally:
            runner.finalize()

        # Calibration: a host rule that waits for DONE before forwarding IRQ
        # must lose the real early CPU interrupt witnessed above.
        filtered = make_ibex_uart_runner()
        real_step = filtered.sessions["uart"].step_local

        def wait_for_done_filter(inputs):
            outputs = dict(real_step(inputs))
            if not outputs["tx_done"]:
                outputs["irq"] = 0
            return outputs

        filtered.sessions["uart"].step_local = wait_for_done_filter
        try:
            filtered_result = DependencyScheduler().run(filtered, genome)
            self.assertEqual("complete", filtered_result.status)
            filtered_events = filtered.events
            filtered_done = next(event["event_id"] for event in filtered_events
                                 if event.get("component") == "uart"
                                 and event.get("outputs", {}).get("tx_done") == 1)
            self.assertFalse(any(event.get("component") == "cpu"
                                 and event.get("outputs", {}).get("irq_taken_pre") == 1
                                 and event["event_id"] < filtered_done
                                 for event in filtered_events))
            self.assertIn("cpu_early_irq_take_missing",
                          check_uart_early_irq_chain(
                              filtered_events,
                              filtered.final_state_document())["findings"])
        finally:
            filtered.finalize()


if __name__ == "__main__":
    unittest.main()
