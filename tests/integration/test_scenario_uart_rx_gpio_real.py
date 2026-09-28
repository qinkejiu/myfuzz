"""Two real UART RX frames propagate through Ibex ISR into real GPIO RTL."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, GenomeCodec, MemoryImage, ScenarioGenome, Trigger


ROOT = Path(__file__).resolve().parents[2]
GENOME_PATH = ROOT / "configs/scenario/ibex_uart_rx_gpio_two_rounds.json"
BIT_TICKS = 64  # NCO=0x4000 makes one UART bit occupy 64 UART-local ticks.


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15
            | 2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _image(words: tuple[int, ...]) -> str:
    return b"".join(word.to_bytes(4, "little") for word in words).hex()


def _frame_actions(frame: int, byte: int, trigger: Trigger,
                   start_delay: int) -> tuple[Action, ...]:
    bits = (0, *((byte >> bit) & 1 for bit in range(8)), 1)
    return tuple(Action(
        f"frame-{frame}-bit-{index}", "uart", "uart_rx", level,
        "IP_TO_CPU_TO_IP", trigger, delay_component="uart",
        delay_ticks=start_delay + index * BIT_TICKS)
        for index, level in enumerate(bits))


def make_uart_rx_gpio_genome() -> ScenarioGenome:
    main = (
        0x400000b7,                 # x1: UART base
        0x40000137,                 # x2: NCO=0x4000 in CTRL[31:16]
        _addi(2, 2, 2),             # RX enable
        _sw(2, 1, 0x10),            # UART.CTRL, real CPU MMIO
        _addi(2, 0, 2),
        _sw(2, 1, 0x04),            # UART.INTR_ENABLE.rx_watermark
        0x40001237,                 # x4: GPIO base
        _addi(2, 0, 255),
        _sw(2, 4, 0x20),            # GPIO.DIRECT_OE
        0x000102b7, 0x10028293, 0x30529073,  # Ibex external IRQ vector=0x1012c
        0x000012b7, 0x80028293, 0x3042a073,  # mie.MEIE
        _addi(5, 0, 8), 0x3002a073,  # mstatus.MIE
        0x0000006f,
    )
    isr = (
        0x400000b7, _lw(2, 1, 0x18),  # UART.RDATA pop, true RTL value
        0x40001237, _sw(2, 4, 0x14),  # GPIO.DIRECT_OUT from CPU register
        _sw(2, 0, 0x200),             # persistent RAM snapshot
        *((0x00000013,) * 16),        # RX watermark IRQ deassert pipeline
        0x30200073,                   # mret
    )
    first_trigger = Trigger("AFTER_OUTPUT", "cpu", "data_addr", (1 << 32) - 1,
                            0x40000004)
    second_trigger = Trigger("AFTER_OUTPUT", "cpu", "data_addr", (1 << 32) - 1,
                             0x40001014)
    return ScenarioGenome(
        testcase_id="ibex-uart-rx-gpio-two-rounds", direction="IP_TO_CPU_TO_IP",
        path_id="uart-external-rx-rtl-fifo-irq-ibex-isr-gpio-out",
        schedule_order=("cpu", "uart", "gpio"), max_steps=5400,
        actions=(_frame_actions(1, 0xa5, first_trigger, 128)
                 + _frame_actions(2, 0x3c, second_trigger, 128)),
        initial_images=(
            MemoryImage("cpu.main", "cpu", 0x10080, _image(main)),
            MemoryImage("cpu.isr.vector", "cpu", 0x1012c, _image(isr)),
        ))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealUartRxGpioTests(unittest.TestCase):
    def test_two_uart_frames_reach_real_cpu_and_gpio_then_replay(self):
        from myfuzz.scenario.uart_gpio_example import make_ibex_uart_rx_gpio_runner

        genome = GenomeCodec.decode(GENOME_PATH.read_bytes())
        self.assertEqual(make_uart_rx_gpio_genome(), genome)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            trace = save_evidence_bundle(genome, make_ibex_uart_rx_gpio_runner, bundle)
            self.assertEqual("complete", trace.status)
            events = trace.events
            injections = [event for event in events
                          if event.get("kind") == "source_injection"]
            self.assertEqual(
                [f"frame-{frame}-bit-{bit}" for frame in (1, 2)
                 for bit in range(10)],
                [event["action_id"] for event in injections])
            self.assertTrue(all(event["component"] == "uart"
                                and event["port"] == "uart_rx"
                                and event["source_ref"] == "external_uart_rx"
                                for event in injections))
            config = next(event for event in events
                          if event.get("kind") == "mmio_delivery"
                          and event.get("device_id") == "uart"
                          and event.get("offset") == 0x04
                          and event.get("write"))
            self.assertLess(config["event_id"], injections[0]["event_id"])
            reads = [event for event in events
                     if event.get("kind") == "mmio_delivery"
                     and event.get("device_id") == "uart"
                     and event.get("offset") == 0x18
                     and not event.get("write")]
            writes = [event for event in events
                      if event.get("kind") == "mmio_delivery"
                      and event.get("device_id") == "gpio"
                      and event.get("offset") == 0x14
                      and event.get("write")]
            ram_writes = [event for event in events
                          if event.get("kind") == "memory_write"
                          and event.get("component") == "cpu"
                          and event.get("address") == 0x200]
            self.assertEqual([0xa5, 0x3c],
                             [event["read_value"] & 0xff for event in reads])
            self.assertEqual([0xa5, 0x3c],
                             [event["write_value"] & 0xff for event in writes])
            self.assertEqual([0xa5, 0x3c],
                             [event["value"] & 0xff for event in ram_writes])
            self.assertEqual(0, reads[0]["source_transaction"]["source_epoch"])
            self.assertEqual(0, reads[1]["source_transaction"]["source_epoch"])
            self.assertLess(writes[0]["event_id"], injections[10]["event_id"])
            for round_index, expected in enumerate((0xa5, 0x3c)):
                with self.subTest(expected=hex(expected)):
                    read, write, ram = (reads[round_index],
                                        writes[round_index],
                                        ram_writes[round_index])
                    frame_start = injections[round_index * 10]["event_id"]
                    frame_stop = injections[round_index * 10 + 9]["event_id"]
                    next_frame = (injections[10]["event_id"] if round_index == 0
                                  else len(events) + 1)
                    irq = next(event for event in events
                               if frame_stop < event["event_id"] < read["event_id"]
                               and event.get("kind") == "dataflow_delivery"
                               and event.get("source") == ("uart", "irq")
                               and event.get("target") == ("cpu", "irq")
                               and event.get("value") == 1)
                    self.assertTrue(any(irq["event_id"] < event["event_id"]
                                        < read["event_id"]
                                        and event.get("component") == "cpu"
                                        and event.get("outputs", {}).get("irq_taken_pre") == 1
                                        for event in events))
                    response = next(event for event in events
                                    if event["event_id"] > read["event_id"]
                                    and event.get("component") == "cpu"
                                    and event.get("outputs", {}).get("data_rsp_consumed") == 1
                                    and event["outputs"].get("data_rsp_source_sequence")
                                    == read["source_transaction"]["source_sequence"]
                                    and event["outputs"].get("data_rsp_source_epoch")
                                    == read["source_transaction"]["source_epoch"])
                    self.assertEqual(read["read_value"],
                                     response["outputs"]["data_rsp_rdata"])
                    self.assertLess(frame_start, frame_stop)
                    self.assertLess(frame_stop, irq["event_id"])
                    self.assertLess(read["event_id"], response["event_id"])
                    self.assertLess(response["event_id"], write["event_id"])
                    self.assertLess(write["event_id"], ram["event_id"])
                    self.assertLess(ram["event_id"], next_frame)
                    self.assertTrue(any(write["event_id"] < event["event_id"]
                                        < next_frame
                                        and event.get("component") == "gpio"
                                        and event.get("outputs", {}).get("gpio_out") == expected
                                        for event in events))
            self.assertFalse(any(event.get("kind") == "reset_barrier" for event in events))
            final = json.loads((bundle / "final_state.json").read_text())
            self.assertTrue(all(value == 0 for value in final["pending_responses"].values()))
            replay = replay_evidence_bundle(bundle, make_ibex_uart_rx_gpio_runner)
            self.assertTrue(replay.matches, replay)
            self.assertEqual("full", replay.verification_scope)


if __name__ == "__main__":
    unittest.main()
