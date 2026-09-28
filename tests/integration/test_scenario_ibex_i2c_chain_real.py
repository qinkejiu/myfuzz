"""Two I2C peer bytes traverse real Controller RTL, Ibex IRQ, and RAM."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, GenomeCodec, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.replay import record_scenario
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
GENOME_PATH = ROOT / "configs/scenario/ibex_i2c_two_rounds.json"


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15
            | 2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _bne(rs1: int, rs2: int, offset: int) -> int:
    immediate = offset & 0x1fff
    return ((immediate >> 12) << 31 | ((immediate >> 5) & 0x3f) << 25
            | rs2 << 20 | rs1 << 15 | 1 << 12
            | ((immediate >> 1) & 15) << 8 | ((immediate >> 11) & 1) << 7
            | 0x63)


def _csrrs(csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | 2 << 12 | 0x73


def _image(words: tuple[int, ...]) -> str:
    return b"".join(word.to_bytes(4, "little") for word in words).hex()


def make_i2c_genome() -> ScenarioGenome:
    main = (
        _lui(1, 0x40000),             # I2C Controller MMIO base
        _lui(2, 0x100), _addi(2, 2, 0x10), _sw(2, 1, 0x3c),
        _lui(2, 0x20), _addi(2, 2, 2), _sw(2, 1, 0x40),
        _lui(2, 0x80), _addi(2, 2, 8), _sw(2, 1, 0x44),
        _lui(2, 0x40), _addi(2, 2, 4), _sw(2, 1, 0x48),
        _lui(2, 0x80), _addi(2, 2, 8), _sw(2, 1, 0x4c),
        _addi(2, 0, 0x202), _sw(2, 1, 0x04),
        _addi(2, 0, 1), _sw(2, 1, 0x10),
        _addi(5, 0, 0x200),          # persistent RAM destination
        _addi(6, 0, 0),              # completed round count
        _addi(8, 0, 0x200),          # W1C cmd_complete
        _addi(9, 0, 0x1a1), _addi(10, 0, 0x601),
        _lui(7, 0x10), _addi(7, 7, 0x12c), _csrrs(0x305, 7),
        _lui(7, 1), _addi(7, 7, -2048), _csrrs(0x304, 7),
        _addi(7, 0, 8), _csrrs(0x300, 7),
        _sw(9, 1, 0x1c), _sw(10, 1, 0x1c),
        0x0000006f,
    )
    isr = (
        _lw(3, 1, 0x18),           # real RDATA pop
        _sw(3, 5, 0),              # persistent RAM records received byte
        _sw(8, 1, 0x00),           # real W1C cmd_complete
        _addi(5, 5, 4), _addi(6, 6, 1),
        _addi(4, 0, 1),
        _bne(6, 4, 12),            # launch next transfer once
        _sw(9, 1, 0x1c), _sw(10, 1, 0x1c),
        *((0x00000013,) * 16),
        0x30200073,
    )
    return ScenarioGenome(
        testcase_id="ibex-i2c-two-rounds", direction="IP_TO_CPU",
        path_id="i2c-peer-real-controller-irq-ibex-rdata-ram",
        schedule_order=("cpu", "i2c"), max_steps=7000,
        actions=(
            Action("peer-first", "i2c", "peer_payload_1", 0x5a,
                   "IP_TO_CPU", Trigger("START")),
            Action("peer-second", "i2c", "peer_payload_2", 0xa6,
                   "IP_TO_CPU", Trigger("AFTER_OUTPUT", "cpu", "data_addr",
                                        0xffffffff, 0x200)),
        ),
        initial_images=(
            MemoryImage("cpu.main", "cpu", 0x10080, _image(main)),
            MemoryImage("cpu.isr.vector", "cpu", 0x1012c, _image(isr)),
        ))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealIbexI2cChainTests(unittest.TestCase):
    def test_two_peer_bytes_reach_ibex_through_controller_irq_and_rdata(self):
        from myfuzz.scenario.ibex_i2c_example import make_ibex_i2c_runner

        genome = GenomeCodec.decode(GENOME_PATH.read_bytes())
        self.assertEqual(make_i2c_genome(), genome)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            runners = []

            def factory():
                runner = make_ibex_i2c_runner()
                runners.append(runner)
                return runner

            trace = save_evidence_bundle(genome, factory, bundle)
            self.assertEqual("complete", trace.status)
            self.assertEqual(9, runners[0].bindings[0].source_bit_offset)
            events = trace.events
            injections = [e for e in events if e.get("kind") == "source_injection"]
            self.assertEqual(["peer-first", "peer-second"],
                             [e["action_id"] for e in injections])
            self.assertTrue(all(e["component"] == "i2c"
                                and e["source_ref"] == "external_i2c_peer"
                                for e in injections))
            writes = [e for e in events if e.get("kind") == "mmio_delivery"
                      and e.get("device_id") == "i2c" and e.get("write")]
            self.assertEqual([0x1a1, 0x601, 0x1a1, 0x601],
                             [e["write_value"] for e in writes
                              if e["offset"] == 0x1c])
            self.assertEqual({0x3c: 0x00100010, 0x40: 0x00020002,
                              0x44: 0x00080008, 0x48: 0x00040004,
                              0x4c: 0x00080008, 0x04: 0x202, 0x10: 1},
                             {e["offset"]: e["write_value"] for e in writes
                              if e["offset"] not in (0x1c, 0x00)})
            self.assertEqual([0x200, 0x200],
                             [e["write_value"] for e in writes
                              if e["offset"] == 0x00])
            reads = [e for e in events if e.get("kind") == "mmio_delivery"
                     and e.get("device_id") == "i2c" and e.get("offset") == 0x18
                     and not e.get("write")]
            self.assertEqual([0x5a, 0xa6], [e["read_value"] & 0xff for e in reads])
            ram = [e for e in events if e.get("kind") == "memory_write"
                   and e.get("component") == "cpu"
                   and e.get("address") in (0x200, 0x204)]
            self.assertEqual([(0x200, 0x5a), (0x204, 0xa6)],
                             [(e["address"], e["value"]) for e in ram])
            self.assertLess(ram[0]["event_id"], injections[1]["event_id"])
            commands = [e for e in writes if e["offset"] == 0x1c
                        and e["write_value"] == 0x601]
            for command, read, write in zip(commands, reads, ram):
                irq = next(e for e in events
                           if e.get("kind") == "dataflow_delivery"
                           and e.get("source") == ("i2c", "irq")
                           and e.get("target") == ("cpu", "irq")
                           and e.get("value") == 1
                           and command["event_id"] < e["event_id"] < read["event_id"])
                self.assertTrue(events[irq["producer_event_id"] - 1]
                                ["outputs"]["irq"] & 0x200)
                self.assertTrue(any(irq["event_id"] < e["event_id"] < read["event_id"]
                                    and e.get("component") == "cpu"
                                    and e.get("outputs", {}).get("irq_taken_pre") == 1
                                    for e in events))
                response = next(e for e in events
                                if e["event_id"] > read["event_id"]
                                and e.get("component") == "cpu"
                                and e.get("outputs", {}).get("data_rsp_consumed") == 1
                                and e["outputs"].get("data_rsp_source_sequence")
                                == read["source_transaction"]["source_sequence"])
                self.assertEqual(read["read_value"], response["outputs"]["data_rsp_rdata"])
                self.assertLess(response["event_id"], write["event_id"])
            peer = runners[0].sessions["i2c"].peer
            self.assertEqual((2, 2, 2, 2), (peer.start_count, peer.stop_count,
                                           peer.ack_count, peer.payload_index))
            self.assertFalse(any(e.get("kind") == "reset_barrier" for e in events))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay)

    def test_cut_controller_irq_prevents_cpu_receipt(self):
        def cut_factory():
            from myfuzz.scenario.ibex_i2c_example import make_ibex_i2c_runner

            connected = make_ibex_i2c_runner()
            return ScenarioRunner(sessions=connected.sessions,
                                  ownership=connected.ownership, bindings=())

        trace = record_scenario(make_i2c_genome(), cut_factory)
        self.assertEqual("path_incomplete", trace.status)
        self.assertFalse(any(e.get("kind") == "memory_write"
                             and e.get("address") in (0x200, 0x204)
                             for e in trace.events))


if __name__ == "__main__":
    unittest.main()
