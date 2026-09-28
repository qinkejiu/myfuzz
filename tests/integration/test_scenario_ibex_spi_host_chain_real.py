"""Two SPI peer responses traverse real Host RTL, Ibex IRQ, and RAM."""

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
GENOME_PATH = ROOT / "configs/scenario/ibex_spi_host_two_rounds.json"


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


def make_spi_host_genome() -> ScenarioGenome:
    main = (
        _lui(1, 0x40000),             # SPI Host MMIO base
        _lui(2, 0xa0000), _addi(2, 2, 1),
        _sw(2, 1, 0x10),              # CONTROL enable, output enable
        _addi(2, 0, 8), _sw(2, 1, 0x18),  # CONFIGOPTS
        _addi(2, 0, 4), _sw(2, 1, 0x34),  # EVENT_ENABLE.rx_full
        _addi(2, 0, 2), _sw(2, 1, 0x04),  # INTR_ENABLE.spi_event
        _addi(5, 0, 0x200),          # persistent RAM destination
        _addi(6, 0, 0),              # completed round count
        _lui(7, 0x10), _addi(7, 7, 0x12c), _csrrs(0x305, 7),
        _lui(7, 1), _addi(7, 7, -2048), _csrrs(0x304, 7),
        _addi(7, 0, 8), _csrrs(0x300, 7),
        _addi(2, 0, 0x68), _sw(2, 1, 0x20),  # first four-byte RX command
        0x0000006f,
    )
    isr = (
        _lw(3, 1, 0x24),           # real RXDATA pop
        _sw(3, 5, 0),              # persistent RAM records received word
        _addi(5, 5, 4), _addi(6, 6, 1),
        _addi(4, 0, 1),
        _bne(6, 4, 8),             # launch second command once
        _sw(2, 1, 0x20),
        *((0x00000013,) * 16),
        0x30200073,
    )
    return ScenarioGenome(
        testcase_id="ibex-spi-host-two-rounds",
        direction="IP_TO_CPU",
        path_id="spi-peer-real-host-irq-ibex-rxdata-ram",
        schedule_order=("cpu", "spi"), max_steps=5000,
        actions=(
            Action("peer-first", "spi", "peer_payload_1", 0x78563412,
                   "IP_TO_CPU", Trigger("START")),
            Action("peer-second", "spi", "peer_payload_2", 0xf00f5aa5,
                   "IP_TO_CPU", Trigger("AFTER_OUTPUT", "cpu", "data_addr",
                                        0xffffffff, 0x200)),
        ),
        initial_images=(
            MemoryImage("cpu.main", "cpu", 0x10080, _image(main)),
            MemoryImage("cpu.isr.vector", "cpu", 0x1012c, _image(isr)),
        ))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealIbexSpiHostChainTests(unittest.TestCase):
    def test_rfuzz_record_mutates_peer_source_through_real_rtl(self):
        from myfuzz.scenario.opentitan_mutation import make_opentitan_mutation_bundle

        factory, decoder, targets, seed = make_opentitan_mutation_bundle("spi")
        path = decoder.graph.paths_to(targets[0].target_id,
                                      direction=seed.direction)[0]
        selected_source = path.source_ids.index("spi.peer_payload_1")
        mutated = decoder.decode((bytes((0, 0, selected_source, 0, 0, 1, 0, 0)),))
        self.assertEqual(seed.actions[0].value ^ 1, mutated.actions[0].value)
        trace = record_scenario(mutated, factory)
        self.assertEqual("complete", trace.status)
        reads = [event["read_value"] for event in trace.events
                 if event.get("kind") == "mmio_delivery"
                 and event.get("device_id") == "spi"
                 and event.get("offset") == 0x24
                 and not event.get("write")]
        ram = [event["value"] for event in trace.events
               if event.get("kind") == "memory_write"
               and event.get("address") in (0x200, 0x204)]
        self.assertEqual([0x78563413, 0xf00f5aa5], reads)
        self.assertEqual(reads, ram)

    def test_cut_host_irq_prevents_cpu_receipt(self):
        from myfuzz.scenario.ibex_spi_host_example import make_ibex_spi_host_runner

        def cut_factory():
            connected = make_ibex_spi_host_runner()
            return ScenarioRunner(sessions=connected.sessions,
                                  ownership=connected.ownership, bindings=())

        trace = record_scenario(make_spi_host_genome(), cut_factory)
        self.assertEqual("path_incomplete", trace.status)
        self.assertFalse(any(event.get("kind") == "memory_write"
                             and event.get("address") in (0x200, 0x204)
                             for event in trace.events))

    def test_two_peer_words_reach_ibex_through_host_irq_and_rxdata(self):
        from myfuzz.scenario.ibex_spi_host_example import make_ibex_spi_host_runner

        genome = GenomeCodec.decode(GENOME_PATH.read_bytes())
        self.assertEqual(make_spi_host_genome(), genome)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            runners = []

            def factory():
                runner = make_ibex_spi_host_runner()
                runners.append(runner)
                return runner

            trace = save_evidence_bundle(genome, factory, bundle)
            self.assertEqual("complete", trace.status)
            events = trace.events
            injections = [event for event in events
                          if event.get("kind") == "source_injection"]
            self.assertEqual(["peer-first", "peer-second"],
                             [event["action_id"] for event in injections])
            self.assertTrue(all(event["component"] == "spi"
                                and event["port"] in ("peer_payload_1", "peer_payload_2")
                                and event["source_ref"] == "external_spi_peer"
                                for event in injections))
            host_writes = [event for event in events
                           if event.get("kind") == "mmio_delivery"
                           and event.get("device_id") == "spi"
                           and event.get("write")]
            commands = [event for event in host_writes if event["offset"] == 0x20]
            self.assertEqual([0x68, 0x68],
                             [event["write_value"] for event in commands])
            self.assertEqual({0x04, 0x10, 0x18, 0x34},
                             {event["offset"] for event in host_writes}
                             - {0x20})
            self.assertLess(injections[0]["event_id"], commands[0]["event_id"])
            self.assertLess(injections[1]["event_id"], commands[1]["event_id"])
            reads = [event for event in events
                     if event.get("kind") == "mmio_delivery"
                     and event.get("device_id") == "spi"
                     and event.get("offset") == 0x24
                     and not event.get("write")]
            self.assertEqual([0x78563412, 0xf00f5aa5],
                             [event["read_value"] for event in reads])
            ram = [event for event in events
                   if event.get("kind") == "memory_write"
                   and event.get("component") == "cpu"
                   and event.get("address") in (0x200, 0x204)]
            self.assertEqual([(0x200, 0x78563412), (0x204, 0xf00f5aa5)],
                             [(event["address"], event["value"]) for event in ram])
            self.assertLess(ram[0]["event_id"], injections[1]["event_id"])
            for command, read, write in zip(commands, reads, ram):
                irq = next(event for event in events
                           if event.get("kind") == "dataflow_delivery"
                           and event.get("source") == ("spi", "irq_event")
                           and event.get("target") == ("cpu", "irq")
                           and event.get("value") == 1
                           and command["event_id"] < event["event_id"]
                           < read["event_id"])
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
                                == read["source_transaction"]["source_sequence"])
                self.assertEqual(read["read_value"],
                                 response["outputs"]["data_rsp_rdata"])
                self.assertLess(response["event_id"], write["event_id"])
            peer = runners[0].sessions["spi"].peer
            self.assertEqual(2, len(peer.completed_frames))
            self.assertEqual([4, 4], [len(frame) for frame in peer.completed_frames])
            self.assertEqual(64, peer.sample_count)
            self.assertEqual(8, peer.payload_index)
            self.assertFalse(any(event.get("kind") == "reset_barrier"
                                 for event in events))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay)


if __name__ == "__main__":
    unittest.main()
