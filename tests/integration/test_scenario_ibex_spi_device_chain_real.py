"""External SPI frames propagate through real Device RTL into Ibex."""

from __future__ import annotations

import os
import unittest

from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.replay import record_scenario
from myfuzz.scenario.runner import ScenarioRunner


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15
            | 2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _csrrs(csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | 2 << 12 | 0x73


def _image(words: tuple[int, ...]) -> str:
    return b"".join(word.to_bytes(4, "little") for word in words).hex()


def make_spi_device_genome() -> ScenarioGenome:
    main = (
        _lui(1, 0x40000),
        _lui(2, 0x81010), _addi(2, 2, 0x202),
        _sw(2, 1, 0xa8),  # real CPU write configures upload opcode 0x02
        _addi(2, 0, 1), _sw(2, 1, 0x04),  # enable real upload IRQ
        _addi(5, 0, 0x200),
        _lui(9, 0x40002), _addi(9, 9, -512),  # ingress SRAM 0x40001e00
        _lui(7, 0x10), _addi(7, 7, 0x12c), _csrrs(0x305, 7),
        _lui(7, 1), _addi(7, 7, -2048), _csrrs(0x304, 7),
        _addi(7, 0, 8), _csrrs(0x300, 7),
        0x0000006f,
    )
    isr = (
        _lw(3, 1, 0x44),  # pop real command FIFO
        _sw(3, 5, 0),
        _lw(4, 1, 0x48),  # pop real address FIFO
        _sw(4, 5, 4),
        _lw(8, 9, 0),  # real uploaded payload buffer
        _sw(8, 5, 8),
        _addi(5, 5, 12),
        _addi(7, 0, 1), _sw(7, 1, 0x00),
        0x30200073,
    )
    return ScenarioGenome(
        testcase_id="ibex-spi-device-two-uploads",
        direction="IP_TO_CPU_TO_IP",
        path_id="external-spi-device-upload-irq-ibex-fifo-ram",
        schedule_order=("cpu", "spi_device"), max_steps=1600,
        actions=(
            Action("external-first", "spi_device", "frame_1", 0x0012345a,
                   "IP_TO_CPU_TO_IP",
                   Trigger("AFTER_OUTPUT", "cpu", "data_addr", 0xffffffff,
                           0x40000004), delay_component="cpu", delay_ticks=30),
            Action("external-second", "spi_device", "frame_2", 0x005678a6,
                   "IP_TO_CPU_TO_IP",
                   Trigger("AFTER_OUTPUT", "cpu", "data_addr", 0xffffffff,
                           0x40000000), delay_component="cpu", delay_ticks=30),
        ),
        initial_images=(
            MemoryImage("cpu.main", "cpu", 0x10080, _image(main)),
            MemoryImage("cpu.isr", "cpu", 0x1012c, _image(isr)),
        ))


def make_spi_device_jedec_genome() -> ScenarioGenome:
    main = (
        _lui(1, 0x40000),
        _addi(2, 0, 0x10), _sw(2, 1, 0x10),
        _lui(2, 0x0a11), _addi(2, 2, 0x234), _sw(2, 1, 0x30),
        _lui(2, 0x80120), _addi(2, 2, 0x09f), _sw(2, 1, 0x88),
        0x0000006f,
    )
    return ScenarioGenome(
        testcase_id="ibex-spi-device-jedec-read",
        direction="CPU_TO_IP",
        path_id="ibex-csr-real-spi-device-jedec-external-read",
        schedule_order=("cpu", "spi_device"), max_steps=800,
        actions=(Action("external-jedec-read", "spi_device", "read_jedec", 1,
                        "CPU_TO_IP", Trigger("AFTER_OUTPUT", "cpu", "data_addr",
                                             0xffffffff, 0x40000088),
                        delay_component="cpu", delay_ticks=30),),
        initial_images=(MemoryImage("cpu.main", "cpu", 0x10080, _image(main)),))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealIbexSpiDeviceChainTests(unittest.TestCase):
    def test_cut_device_irq_prevents_cpu_fifo_receipt(self):
        from myfuzz.scenario.ibex_spi_device_example import make_ibex_spi_device_runner

        def cut_factory() -> ScenarioRunner:
            connected = make_ibex_spi_device_runner()
            return ScenarioRunner(sessions=connected.sessions,
                                  ownership=connected.ownership, bindings=())

        trace = record_scenario(make_spi_device_genome(), cut_factory)
        self.assertEqual("path_incomplete", trace.status)
        self.assertTrue(any(event.get("kind") == "source_injection"
                            and event.get("action_id") == "external-first"
                            for event in trace.events))
        self.assertFalse(any(event.get("kind") == "memory_write"
                             and event.get("address") in (0x200, 0x204, 0x208)
                             for event in trace.events))

    def test_cpu_configuration_changes_real_external_jedec_read(self):
        from myfuzz.scenario.ibex_spi_device_example import make_ibex_spi_device_runner

        trace = record_scenario(make_spi_device_jedec_genome(),
                                make_ibex_spi_device_runner)
        self.assertEqual("complete", trace.status)
        writes = [(event["offset"], event["write_value"])
                  for event in trace.events
                  if event.get("kind") == "mmio_delivery"
                  and event.get("device_id") == "spi_device"
                  and event.get("write")]
        self.assertEqual([(0x10, 0x10), (0x30, 0x00a11234),
                          (0x88, 0x8012009f)], writes)
        observed = [event for event in trace.events
                    if event.get("outputs", {}).get("jedec_read") == 0xa13412]
        self.assertTrue(observed)
        self.assertLess(next(event["event_id"] for event in trace.events
                             if event.get("kind") == "mmio_delivery"
                             and event.get("offset") == 0x88),
                        observed[0]["event_id"])

    def test_rfuzz_mutates_external_address_through_real_fifo(self):
        from myfuzz.scenario.opentitan_mutation import make_opentitan_mutation_bundle

        factory, decoder, targets, seed = make_opentitan_mutation_bundle("spi_device")
        path = decoder.graph.paths_to(targets[0].target_id,
                                      direction=seed.direction)[0]
        source = path.source_ids.index("spi_device.frame_1")
        changed = decoder.decode((bytes((0, 0, source, 8, 0, 1, 0, 0)),))
        self.assertEqual(seed.actions[0].value ^ (1 << 8),
                         changed.actions[0].value)
        trace = record_scenario(changed, factory)
        self.assertEqual("complete", trace.status)
        addresses = [event["read_value"] & 0xffffff for event in trace.events
                     if event.get("kind") == "mmio_delivery"
                     and event.get("device_id") == "spi_device"
                     and event.get("offset") == 0x48
                     and not event.get("write")]
        self.assertEqual([0x001235, 0x005678], addresses)

    def test_rfuzz_cpu_config_mutation_changes_real_device_irq(self):
        from myfuzz.scenario.opentitan_mutation import make_opentitan_mutation_bundle

        factory, decoder, targets, seed = make_opentitan_mutation_bundle("spi_device")
        path = decoder.graph.paths_to(targets[0].target_id,
                                      direction=seed.direction)[0]
        source = path.source_ids.index("cpu.program.immediate")
        changed = decoder.decode((bytes((0, 0, source, 0, 0, 1, 0, 0)),))
        trace = record_scenario(changed, factory)
        config_writes = [event["write_value"] for event in trace.events
                         if event.get("kind") == "mmio_delivery"
                         and event.get("device_id") == "spi_device"
                         and event.get("offset") == 0xa8
                         and event.get("write")]
        self.assertEqual([0x81010203], config_writes)
        self.assertFalse(any(event.get("kind") == "dataflow_delivery"
                             and event.get("source") == ("spi_device", "irq")
                             and event.get("value") == 1
                             for event in trace.events))

    def test_two_uploads_reach_cpu_from_real_fifo_without_reset(self):
        from myfuzz.scenario.ibex_spi_device_example import make_ibex_spi_device_runner

        trace = record_scenario(make_spi_device_genome(),
                                make_ibex_spi_device_runner)
        self.assertEqual("complete", trace.status)
        injections = [event for event in trace.events
                      if event.get("kind") == "source_injection"]
        self.assertEqual(["external-first", "external-second"],
                         [event["action_id"] for event in injections])
        command_reads = [event["read_value"] for event in trace.events
                         if event.get("kind") == "mmio_delivery"
                         and event.get("device_id") == "spi_device"
                         and event.get("offset") == 0x44
                         and not event.get("write")]
        address_reads = [event["read_value"] for event in trace.events
                         if event.get("kind") == "mmio_delivery"
                         and event.get("device_id") == "spi_device"
                         and event.get("offset") == 0x48
                         and not event.get("write")]
        self.assertEqual([0x02, 0x02], [value & 0xff for value in command_reads])
        self.assertEqual([0x001234, 0x005678],
                         [value & 0xffffff for value in address_reads])
        stores = [event for event in trace.events
                  if event.get("kind") == "memory_write"
                  and event.get("address") in (0x200, 0x204, 0x208,
                                                0x20c, 0x210, 0x214)]
        self.assertEqual([0x200, 0x204, 0x208, 0x20c, 0x210, 0x214],
                         [event["address"] for event in stores])
        self.assertEqual(0x5a, stores[2]["value"] & 0xff)
        self.assertEqual(0xa6, stores[5]["value"] & 0xff)
        self.assertFalse(any(event.get("kind") == "reset_barrier"
                             for event in trace.events))


if __name__ == "__main__":
    unittest.main()
