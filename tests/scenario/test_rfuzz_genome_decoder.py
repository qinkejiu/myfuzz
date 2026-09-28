"""RFuzz fixed records encode source decisions for one complete testcase."""

import unittest

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder


class GenomeRecordDecoderTests(unittest.TestCase):
    def setUp(self):
        self.graph = DependencyGraph(
            sources=(FuzzableSource("cpu.program", "cpu", "cpu.main", 0, 32,
                                    ("CPU_TO_IP",), kind="memory_image"),
                     FuzzableSource("gpio.pin9", "gpio", "pin", 9, 1,
                                    ("IP_TO_CPU",))),
            rules=(DependencyRule("ip.config", ("cpu.program",),
                                  "PERSISTENT_STATE_RULE"),
                   DependencyRule("cpu.irq", ("gpio.pin9",),
                                  "DATA_BINDING")))
        self.ownership = compile_ownership(
            (InputField("gpio", "pin", 16), InputField("cpu", "irq", 1)),
            (InputOwner("gpio", "pin", 0, 16, "source", "external"),
             InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq")))
        cpu = ScenarioGenome(
            testcase_id="cpu-seed", direction="CPU_TO_IP", path_id="cpu-ip",
            schedule_order=("cpu", "gpio"), max_steps=50, actions=(),
            initial_images=(MemoryImage("cpu.main", "cpu", 0x10080,
                                        "13011000"),))
        gpio = ScenarioGenome(
            testcase_id="gpio-seed", direction="IP_TO_CPU", path_id="gpio-cpu",
            schedule_order=("cpu", "gpio"), max_steps=50,
            actions=(Action("edge", "gpio", "pin", 0x100, "IP_TO_CPU",
                            Trigger("START"), width=10),))
        self.decoder = GenomeRecordDecoder(
            graph=self.graph, ownership=self.ownership,
            templates=(DecoderTemplate("ip.config", cpu),
                       DecoderTemplate("cpu.irq", gpio)))

    def test_template_selector_changes_direction_and_upstream_source(self):
        no_op = bytes(8)
        cpu_record = bytes((0, 0, 0, 20, 0, 1, 0, 0))
        gpio_record = bytes((1, 0, 0, 0, 0, 1, 0, 0))
        cpu = self.decoder.decode((cpu_record,))
        gpio = self.decoder.decode((gpio_record,))
        self.assertEqual("CPU_TO_IP", cpu.direction)
        self.assertEqual("13010000", cpu.initial_images[0].data_hex)
        self.assertEqual("IP_TO_CPU", gpio.direction)
        self.assertEqual(0x300, gpio.actions[0].value)
        self.assertEqual("13011000", self.decoder.decode((no_op,)).initial_images[0].data_hex)
        self.assertNotEqual(cpu.testcase_id, gpio.testcase_id)

    def test_multiple_records_are_one_testcase_and_delay_is_local(self):
        select_gpio = bytes((1, 0, 0, 0, 0, 0, 0, 0))
        change_delay = bytes((99, 0, 0, 0, 0, 2, 7, 0))
        genome = self.decoder.decode((select_gpio, change_delay))
        self.assertEqual(50, genome.max_steps)
        self.assertEqual(7, genome.actions[0].delay_ticks)
        self.assertEqual(0x100, genome.actions[0].value)
        self.assertEqual(1, len(genome.actions))

    def test_wrong_record_size_is_rejected_before_rtl_start(self):
        with self.assertRaisesRegex(ValueError, "eight bytes"):
            self.decoder.decode((b"\x00",))

    def test_same_raw_records_decode_identically_after_other_candidates(self):
        record = bytes((1, 0, 0, 0, 0, 1, 0, 0))
        first = self.decoder.decode((record,))
        self.decoder.decode((bytes((0, 0, 0, 20, 0, 1, 0, 0)),))
        self.assertEqual(first, self.decoder.decode((record,)))

    def test_decoder_manifest_carries_templates_graph_and_input_ownership(self):
        document = self.decoder.document()
        self.assertEqual("scenario_rfuzz_decoder.v1", document["schema_version"])
        self.assertEqual(2, len(document["templates"]))
        self.assertTrue(any(item["kind"] == "memory_image"
                            for item in document["sources"]))
        self.assertTrue(any(item["kind"] == "bound"
                            for item in document["ownership"]["owners"]))
        recovered = GenomeRecordDecoder.from_document(document)
        raw = (bytes((1, 0, 0, 0, 0, 1, 0, 0)),)
        self.assertEqual(self.decoder.decode(raw), recovered.decode(raw))


if __name__ == "__main__":
    unittest.main()
