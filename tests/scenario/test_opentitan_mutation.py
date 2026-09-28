"""Trusted RFuzz mutation sources for real OpenTitan chains."""

import unittest

from myfuzz.scenario.opentitan_mutation import make_opentitan_mutation_bundle


class OpenTitanMutationTests(unittest.TestCase):
    CASES = {
        "spi": ("spi", 32, 84, {"peer_payload_1", "peer_payload_2"}),
        "i2c": ("i2c", 8, 84, {"peer_payload_1", "peer_payload_2"}),
        "timer": ("timer", None, 436, set()),
        "spi_device": ("spi_device", 32, 84, {"frame_1", "frame_2"}),
    }

    def test_bundle_has_trusted_sources_and_real_runner(self):
        for component_id, (device, width, cpu_bit, ports) in self.CASES.items():
            with self.subTest(component_id=component_id):
                factory, decoder, targets, seed = make_opentitan_mutation_bundle(component_id)
                runner = factory()
                self.assertTrue(decoder.trusted_for_search)
                self.assertEqual("scenario_rfuzz_decoder.v2", decoder.document()["schema_version"])
                self.assertEqual({"cpu", device}, set(runner.sessions))
                self.assertEqual(runner.ownership.document(), decoder.ownership.document())
                self.assertEqual(1, len(targets))
                self.assertEqual("cpu", targets[0].component)
                self.assertEqual("irq_taken_pre", targets[0].port)
                self.assertEqual(seed.direction, decoder.templates[0].genome.direction)
                sources = tuple(decoder.graph.sources.values())
                self.assertEqual(1 + len(ports), len(sources))
                self.assertEqual(ports, {source.port for source in sources
                                         if source.kind == "source"})
                program = next(source for source in sources if source.kind == "memory_image")
                self.assertEqual(("cpu", "cpu.main", cpu_bit, 1),
                                 (program.component, program.port,
                                  program.bit_offset, program.width))
                for source in sources:
                    self.assertEqual((seed.direction,), source.directions)
                    if source.kind == "source":
                        self.assertEqual(width, source.width)
                        self.assertEqual(device, source.component)
                paths = decoder.graph.paths_to(targets[0].target_id,
                                               direction=seed.direction)
                self.assertEqual(1, len(paths))
                self.assertEqual(set(decoder.graph.sources), set(paths[0].source_ids))
                self.assertFalse(decoder.graph.paths_to(targets[0].target_id,
                                                        direction="IP_TO_IP"))

    def test_every_declared_source_mutates_from_one_eight_byte_record(self):
        for component_id in self.CASES:
            with self.subTest(component_id=component_id):
                _, decoder, targets, seed = make_opentitan_mutation_bundle(component_id)
                path = decoder.graph.paths_to(targets[0].target_id,
                                              direction=seed.direction)[0]
                for index, source_id in enumerate(path.source_ids):
                    with self.subTest(source_id=source_id):
                        source = decoder.graph.sources[source_id]
                        record = bytes((0, 0, index, 0, 0, 1, 0, 0))
                        changed = decoder.decode((record,))
                        self.assertEqual(seed.direction, changed.direction)
                        if source.kind == "memory_image":
                            self.assertEqual(seed.actions, changed.actions)
                            before = next(item for item in seed.initial_images
                                          if item.image_id == source.port)
                            after = next(item for item in changed.initial_images
                                         if item.image_id == source.port)
                            self.assertEqual(1 << source.bit_offset,
                                             int.from_bytes(before.data, "little") ^
                                             int.from_bytes(after.data, "little"))
                            word_start = (source.bit_offset // 32) * 4
                            self.assertEqual(0x13, after.data[word_start] & 0x7f)
                        else:
                            self.assertEqual(seed.initial_images, changed.initial_images)
                            differences = [(old, new) for old, new in zip(seed.actions, changed.actions)
                                           if old != new]
                            self.assertEqual(1, len(differences))
                            old, new = differences[0]
                            self.assertEqual(source.port, new.port)
                            self.assertEqual(old.value ^ 1, new.value)

    def test_bound_irq_and_runtime_response_are_not_mutation_sources(self):
        for component_id in self.CASES:
            with self.subTest(component_id=component_id):
                _, decoder, _, seed = make_opentitan_mutation_bundle(component_id)
                self.assertFalse(any(source.port in {"irq", "rdata", "data_rdata"}
                                     for source in decoder.graph.sources.values()))
                with self.assertRaisesRegex(ValueError, "bound"):
                    decoder.ownership.mutation_source("cpu", "irq", 0, 1,
                                                      direction=seed.direction)

    def test_spi_device_path_names_persistent_configuration_and_fifo_state(self):
        _, decoder, targets, seed = make_opentitan_mutation_bundle("spi_device")
        rules = {rule.target: rule for variants in decoder.graph.rules.values()
                 for rule in variants}
        self.assertEqual("PERSISTENT_STATE_RULE",
                         rules["spi_device.config_state"].kind)
        self.assertEqual("PERSISTENT_STATE_RULE",
                         rules["spi_device.upload_fifo_state"].kind)
        paths = decoder.graph.paths_to(targets[0].target_id,
                                       direction=seed.direction)
        self.assertEqual({"cpu.program.immediate", "spi_device.frame_1",
                          "spi_device.frame_2"}, set(paths[0].source_ids))

    def test_unknown_component_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "component"):
            make_opentitan_mutation_bundle("gpio")

    def test_explicit_peripheral_names_select_the_same_seed(self):
        for alias, component_id in (("spi_host", "spi"), ("rv_timer", "timer")):
            with self.subTest(alias=alias):
                _, aliased, _, aliased_seed = make_opentitan_mutation_bundle(alias)
                _, direct, _, direct_seed = make_opentitan_mutation_bundle(component_id)
                self.assertEqual(direct_seed, aliased_seed)
                self.assertEqual(direct.document(), aliased.document())


if __name__ == "__main__":
    unittest.main()
