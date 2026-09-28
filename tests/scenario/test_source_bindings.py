"""A campaign profile, rather than a decoder document, authorizes graph sources."""

import unittest

from myfuzz.scenario.dependency import (DependencyGraph, DependencyRule,
                                        FuzzableSource, SourceBinding,
                                        SourceBindings)
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.feedback import CoverageTarget


class SourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.ownership = compile_ownership(
            (InputField("gpio", "pin", 2),),
            (InputOwner("gpio", "pin", 0, 2, "source", "external_b"),))
        self.genome = ScenarioGenome(
            "seed", "IP_TO_CPU", "target", ("gpio",), 2,
            (Action("pin", "gpio", "pin", 0, "IP_TO_CPU", Trigger("START"),
                    width=2),))

    def decoder(self, sources, bindings, *, ownership=None, genome=None):
        graph = DependencyGraph(
            sources=tuple(sources),
            rules=(DependencyRule("target", (sources[0].source_id,),
                                  "DATA_BINDING"),))
        return GenomeRecordDecoder(
            graph=graph, ownership=ownership or self.ownership,
            templates=(DecoderTemplate("target", genome or self.genome),),
            source_bindings=SourceBindings(tuple(bindings)))

    def test_legal_subrange_alias_passes_and_forged_single_source_fails(self):
        source = FuzzableSource("b.pin1", "gpio", "pin", 1, 1,
                                ("IP_TO_CPU",))
        binding = SourceBinding("b.pin1", "source", "gpio", "pin", 1, 1,
                                "external_b")
        decoder = self.decoder((source,), (binding,))
        ScenarioRfuzzExecutor(
            run_id="trusted-search", decoder=decoder, factory=lambda: None,
            targets=(CoverageTarget("target", "gpio", "out", 1, 1),))
        changed = decoder.decode((bytes((0, 0, 0, 0, 0, 1, 0, 0)),))
        self.assertEqual(2, changed.actions[0].value)
        forged = FuzzableSource("forged", "gpio", "pin", 1, 1,
                                 ("IP_TO_CPU",))
        with self.assertRaisesRegex(ValueError, "binding|source"):
            self.decoder((forged,), (binding,))

    def test_double_alias_wrong_owner_and_range_fail_before_decode(self):
        source = FuzzableSource("b.pin1", "gpio", "pin", 1, 1,
                                ("IP_TO_CPU",))
        alias = FuzzableSource("alias", "gpio", "pin", 1, 1,
                               ("IP_TO_CPU",))
        binding = SourceBinding("b.pin1", "source", "gpio", "pin", 1, 1,
                                "external_b")
        for sources, bindings in (
                ((source, alias), (binding, SourceBinding(
                    "alias", "source", "gpio", "pin", 1, 1, "external_b"))),
                ((source,), (SourceBinding(
                    "b.pin1", "source", "gpio", "pin", 1, 1, "forged"),)),
                ((source,), (SourceBinding(
                    "b.pin1", "source", "gpio", "pin", 0, 1, "external_b"),))):
            with self.subTest(sources=sources, bindings=bindings):
                with self.assertRaises(ValueError):
                    self.decoder(sources, bindings)

    def test_memory_image_binding_must_name_initial_image(self):
        source = FuzzableSource("program", "cpu", "boot", 0, 8,
                                ("CPU_TO_IP",), kind="memory_image")
        genome = ScenarioGenome(
            "seed", "CPU_TO_IP", "target", ("cpu",), 2, (),
            initial_images=(MemoryImage("boot", "cpu", 0x1000, "11"),))
        for owner_ref in ("initial_image:cpu:boot", "committed_ram"):
            binding = SourceBinding("program", "memory_image", "cpu", "boot",
                                    0, 8, owner_ref, 0x1000)
            if owner_ref.startswith("initial_image:"):
                self.decoder((source,), (binding,), genome=genome)
            else:
                with self.assertRaisesRegex(ValueError, "image|owner"):
                    self.decoder((source,), (binding,), genome=genome)
        wrong_address = SourceBinding(
            "program", "memory_image", "cpu", "boot", 0, 8,
            "initial_image:cpu:boot", 0x2000)
        with self.assertRaisesRegex(ValueError, "image|address"):
            self.decoder((source,), (wrong_address,), genome=genome)

    def test_document_cannot_self_authorize_modified_graph(self):
        source = FuzzableSource("b.pin1", "gpio", "pin", 1, 1,
                                ("IP_TO_CPU",))
        binding = SourceBinding("b.pin1", "source", "gpio", "pin", 1, 1,
                                "external_b")
        document = self.decoder((source,), (binding,)).document()
        document["sources"][0]["source_id"] = "forged"
        document["source_bindings"][0]["source_id"] = "forged"
        with self.assertRaises(ValueError):
            GenomeRecordDecoder.from_document(
                document, source_bindings=SourceBindings((binding,)))

    def test_late_graph_replacement_cannot_authorize_delay_operator(self):
        source = FuzzableSource("b.pin1", "gpio", "pin", 1, 1,
                                ("IP_TO_CPU",))
        binding = SourceBinding("b.pin1", "source", "gpio", "pin", 1, 1,
                                "external_b")
        decoder = self.decoder((source,), (binding,))
        decoder.graph.sources["b.pin1"] = FuzzableSource(
            "b.pin1", "gpio", "pin", 0, 1, ("IP_TO_CPU",))
        with self.assertRaisesRegex(ValueError, "binding|source"):
            decoder.decode((bytes((0, 0, 0, 0, 0, 2, 5, 0)),))

    def test_self_reported_document_cannot_start_new_search(self):
        source = FuzzableSource("b.pin1", "gpio", "pin", 1, 1,
                                ("IP_TO_CPU",))
        binding = SourceBinding("b.pin1", "source", "gpio", "pin", 1, 1,
                                "external_b")
        document = self.decoder((source,), (binding,)).document()
        document["sources"][0]["source_id"] = "forged"
        document["source_bindings"][0]["source_id"] = "forged"
        document["rules"][0]["prerequisites"] = ["forged"]
        untrusted = GenomeRecordDecoder.from_document(document)
        with self.assertRaisesRegex(ValueError, "trusted|replay"):
            ScenarioRfuzzExecutor(
                run_id="new-search", decoder=untrusted, factory=lambda: None,
                targets=(CoverageTarget("target", "gpio", "out", 1, 1),))
        replay = ScenarioRfuzzExecutor(
            run_id="replay", decoder=untrusted, factory=lambda: None,
            targets=(CoverageTarget("target", "gpio", "out", 1, 1),),
            replay_only=True)
        self.assertIs(replay.decoder, untrusted)

    def test_direct_legacy_decoder_needs_explicit_search_compatibility(self):
        source = FuzzableSource("b.pin1", "gpio", "pin", 1, 1,
                                ("IP_TO_CPU",))
        graph = DependencyGraph(
            sources=(source,),
            rules=(DependencyRule("target", ("b.pin1",), "DATA_BINDING"),))
        legacy = GenomeRecordDecoder(
            graph=graph, ownership=self.ownership,
            templates=(DecoderTemplate("target", self.genome),))
        target = (CoverageTarget("target", "gpio", "out", 1, 1),)
        with self.assertRaisesRegex(ValueError, "trusted|legacy"):
            ScenarioRfuzzExecutor(run_id="search", decoder=legacy,
                                  factory=lambda: None, targets=target)
        ScenarioRfuzzExecutor(run_id="legacy", decoder=legacy,
                              factory=lambda: None, targets=target,
                              allow_legacy_search=True)

    def test_from_document_with_external_binding_still_cannot_search(self):
        source = FuzzableSource("b.pin1", "gpio", "pin", 1, 1,
                                ("IP_TO_CPU",))
        binding = SourceBinding("b.pin1", "source", "gpio", "pin", 1, 1,
                                "external_b")
        document = self.decoder((source,), (binding,)).document()
        recovered = GenomeRecordDecoder.from_document(
            document, source_bindings=SourceBindings((binding,)))
        target = (CoverageTarget("target", "gpio", "out", 1, 1),)
        with self.assertRaisesRegex(ValueError, "replay|trusted"):
            ScenarioRfuzzExecutor(run_id="search", decoder=recovered,
                                  factory=lambda: None, targets=target)
        with self.assertRaisesRegex(ValueError, "replay|trusted"):
            ScenarioRfuzzExecutor(run_id="search", decoder=recovered,
                                  factory=lambda: None, targets=target,
                                  allow_legacy_search=True)
        ScenarioRfuzzExecutor(run_id="replay", decoder=recovered,
                              factory=lambda: None, targets=target,
                              replay_only=True)

    def test_oversized_binding_fails_before_iterating_its_bits(self):
        source = FuzzableSource("huge", "gpio", "pin", 0, 10**12,
                                ("IP_TO_CPU",))
        graph = DependencyGraph(sources=(source,), rules=())
        bindings = SourceBindings((SourceBinding(
            "huge", "source", "gpio", "pin", 0, 10**12, "external_b"),))

        class OwnershipProbe:
            def mutation_source(self, *args, **kwargs):
                raise AssertionError("ownership lookup must not run")

        with self.assertRaisesRegex(ValueError, "width|bound"):
            bindings.validate(graph, OwnershipProbe(), ())


if __name__ == "__main__":
    unittest.main()
