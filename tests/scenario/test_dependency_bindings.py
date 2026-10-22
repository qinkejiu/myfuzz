"""Trusted source bindings must cover every candidate genome exactly."""

from dataclasses import replace
import unittest

from myfuzz.scenario.dependency import (
    DependencyGraph, FuzzableSource, SourceBinding, SourceBindings,
)
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.ownership import compile_ownership


class SourceBindingsTests(unittest.TestCase):
    def setUp(self):
        self.source = FuzzableSource(
            "program", "cpu", "boot", 4, 12, ("CPU_TO_IP",),
            kind="memory_image", image_address=0x1000)
        self.binding = SourceBinding(
            "program", "memory_image", "cpu", "boot", 4, 12,
            "initial_image:cpu:boot", image_address=0x1000)
        self.image = MemoryImage("boot", "cpu", 0x1000, "0011")
        self.genome = ScenarioGenome(
            "seed", "CPU_TO_IP", "target", ("cpu", "other"), 2, (),
            initial_images=(self.image,))
        self.ownership = compile_ownership((), ())

    def validate(self, *genomes, source=None):
        graph = DependencyGraph(sources=(source or self.source,), rules=())
        SourceBindings((self.binding,)).validate(graph, self.ownership, genomes)

    def test_graph_image_address_must_equal_binding(self):
        with self.assertRaisesRegex(ValueError, "trusted binding"):
            self.validate(self.genome,
                          source=replace(self.source, image_address=0x2000))

    def test_legacy_unbound_graph_uses_trusted_profile_address(self):
        source = replace(self.source, image_address=None)
        self.validate(self.genome, source=source)
        wrong_address = replace(self.genome, initial_images=(
            replace(self.image, address=0x2000),))
        with self.assertRaisesRegex(ValueError, "address"):
            self.validate(wrong_address, source=source)

    def test_every_genome_must_contain_matching_image(self):
        for images in ((), (replace(self.image, component="other"),),
                       (replace(self.image, image_id="other"),)):
            missing = replace(self.genome, initial_images=images)
            for genomes in ((self.genome, missing), (missing, self.genome)):
                with self.subTest(images=images, genomes=genomes):
                    with self.assertRaisesRegex(ValueError, "initial image"):
                        self.validate(*genomes)

    def test_duplicate_matching_images_are_rejected(self):
        duplicate = replace(self.genome)
        # Bypass the constructor to exercise this validation boundary directly.
        object.__setattr__(duplicate, "initial_images", (self.image, self.image))
        with self.assertRaisesRegex(ValueError, "unique|multiple|duplicate"):
            self.validate(self.genome, duplicate)

    def test_every_matching_image_must_have_bound_address(self):
        wrong_address = replace(self.genome, initial_images=(
            replace(self.image, address=0x2000),))
        with self.assertRaisesRegex(ValueError, "address"):
            self.validate(self.genome, wrong_address)

    def test_every_matching_image_must_cover_entire_source_range(self):
        too_short = replace(self.genome, initial_images=(
            replace(self.image, data_hex="00"),))
        with self.assertRaisesRegex(ValueError, "exceeds initial image"):
            self.validate(self.genome, too_short)

    def test_memory_binding_requires_at_least_one_genome(self):
        with self.assertRaisesRegex(ValueError, "initial image"):
            self.validate()

    def test_all_genomes_with_one_matching_image_are_accepted(self):
        other = MemoryImage("unrelated", "other", 0x2000, "ff")
        second = replace(self.genome, testcase_id="second", initial_images=(
            other, replace(self.image, data_hex="ffff")))
        self.validate(self.genome, second)

    def test_explicit_source_genomes_select_subset_without_weakening_default(self):
        missing = replace(self.genome, initial_images=())
        graph = DependencyGraph(sources=(self.source,), rules=())
        bindings = SourceBindings((self.binding,))
        with self.assertRaises(ValueError):
            bindings.validate(graph, self.ownership, (self.genome, missing))
        bindings.validate(graph, self.ownership, (self.genome, missing),
                          image_genomes={"program": (self.genome,)})
        for relevant in ((), (missing,), (self.genome, missing)):
            with self.subTest(relevant=relevant):
                with self.assertRaises(ValueError):
                    bindings.validate(graph, self.ownership, (self.genome, missing),
                                      image_genomes={"program": relevant})


if __name__ == "__main__":
    unittest.main()
