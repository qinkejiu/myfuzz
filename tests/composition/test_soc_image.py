"""Step 6B: raw instruction candidates become a real, frozen boot image."""
from __future__ import annotations

import unittest

from myfuzz.composition.soc_image import (
    IMAGE_SCHEMA,
    ImagePlan,
    SocImageError,
    build_image_plan,
    combined_input_layout,
    combined_layout_hash,
    image_plan_document,
)

from .soc_generation_fixture import ROOT, example_plan


def _candidate(offer=1, address=0x10000, data=0x00000013, be=0xF) -> int:
    # The profile layout occupies the low seven bits.  The image plan appends
    # instruction fields after it rather than defining a disconnected ABI.
    base = 7
    return (offer & 1) << base | ((address & 0xFFFFFFFF) << (base + 1)) \
        | ((data & 0xFFFFFFFF) << (base + 33)) | ((be & 0xF) << (base + 65))


def _data_candidate(*, address=0x80000000, value=0x11223344, be=0xF) -> int:
    base = 7 + 69
    return (1 << base) | ((address & 0xFFFFFFFF) << (base + 1)) \
        | ((value & 0xFFFFFFFF) << (base + 33)) | ((be & 0xF) << (base + 65))


class ImagePlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()
        cls.image = build_image_plan(cls.plan)

    def test_the_instruction_segment_is_bounded_and_positioned(self) -> None:
        self.assertEqual(145, self.image.raw_width)
        names = [item.name for item in self.image.segments]
        self.assertEqual(["init_offer", "init_address", "init_data", "init_be",
                          "data_offer", "data_address", "data_value", "data_be"], names)
        self.assertEqual(7, self.image.segment("init_offer").raw_lo)
        self.assertEqual((8, 39), (self.image.segment("init_address").raw_lo,
                                   self.image.segment("init_address").raw_hi))
        self.assertEqual((72, 75), (self.image.segment("init_be").raw_lo,
                                    self.image.segment("init_be").raw_hi))
        self.assertEqual(76, self.image.segment("data_offer").raw_lo)

    def test_the_entry_address_must_be_inside_an_executable_region(self) -> None:
        self.assertEqual(0x10000, self.image.entry_address)
        self.assertEqual("rom0", self.image.region_id)
        document = image_plan_document(self.image)
        self.assertEqual(IMAGE_SCHEMA, document["schema_version"])
        self.assertEqual(32, document["isa"]["xlen"])
        self.assertEqual(["I"], list(document["isa"]["extensions"]))

    def test_the_image_plan_is_isolated_from_the_fuzz_layout(self) -> None:
        self.assertNotEqual(combined_layout_hash(self.plan, self.image), "")

    def test_a_plan_without_an_executable_region_is_refused(self) -> None:
        from dataclasses import replace

        regions = self.plan.plan["address_map"]["memory_regions"]
        stripped = replace(
            self.plan,
            plan={**self.plan.plan,
                  "address_map": {**self.plan.plan["address_map"],
                                  "memory_regions": [
                                      {**region, "permissions": {**region["permissions"],
                                                                 "execute": False}}
                                      for region in regions]}})
        with self.assertRaises(SocImageError) as error:
            build_image_plan(stripped)
        self.assertIn("no-executable-region-declared", str(error.exception))

    def test_a_misaligned_entry_address_is_refused(self) -> None:
        from dataclasses import replace

        cpu = next(item for item in self.plan.instances if item.kind == "cpu")
        broken_cpu = replace(cpu, profile=replace(
            cpu.profile, cpu=replace(cpu.profile.cpu, reset_vector=0x10002)))
        broken = replace(self.plan, instances=tuple(
            broken_cpu if item.instance_id == cpu.instance_id else item
            for item in self.plan.instances))
        with self.assertRaises(SocImageError) as error:
            build_image_plan(broken)
        self.assertIn("entry-address-misaligned", str(error.exception))


class MaterialisationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.image = build_image_plan(example_plan())

    def test_a_sample_without_a_candidate_yields_an_explicit_empty_image(self) -> None:
        result = self.image.materialize(0)
        self.assertEqual(0, result.accepted)
        self.assertEqual(b"", result.image)
        self.assertEqual("frozen_before_cpu_release", result.freeze_policy)

    def test_an_accepted_candidate_is_committed_to_the_image(self) -> None:
        result = self.image.materialize(_candidate(data=0x00000013))
        self.assertEqual(1, result.accepted)
        self.assertEqual(1, result.committed)
        self.assertEqual(b"\x13\x00\x00\x00", result.image[:4])
        self.assertEqual(1, result.counters["instruction_initializations"])

    def test_data_segment_initializes_only_a_declared_writable_region(self) -> None:
        result = self.image.materialize(_data_candidate())
        self.assertEqual(b"\x44\x33\x22\x11", result.region_images["ram0"][:4])
        self.assertEqual(1, result.counters["data_initializations"])
        self.assertEqual(0x80000000, result.data_initializations[0]["address"])

    def test_data_segment_rejects_an_address_outside_writable_memory(self) -> None:
        with self.assertRaises(SocImageError) as error:
            self.image.materialize(_data_candidate(address=0x40000000))
        self.assertIn("data-address-unmapped", str(error.exception))

    def test_code_and_data_merge_when_one_region_is_rwx(self) -> None:
        from dataclasses import replace

        plan = example_plan()
        regions = plan.plan["address_map"]["memory_regions"]
        rom = next(region for region in regions if region["region_id"] == "rom0")
        ram = next(region for region in regions if region["region_id"] == "ram0")
        unified = {
            **rom,
            "size": max(int(rom["size"]), 0x20),
            "permissions": {"read": True, "write": True, "execute": True},
        }
        single = replace(
            plan,
            plan={**plan.plan,
                  "address_map": {**plan.plan["address_map"],
                                  "memory_regions": [unified]}},
        )
        image = build_image_plan(single)
        result = image.materialize_many((
            _candidate(address=int(unified["base"]), data=0x00000013),
            _data_candidate(address=int(unified["base"]) + 4,
                            value=0x11223344),
        ))
        self.assertEqual(b"\x13\x00\x00\x00\x44\x33\x22\x11",
                         result.region_images[str(unified["region_id"])][:8])

    def test_a_sparse_data_image_cannot_exceed_the_global_bound(self) -> None:
        from dataclasses import replace
        from myfuzz.composition.soc_image import MAX_IMAGE_BYTES

        plan = example_plan()
        regions = []
        for region in plan.plan["address_map"]["memory_regions"]:
            if region["region_id"] == "ram0":
                region = {**region, "size": MAX_IMAGE_BYTES + 0x1000}
            regions.append(region)
        enlarged = replace(
            plan,
            plan={**plan.plan,
                  "address_map": {**plan.plan["address_map"],
                                  "memory_regions": regions}},
        )
        image = build_image_plan(enlarged)
        raw = _data_candidate(address=0x80000000 + MAX_IMAGE_BYTES,
                              value=0xAA, be=1)
        with self.assertRaisesRegex(SocImageError, "data-image-exceeds-bound"):
            image.materialize(raw)

    def test_multiple_candidate_words_build_one_frozen_initial_state(self) -> None:
        result = self.image.materialize_many((
            _candidate(address=0x10000, data=0x00000013),
            _data_candidate(address=0x80000004, value=0xAABBCCDD),
        ))
        self.assertEqual(b"\x13\x00\x00\x00", result.region_images["rom0"][:4])
        self.assertEqual(b"\xdd\xcc\xbb\xaa", result.region_images["ram0"][4:8])
        self.assertEqual(2, result.accepted)

    def test_the_same_raw_sample_produces_the_same_bytes(self) -> None:
        first = self.image.materialize(_candidate(data=0x00000013))
        second = self.image.materialize(_candidate(data=0x00000013))
        self.assertEqual(first.content_hash, second.content_hash)
        self.assertEqual(first.image, second.image)

    def test_an_unmapped_candidate_address_is_rejected(self) -> None:
        with self.assertRaises(SocImageError) as error:
            self.image.materialize(_candidate(address=0x90000))
        self.assertIn("instruction-address-unmapped", str(error.exception))

    def test_a_candidate_outside_the_declared_segment_is_rejected(self) -> None:
        with self.assertRaises(SocImageError) as error:
            self.image.materialize(1 << 145)
        self.assertIn("raw-sample-exceeds-image-segment", str(error.exception))

    def test_isa_repair_is_reported_and_changes_identity(self) -> None:
        from myfuzz.composition.soc_image import image_plan_document

        repaired = build_image_plan(example_plan(), isa_repair=True)
        raw = build_image_plan(example_plan(), isa_repair=False)
        self.assertTrue(image_plan_document(repaired)["isa_repair"])
        self.assertFalse(image_plan_document(raw)["isa_repair"])
        self.assertNotEqual(repaired.image_hash, raw.image_hash)
        # A legal 32-bit encoding is untouched by the repair layer, so both
        # configurations agree on the bytes while their identity differs.
        candidate = _candidate(data=0x00000013)
        self.assertEqual(repaired.materialize(candidate).image,
                         raw.materialize(candidate).image)
        self.assertIn("isa_legal_corrections",
                      repaired.materialize(candidate).counters)

    def test_the_image_can_be_written_as_a_readmemh_file(self) -> None:
        import tempfile
        from pathlib import Path

        result = self.image.materialize(_candidate())
        with tempfile.TemporaryDirectory(prefix=".myfuzz-image-", dir=ROOT) as temporary:
            path = self.image.write_hex(result.image, Path(temporary) / "boot.hex")
            text = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(result.image), len(text))
        self.assertEqual("13", text[0])

    def test_the_lifecycle_states_which_event_restores_what(self) -> None:
        lifecycle = self.image.lifecycle
        self.assertIn("test_begin", lifecycle)
        self.assertIn("dut_reset", lifecycle)
        self.assertIn("driver_reset", lifecycle)
        self.assertIn("memory is not touched", lifecycle["driver_reset"])
        self.assertIn("does not resupply", lifecycle["dut_reset"])

    def test_the_image_plan_declares_its_diagnostics(self) -> None:
        document = image_plan_document(self.image)
        self.assertTrue(document["diagnostics"])
        self.assertTrue(any("unmapped" in item for item in document["diagnostics"]))


class LayoutBindingTests(unittest.TestCase):
    def test_the_image_segment_and_the_fuzz_layout_share_one_identity(self) -> None:
        plan = example_plan()
        image = build_image_plan(plan)
        first = combined_layout_hash(plan, image)
        second = combined_layout_hash(plan, build_image_plan(plan))
        self.assertEqual(first, second)
        other = build_image_plan(plan, isa_repair=False)
        self.assertNotEqual(first, combined_layout_hash(plan, other))

    def test_combined_layout_is_the_transport_abi_not_only_a_hash(self) -> None:
        plan = example_plan()
        image = build_image_plan(plan)
        layout = combined_input_layout(plan, image)
        self.assertEqual(image.raw_width, layout.raw_width)
        self.assertEqual(10, len(layout.fields))
        self.assertEqual("cpu0::event_i:event_i", layout.fields[0].field_id)
        self.assertEqual("soc_image:init_offer", layout.fields[2].field_id)
        self.assertEqual("soc_image:data_be", layout.fields[-1].field_id)
        self.assertEqual(image.instruction_raw_lo, layout.fields[2].raw_lo)

    def test_the_special_inputs_still_bind_to_their_own_segment(self) -> None:
        """The image segment must not overlap the fuzz segment of the layout."""
        plan = example_plan()
        image = build_image_plan(plan)
        fuzz_width = int(plan.raw_layout["raw_width"])
        self.assertEqual(7, fuzz_width)
        self.assertEqual(145, image.raw_width)
        self.assertEqual(fuzz_width, image.instruction_raw_lo)


if __name__ == "__main__":
    unittest.main()
