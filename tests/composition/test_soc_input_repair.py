"""Roadmap item 3: multiple candidates, register/control-flow setup, dependency
repair, committed-input protection, bounded unknowns and a declared ISA scope.

Each test names the sub-item it proves, and every capability has a positive case
(a program that really composes and whose artifact is recorded under
``runs/soc-input-repair/<name>/``) and a negative case that asserts the exact
refusal string.  ``test_soc_input_repair_replay.py`` re-runs every recorded
artifact from its own saved inputs and compares the documents byte for byte.

Nothing here edits a component or DUT RTL or a real profile: a case changes only
the *composition plan* it composes (a declared extension set, a smaller ROM),
using ``dataclasses.replace`` on the in-memory plan.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from myfuzz.composition.soc_candidate_program import (
    BRANCH_DISPLACEMENT_BOUND,
    CandidateProgramError,
    CandidateProgramPolicy,
    DATA_BASE_REGISTER,
    MMIO_BASE_REGISTER,
    STACK_POINTER_REGISTER,
    build_candidate_program,
    decode_word,
    encode_addi,
    encode_beq,
    encode_jal,
    encode_jalr,
    encode_lui,
    encode_lw,
    encode_sw,
    project_address,
)
from myfuzz.composition.soc_image import combined_input_layout, image_plan_document

from .soc_generation_fixture import ROOT, example_plan
from .soc_input_repair_cases import (
    ARTIFACT_ROOT,
    build_request,
    program_for,
    read_case,
    record_case,
    resolve_address,
    run_case,
)


def _base_program(**overrides):
    spec = {"instruction_candidates": 1, "data_candidates": 1}
    spec.update(overrides)
    return program_for(spec), spec


def _reference_payload(slot, address, word, *, be=0xF):
    """One raw word for the legacy image segments of a slot (fuzz channel)."""
    value = 1 << slot.segment("offer").raw_lo
    value |= (address & 0xFFFFFFFF) << slot.segment("address").raw_lo
    role = "data" if slot.kind == "instruction" else "value"
    value |= (word & 0xFFFFFFFF) << slot.segment(role).raw_lo
    value |= (be & 0xF) << slot.segment("be").raw_lo
    return value


class MultipleCandidateTests(unittest.TestCase):
    """Item 1: several candidates per test, declared and fuzzable."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()

    def test_the_plan_declares_every_slot_address_and_the_selection_rule(self) -> None:
        program = build_candidate_program(
            self.plan, instruction_candidates=3, data_candidates=2)
        document = image_plan_document(program.image)
        candidates = document["candidates"]
        self.assertEqual(3, candidates["instruction_count"])
        self.assertEqual(2, candidates["data_count"])
        self.assertIn("each slot may be offered by at most one word",
                      candidates["selection"])
        instruction = [item["prefix"] for item in candidates["instruction"]]
        self.assertEqual(["init", "init1", "init2"], instruction)
        self.assertEqual(
            [program.program_base + 4 * index for index in range(3)],
            [item["declared_address"] for item in candidates["instruction"]])
        self.assertEqual(
            [program.register_bindings["data_base"]["value"] + 4 * index
             for index in range(2)],
            [item["declared_address"] for item in candidates["data"]])

    def test_the_input_layout_exposes_every_slot_field(self) -> None:
        program = build_candidate_program(
            self.plan, instruction_candidates=3, data_candidates=2)
        layout = combined_input_layout(self.plan, program.image)
        image_fields = [field for field in layout.fields
                        if field.owner == "soc_image"]
        self.assertEqual(4 * (3 + 2), len(image_fields))
        self.assertEqual(
            {"init_offer", "init_address", "init_data", "init_be",
             "init1_offer", "init1_address", "init1_data", "init1_be",
             "init2_offer", "init2_address", "init2_data", "init2_be",
             "data_offer", "data_address", "data_value", "data_be",
             "data1_offer", "data1_address", "data1_value", "data1_be"},
            {field.role for field in image_fields})
        for field in image_fields:
            self.assertTrue(any(item.startswith("soc_image.candidate_slot.")
                                for item in field.evidence), field.field_id)

    def test_several_candidates_are_placed_and_frozen_in_one_test(self) -> None:
        program = build_candidate_program(
            self.plan, instruction_candidates=3, data_candidates=2)
        slots = program.slots
        request = build_request(program, [
            # The raw address is wrong on purpose: the address policy places the
            # slot at its declared address.
            {"slot": "init", "address": 3, "word": 0x00000013},
            {"slot": "init1", "address": "@slot:init1", "word": 0x00000013},
            {"slot": "init2", "address": "@slot:init2", "word": 0x00000013},
            {"slot": "data", "address": "@slot:data", "word": 0x11223344},
            {"slot": "data1", "address": "@slot:data1", "word": 0xAABBCCDD},
        ])
        result = program.repairer().repair_test(request)
        self.assertEqual(5, result.counters["slots_placed"])
        self.assertEqual(3, result.counters["instruction_slots_placed"])
        self.assertEqual(2, result.counters["data_slots_placed"])
        self.assertEqual(1, result.counters["address_repair"])
        self.assertEqual(
            [slots.slot("init").declared_address,
             slots.slot("init1").declared_address,
             slots.slot("init2").declared_address],
            [item["declared_address"] for item in result.placements
             if item["kind"] == "instruction"])
        rom = result.image.region_images["rom0"]
        for index in range(3):
            offset = slots.slot(["init", "init1", "init2"][index]).declared_address \
                - program.image.base
            self.assertEqual(b"\x13\x00\x00\x00", rom[offset:offset + 4])
        ram = result.image.region_images["ram0"]
        self.assertEqual(b"\x44\x33\x22\x11", ram[0:4])
        self.assertEqual(b"\xdd\xcc\xbb\xaa", ram[4:8])

    def test_recording_the_case_writes_the_artifact_and_the_frozen_image(self) -> None:
        spec = _multicandidate_spec()
        directory = record_case(spec)
        self.assertTrue((directory / "case.json").is_file())
        self.assertTrue((directory / "boot.hex").is_file())
        record = read_case(spec["name"])
        self.assertNotIn("error", record)
        self.assertEqual(5, len(record["test"]["placements"]))

    def test_a_candidate_count_outside_the_declared_bound_is_refused(self) -> None:
        record = run_case({"name": "probe-count", "item": "1",
                           "instruction_candidates": 0})
        self.assertEqual("candidate-count-invalid:instruction_candidates:0",
                         record["error"])

    def test_a_program_that_does_not_fit_the_declared_region_is_refused(self) -> None:
        record = run_case({"name": "probe-region", "item": "1",
                           "instruction_candidates": 64,
                           "rom_size": 0x100})
        self.assertIn("candidate-program-exceeds-region:", record["error"])
        self.assertIn("0x", record["error"])


class PrologueTests(unittest.TestCase):
    """Item 2: the registers a candidate program needs are generated, or refused."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()

    def test_the_prologue_is_generated_from_the_plan_and_written_to_the_image(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=2)
        bindings = program.document()["prologue"]["register_bindings"]
        self.assertEqual(0x8001_0000, bindings["stack_pointer"]["value"])
        self.assertEqual(0x8000_0000, bindings["data_base"]["value"])
        self.assertEqual(0x4000_0000, bindings["mmio_base"]["value"])
        self.assertEqual(STACK_POINTER_REGISTER, bindings["stack_pointer"]["register"])
        self.assertEqual(DATA_BASE_REGISTER, bindings["data_base"]["register"])
        self.assertEqual(MMIO_BASE_REGISTER, bindings["mmio_base"]["register"])
        result = program.repairer().repair_test([], directed={
            "init": encode_lw(6, DATA_BASE_REGISTER, 0x40),
            "init1": encode_addi(7, 6, 1)})
        rom = result.image.region_images[program.image.region_id]
        self.assertEqual(program.entry_bytes(),
                         rom[:program.prologue_address - program.image.base])
        prologue = rom[program.prologue_address - program.image.base:
                       program.program_base - program.image.base]
        self.assertEqual(program.prologue_bytes(), prologue)
        # The static image is the plan's frozen part; the test's own slots are
        # overlaid on top of it, so the two agree outside the program window.
        self.assertEqual(program.entry_bytes(),
                         program.static_image()[:program.prologue_address
                                                - program.image.base])

    def test_the_static_image_is_the_fixed_boot_image_a_test_overlays(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=2)
        static = program.static_image()
        self.assertEqual(program.program_base + program.program_size
                         - program.image.base, len(static))
        result = program.repairer().repair_test([], directed={
            "init": encode_addi(6, 0, 1), "init1": encode_addi(7, 0, 2)})
        for offset in range(len(static)):
            address = program.image.base + offset
            if program.program_base <= address < program.program_base + 8:
                continue
            self.assertEqual(static[offset], result.image.image[offset],
                             f"static and test image differ at 0x{address:08x}")
        self.assertNotEqual(static, result.image.image)

    def test_the_generated_prologue_words_really_load_the_declared_values(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        prologue = program.prologue_bytes()
        words = [int.from_bytes(prologue[index:index + 4], "little")
                 for index in range(0, len(prologue), 4)]
        # 0x80000000 and 0x80010000 both have no low twelve bits set, so the
        # assembler emits `lui` + `addi rd, rd, 0`; the lui immediate is the
        # declared value's upper twenty bits.
        self.assertIn(encode_lui(STACK_POINTER_REGISTER, 0x80010), words)
        self.assertIn(encode_lui(DATA_BASE_REGISTER, 0x80000), words)
        self.assertIn(encode_lui(MMIO_BASE_REGISTER, 0x40000), words)

    def test_an_unknown_value_may_be_stored_but_never_steers_an_address(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=2)
        result = program.repairer().repair_test([], directed={
            # x6 = an MMIO read (DUT state: bounded unknown) ...
            "init": encode_lw(6, MMIO_BASE_REGISTER, 0),
            # ... stored into RAM: the unknown value is frozen, not refused.
            "init1": encode_sw(6, DATA_BASE_REGISTER, 0x40)})
        kinds = {item.kind for item in result.unknowns}
        self.assertIn("mmio-read", kinds)
        self.assertIn("store-value", kinds)
        self.assertEqual(2, result.counters["unknown_values"])

    def test_a_directed_candidate_with_an_unset_base_is_refused(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test(
                [], directed={"init": encode_lw(6, 5, 0)})
        self.assertEqual("candidate-base-register-unset:x5", str(caught.exception))

    def test_an_indirect_jump_with_an_unset_base_is_refused(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test(
                [], directed={"init": encode_jalr(0, 5, 0)})
        self.assertEqual("candidate-base-register-unset:x5", str(caught.exception))

    def test_a_fuzz_candidate_with_an_unset_base_is_repaired_by_projection(self) -> None:
        """The fuzz channel repairs the base register field, and records it."""
        program = build_candidate_program(self.plan, instruction_candidates=1,
                                          isa_repair=False)
        slot = program.slots.slot("init")
        raw = _reference_payload(slot, slot.declared_address, encode_lw(6, 31, 0x40))
        result = program.repairer().repair_test([raw])
        self.assertEqual(1, result.counters["register_repair"])
        record = next(item for item in result.records if item.kind == "register")
        self.assertEqual((31, DATA_BASE_REGISTER),
                         (record.before, record.after))
        self.assertEqual(encode_lw(6, DATA_BASE_REGISTER, 0x40),
                         result.placements[0]["word_value"])


class ControlFlowTests(unittest.TestCase):
    """Item 3: declared alignment, region and target policy."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()

    def test_a_target_inside_the_region_but_outside_the_program_is_projected(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=3)
        window, size = program.window()
        # Choose a raw target inside rom0, outside the program window, whose
        # projection lands on the last declared slot.
        wanted = 2
        target = _raw_target_projecting_to(window, size, wanted)
        result = program.repairer().repair_test([], directed={
            "init": encode_jal(0, target - window),
            "init1": encode_addi(0, 0, 0),
            "init2": encode_addi(0, 0, 0)})
        self.assertEqual(1, result.counters["target_repair"])
        record = next(item for item in result.records if item.kind == "target")
        self.assertEqual(target, record.before)
        self.assertEqual(window + 4 * wanted, record.after)
        self.assertEqual(encode_jal(0, record.after - window),
                         result.placements[0]["word_value"])
        # The projected target is a declared successor, so the slot the raw
        # target would have skipped is analysed as unreachable.
        self.assertIn("init1",
                      [item.slot for item in result.unknowns
                       if item.kind == "unreachable-slot"])

    def test_a_target_outside_the_executable_region_is_refused_not_clamped(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        window, _size = program.window()
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test([], directed={
                "init": encode_jal(0, 0x2_0000 - window)})
        self.assertEqual("candidate-target-outside-executable-region:0x00020000",
                         str(caught.exception))

    def test_the_strict_target_policy_refuses_instead_of_projecting(self) -> None:
        program = build_candidate_program(
            self.plan, instruction_candidates=2,
            policy=CandidateProgramPolicy(target_policy="strict"))
        window, size = program.window()
        target = _raw_target_projecting_to(window, size, 1)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test([], directed={
                "init": encode_jal(0, target - window),
                "init1": encode_addi(0, 0, 0)})
        self.assertEqual(f"candidate-target-outside-declared-program:0x{target:08x}",
                         str(caught.exception))

    def test_a_projected_displacement_that_does_not_fit_is_refused(self) -> None:
        """A declared bound, checked: a branch reaches 4 KiB and no further.

        The program window is 8 KiB (2048 four-byte slots).  A branch in the
        last slot whose encodable target sits just past the window is projected
        onto an early slot, and the projected displacement no longer fits the
        branch encoding -- so the candidate is refused by name instead of being
        silently truncated.
        """
        slots = 2048
        program = build_candidate_program(
            self.plan, instruction_candidates=slots,
            policy=CandidateProgramPolicy(require_all_slots=False))
        window, size = program.window()
        self.assertEqual(slots * 4, size)
        self.assertGreater(size, BRANCH_DISPLACEMENT_BOUND)
        last = slots - 1
        # window + size is just outside the window (four-byte aligned) and one
        # encodable word away from the branch in the last slot.
        target = window + size
        projected = project_address(target, window, size)
        self.assertLess(projected, window + BRANCH_DISPLACEMENT_BOUND)
        displacement = projected - (window + 4 * last)
        self.assertLessEqual(displacement, -BRANCH_DISPLACEMENT_BOUND)
        directed = {_slot_name(index): encode_addi(0, 0, 0) for index in range(slots)}
        directed[_slot_name(last)] = encode_beq(0, 0, target - (window + 4 * last))
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test([], directed=directed)
        self.assertEqual(
            f"candidate-target-immediate-unencodable:branch:{displacement}",
            str(caught.exception))

    def test_an_encodable_target_inside_the_window_is_the_declared_slot(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=4)
        window, size = program.window()
        result = program.repairer().repair_test([], directed={
            "init": encode_jal(0, 8),
            "init1": encode_addi(0, 0, 0),
            "init2": encode_addi(0, 0, 0),
            "init3": encode_addi(0, 0, 0)})
        self.assertEqual(0, result.counters["target_repair"])
        placement = next(item for item in result.placements if item["slot"] == "init2")
        self.assertEqual(window + 8, placement["declared_address"])
        self.assertIn("init1", [item.slot for item in result.unknowns
                                if item.kind == "unreachable-slot"])

    def test_the_program_window_projection_is_the_address_projection(self) -> None:
        """One function projects data addresses and branch targets alike.

        The oracle here is the campaign projector's own repair formula
        (``first + ((address // 4) % slots) * 4`` with
        ``first = (base + 3) & ~3``), written out independently so the test
        fails if the target projection ever becomes a second policy.
        """
        program = build_candidate_program(self.plan, instruction_candidates=4)
        window, size = program.window()
        first = (window + 3) & ~3
        slots = (window + size - first) // 4
        for target in (window, window + 4, window + 0x100, window - 4,
                       window + size, 0x1234):
            self.assertEqual(first + ((target // 4) % slots) * 4,
                             project_address(target, window, size))


class DependencyTests(unittest.TestCase):
    """Item 4: declared dependencies are repaired by construction or refused."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()

    def test_a_store_before_a_load_is_repaired_by_the_declared_order(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=3)
        result = program.repairer().repair_test([], directed={
            "init": encode_addi(5, 0, 42),
            "init1": encode_sw(5, DATA_BASE_REGISTER, 0x40),
            "init2": encode_lw(6, DATA_BASE_REGISTER, 0x40)})
        edge = next(item for item in result.dependencies
                    if item.kind == "store-before-load")
        self.assertEqual("satisfied", edge.status)
        self.assertEqual(42, edge.value)
        self.assertEqual(1, result.counters["dependencies_satisfied"])

    def test_a_load_before_the_only_store_is_refused_by_name(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=2)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test([], directed={
                "init": encode_lw(6, MMIO_BASE_REGISTER, 0),
                "init1": encode_sw(6, MMIO_BASE_REGISTER, 0)})
        self.assertEqual("dependency-load-before-store:0x40000000",
                         str(caught.exception))

    def test_an_mmio_write_before_read_is_satisfied_and_recorded(self) -> None:
        program = build_candidate_program(
            self.plan, instruction_candidates=3,
            policy=CandidateProgramPolicy(mmio_read_requires_write=True))
        result = program.repairer().repair_test([], directed={
            "init": encode_addi(5, 0, 0x123),
            "init1": encode_sw(5, MMIO_BASE_REGISTER, 4),
            "init2": encode_lw(6, MMIO_BASE_REGISTER, 4)})
        edge = next(item for item in result.dependencies
                    if item.kind == "mmio-write-before-read")
        self.assertEqual("satisfied", edge.status)
        self.assertEqual(0x123, edge.value)

    def test_an_mmio_read_without_a_preceding_write_is_refused(self) -> None:
        program = build_candidate_program(
            self.plan, instruction_candidates=1,
            policy=CandidateProgramPolicy(mmio_read_requires_write=True))
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test(
                [], directed={"init": encode_lw(6, MMIO_BASE_REGISTER, 0)})
        self.assertEqual("dependency-mmio-read-before-write:0x40000000",
                         str(caught.exception))

    def test_a_resolved_response_may_feed_the_next_address(self) -> None:
        """A data candidate freezes a pointer; the load response is the address."""
        program = build_candidate_program(self.plan, instruction_candidates=2,
                                          data_candidates=1)
        data_slot = program.slots.slot("data")
        pointer = 0x8000_0100
        result = program.repairer().repair_test(
            [_reference_payload(data_slot, data_slot.declared_address, pointer)],
            directed={"init": encode_lw(6, DATA_BASE_REGISTER, 0),
                      "init1": encode_lw(7, 6, 0)})
        edge = next(item for item in result.dependencies
                    if item.kind == "response-feeds-address")
        self.assertEqual("resolved", edge.status)
        self.assertEqual(pointer, edge.address)

    def test_an_unresolvable_response_address_is_refused(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=2)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test([], directed={
                "init": encode_lw(6, MMIO_BASE_REGISTER, 0),
                "init1": encode_lw(7, 6, 0)})
        self.assertEqual("dependency-response-address-unresolved:x6:init",
                         str(caught.exception))

    def test_a_write_the_declared_permission_forbids_is_refused(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=3)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test([], directed={
                "init": encode_lui(5, 0x10),
                "init1": encode_addi(6, 0, 7),
                "init2": encode_sw(6, 5, 0)})
        self.assertEqual("candidate-access-permission-denied:write:0x00010000",
                         str(caught.exception))

    def test_an_access_outside_every_declared_window_is_refused(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=2)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test([], directed={
                "init": encode_lui(5, 0x90),
                "init1": encode_lw(6, 5, 0)})
        self.assertEqual("candidate-access-address-unmapped:0x00090000",
                         str(caught.exception))


class CommittedInputTests(unittest.TestCase):
    """Item 5: a repair may only change what the test has not committed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()

    def test_an_uncommitted_address_is_repaired_and_recorded(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        slot = program.slots.slot("init")
        raw = _reference_payload(slot, 3, 0x00000013)
        result = program.repairer().repair_test([raw])
        self.assertEqual(1, result.counters["address_repair"])
        record = next(item for item in result.records if item.kind == "address")
        self.assertEqual((3, slot.declared_address), (record.before, record.after))
        applied = slot.segment("address").extract(result.request[0])
        self.assertEqual(slot.declared_address, applied)

    def test_a_repair_that_would_rewrite_a_committed_word_is_refused(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        slot = program.slots.slot("init")
        first = _reference_payload(slot, slot.declared_address, 0x00000013)
        second = _reference_payload(slot, slot.declared_address + 4, 0x00000013)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test([first, second])
        self.assertEqual(
            f"repair-would-rewrite-committed-word:init:0x{slot.declared_address:08x}",
            str(caught.exception))

    def test_a_seed_that_would_rewrite_the_frozen_entry_is_refused(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        slot = program.slots.slot("init")
        raw = _reference_payload(slot, slot.declared_address, 0x00000013)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test(
                [raw], seeds={program.entry_address: bytes(4)})
        self.assertEqual(
            f"repair-would-rewrite-committed-word:seed:0x{program.entry_address:08x}",
            str(caught.exception))

    def test_a_repairer_that_already_committed_a_test_refuses_a_second_one(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        slot = program.slots.slot("init")
        raw = _reference_payload(slot, slot.declared_address, 0x00000013)
        repairer = program.repairer()
        repairer.repair_test([raw])
        with self.assertRaises(CandidateProgramError) as caught:
            repairer.repair_test([raw])
        self.assertEqual("candidate-repairer-already-committed",
                         str(caught.exception))


class UnknownValueTests(unittest.TestCase):
    """Item 6: an underivable fact is bounded and recorded, or refused."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()

    def test_an_unset_register_read_is_recorded_with_its_bound(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1,
                                          isa_repair=False)
        slot = program.slots.slot("init")
        raw = _reference_payload(slot, slot.declared_address,
                                 encode_addi(6, 31, 1))
        result = program.repairer().repair_test([raw])
        record = next(item for item in result.unknowns
                      if item.kind == "unset-register-read")
        self.assertIn("never used as an address", record.bound)
        self.assertEqual("reads x31", record.detail)

    def test_an_underivable_branch_direction_is_recorded_and_both_paths_analysed(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=3)
        result = program.repairer().repair_test([], directed={
            "init": encode_lw(5, MMIO_BASE_REGISTER, 0),
            "init1": encode_beq(5, 0, 4),
            "init2": encode_addi(6, 0, 1)})
        record = next(item for item in result.unknowns
                      if item.kind == "branch-direction")
        self.assertIn("either successor is possible", record.bound)

    def test_an_unbounded_encoding_is_refused_with_a_named_error(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test([], directed={"init": 0x0000_007F})
        self.assertEqual("candidate-encoding-unsupported:0x0000007f:slot=init",
                         str(caught.exception))


class IsaScopeTests(unittest.TestCase):
    """Item 7: the supported ISA range is declared, and the rest is refused."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()

    def test_the_isa_scope_is_declared_and_32_bit_only(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        isa = program.document()["isa"]
        self.assertEqual([32], isa["accepted_instruction_widths"])
        self.assertEqual([32], isa["emitted_instruction_widths"])
        self.assertFalse(isa["compressed_placement"])
        self.assertEqual(["I"], isa["extensions"])

    def test_a_compressed_profile_is_understood_but_not_placed(self) -> None:
        record = run_case({"name": "probe-c-profile", "item": "7",
                           "instruction_candidates": 1,
                           "contract_extensions": ["i", "m", "c"],
                           "request": [{"slot": "init", "address": "@slot:init",
                                        "word": 0x00000013}]})
        self.assertNotIn("error", record)
        isa = record["program"]["isa"]
        self.assertTrue(isa["compressed_declared"])
        self.assertFalse(isa["compressed_placement"])

    def test_a_16_bit_candidate_is_refused_by_name(self) -> None:
        program = build_candidate_program(self.plan, instruction_candidates=1)
        with self.assertRaises(CandidateProgramError) as caught:
            program.repairer().repair_test([], directed={"init": 0x0001})
        self.assertEqual("candidate-instruction-width-unsupported:16:slot=init",
                         str(caught.exception))

    def test_an_m_extension_profile_accepts_an_m_word(self) -> None:
        record = run_case({"name": "probe-m-profile", "item": "7",
                           "instruction_candidates": 1,
                           "contract_extensions": ["i", "m"],
                           "request": [{"slot": "init", "address": "@slot:init",
                                        "word": 0x022282B3}]})
        self.assertNotIn("error", record)
        self.assertIn("M", record["program"]["isa"]["extensions"])

    def test_an_extension_the_generator_cannot_emit_is_refused(self) -> None:
        record = run_case({"name": "probe-f-profile", "item": "7",
                           "instruction_candidates": 1,
                           "contract_extensions": ["i", "f"]})
        self.assertEqual("candidate-isa-extension-unsupported:f", record["error"])


# ---------------------------------------------------------------------------
# artifacts: one recorded positive and negative case per capability
# ---------------------------------------------------------------------------
#
# Every case is declarative data, so ``test_soc_input_repair_replay.py`` can
# rebuild it from its own record and compare the documents byte for byte.  The
# ``expect`` block is what the recording test asserts; the refusal string of a
# negative case is asserted exactly.

CASES: tuple[dict, ...] = (
    # -- item 1: several instruction and data candidates per test ----------
    {"name": "item1-multiple-candidates", "item": "1",
     "instruction_candidates": 3, "data_candidates": 2,
     "request": [
         {"slot": "init", "address": 3, "word": 0x00000013},
         {"slot": "init1", "address": "@slot:init1", "word": 0x00000013},
         {"slot": "init2", "address": "@slot:init2", "word": 0x00000013},
         {"slot": "data", "address": "@slot:data", "word": 0x11223344},
         {"slot": "data1", "address": "@slot:data1", "word": 0xAABBCCDD}],
     "expect": {"counters": {"instruction_slots_placed": 3, "data_slots_placed": 2,
                             "address_repair": 1}}},
    {"name": "item1-count-bound-refused", "item": "1",
     "instruction_candidates": 0,
     "expect_error": "candidate-count-invalid:instruction_candidates:0"},
    {"name": "item1-region-bound-refused", "item": "1",
     "instruction_candidates": 64, "rom_size": 0x100,
     "expect_error": "candidate-program-exceeds-region:0x10198>0x10100"},
    # -- item 2: registers the program needs, generated or refused ---------
    {"name": "item2-prologue-and-frozen-load", "item": "2",
     "instruction_candidates": 2,
     "directed": {"init": encode_lw(6, DATA_BASE_REGISTER, 0),
                  "init1": encode_sw(6, DATA_BASE_REGISTER, 0x40)},
     "expect": {"counters": {"instruction_slots_placed": 2},
                "dependency_kinds": ["load-from-frozen-image"]}},
    {"name": "item2-unset-base-refused", "item": "2",
     "directed": {"init": encode_lw(6, 5, 0)},
     "expect_error": "candidate-base-register-unset:x5"},
    {"name": "item2-fuzz-base-repaired", "item": "2",
     "instruction_candidates": 1, "isa_repair": False,
     "request": [{"slot": "init", "address": "@slot:init",
                  "word": encode_lw(6, 31, 0x40)}],
     "expect": {"counters": {"register_repair": 1}}},
    # -- item 3: control flow ---------------------------------------------
    {"name": "item3-target-projected", "item": "3",
     "instruction_candidates": 3,
     # The raw target 0x1019c is outside the 12-byte program window and its
     # projection lands on the last slot, skipping the middle one.
     "directed": {"init": encode_jal(0, 0x104),
                  "init1": encode_addi(0, 0, 0),
                  "init2": encode_addi(0, 0, 0)},
     "expect": {"counters": {"target_repair": 1},
                "dependency_kinds": [], "unknown_kinds": ["unreachable-slot"]}},
    {"name": "item3-target-outside-region-refused", "item": "3",
     "directed": {"init": encode_jal(0, 0x20000 - 0x10098)},
     "expect_error": "candidate-target-outside-executable-region:0x00020000"},
    {"name": "item3-target-strict-refused", "item": "3",
     "instruction_candidates": 2,
     "policy": {"target_policy": "strict"},
     "directed": {"init": encode_jal(0, 0x100), "init1": encode_addi(0, 0, 0)},
     "expect_error": "candidate-target-outside-declared-program:0x00010198"},
    {"name": "item3-target-unencodable-refused", "item": "3",
     "instruction_candidates": 2048, "compact": True,
     # Every slot is filled so the branch in the last slot is reachable: the
     # projected displacement is -8036, past the 4 KiB branch encoding bound.
     "directed": {**{("init" if index == 0 else f"init{index}"):
                     encode_addi(0, 0, 0) for index in range(2048)},
                  "init2047": encode_beq(0, 0, 4)},
     "expect_error": "candidate-target-immediate-unencodable:branch:-8036"},
    # -- item 4: data and MMIO dependencies -------------------------------
    {"name": "item4-store-before-load", "item": "4",
     "instruction_candidates": 3,
     "directed": {"init": encode_addi(5, 0, 42),
                  "init1": encode_sw(5, DATA_BASE_REGISTER, 0x40),
                  "init2": encode_lw(6, DATA_BASE_REGISTER, 0x40)},
     "expect": {"counters": {"dependencies_satisfied": 1},
                "dependency_kinds": ["store-before-load"]}},
    {"name": "item4-load-before-store-refused", "item": "4",
     "instruction_candidates": 2,
     "directed": {"init": encode_lw(6, MMIO_BASE_REGISTER, 0),
                  "init1": encode_sw(6, MMIO_BASE_REGISTER, 0)},
     "expect_error": "dependency-load-before-store:0x40000000"},
    {"name": "item4-mmio-write-before-read", "item": "4",
     "instruction_candidates": 3,
     "policy": {"mmio_read_requires_write": True},
     "directed": {"init": encode_addi(5, 0, 0x123),
                  "init1": encode_sw(5, MMIO_BASE_REGISTER, 4),
                  "init2": encode_lw(6, MMIO_BASE_REGISTER, 4)},
     "expect": {"counters": {"dependencies_satisfied": 1},
                "dependency_kinds": ["mmio-write-before-read", "mmio-write"]}},
    {"name": "item4-mmio-read-before-write-refused", "item": "4",
     "policy": {"mmio_read_requires_write": True},
     "directed": {"init": encode_lw(6, MMIO_BASE_REGISTER, 0)},
     "expect_error": "dependency-mmio-read-before-write:0x40000000"},
    {"name": "item4-response-feeds-address", "item": "4",
     "instruction_candidates": 2,
     "request": [{"slot": "data", "address": "@slot:data", "word": 0x80000100}],
     "directed": {"init": encode_lw(6, DATA_BASE_REGISTER, 0),
                  "init1": encode_lw(7, 6, 0)},
     "expect": {"dependency_kinds": ["load-from-frozen-image",
                                     "response-feeds-address"]}},
    {"name": "item4-response-address-unresolved-refused", "item": "4",
     "instruction_candidates": 2,
     "directed": {"init": encode_lw(6, MMIO_BASE_REGISTER, 0),
                  "init1": encode_lw(7, 6, 0)},
     "expect_error": "dependency-response-address-unresolved:x6:init"},
    {"name": "item4-permission-refused", "item": "4",
     "instruction_candidates": 3,
     "directed": {"init": encode_lui(5, 0x10), "init1": encode_addi(6, 0, 7),
                  "init2": encode_sw(6, 5, 0)},
     "expect_error": "candidate-access-permission-denied:write:0x00010000"},
    {"name": "item4-unmapped-refused", "item": "4",
     "instruction_candidates": 2,
     "directed": {"init": encode_lui(5, 0x90), "init1": encode_lw(6, 5, 0)},
     "expect_error": "candidate-access-address-unmapped:0x00090000"},
    # -- item 5: only uncommitted inputs may change -----------------------
    {"name": "item5-address-repaired", "item": "5",
     "request": [{"slot": "init", "address": 3, "word": 0x00000013}],
     "expect": {"counters": {"address_repair": 1}}},
    {"name": "item5-committed-word-refused", "item": "5",
     "request": [{"slot": "init", "address": "@slot:init", "word": 0x00000013},
                 {"slot": "init", "address": "@window+4", "word": 0x00000013}],
     "expect_error": "repair-would-rewrite-committed-word:init:0x00010098"},
    {"name": "item5-seed-overwrite-refused", "item": "5",
     "request": [{"slot": "init", "address": "@slot:init", "word": 0x00000013}],
     "seeds": [{"address": 0x10000, "bytes": "00000000"}],
     "expect_error": "repair-would-rewrite-committed-word:seed:0x00010000"},
    # -- item 6: bounded unknowns -----------------------------------------
    {"name": "item6-unknown-values-bounded", "item": "6",
     "instruction_candidates": 3,
     "directed": {"init": encode_lw(5, MMIO_BASE_REGISTER, 0),
                  "init1": encode_beq(5, 0, 4),
                  "init2": encode_addi(6, 0, 1)},
     "expect": {"counters": {"unknown_values": 2},
                "unknown_kinds": ["branch-direction", "mmio-read"],
                "dependency_kinds": []}},
    {"name": "item6-encoding-refused", "item": "6",
     "directed": {"init": 0x0000007F},
     "expect_error": "candidate-encoding-unsupported:0x0000007f:slot=init"},
    # -- item 7: the declared ISA scope -----------------------------------
    {"name": "item7-m-profile-accepted", "item": "7",
     "contract_extensions": ["i", "m"],
     "request": [{"slot": "init", "address": "@slot:init", "word": 0x022282B3}],
     "expect": {"counters": {"instruction_slots_placed": 1},
                "isa_extensions": ["I", "M"]}},
    {"name": "item7-c-profile-declared", "item": "7",
     "contract_extensions": ["i", "m", "c"],
     "request": [{"slot": "init", "address": "@slot:init", "word": 0x00000013}],
     "expect": {"counters": {"isa_repair": 0}}},
    {"name": "item7-f-profile-refused", "item": "7",
     "contract_extensions": ["i", "f"],
     "expect_error": "candidate-isa-extension-unsupported:f"},
    {"name": "item7-compressed-refused", "item": "7",
     "directed": {"init": 0x0001},
     "expect_error": "candidate-instruction-width-unsupported:16:slot=init"},
)


class ArtifactTests(unittest.TestCase):
    """Every capability is recorded under ``runs/`` and replays from its record."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()

    def test_every_case_records_the_expected_outcome(self) -> None:
        for spec in CASES:
            with self.subTest(case=spec["name"]):
                directory = record_case(spec)
                self.assertTrue((directory / "case.json").is_file(), spec["name"])
                record = read_case(spec["name"])
                self.assertEqual(spec["item"], record["item"])
                if "expect_error" in spec:
                    self.assertEqual(spec["expect_error"], record.get("error"),
                                     f"{spec['name']} refused with the wrong reason")
                    continue
                self.assertNotIn("error", record, record.get("error"))
                expectation = spec["expect"]
                counters = record["test"]["counters"]
                for name, value in expectation.get("counters", {}).items():
                    self.assertEqual(value, counters[name], f"{spec['name']}:{name}")
                if "dependency_kinds" in expectation:
                    self.assertEqual(sorted(expectation["dependency_kinds"]),
                                     sorted({item["kind"]
                                             for item in record["test"]["dependencies"]}),
                                     spec["name"])
                if "isa_extensions" in expectation:
                    self.assertEqual(expectation["isa_extensions"],
                                     record["program"]["isa"]["extensions"], spec["name"])
                if "unknown_kinds" in expectation:
                    self.assertEqual(sorted(expectation["unknown_kinds"]),
                                     sorted({item["kind"]
                                             for item in record["test"]["unknowns"]}),
                                     spec["name"])
                self.assertTrue(record["image_hash"].startswith("sha256:"))
                self.assertEqual(
                    record["test"]["image"]["content_hash"], record["image_hash"])

    def test_the_recorded_image_is_the_hex_file_beside_it(self) -> None:
        for spec in CASES:
            if "expect_error" in spec:
                continue
            with self.subTest(case=spec["name"]):
                directory = record_case(spec)
                record = read_case(spec["name"])
                text = (directory / "boot.hex").read_text(encoding="utf-8")
                self.assertEqual(str(record["boot_hex"]), text)
                size = len(bytes.fromhex(text.replace("\n", "")))
                self.assertEqual(int(record["test"]["image"]["bytes"]), size)


def _slot_name(index: int) -> str:
    """The declared prefix of instruction slot ``index``."""
    return "init" if index == 0 else f"init{index}"


def _raw_target_projecting_to(window: int, size: int, slot: int) -> int:
    """A raw target outside the window whose projection lands on ``slot``."""
    slots = size // 4
    if not 0 <= slot < slots:
        raise AssertionError("slot outside the declared program window")
    target = window + size + 4 * slot          # outside the window
    while project_address(target, window, size) != window + 4 * slot:
        target += 4
    return target


def _multicandidate_spec() -> dict:
    return {"name": "item1-multiple-candidates", "item": "1",
            "instruction_candidates": 3, "data_candidates": 2,
            "request": [
                {"slot": "init", "address": 3, "word": 0x00000013},
                {"slot": "init1", "address": "@slot:init1", "word": 0x00000013},
                {"slot": "init2", "address": "@slot:init2", "word": 0x00000013},
                {"slot": "data", "address": "@slot:data", "word": 0x11223344},
                {"slot": "data1", "address": "@slot:data1", "word": 0xAABBCCDD}]}


if __name__ == "__main__":
    unittest.main()
