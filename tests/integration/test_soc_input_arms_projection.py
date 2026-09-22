"""Roadmap phase 1A: the three projection arms, field by field, on real plans.

The RFuzz input chain has two halves.  This module covers the first one: for a
concrete composition plan, what does each arm do to *one* raw field, and what
does it refuse?

* ``direct_input`` is the identity projection: the record is the stimulus.
* ``constrained_baseline`` may only touch environment-owned bits below the
  profile layout width, and only through the compiled policy.
* ``dependency_repair`` places instruction/data candidates into the declared
  program, repairs addresses, registers and control-flow targets, and refuses a
  slot a test has already committed.

Every assertion below is made against values derived from the real plan
(``combined_input_layout``, ``compile_input_constraints``, ``build_image_plan``)
rather than a hand-written copy of the ABI: the frozen table is checked *first*,
so a silent layout change fails here instead of quietly reinterpreting an old
corpus.  The transport half lives in ``test_soc_input_transport_ab.py``.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.input_constraints import (
    compile_input_constraints,
    project_sample_values,
)
from myfuzz.composition.soc_candidate_program import (
    CandidateProgramError,
    CandidateProgramPolicy,
    build_candidate_program,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
from myfuzz.integration.soc_builder import (
    ProfileCampaignProjector,
    SocBuildError,
    SocRawProjector,
    _peer_projection_slots,
    _provisional_record_width,
    build_projection_arms,
)

from tests.composition.soc_generation_fixture import ROOT, example_request

FIXTURES = ROOT / "examples/soc_generation"
IBEX_REQUEST = "examples/soc_generation/request-ibex.json"
PEER_PROFILE_NAMES = ("novacore", "novauart_link", "novaspi", "novagpio")

#: The frozen ABI of four real compositions, as ``(owner, role)`` in raw-bit
#: order with the total width.  A layout change must fail this test on purpose:
#: an old corpus and an old constraint policy are only replayable against the
#: mapping they were produced with.
FROZEN_ABI = {
    ("ibex", "cpu_execute"): (
        141,
        (("gpio0::pin_mode_i", "pin_mode_i"),
         ("soc_image", "init_offer"),
         ("soc_image", "init_address"),
         ("soc_image", "init_data"),
         ("soc_image", "init_be"),
         ("soc_image", "data_offer"),
         ("soc_image", "data_address"),
         ("soc_image", "data_value"),
         ("soc_image", "data_be")),
    ),
    ("example", "cpu_execute"): (
        145,
        (("cpu0::event_i", "event_i"),
         ("gpio0::pin_mode_i", "pin_mode_i"),
         ("soc_image", "init_offer"),
         ("soc_image", "init_address"),
         ("soc_image", "init_data"),
         ("soc_image", "init_be"),
         ("soc_image", "data_offer"),
         ("soc_image", "data_address"),
         ("soc_image", "data_value"),
         ("soc_image", "data_be")),
    ),
    ("peers", "cpu_execute"): (
        179,
        (("cpu0::event_i", "event_i"),
         ("gpio0::pin_mode_i", "pin_mode_i"),
         ("soc_image", "init_offer"),
         ("soc_image", "init_address"),
         ("soc_image", "init_data"),
         ("soc_image", "init_be"),
         ("soc_image", "data_offer"),
         ("soc_image", "data_address"),
         ("soc_image", "data_value"),
         ("soc_image", "data_be"),
         ("soc_peer", "gpio.drive:peer_drive_value_i"),
         ("soc_peer", "gpio.drive:peer_drive_valid_i"),
         ("soc_peer", "spi.arm_byte:tx_request_valid_i"),
         ("soc_peer", "spi.arm_byte:tx_request_data_i"),
         ("soc_peer", "uart.tx_byte:tx_request_valid_i"),
         ("soc_peer", "uart.tx_byte:tx_request_data_i")),
    ),
    ("example", "bfm_isolated"): (
        369,
        (("cpu0::event_i", "event_i"),
         ("gpio0::pin_mode_i", "pin_mode_i"),
         ("soc_stimulus", "reserved"),
         ("soc_stimulus", "stim_offer"),
         ("soc_stimulus", "stim_target_selector"),
         ("soc_stimulus", "stim_offset"),
         ("soc_stimulus", "stim_write"),
         ("soc_stimulus", "stim_wdata"),
         ("soc_stimulus", "stim_be"),
         ("soc_stimulus", "reserved"),
         ("soc_image", "init_offer"),
         ("soc_image", "init_address"),
         ("soc_image", "init_data"),
         ("soc_image", "init_be"),
         ("soc_image", "data_offer"),
         ("soc_image", "data_address"),
         ("soc_image", "data_value"),
         ("soc_image", "data_be")),
    ),
}


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def peer_profiles() -> dict:
    profiles: dict = {}
    for name in PEER_PROFILE_NAMES:
        relative = f"examples/soc_generation/profiles/{name}.json"
        profile = load_component_profile(ROOT / relative)
        profiles[relative] = profile
        profiles.setdefault(profile.component_id, profile)
    return profiles


def ibex_profiles() -> dict:
    profiles: dict = {}
    document = json.loads((ROOT / IBEX_REQUEST).read_text(encoding="utf-8"))
    references = [document["cpu"]["profile"]] + [
        item["profile"] for item in document.get("peripherals", [])]
    for item in references:
        profile = load_component_profile(ROOT / item)
        profiles[item] = profile
        profiles.setdefault(profile.component_id, profile)
    return profiles


def ibex_plan(drive_profile: str = "cpu_execute"):
    document = json.loads((ROOT / IBEX_REQUEST).read_text(encoding="utf-8"))
    request = load_composition_request(document, profiles=ibex_profiles())
    return build_composition(request, base_dir=ROOT, drive_profile=drive_profile)


def peer_plan(drive_profile: str = "cpu_execute"):
    from tests.integration.test_soc_peer_models import build_peer_plan

    return build_peer_plan(drive_profile=drive_profile)


def example_plan(drive_profile: str = "cpu_execute"):
    from tests.composition.soc_generation_fixture import example_plan as build

    return build() if drive_profile == "cpu_execute" else build_composition(
        example_request(), base_dir=ROOT, drive_profile=drive_profile)


def field_by_role(layout, owner: str, role: str):
    matches = [field for field in layout.fields
               if field.owner == owner and field.role == role]
    if len(matches) != 1:
        raise AssertionError(f"expected one {owner}/{role}, found {len(matches)}")
    return matches[0]


def put(value: int, field, raw: int) -> int:
    """Place one value in one field of a raw word, without touching other bits."""
    mask = ((1 << field.width) - 1) << field.raw_lo
    return (value & ~mask) | ((raw & ((1 << field.width) - 1)) << field.raw_lo)


def segment(value: int, field) -> int:
    return (value >> field.raw_lo) & ((1 << field.width) - 1)


def arms_for(plan, *, instruction_candidates: int = 1, data_candidates: int = 1,
             data_slot_offset: int | None = None,
             candidate_program: bool = False):
    """The three arms of one plan, built the way the production path builds them.

    The declared candidate program is built when a test declares more than one
    candidate, exactly as ``_build_profile_campaign_artifact`` decides it, or when
    a caller asks for one explicitly (``candidate_program=True``): a caller that
    needs the repair arm to place a *chosen* word, as the chain report does, must
    have the program even for a single candidate.
    """
    image = build_image_plan(
        plan, instruction_candidates=instruction_candidates,
        data_candidates=data_candidates)
    layout = combined_input_layout(plan, image)
    policy = compile_input_constraints(plan, drive_profile=plan.drive_profile)
    program = None
    if candidate_program or instruction_candidates > 1 or data_candidates > 1:
        policy_object = CandidateProgramPolicy(
            **({} if data_slot_offset is None else {"data_slot_offset": data_slot_offset}))
        program = build_candidate_program(
            plan, instruction_candidates=instruction_candidates,
            data_candidates=data_candidates, policy=policy_object,
            # The record is the combined ABI, which is wider than the image
            # segment whenever the composition appends a peer's request fields or
            # a synthetic master's stimulus.  Declaring the image width here would
            # make the program refuse a record that legally carries those bits.
            raw_width=int(_provisional_record_width(plan, image)))
    arms = build_projection_arms(
        layout=layout, constraint_hash=policy.policy_hash,
        special_width=int(plan.raw_layout["raw_width"]), policy=policy, image=image,
        candidate_program=program,
        peer_slots=_peer_projection_slots(plan, layout, base_dir=ROOT))
    return image, layout, policy, arms


# ---------------------------------------------------------------------------
# the frozen ABI
# ---------------------------------------------------------------------------


class FrozenAbiTests(unittest.TestCase):
    """The observed field table is frozen before any A/B assertion is trusted."""

    def test_the_observed_layouts_are_contiguous_and_unchanged(self) -> None:
        cases = {
            ("ibex", "cpu_execute"): lambda: ibex_plan(),
            ("example", "cpu_execute"): lambda: example_plan("cpu_execute"),
            ("peers", "cpu_execute"): lambda: peer_plan("cpu_execute"),
            ("example", "bfm_isolated"): lambda: example_plan("bfm_isolated"),
        }
        for key, build in cases.items():
            with self.subTest(composition=key):
                plan = build()
                image = build_image_plan(plan)
                layout = combined_input_layout(plan, image)
                width, roles = FROZEN_ABI[key]
                self.assertEqual(width, layout.raw_width)
                self.assertEqual(roles, tuple((field.owner, field.role)
                                              for field in layout.fields))
                cursor = 0
                for field in sorted(layout.fields, key=lambda item: item.raw_lo):
                    self.assertEqual(cursor, field.raw_lo, field.field_id)
                    cursor = field.raw_hi + 1
                self.assertEqual(layout.raw_width, cursor)

    def test_the_layout_hash_identity_covers_every_field_binding(self) -> None:
        plan = ibex_plan()
        image = build_image_plan(plan)
        layout = combined_input_layout(plan, image)
        self.assertTrue(layout.layout_hash)
        document = layout.to_raw_abi().document() if hasattr(
            layout.to_raw_abi(), "document") else None
        abi = layout.to_raw_abi()
        self.assertEqual(layout.raw_width, abi.raw_width)
        # Total use: every raw bit belongs to exactly one field, which is what
        # makes "only this field changed" a meaningful statement.
        abi.validate_total_use()
        self.assertIsNone(document)


# ---------------------------------------------------------------------------
# direct_input
# ---------------------------------------------------------------------------


class DirectInputArmTests(unittest.TestCase):
    """``direct_input`` is the identity projection, by construction."""

    def test_every_bit_of_every_frozen_field_survives_unchanged(self) -> None:
        plan = ibex_plan()
        image, layout, policy, arms = arms_for(plan, instruction_candidates=3,
                                               data_candidates=1, data_slot_offset=0x80)
        arm = arms["direct_input"]
        self.assertIsInstance(arm, SocRawProjector)
        for field in layout.fields:
            for raw in (0, (1 << field.width) - 1, 1 << (field.width - 1)):
                value = put(0, field, raw)
                with self.subTest(field=field.field_id, raw=raw):
                    self.assertEqual([value], list(arm.project_records([value])))

    def test_a_word_with_every_bit_set_is_not_rewritten(self) -> None:
        plan = example_plan()
        image, layout, policy, arms = arms_for(plan)
        saturated = (1 << layout.raw_width) - 1
        self.assertEqual([saturated], list(arms["direct_input"].project_records([saturated])))


# ---------------------------------------------------------------------------
# constrained_baseline
# ---------------------------------------------------------------------------


class ConstrainedBaselineArmTests(unittest.TestCase):
    """The constraint-only arm may only project environment-owned prefix bits."""

    def test_projection_equals_the_compiled_policy_on_the_profile_prefix(self) -> None:
        plan = example_plan()
        image, layout, policy, arms = arms_for(plan)
        arm = arms["constrained_baseline"]
        special_width = int(plan.raw_layout["raw_width"])
        self.assertEqual(special_width, arm.special_width)
        for raw in (0, 1, 0x7F, 0x55, 0x2A):
            with self.subTest(raw=raw):
                expected = project_sample_values(policy, raw, raw_width=special_width)
                self.assertEqual(expected, arm.project(raw))

    def test_the_example_prefix_is_unconstrained_so_the_arm_is_the_identity_there(self) -> None:
        """An unconstrained field is preserved; the arm does not invent limits.

        Every value of the 7-bit prefix is checked, so this is the exhaustive
        statement that the comparison's "constrained" arm differs from
        ``direct_input`` only through rules the plan really declares -- which,
        for this fixture, is none.  A plan that declares a range or enum is
        covered by :class:`DeclaredConstraintTests` below.
        """
        plan = example_plan()
        image, layout, policy, arms = arms_for(plan)
        arm = arms["constrained_baseline"]
        special_width = int(plan.raw_layout["raw_width"])
        self.assertEqual(7, special_width)
        for raw in range(1 << special_width):
            self.assertEqual(raw, arm.project(raw), hex(raw))

    def test_a_dynamic_image_offer_above_the_prefix_is_refused(self) -> None:
        plan = example_plan()
        image, layout, policy, arms = arms_for(plan)
        arm = arms["constrained_baseline"]
        special_width = int(plan.raw_layout["raw_width"])
        offer = field_by_role(layout, "soc_image", "init_offer")
        self.assertGreaterEqual(offer.raw_lo, special_width)
        with self.assertRaisesRegex(SocBuildError,
                                    "profile-dynamic-image-loading-unsupported"):
            arm.project(1 << offer.raw_lo)

    def test_peer_and_stimulus_bits_above_the_prefix_stay_usable(self) -> None:
        """Environment-owned runtime fields are not image-owned, so they pass."""
        plan = peer_plan()
        image, layout, policy, arms = arms_for(plan)
        arm = arms["constrained_baseline"]
        for owner in ("soc_peer", "soc_stimulus"):
            fields = [field for field in layout.fields if field.owner == owner]
            if not fields:
                continue
            raw = 0
            for field in fields:
                raw = put(raw, field, (1 << field.width) - 1)
            with self.subTest(owner=owner):
                self.assertEqual(raw, arm.project(raw))


class DeclaredConstraintTests(unittest.TestCase):
    """When the plan *does* declare a constraint, the arm applies exactly it."""

    def _layout_and_policy(self, values, *, width: int = 4):
        from myfuzz.composition.input_constraints import compile_rules
        from myfuzz.composition.input_layout import InputLayout, LayoutField

        layout = InputLayout("input_layout.v1", 8, (
            LayoutField("special", "cpu", "event", width, 0, width - 1, "bits",
                        {"randomizable": True}),
            # A reserved tail rather than an image-owned one: this fixture is
            # about the constraint arm, and an image owner would trigger the
            # separate ``profile-dynamic-image-loading-unsupported`` check.
            LayoutField("reserved_tail", "soc_stimulus", "reserved", 8 - width, width, 7,
                        "bits", {}),
        ), "test-layout")
        policy = compile_rules([{
            "rule_id": "legal-special", "category": "environment_hard",
            "owner": "environment", "primitive": "value_enum", "phase": "sample",
            "fields": ["special"], "read_set": [], "write_set": ["special"],
            "raw_bits": [[0, width - 1]], "parameters": [["values", list(values)]],
            "basis": "test legal event values",
        }], drive_profile="cpu_execute", layout_hash="test-layout", plan_hash="test-plan")
        arm = ProfileCampaignProjector(layout, policy.policy_hash, width, policy=policy)
        return arm, policy

    def test_an_illegal_value_becomes_a_declared_one_and_a_legal_one_is_kept(self) -> None:
        arm, policy = self._layout_and_policy([2, 6])
        for raw in (2, 6):
            self.assertEqual(raw, arm.project(raw))
        for raw in (0, 1, 3, 4, 5, 7, 15):
            projected = arm.project(raw)
            self.assertIn(projected, (2, 6), hex(raw))
            self.assertEqual(project_sample_values(policy, raw, raw_width=4), projected)

    def test_the_projection_never_touches_the_bits_above_the_prefix(self) -> None:
        arm, _ = self._layout_and_policy([2, 6])
        self.assertEqual(0xF0, arm.project(0xF0) & 0xF0)
        self.assertEqual(0x02, arm.project(0xF0) & 0x0F)


# ---------------------------------------------------------------------------
# dependency_repair, field by field
# ---------------------------------------------------------------------------


class DependencyRepairArmTests(unittest.TestCase):
    """One changed raw field changes exactly its own projected field."""

    SLOTS = 3

    def setUp(self) -> None:
        self.plan = ibex_plan()
        self.image, self.layout, self.policy, self.arms = arms_for(
            self.plan, instruction_candidates=self.SLOTS, data_candidates=1,
            data_slot_offset=0x80)
        self.arm = self.arms["dependency_repair"]
        self.program = self.arm.candidate_program

    def _offer_word(self, prefix: str, *, address: int, word: int, be: int = 0xF) -> int:
        """A raw word whose only set bits are one candidate slot's own fields."""
        slot = self.program.slots.slot(prefix)
        raw = 0
        for segment_name, value in (("offer", 1),
                                    ("address", address),
                                    ("data" if slot.kind == "instruction" else "value", word),
                                    ("be", be)):
            field = field_by_role(
                self.layout, "soc_image", f"{slot.segment(segment_name).name}")
            raw = put(raw, field, value)
        return raw

    def _slot_order(self) -> list[str]:
        return [slot.prefix for slot in self.program.slots.slots()]

    def _all_offers(self, **overrides) -> list[int]:
        """Every declared slot offered once, so the program can run.

        The declared program requires each of its slots to be offered exactly
        once per test; a refusal for an unoffered slot is a different check.
        ``overrides`` maps ``slot prefix -> {"address": .., "word": .., "be": ..}``.
        """
        words = []
        for slot in self.program.slots.slots():
            settings = dict(overrides.get(slot.prefix, {}))
            words.append(self._offer_word(
                slot.prefix,
                address=settings.get("address", slot.declared_address),
                word=settings.get(
                    "word", 0x00000013 if slot.kind == "instruction" else 0x1234ABCD),
                be=settings.get("be", 0xF)))
        return words

    def test_each_instruction_candidate_slot_has_its_own_declared_address(self) -> None:
        slots = [slot for slot in self.image.candidates.slots() if slot.kind == "instruction"]
        self.assertEqual(self.SLOTS, len(slots))
        declared = [slot.declared_address for slot in slots]
        self.assertEqual(len(set(declared)), self.SLOTS, declared)
        for slot in slots:
            base, size = self.image.base, self.image.size
            self.assertTrue(base <= slot.declared_address < base + size, slot.prefix)

    def test_one_changed_address_field_changes_only_that_field(self) -> None:
        slot = self.image.candidates.instruction[0]
        legal = slot.declared_address
        # A deliberately wrong, unaligned address inside the region.
        wrong = legal + 4 * 3 + 2
        words = self._all_offers(**{slot.prefix: {"address": wrong}})
        projected = list(self.arm.project_records(words))
        self.assertEqual(len(words), len(projected))
        address_field = field_by_role(self.layout, "soc_image", f"{slot.prefix}_address")
        repaired = segment(projected[0], address_field)
        self.assertNotEqual(wrong, repaired)
        self.assertEqual(0, repaired % 4, "the repair must land on a full word")
        base, size = self.image.base, self.image.size
        self.assertTrue(base <= repaired and repaired + 4 <= base + size)
        self.assertEqual(1, self.arm.repair_counts["address_repair"])
        # Every other field of the word is untouched by the address repair.
        for field in self.layout.fields:
            if field.field_id == address_field.field_id:
                continue
            with self.subTest(field=field.field_id):
                self.assertEqual(segment(words[0], field), segment(projected[0], field))

    def test_a_data_field_is_placed_verbatim_at_the_declared_address(self) -> None:
        slot = self.program.slots.instruction[0]
        words = self._all_offers(**{slot.prefix: {"word": 0x00000013}})
        list(self.arm.project_records(words))
        placements = {item["slot"]: item for item in self.arm.last_repaired_test.placements}
        self.assertEqual(0x00000013, placements[slot.prefix]["word_value"])
        self.assertEqual(slot.declared_address, placements[slot.prefix]["declared_address"])
        # The offer bit survives into the applied word: the image really loads it.
        offer = field_by_role(self.layout, "soc_image", f"{slot.prefix}_offer")
        self.assertEqual(1, segment(words[0], offer))

    def test_every_instruction_slot_is_placed_and_the_counters_say_so(self) -> None:
        words = self._all_offers()
        list(self.arm.project_records(words))
        repaired = self.arm.last_repaired_test
        self.assertEqual(self.SLOTS, repaired.counters["instruction_slots_placed"])
        self.assertEqual(1, repaired.counters["data_slots_placed"])
        # ``slots_offered`` counts every declared slot, instruction and data.
        self.assertEqual(self.SLOTS + 1, repaired.counters["slots_offered"])
        self.assertEqual(self.SLOTS + 1, len(repaired.artifacts["placed_words"]))

    def test_a_data_candidate_lands_at_its_own_declared_address(self) -> None:
        slot = self.program.slots.data[0]
        words = self._all_offers(**{slot.prefix: {"word": 0xDEADBEEF}})
        list(self.arm.project_records(words))
        placements = [item for item in self.arm.last_repaired_test.placements
                      if item["slot"] == slot.prefix]
        self.assertEqual(1, len(placements))
        self.assertEqual("data", placements[0]["kind"])
        self.assertEqual(slot.declared_address, placements[0]["declared_address"])
        self.assertEqual(0xDEADBEEF, placements[0]["word_value"])

    def test_the_program_window_is_its_own_declared_region_not_the_image_entry(self) -> None:
        """The declared program has its own window; the two are not the same.

        The image plan places slot 0 at the declared entry, while the declared
        program places its first slot after the generated entry trampoline and
        prologue.  Conflating them would silently move every candidate.
        """
        self.assertNotEqual(self.image.base, self.program.program_base)
        self.assertEqual(self.program.entry_address, self.image.base)
        base, size = self.program.window()
        self.assertEqual(base, self.program.program_base)
        self.assertEqual(size, self.SLOTS * 4)
        for slot in self.program.slots.instruction:
            self.assertTrue(base <= slot.declared_address < base + size, slot.prefix)
        # A data slot lives in the writable region, not in the code window: the
        # two windows are declared separately and must not be conflated.
        data = self.program.slots.data[0]
        self.assertFalse(base <= data.declared_address < base + size)
        self.assertTrue(self.image.data_base <= data.declared_address
                        < self.image.data_base + self.image.data_size)

    def test_a_raw_word_outside_the_layout_is_refused_by_name(self) -> None:
        words = self._all_offers()
        words.append(1 << (self.layout.raw_width + 1))
        with self.assertRaisesRegex(SocBuildError, "candidate-raw-word-outside-layout"):
            self.arm.project_records(words)

    def test_two_offers_of_the_same_slot_are_refused_as_a_committed_rewrite(self) -> None:
        slot = self.program.slots.instruction[0]
        words = self._all_offers()
        words.append(self._offer_word(slot.prefix, address=slot.declared_address,
                                      word=0x00000033))
        with self.assertRaisesRegex(
                SocBuildError, "repair-would-rewrite-committed-word"):
            self.arm.project_records(words)

    def test_a_missing_instruction_slot_is_refused_rather_than_silently_filled(self) -> None:
        """Every declared instruction slot must be offered exactly once."""
        words = self._all_offers()
        slot = self.program.slots.instruction[1]
        offered = [word for word, prefix in zip(words, self._slot_order())
                   if prefix != slot.prefix]
        with self.assertRaisesRegex(SocBuildError,
                                    "candidate-slot-not-offered:" + slot.prefix):
            self.arm.project_records(offered)

    def test_a_missing_data_slot_is_not_required_by_the_declared_program(self) -> None:
        """The data slot carries no instruction word, so it may be left out.

        ``require_all_slots`` is about the one instruction word per declared
        instruction slot; a data slot is a memory candidate and an unoffered one
        simply contributes nothing.
        """
        words = self._all_offers()
        data = self.program.slots.data[0]
        offered = [word for word, prefix in zip(words, self._slot_order())
                   if prefix != data.prefix]
        list(self.arm.project_records(offered))
        repaired = self.arm.last_repaired_test
        self.assertEqual(0, repaired.counters["data_slots_placed"])
        self.assertEqual(self.SLOTS, repaired.counters["instruction_slots_placed"])

    def test_a_partial_byte_enable_offer_is_refused_not_rounded(self) -> None:
        slot = self.program.slots.instruction[0]
        words = self._all_offers(**{slot.prefix: {"be": 0x3}})
        with self.assertRaisesRegex(SocBuildError, "candidate-offer-not-full-word"):
            self.arm.project_records(words)

    def test_the_placement_records_the_slot_the_address_and_the_source(self) -> None:
        words = self._all_offers()
        list(self.arm.project_records(words))
        repaired = self.arm.last_repaired_test
        self.assertTrue(repaired.image.content_hash)
        self.assertTrue(repaired.image.image)
        artifacts = dict(repaired.artifacts)
        self.assertTrue(artifacts["static_image_hash"].startswith("sha256:"))
        self.assertTrue(artifacts["entry_image_hash"].startswith("sha256:"))
        self.assertEqual(artifacts["program_window"]["base"], self.program.program_base)
        for item in repaired.placements:
            self.assertIn(item["source"], ("fuzz", "directed"))
            self.assertIn("address_hex", item)


# ---------------------------------------------------------------------------
# instruction and target legality
# ---------------------------------------------------------------------------


class InstructionLegalityTests(unittest.TestCase):
    """The one-slot image path: the reference ISA layer repairs and records.

    This layer sits *in front of* the declared-program analyser, so its contract
    is the one an offered instruction meets first.  What it accepts is placed
    verbatim; what it cannot place is refused with the layer's own name, and
    every correction it makes is recorded in ``initialization_records`` -- which
    is what makes "the raw word became *this* executed word" auditable.  The
    declared-program layer's own named refusals are covered by
    ``tests/composition/test_soc_input_repair.py`` and by
    :class:`DeclaredProgramRepairTests` below.
    """

    def setUp(self) -> None:
        self.plan = ibex_plan()
        self.image, self.layout, self.policy, self.arms = arms_for(
            self.plan, instruction_candidates=1, data_candidates=1)
        self.arm = self.arms["dependency_repair"]
        self.slot = self.image.candidates.instruction[0]

    def _offer(self, word: int, *, address: int | None = None, be: int = 0xF) -> int:
        raw = 0
        for role, value in ((f"{self.slot.prefix}_offer", 1),
                            (f"{self.slot.prefix}_address",
                             self.slot.declared_address if address is None else address),
                            (f"{self.slot.prefix}_data", word),
                            (f"{self.slot.prefix}_be", be)):
            raw = put(raw, field_by_role(self.layout, "soc_image", role), value)
        return raw

    def _frozen(self, word: int, *, address: int | None = None, be: int = 0xF,
                project: bool = True):
        """The image the projector froze for one offered candidate.

        ``project=True`` is the arm's own applied word; ``project=False``
        materialises the offered word directly, which is how the reference
        layer's correction is observed (the arm has, by then, already stored the
        corrected word back into the applied word, so a re-materialisation of its
        output is idempotent by construction).
        """
        offered = self._offer(word, address=address, be=be)
        if project:
            values = list(self.arm.project_records([offered]))
            self.assertEqual(1, len(values))
        else:
            values = [offered]
        result = self.image.materialize_many(values)
        self.assertEqual(1, len(result.candidates))
        return result

    def test_a_legal_instruction_is_placed_verbatim(self) -> None:
        result = self._frozen(0x00100093)       # addi x1, x0, 0
        self.assertEqual(1, len(result.initialization_records))
        self.assertEqual(
            0x00100093,
            int(result.initialization_records[0]["corrected_candidate"]["data"]))

    def test_the_reference_layer_really_corrects_an_illegal_encoding(self) -> None:
        """A word the ISA layer cannot place is corrected, never executed raw.

        The projector writes the corrected word back into the applied raw word
        (that is how a later re-materialisation stays idempotent), so the record's
        ``raw_candidate`` and ``corrected_candidate`` agree by the time it is
        read.  The correction is nevertheless observable and attributable: the
        frozen word differs from the offered word, and the run's own
        ``isa_legal_corrections`` counter records that the rule fired.
        """
        direct = self._frozen(0x0000100F, project=False)
        record = direct.initialization_records[0]
        frozen = int(record["corrected_candidate"]["data"])
        self.assertNotEqual(0x0000100F, frozen)
        # The corrected word is one the declared ISA really decodes, which is
        # the property the raw word did not have.
        from myfuzz.composition.soc_candidate_program import decode_word
        decoded = decode_word(frozen)
        self.assertTrue(decoded.name)
        self.assertEqual(["isa_legal"], list(record["rules_applied"]))
        self.assertEqual(1, int(direct.counters["isa_legal_corrections"]))
        # The arm's applied word carries the same correction, so what is driven
        # is what the record says was frozen.
        applied = self._frozen(0x0000100F)
        self.assertEqual(frozen,
                         int(applied.initialization_records[0]["corrected_candidate"]["data"]))

    def test_the_recorded_correction_is_inside_the_declared_slot(self) -> None:
        result = self._frozen(0x0000100F)
        corrected = result.initialization_records[0]["corrected_candidate"]
        self.assertEqual(self.slot.declared_address, int(corrected["address"]))
        self.assertEqual(0xF, int(corrected["be"]))

    def test_a_half_word_byte_enable_is_repaired_to_the_full_word(self) -> None:
        """A candidate is a whole word, so a narrower enable is repaired.

        An instruction is fetched as a word and a half-written word is not a
        program, so the image projection has exactly one legal value for this
        field.  Refusing instead made every real RFuzz campaign fail on its first
        corpus entry, because the mutator legitimately explores byte enables; the
        projection therefore repairs the enable and records the repair, the same
        way it already repairs a misplaced address.
        """
        arm = self.arms["dependency_repair"]
        before = dict(arm.repair_counts)
        result = self._frozen(0x00100093, be=0x3)
        record = result.initialization_records[0]
        self.assertEqual(0xF, int(record["corrected_candidate"]["be"]),
                         "the placed word must be a full-word write")
        self.assertEqual(0x00100093, int(record["corrected_candidate"]["data"]))
        self.assertEqual(int(before.get("byte_enable_repair", 0)) + 1,
                         int(arm.repair_counts.get("byte_enable_repair", 0)),
                         "the repair must be counted, not silent")

    def test_an_address_outside_the_declared_slot_is_repaired_onto_the_slot(self) -> None:
        """An out-of-slot offer is projected onto a legal slot and recorded.

        The refusal case is a plan whose address policy forbids the rewrite
        (``candidate-slot-address-misplaced``), or an address the declared region
        cannot hold at all; what must never happen is an out-of-region address
        being carried into the image unrecorded.
        """
        offered = self.image.base + self.image.size + 4
        result = self._frozen(0x00100093, address=offered)
        frozen = int(result.initialization_records[0]["corrected_candidate"]["address"])
        self.assertTrue(self.image.base <= frozen < self.image.base + self.image.size,
                        hex(frozen))
        self.assertEqual(0, frozen % 4)
        self.assertNotEqual(offered, frozen)
        # The repair is the declared-slot projection: a full aligned word inside
        # the declared slot's own region, never the out-of-region address.
        self.assertLess(frozen + 4, self.image.base + self.image.size)
        self.assertEqual(1, self.image.materialize_many(
            list(self.arm.project_records([self._offer(0x00100093)]))).accepted)


class DeclaredProgramRepairTests(unittest.TestCase):
    """The declared-program arm records what it repaired, at the arm boundary."""

    def setUp(self) -> None:
        self.plan = ibex_plan()
        self.image, self.layout, self.policy, self.arms = arms_for(
            self.plan, instruction_candidates=2, data_candidates=1)
        self.arm = self.arms["dependency_repair"]
        self.program = self.arm.candidate_program

    def _words(self, word: int) -> list[int]:
        words = []
        for slot in self.program.slots.slots():
            raw = 0
            for name, value in (("offer", 1), ("address", slot.declared_address),
                                ("data" if slot.kind == "instruction" else "value",
                                 word if slot.kind == "instruction" else 0),
                                ("be", 0xF)):
                field = field_by_role(
                    self.layout, "soc_image", slot.segment(name).name)
                raw = put(raw, field, value)
            words.append(raw)
        return words

    def _first_slot(self):
        return self.program.slots.instruction[0]

    def test_the_analyser_sees_the_isa_layer_s_corrected_word(self) -> None:
        """The two layers agree on which word is really placed."""
        projected = list(self.arm.project_records(self._words(0x0000100F)))
        self.assertEqual(len(self.program.slots.slots()), len(projected))
        placement = next(item for item in self.arm.last_repaired_test.placements
                         if item["slot"] == self._first_slot().prefix)
        probe = self.image.materialize_many(
            [int(item) & ((1 << self.image.raw_width) - 1) for item in projected])
        corrected = [int(record["corrected_candidate"]["data"])
                     for record in probe.initialization_records
                     if int(record["corrected_candidate"]["address"])
                     == self._first_slot().declared_address]
        self.assertEqual(1, len(corrected), corrected)
        self.assertEqual(corrected[0], int(placement["word_value"]))

    def test_a_word_the_isa_layer_repaired_is_what_the_program_places(self) -> None:
        """The analyser's input is the corrected word, so both layers must agree.

        A word the reference layer cannot place is replaced *before* the declared
        program sees it.  The arm-level obligation is therefore that the
        placement equals the correction the image records -- not that a register
        projection happened, which is decided on the corrected word.  Dependency
        and register refusals of the declared program itself are covered by
        ``tests/composition/test_soc_input_repair.py``.
        """
        words = self._words(0x0004A283)
        projected = list(self.arm.project_records(words))
        placement = next(item for item in self.arm.last_repaired_test.placements
                         if item["slot"] == self._first_slot().prefix)
        probe = self.image.materialize_many(
            [int(item) & ((1 << self.image.raw_width) - 1) for item in projected])
        corrected = [int(record["corrected_candidate"]["data"])
                     for record in probe.initialization_records
                     if int(record["corrected_candidate"]["address"])
                     == self._first_slot().declared_address]
        self.assertEqual(1, len(corrected), corrected)
        self.assertEqual(corrected[0], int(placement["word_value"]))


class MmioLegalityTests(unittest.TestCase):
    """A refused MMIO offer is refused, never rewritten into a legal request."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan("bfm_isolated")
        cls.image, cls.layout, cls.policy, cls.arms = arms_for(cls.plan)
        cls.arm = cls.arms["dependency_repair"]

    def _offer(self, *, selector: int, offset: int, write: int, wdata: int = 0,
               be: int = 0xF) -> int:
        raw = 0
        for role, value in (("stim_offer", 1), ("stim_target_selector", selector),
                            ("stim_offset", offset), ("stim_write", write),
                            ("stim_wdata", wdata), ("stim_be", be)):
            raw = put(raw, field_by_role(self.layout, "soc_stimulus", role), value)
        return raw

    def test_a_legal_offer_is_passed_through_unchanged(self) -> None:
        windows = self.plan.synthetic["parameters"]["WINDOW_BASE"]
        raw = self._offer(selector=0, offset=int(windows[0]), write=0)
        self.assertEqual([raw], list(self.arm.project_records([raw])))

    def test_an_out_of_range_selector_is_carried_not_remapped(self) -> None:
        selector = field_by_role(self.layout, "soc_stimulus", "stim_target_selector")
        raw = self._offer(selector=(1 << selector.width) - 1, offset=0, write=0)
        projected = self.arm.project_records([raw])
        self.assertEqual([raw], list(projected),
                         "the raw offer must reach the driver unchanged")

    def test_the_projection_does_not_apply_the_constraint_policy_to_mmio(self) -> None:
        windows = self.plan.synthetic["parameters"]["WINDOW_BASE"]
        raw = self._offer(selector=0, offset=int(windows[0]), write=1, wdata=0)
        offset = field_by_role(self.layout, "soc_stimulus", "stim_offset")
        self.assertEqual(windows[0], segment(raw, offset))
        self.assertEqual(raw, self.arm.project(raw))


# ---------------------------------------------------------------------------
# peer pulse spacing
# ---------------------------------------------------------------------------


class PeerSpacingTests(unittest.TestCase):
    """A raw peer event plan the model cannot accept is refused before a run."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = peer_plan()
        cls.image, cls.layout, cls.policy, cls.arms = arms_for(cls.plan)
        cls.arm = cls.arms["dependency_repair"]

    def _pulse(self, instance_id: str, slot_name: str, payload_field: str, payload: int) -> int:
        slot = self.plan.peer(instance_id).slot(slot_name) if hasattr(
            self.plan.peer(instance_id), "slot") else next(
            item for item in self.plan.peer(instance_id).slots if item.slot == slot_name)
        raw = 0
        for signal in slot.signals:
            field = next(item for item in self.layout.fields
                         if item.port == signal.top_port)
            if signal.source == "pulse":
                raw = put(raw, field, 1)
            elif signal.source == "payload":
                raw = put(raw, field, payload)
        return raw

    def test_two_pulses_closer_than_the_declared_gap_are_refused(self) -> None:
        uart = next(peer for peer in self.plan.peers if peer.instance_id == "uart0")
        slot = next(item for item in uart.slots if item.slot == "uart.tx_byte")
        raw = self._pulse("uart0", "uart.tx_byte", "payload", 0x31)
        with self.assertRaisesRegex(SocBuildError, "peer-event-gap-violation:uart0"):
            self.arm.project_records([raw, raw])

    def test_a_legal_gap_is_accepted_and_decoded(self) -> None:
        uart = next(peer for peer in self.plan.peers if peer.instance_id == "uart0")
        slot = next(item for item in uart.slots if item.slot == "uart.tx_byte")
        raw = self._pulse("uart0", "uart.tx_byte", "payload", 0x31)
        values = [raw] + [0] * slot.minimum_gap_cycles + [raw]
        projected = self.arm.project_records(values)
        self.assertEqual(len(values), len(projected))
        events = self.arm.last_peer_events
        self.assertEqual(2, len(events))
        self.assertEqual([0, slot.minimum_gap_cycles + 1],
                         [int(item["cycle"]) for item in events])

    def test_all_three_peer_instances_are_present_in_one_composition(self) -> None:
        self.assertEqual({"uart0", "spi0", "gpio0"},
                         {peer.instance_id for peer in self.plan.peers})


# ---------------------------------------------------------------------------
# refusal classification
# ---------------------------------------------------------------------------


class RefusalClassificationTests(unittest.TestCase):
    """A refusal is a named capability gap, never an unclassified exception."""

    def test_an_unknown_plan_revision_is_refused_by_the_layout_builder(self) -> None:
        plan = ibex_plan()
        image = build_image_plan(plan)
        from dataclasses import replace

        forged = replace(image, plan_hash="sha256:" + "0" * 64)
        with self.assertRaisesRegex(Exception, "image-plan-composition-mismatch"):
            combined_input_layout(plan, forged)

    def test_a_projector_cannot_be_built_without_a_valid_address_policy(self) -> None:
        plan = ibex_plan()
        image, layout, policy, _ = arms_for(plan)
        with self.assertRaisesRegex(SocBuildError, "profile-image-address-policy-invalid"):
            ProfileCampaignProjector(
                layout, policy.policy_hash, int(plan.raw_layout["raw_width"]),
                policy=policy, image_plan=image, image_address_policy="guess")

    def test_a_candidate_program_without_an_image_plan_is_refused(self) -> None:
        plan = ibex_plan()
        image, layout, policy, _ = arms_for(plan)
        program = build_candidate_program(plan, instruction_candidates=2,
                                          data_candidates=1)
        with self.assertRaisesRegex(SocBuildError,
                                    "profile-candidate-program-without-an-image-plan"):
            ProfileCampaignProjector(
                layout, policy.policy_hash, int(plan.raw_layout["raw_width"]),
                policy=policy, image_plan=None, candidate_program=program)

    def test_a_malformed_peer_slot_contract_is_refused(self) -> None:
        plan = peer_plan()
        image, layout, policy, _ = arms_for(plan)
        with self.assertRaisesRegex(SocBuildError, "profile-peer-slot-contract-invalid"):
            ProfileCampaignProjector(
                layout, policy.policy_hash, int(plan.raw_layout["raw_width"]),
                policy=policy, image_plan=image,
                peer_slots=({"instance_id": "uart0", "slot": "uart.tx_byte",
                             "minimum_gap_cycles": "many", "pulse_ports": ("p",)},))


if __name__ == "__main__":                          # pragma: no cover
    unittest.main()
