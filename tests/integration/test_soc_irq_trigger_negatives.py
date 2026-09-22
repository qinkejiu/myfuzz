"""Per-trigger interrupt negatives: latch, mask and ID-mapping injection.

Roadmap phase 3 (``docs/superpowers/plans/2026-09-22-soc-next-steps-roadmap.md``)
and Task 2 of ``2026-09-22-soc-interrupt-multisource-implementation.md`` ask for
one thing the existing suites do not do: every *admitted* trigger combination of
the interrupt planner, driven on a real composed SoC, must have its own
source-specific negative for the three ways a multi-source interrupt plan can be
wrong, and each negative must be attributed to the connection/controller rather
than to the peripheral.

Why each class of negative exists, and what it proves here
----------------------------------------------------------

* **Source-specific latch/connection injection.**  Each admitted lane gets the
  one defect that can hide *that* lane and nothing else.  A lane whose input is a
  bounded moment (the three edge-detected triggers, whose converter output is one
  cycle wide) survives to software only because the controller latches it, so its
  ``LATCH_MASK`` bit is removed.  A lane whose input is a held level (``level``,
  and ``pulse`` as ``novagpio`` really behaves) has no load-bearing latch bit, so
  its controller input is pinned to zero instead.  Either way that source must
  fail to close while the other one closes normally.  The run is then put into an
  ``EvidencePackage`` whose attribution is a composition finding, and the
  boundary classifier must return ``composition_defect`` rather than a
  component-internal candidate: a dropped source says something about the
  interrupt path, not about the peripheral, which still latched its condition.
* **Mask injection.**  A wrong controller enable mask must never claim the
  masked source while the unmasked source still closes.  This module runs the
  single-source program (which enables exactly one declared source) against a
  sample that drives *both* sources, so the masked source really pends.  The
  case also carries the warning of the 2026-09-21 report: the aggregate
  ``all_sources_closed`` counter reads 1 in that run while a declared source is
  still pending and was never claimed, so the counter alone is never accepted as
  proof anywhere in this module.
* **ID mapping permutation.**  Swapping which source feeds which controller bit
  must be refused by the independent structure audit (its ``interrupt_paths``
  check re-reads the elaborated vector against the plan).  The run on the same
  mutant is the second half, and it is also where the aggregate counter is shown
  to be worthless as proof: with only the *companion* physically driven, the CPU
  claims id 1 -- the id the plan maps to this module's trigger lane -- and keeps
  claiming it, so ``interrupt_completions`` reaches the declared source count and
  ``all_sources_closed`` reads 1, while no ISR entry ever read a peripheral cause
  at all.  The plan's id-1 instance never asserted anything; the counter says
  closed anyway.
* **A sample without the observable trajectory.**  A sample that never applies an
  event produces no notification, no claim, no clear and no COMPLETE.  That is
  ``not_assessed`` -- the project's own verdict for an unobserved property
  (``soc_input_chain_report.REPLAY_NOT_ASSESSED``, the same convention as
  ``soc_peer_oracle``) -- never ``pass``.

What the frozen admission is
----------------------------

``component_profile.INTERRUPT_TRIGGERS`` is the admitted set:
``level``, ``pulse``, ``rising_edge``, ``falling_edge``, ``both_edges``.
``level`` and ``pulse`` are wired straight into the controller;
``rising_edge``/``falling_edge``/``both_edges`` pass through
``soc_irq_edge_detect``.  ``pulse``, ``rising_edge``, ``falling_edge`` and
``both_edges`` ask the controller to latch; ``level`` does not.  All five are
driven here on the same two-source topology -- the trigger-under-test source as
source id 1, a plain ``level`` companion as source id 2 -- so every negative is
phrased as "source 1 changed, source 2 did not".

Honest limits, stated in the tests themselves
---------------------------------------------

The peripheral used here (``novagpio``) *holds* its interrupt condition as a
level; it does not emit a bounded pulse.  The declared ``pulse`` trigger is
therefore a profile claim about a source shape this RTL does not physically
produce, so clearing the pulse lane's latch bit is not load-bearing and the run
still closes.  That is asserted explicitly rather than glossed over (the pulse
class's own extra test, which compiles that mutant too): the ``pulse`` lane's
drop negative is the connection injection, and the latch semantics of a real
bounded pulse are covered where such a pulse exists --
``soc_irq_edge_detect``'s one-cycle output for the three edge triggers, and the
controller's own RTL verification.

The per-source evidence available from the generated program is bounded by its
report block: the *first* claim id, the total completion count, the last ISR
entry's pending word and the first non-zero cause it read.  Every assertion below
uses those per-source fields, and every run's whole trajectory is printed as
``MYFUZZ_IRQ_NEG_REPORT`` so the reading is in the log rather than only in an
assertion.

Injection never edits the checked-in RTL
----------------------------------------

Every injection rewrites a *rendered top* that has been written to a temporary
file outside ``src/``; the checked-in ``soc_irq_controller.sv`` and
``soc_irq_edge_detect.sv`` are only ever read, and each real class re-hashes them
after its builds (``test_the_injection_never_edits_the_real_rtl``).

The pure half of this module (admission, rendered mutation targets, the
``not_assessed`` rule) runs with no toolchain.  The real-RTL half is gated by
``MYFUZZ_SOC_REAL=1``; when that flag is set nothing here skips, and a missing
simulator is a failure that names Verilator.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import unittest
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from myfuzz.composition.component_profile import (
    INTERRUPT_EDGE_PARAMETER,
    INTERRUPT_TRIGGERS,
    INTERRUPT_TRIGGERS_DIRECT,
    INTERRUPT_TRIGGERS_EDGE_DETECTED,
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.input_constraints import compile_input_constraints
from myfuzz.composition.soc_boot_program import (
    ProgramRequest,
    build_boot_program,
    image_hex,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_defect_confirmation import confirm_component_defect
from myfuzz.composition.soc_failure_evidence import (
    COMPONENT_CANDIDATE,
    COMPOSITION_DEFECT,
    build_evidence_package,
    classify_boundary,
    replay_package,
)
from myfuzz.composition.soc_input_chain_report import (
    REPLAY_AGREEMENT,
    REPLAY_NOT_ASSESSED,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    ExternalEvent,
    RuntimeSample,
    SocRuntimeError,
    build_profile_runtime,
    run_sample,
)
from myfuzz.composition.soc_structure_audit import FAIL, PASS, audit_structure

from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_dependency_replay import applied_legality
from tests.integration.test_soc_irq_edge_lifecycle import read32

OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"

IBEX_PROFILE = "configs/cpus/ibex/component_profile.json"
GPIO_PROFILE = "examples/soc_generation/profiles/novagpio.json"
REQUEST_FILE = "examples/soc_generation/request-ibex.json"
#: Scratch composition inputs.  A patched profile is a *new* file, so it must
#: live under the repository root for the request's relative reference to
#: resolve; nothing checked in is touched.
SCRATCH = ROOT / "runs/irq-trigger-negatives"

#: This module's trigger-under-test source and its plain level companion.  The
#: names sort so that ``atrig0`` is source id 1 and ``blevel0`` is source id 2:
#: the planner numbers sources by stable instance id, and every negative below
#: is phrased as "source 1 changed, source 2 did not".
TRIGGER_INSTANCE = "atrig0"
LEVEL_INSTANCE = "blevel0"
TRIGGER_WINDOW = 0x4000_0000
LEVEL_WINDOW = 0x4000_1000

#: The bounded pulse the ``pulse`` trigger declares.  ``novagpio`` holds its
#: condition, so this width is only the declared capture contract; see the module
#: docstring for what that means for the pulse lane's latch negative.
PULSE_WIDTH_CYCLES = 2

#: One sample window.  The runtime refuses samples longer than its own
#: ``MAX_CYCLES`` (65536); 20000 leaves room for the generated program's bounded
#: poll and for the *late* companion event at cycle 12000.
CYCLES = 20000
#: The trigger source is driven low, then all-ones, inside the window the
#: generated program's own bounded poll covers.
TRIGGER_LOW_CYCLE = 2048
TRIGGER_HIGH_CYCLE = 3072
#: The companion level source is deliberately driven *later*.  The trigger-under-
#: test lane must own the first claim in every baseline, which is what makes
#: ``claim_id`` a per-source observation for the lane under test: a falling-edge
#: source can only be claimed after software clears the held condition it
#: converts, so a companion that arrives later keeps the two lanes' evidence
#: distinguishable for every trigger kind.
COMPANION_LOW_CYCLE = 11000
COMPANION_HIGH_CYCLE = 12000

#: The controller's bitmap bit for source id k is bit k (bit 0 is reserved, see
#: ``soc_irq_controller.sv``), so a source's own enable/pending bit is ``1 << k``.
LATCHED_TRIGGERS = ("pulse",) + INTERRUPT_TRIGGERS_EDGE_DETECTED


def bitmap_bit(source_id: int) -> int:
    """The controller bitmap bit that belongs to one source id."""
    return 1 << source_id


#: The report fields that make up one run's notify -> claim -> clear ->
#: COMPLETE trajectory.  :func:`assess_irq_trajectory` reads exactly these.
TRAJECTORY_FIELDS = (
    "claim_id",
    "handler_entries",
    "pending_before_claim",
    "cause_before_clear",
    "cause_after_clear",
    "complete_accepted",
    "interrupt_completions",
    "all_sources_closed",
    "loop_closed",
    "final_in_service",
)
TRAJECTORY_PASS = "pass"
TRAJECTORY_INCOMPLETE = "incomplete"

RTL_SOURCES = (
    "src/myfuzz/protocols/rtl/soc_irq_controller.sv",
    "src/myfuzz/protocols/rtl/soc_irq_edge_detect.sv",
)

_LATCH = re.compile(r"\.LATCH_MASK\((\d+)'b([01]+)\)")
_SOURCE_VECTOR = re.compile(r"\.source_i\(\{([^{}]+)\}\)")
_EDGE_DETECT = re.compile(r"\.EDGE\((\d+)\), \.PULSE_CYCLES\((\d+)\), \.RESET_LEVEL\((\d+)\)\)")


class TriggerNegativeError(AssertionError):
    """One of this module's own premises about the rendered plan did not hold."""


def _require_verilator() -> str:
    """Verilator, or a skip without the opt-in and a *named failure* with it."""
    tool = shutil.which("verilator")
    if tool is None:
        reason = ("verilator is required for the independent interrupt structure "
                  "audit (with MYFUZZ_SOC_REAL=1 this is a failure, never a skip)")
        if OPT_IN:
            raise AssertionError(reason)
        raise unittest.SkipTest(reason)
    return tool


def _replace_once(text: str, pattern: re.Pattern[str], replacement: str, *,
                  what: str) -> str:
    """One injection: exactly one rewrite, or a failure naming the target."""
    value, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise TriggerNegativeError(
            f"the injection target for {what} was not found exactly once in the "
            f"rendered top (matches={count}); pattern={pattern.pattern!r}")
    if value == text:
        raise TriggerNegativeError(f"the {what} injection changed nothing")
    return value


def _rtl_hashes() -> dict[str, str]:
    return {name: "sha256:" + hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in RTL_SOURCES}


# ---------------------------------------------------------------------------
# the frozen per-trigger plan and its rendered mutation targets
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MutationTargets:
    """The exact spans of one rendered top that the three injections rewrite.

    Every span is derived from the plan (the latch mask the controller was
    rendered with, the net each source id lands on), then *checked* against the
    rendered text, so an injection can never silently rewrite the wrong lane.
    """

    latch_literal: str
    latch_width: int
    latch_mask: int
    source_vector: str
    source_leaves: tuple[str, ...]
    source_ids: tuple[int, ...]

    def leaf_for(self, source_id: int) -> str:
        """The rendered net that carries one source id."""
        index = self.leaf_index(source_id)
        return self.source_leaves[index]

    def leaf_index(self, source_id: int) -> int:
        """One source id's leaf index in the MSB-first rendered vector."""
        if source_id not in self.source_ids:
            raise TriggerNegativeError(f"no rendered net for source id {source_id}")
        return self.source_ids.index(source_id)


def _source_leaf(plan, source_id: int) -> str:
    """The net one source id is rendered on: converter output, or the raw port."""
    record = next(item for item in plan.interrupt_document["sources"]
                  if int(item["source_id"]) == source_id)
    if str(record["normalizer"].get("kind")) == "edge_detect":
        return f"irq_src_{source_id}"
    return f"{record['instance_id']}__{record['port']}"


def _mutation_targets(plan, top: str) -> MutationTargets:
    latch = _LATCH.search(top)
    if latch is None:
        raise TriggerNegativeError("the rendered top has no LATCH_MASK literal")
    vector = _SOURCE_VECTOR.search(top)
    if vector is None:
        raise TriggerNegativeError("the rendered top has no source_i vector")
    leaves = tuple(item.strip() for item in vector.group(1).split(","))
    # MSB first: the highest declared source id is the leftmost leaf, which is
    # also the order the renderer emits and the audit re-reads.
    source_ids = tuple(sorted((int(item["source_id"])
                               for item in plan.interrupt_document["sources"]),
                              reverse=True))
    if len(leaves) != len(source_ids):
        raise TriggerNegativeError(
            f"the rendered source vector has {len(leaves)} leaves for "
            f"{len(source_ids)} declared sources")
    for leaf, identifier in zip(leaves, source_ids):
        expected = _source_leaf(plan, identifier)
        if leaf != expected:
            raise TriggerNegativeError(
                f"source id {identifier} is rendered on {leaf!r}, not the plan's own "
                f"net {expected!r}")
    mask = int(latch.group(2), 2)
    if mask != int(plan.interrupt_document["controller"]["latch_mask"]):
        raise TriggerNegativeError("the rendered LATCH_MASK is not the plan's own mask")
    return MutationTargets(latch_literal=latch.group(0), latch_width=int(latch.group(1)),
                           latch_mask=mask, source_vector=vector.group(0),
                           source_leaves=leaves, source_ids=source_ids)


def latch_cleared_top(top: str, targets: MutationTargets, source_id: int) -> str:
    """One source's latch bit removed; every other bit kept."""
    mask = targets.latch_mask & ~(1 << (source_id - 1))
    literal = f"{targets.latch_width}'b{mask:0{targets.latch_width}b}"
    return _replace_once(top, _LATCH, f".LATCH_MASK({literal})",
                         what=f"latch mask {literal}")


def source_pinned_top(top: str, targets: MutationTargets, source_id: int) -> str:
    """One source's controller input pinned to zero, the other left alone."""
    leaves = list(targets.source_leaves)
    leaves[targets.leaf_index(source_id)] = "1'b0"
    return _replace_once(top, _SOURCE_VECTOR,
                         ".source_i({%s})" % ", ".join(leaves),
                         what=f"source id {source_id} pinned low")


def swapped_top(top: str, targets: MutationTargets) -> str:
    """The two sources' controller bit assignment exchanged."""
    return _replace_once(top, _SOURCE_VECTOR,
                         ".source_i({%s})" % ", ".join(reversed(targets.source_leaves)),
                         what="the two source net assignments swapped")


def drop_injection(trigger: str, top: str, targets: MutationTargets) -> str:
    """The source-specific drop negative for one admitted trigger.

    An edge-detected lane's converter emits a bounded pulse, so its latch bit is
    what keeps the event alive until software claims it: removing that one bit is
    the defect.  A directly wired lane has no pulse to lose -- ``level`` has no
    latch bit at all (its mask bit is 0 by admission) and ``pulse``'s declared
    moment is not what ``novagpio`` physically emits -- so for those two the
    equivalent source-specific defect is pinning the lane's controller input to
    zero, which is the same "that one lane never becomes pending" injection.
    """
    if trigger in INTERRUPT_TRIGGERS_EDGE_DETECTED:
        return latch_cleared_top(top, targets, 1)
    return source_pinned_top(top, targets, 1)


@dataclass(frozen=True, slots=True)
class TriggerPlan:
    """One admitted trigger's composed plan, rendered top and mutation targets."""

    trigger: str
    plan: object
    top: str
    targets: MutationTargets
    sources: tuple[str, ...]
    include_roots: tuple[str, ...]

    def audit(self, top_text: str) -> dict[str, object]:
        """The independent structure audit over one rendered top."""
        return audit_structure(
            self.plan, top_text=top_text, source_files=list(self.sources),
            base_dir=ROOT, include_roots=list(self.include_roots))


_PLANS: dict[str, TriggerPlan] = {}


def trigger_plan(trigger: str) -> TriggerPlan:
    """The one plan/render for one trigger, built once and shared by every class."""
    existing = _PLANS.get(trigger)
    if existing is not None:
        return existing
    if trigger not in INTERRUPT_TRIGGERS:
        raise TriggerNegativeError(f"{trigger!r} is not an admitted trigger")
    document = json.loads((ROOT / GPIO_PROFILE).read_text(encoding="utf-8"))
    declared = document["interrupts"][0]
    declared["trigger"] = trigger
    if trigger == "pulse":
        declared["pulse_width_cycles"] = PULSE_WIDTH_CYCLES
    SCRATCH.mkdir(parents=True, exist_ok=True)
    profile_path = SCRATCH / f"negatives-{trigger}.json"
    profile_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
    relative = profile_path.relative_to(ROOT).as_posix()

    request_document = json.loads((ROOT / REQUEST_FILE).read_text(encoding="utf-8"))
    request_document["request_id"] = f"ibex-irq-trigger-negatives-{trigger}"
    request_document["peripherals"] = [
        {"instance_id": TRIGGER_INSTANCE, "profile": relative, "parameters": {},
         "address": TRIGGER_WINDOW},
        {"instance_id": LEVEL_INSTANCE, "profile": GPIO_PROFILE, "parameters": {},
         "address": LEVEL_WINDOW},
    ]
    profiles: dict = {}
    for reference in (IBEX_PROFILE, relative, GPIO_PROFILE):
        profile = load_component_profile(ROOT / reference)
        profiles[reference] = profile
        profiles.setdefault(profile.component_id, profile)
    request = load_composition_request(request_document, profiles=profiles)
    plan = build_composition(request, base_dir=ROOT)

    records = source_list(plan)
    source_files = tuple(item["path"] for item in records if item["role"] != "include_root")
    include_roots = tuple(sorted({item["path"] for item in records
                                  if item["role"] == "include_root"}))
    top = render_composition(plan)["myfuzz_soc_top.sv"]
    result = TriggerPlan(trigger=trigger, plan=plan, top=top,
                         targets=_mutation_targets(plan, top),
                         sources=source_files, include_roots=include_roots)
    _PLANS[trigger] = result
    return result


def _source_record(plan, instance_id: str) -> dict:
    for item in plan.interrupt_document["sources"]:
        if str(item["instance_id"]) == instance_id:
            return item
    raise TriggerNegativeError(f"the plan has no {instance_id} source")


# ---------------------------------------------------------------------------
# the pure half: admission, rendered mutation targets and the not_assessed rule
# ---------------------------------------------------------------------------


class TriggerAdmissionTests(unittest.TestCase):
    """The admitted trigger set is frozen, not discovered at run time."""

    def test_the_admitted_set_is_the_declared_five(self) -> None:
        self.assertEqual(("level", "pulse", "rising_edge", "falling_edge", "both_edges"),
                         INTERRUPT_TRIGGERS)
        self.assertEqual(("level", "pulse"), INTERRUPT_TRIGGERS_DIRECT)
        self.assertEqual(("rising_edge", "falling_edge", "both_edges"),
                         INTERRUPT_TRIGGERS_EDGE_DETECTED)
        self.assertEqual({"rising_edge": 0, "falling_edge": 1, "both_edges": 2},
                         dict(INTERRUPT_EDGE_PARAMETER))
        self.assertEqual(("pulse", "rising_edge", "falling_edge", "both_edges"),
                         LATCHED_TRIGGERS)

    def test_every_admitted_trigger_has_its_own_composed_lane(self) -> None:
        for trigger in INTERRUPT_TRIGGERS:
            with self.subTest(trigger=trigger):
                fixture = trigger_plan(trigger)
                self.assertEqual(
                    [(TRIGGER_INSTANCE, 1, trigger), (LEVEL_INSTANCE, 2, "level")],
                    [(item["instance_id"], int(item["source_id"]), item["trigger"])
                     for item in fixture.plan.interrupt_document["sources"]])
                self.assertEqual(1 if trigger in LATCHED_TRIGGERS else 0,
                                 fixture.plan.interrupt_document["controller"]["latch_mask"],
                                 trigger)

    def test_each_trigger_renders_the_converter_it_declares(self) -> None:
        for trigger in INTERRUPT_TRIGGERS:
            with self.subTest(trigger=trigger):
                fixture = trigger_plan(trigger)
                support = fixture.plan.interrupt_document["trigger_support"]
                converted = trigger in INTERRUPT_TRIGGERS_EDGE_DETECTED
                # The companion lane is a level source in every topology, so the
                # trigger lane's own kind is what has to appear in the right list.
                self.assertEqual(converted, trigger in support["edge_detected"])
                self.assertEqual(not converted, trigger in support["direct"])
                self.assertIn("level", support["direct"])
                match = _EDGE_DETECT.search(fixture.top)
                if converted:
                    self.assertIsNotNone(match, fixture.top)
                    self.assertEqual(str(INTERRUPT_EDGE_PARAMETER[trigger]), match.group(1))
                else:
                    self.assertIsNone(match, "a directly wired source grew a converter")
                self.assertIn(_source_leaf(fixture.plan, 1), fixture.targets.source_leaves)

    def test_the_rendered_latch_literal_is_the_plan_mask(self) -> None:
        for trigger in INTERRUPT_TRIGGERS:
            with self.subTest(trigger=trigger):
                fixture = trigger_plan(trigger)
                mask = fixture.plan.interrupt_document["controller"]["latch_mask"]
                self.assertEqual(f".LATCH_MASK({fixture.targets.latch_width}'b"
                                 f"{mask:0{fixture.targets.latch_width}b})",
                                 fixture.targets.latch_literal)

    def test_every_injection_target_is_unique_and_changes_the_top(self) -> None:
        for trigger in INTERRUPT_TRIGGERS:
            with self.subTest(trigger=trigger):
                fixture = trigger_plan(trigger)
                targets = fixture.targets
                pinned = source_pinned_top(fixture.top, targets, 1)
                swapped = swapped_top(fixture.top, targets)
                self.assertNotEqual(fixture.top, pinned)
                self.assertNotEqual(fixture.top, swapped)
                self.assertNotEqual(pinned, swapped)
                self.assertIn("1'b0", pinned)
                self.assertIn(targets.leaf_for(2), pinned,
                              "the companion lane must survive the source-1 injection")
                if trigger in LATCHED_TRIGGERS:
                    cleared = latch_cleared_top(fixture.top, targets, 1)
                    self.assertNotEqual(fixture.top, cleared)
                    self.assertIn(f".LATCH_MASK({targets.latch_width}'b0", cleared)
                    self.assertIn(targets.leaf_for(1), cleared,
                                  "the latch injection must not touch the wiring")


class IdMappingPermutationAuditTests(unittest.TestCase):
    """The independent audit refuses a permuted source-to-controller mapping.

    This is the structural half of the ID-permutation negative.  It needs
    Verilator's SystemVerilog frontend (the audit re-elaborates the published
    RTL); without the opt-in a missing tool is a skip, with ``MYFUZZ_SOC_REAL=1``
    it is a failure that names the tool.

    The audit's refusal of a wrongly rendered ``LATCH_MASK`` is *not* re-covered
    here: ``tests/composition/test_soc_interrupt_triggers.py`` already asserts it
    (``test_the_audit_fails_when_the_latch_mask_is_wrong``), and this module's
    latch negative is the real run plus its boundary classification.
    """

    def setUp(self) -> None:
        _require_verilator()

    def test_the_pristine_top_passes_and_the_swapped_top_fails(self) -> None:
        # The control audit runs for one directly wired and one converted lane:
        # those are the only two renderer shapes, and every pristine top has to
        # pass before its mutant's refusal means anything.
        for trigger in ("level", "rising_edge"):
            with self.subTest(trigger=trigger):
                fixture = trigger_plan(trigger)
                pristine = fixture.audit(fixture.top)
                self.assertEqual(PASS, pristine["summary"]["status"],
                                 {item["check_id"]: item["status"]
                                  for item in pristine["findings"] if item["status"] != PASS})
                paths = [item for item in pristine["findings"]
                         if item["check_id"] == "interrupt_paths"]
                self.assertEqual(1, len(paths))
                self.assertEqual(PASS, paths[0]["status"], paths[0])

        for trigger in INTERRUPT_TRIGGERS:
            with self.subTest(trigger=trigger):
                fixture = trigger_plan(trigger)
                audit = fixture.audit(swapped_top(fixture.top, fixture.targets))
                finding = next(item for item in audit["findings"]
                               if item["check_id"] == "interrupt_paths")
                self.assertEqual(FAIL, finding["status"], finding)
                self.assertEqual(FAIL, audit["summary"]["status"], audit["summary"])
                # The refusal names the physical nets it re-read, in the permuted
                # order, so it is a statement about this mutant rather than a
                # generic failure of the audit.
                bits = tuple(finding["actual"]["bits_msb_first"])
                self.assertEqual(tuple(reversed(fixture.targets.source_leaves)), bits)
                self.assertEqual(_source_leaf(fixture.plan, 1), bits[0],
                                 "controller bit 1 now carries source id 1's net")
                self.assertEqual(f"{LEVEL_INSTANCE}__irq_o", bits[1],
                                 "controller bit 0 now carries the companion's net")


# ---------------------------------------------------------------------------
# the trajectory assessment: an unobserved trajectory is not a pass
# ---------------------------------------------------------------------------


def assess_irq_trajectory(values: Mapping[str, int], *,
                          declared_sources: int) -> tuple[str, str]:
    """The project's ``not_assessed`` rule applied to one interrupt report block.

    ``values`` is the report block of one run, read by the field names the
    generated program writes (``soc_boot_program.REPORT_FIELDS``).  The rule is
    the project's own, taken from ``soc_input_chain_report``/``soc_peer_oracle``:
    a property nobody observed is ``not_assessed``, never ``pass``.

      * ``not_assessed`` -- the run recorded no part of the notify -> claim ->
        clear -> COMPLETE trajectory, so the experiment exercised nothing and
        closure may not be inferred in either direction;
      * ``incomplete``   -- part of the trajectory is there and part is missing
        (the shape of every injected fault in this module);
      * ``pass``         -- every declared source's trajectory record is present
        and the aggregate agrees: the run closed with every source claimed by its
        declared id, its condition cleared and COMPLETE accepted.
    """
    if values.get("handler_entries", 0) == 0 and values.get("claim_id", 0) == 0 \
            and values.get("pending_before_claim", 0) == 0 \
            and values.get("interrupt_completions", 0) == 0:
        return REPLAY_NOT_ASSESSED, (
            "the run recorded no notification, no pending bit, no claim and no "
            "completion, so the interrupt trajectory was never observed")
    closed = (values.get("interrupt_completions", 0) == declared_sources
              and values.get("all_sources_closed", 0) == 1
              and values.get("complete_accepted", 0) == 1
              and values.get("cause_before_clear", 0) != 0
              and values.get("cause_after_clear", 0) == 0
              and values.get("final_in_service", 0) == 0
              and values.get("claim_id", 0) > 0)
    if closed:
        return TRAJECTORY_PASS, (
            f"all {declared_sources} declared source(s) recorded pending, a claim id, "
            f"a cleared condition and an accepted COMPLETE")
    return TRAJECTORY_INCOMPLETE, (
        "the run recorded part of the trajectory but not a closed loop for every "
        "declared source: " + ", ".join(f"{name}={values.get(name)}"
                                        for name in TRAJECTORY_FIELDS))


class MissingTrajectoryTests(unittest.TestCase):
    """A sample without a recorded trajectory is ``not_assessed``, not ``pass``."""

    def test_a_report_without_replay_evidence_is_not_assessed(self) -> None:
        """The project's own rule on the project's own report API.

        ``build_chain_report``'s replay section is the applied-trajectory
        comparison; its documented behaviour with no trajectory recorded is
        ``not_assessed``.  The report is pure: it reads no simulator and no files.
        """
        from tests.integration.test_soc_input_chain_report import (
            ChainFixture,
            chain_outcomes,
            report_for,
        )

        fixture = ChainFixture()
        outcomes, _replays = chain_outcomes(fixture)
        report = report_for(fixture, outcomes, None)
        replay = report["replay"]
        self.assertEqual(REPLAY_NOT_ASSESSED, replay["status"], replay["reason"])
        self.assertNotEqual(REPLAY_AGREEMENT, replay["status"])
        self.assertIn("no replay evidence", replay["reason"])
        self.assertIsNone(replay["divergence"])

    def test_the_trajectory_rule_reads_the_whole_loop(self) -> None:
        """The rule is not vacuous: absence, partiality and closure differ."""
        absent = {name: 0 for name in TRAJECTORY_FIELDS}
        verdict, reason = assess_irq_trajectory(absent, declared_sources=2)
        self.assertEqual(REPLAY_NOT_ASSESSED, verdict)
        self.assertNotEqual(TRAJECTORY_PASS, verdict)
        self.assertIn("never observed", reason)

        closed = dict(absent, claim_id=1, handler_entries=2, pending_before_claim=2,
                      cause_before_clear=1, complete_accepted=1,
                      interrupt_completions=2, all_sources_closed=1, loop_closed=1)
        self.assertEqual(TRAJECTORY_PASS,
                         assess_irq_trajectory(closed, declared_sources=2)[0])

        # An aggregate counter that says "closed" while one declared source was
        # never claimed is exactly the 2026-09-21 warning, so it must not pass.
        aggregate_only = dict(closed, interrupt_completions=1)
        self.assertEqual(TRAJECTORY_INCOMPLETE,
                         assess_irq_trajectory(aggregate_only, declared_sources=2)[0])


# ---------------------------------------------------------------------------
# the real half
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReportRun:
    """One executed run plus the report block the generated program wrote."""

    label: str
    program: object
    result: object
    layout: Mapping[str, int]
    sample: RuntimeSample

    def report(self, name: str) -> int:
        if name not in self.layout:
            raise TriggerNegativeError(f"the program declares no report field {name}")
        return read32(self.result, int(self.program.report_address) + int(self.layout[name]))

    def trajectory(self, declared_sources: int) -> tuple[str, str]:
        return assess_irq_trajectory(
            {name: self.report(name) for name in TRAJECTORY_FIELDS},
            declared_sources=declared_sources)


class TriggerSoC:
    """One trigger lane's real two-source SoC: builds, samples and runs.

    Built once per class from the shared :func:`trigger_plan`.  Every injected top
    is written to a temporary file outside ``src/`` and compiled from there, and
    one admitted program image is reused across the runs, so a difference between
    two runs is a difference in the top or in the applied sample -- never in the
    plan, the program or the build flags.
    """

    def __init__(self, trigger: str) -> None:
        self.trigger = trigger
        self.fixture = trigger_plan(trigger)
        self.plan = self.fixture.plan
        self.declared_sources = len(self.plan.interrupt_document["sources"])
        self.rtl_hashes_before = _rtl_hashes()
        self.temporary = tempfile.TemporaryDirectory(prefix=f"myfuzz-irq-neg-{trigger}-")
        self.root = Path(self.temporary.name)
        self.notes: dict[str, object] = {}

        # -- the injected tops, as temporary copies --------------------------
        self.tops = {
            "baseline": self.fixture.top,
            "injected": drop_injection(trigger, self.fixture.top, self.fixture.targets),
            "swapped": swapped_top(self.fixture.top, self.fixture.targets),
        }
        if trigger == "pulse":
            # The negative control the module docstring explains: novagpio holds
            # its condition, so this mutant must still close.
            self.tops["latch_cleared"] = latch_cleared_top(
                self.fixture.top, self.fixture.targets, 1)
        self.top_paths: dict[str, Path] = {}
        for label, text in self.tops.items():
            path = self.root / f"{label}.top.sv"
            path.write_text(text, encoding="utf-8")
            self.top_paths[label] = path
        self.top_hashes = {label: "sha256:" + hashlib.sha256(text.encode()).hexdigest()
                           for label, text in self.tops.items()}

        # -- programs and images ---------------------------------------------
        self.multi = build_boot_program(self.plan,
                                        request=ProgramRequest(exercise_all_sources=True))
        self.single = build_boot_program(self.plan, request=ProgramRequest())
        self.no_trigger = build_boot_program(
            self.plan, request=ProgramRequest(exercise_all_sources=True,
                                              trigger_event=False))
        self.layout = {str(item["name"]): int(item["offset"])
                       for item in self.multi.document["report"]["layout"]}
        self.images: dict[str, Path] = {}
        for label, program in (("multi", self.multi), ("single", self.single),
                               ("no_trigger", self.no_trigger)):
            path = self.root / f"{label}.hex"
            path.write_text(image_hex(program.image), encoding="utf-8")
            self.images[label] = path

        # -- what the mask injection is: exactly one source is enabled --------
        enables = {int(item["source_id"]): bool(item["controller_enable"]["enabled"])
                   for item in self.single.document["sources"]}
        self.notes["single_enables"] = enables
        if not enables[1] or enables[2]:
            raise TriggerNegativeError(
                "the single-source program is expected to enable exactly the trigger "
                f"lane (id 1); enables={enables}")

        # -- the samples ------------------------------------------------------
        self.samples = {
            # The companion arrives later, so the lane under test owns the first
            # claim in every baseline.
            "late": self.sample({"atrig": (TRIGGER_LOW_CYCLE, TRIGGER_HIGH_CYCLE),
                                 "companion": (COMPANION_LOW_CYCLE,
                                               COMPANION_HIGH_CYCLE)},
                                request_id=1),
            # Both lanes arrive together: the mask case needs the masked source
            # pending while the unmasked one is claimed.
            "early": self.sample({"atrig": (TRIGGER_LOW_CYCLE, TRIGGER_HIGH_CYCLE),
                                  "companion": (TRIGGER_LOW_CYCLE, TRIGGER_HIGH_CYCLE)},
                                 request_id=2),
            # Only the companion is driven: the permuted-mapping case.
            "companion_only": self.sample({"companion": (TRIGGER_LOW_CYCLE,
                                                         TRIGGER_HIGH_CYCLE)},
                                          request_id=3),
            # The deliberately trajectory-free sample: no event at all.
            "empty": RuntimeSample(request_id=4, raw=(0,) * CYCLES, events=()),
        }

        # -- builds -----------------------------------------------------------
        wrapped = self._verilator()
        self.builds = {label: self._build(label, path, self.images["multi"], wrapped)
                       for label, path in self.top_paths.items()}

        # -- runs -------------------------------------------------------------
        self.runs: dict[str, ReportRun] = {}
        self.runs["baseline"] = self._run(
            "baseline", "baseline", "multi", "late", request_id=11)
        self.runs["injected"] = self._run(
            "injected", "injected", "multi", "late", request_id=12)
        self.runs["swapped"] = self._run(
            "swapped", "swapped", "multi", "companion_only", request_id=13)
        self.runs["mask"] = self._run(
            "mask", "baseline", "single", "early", request_id=14)
        self.runs["no_trajectory"] = self._run(
            "no_trajectory", "baseline", "no_trigger", "empty", request_id=15)
        if "latch_cleared" in self.builds:
            self.runs["pulse_latch"] = self._run(
                "pulse_latch", "latch_cleared", "multi", "late", request_id=16)
        self.notes["run_status"] = {label: run.result.status
                                    for label, run in sorted(self.runs.items())}
        self.notes["build_hash"] = {label: build.build_hash
                                    for label, build in sorted(self.builds.items())}

    # -- construction helpers ---------------------------------------------

    def sample(self, schedule: Mapping[str, tuple[int, int]], *,
               request_id: int) -> RuntimeSample:
        """Drive each named lane's declared pin low, then all-ones.

        The pin, slot and width come from the generated program's own trigger
        document; only the cycles are rescheduled, so a sample can never invent an
        input the plan does not own.
        """
        templates: dict[str, dict] = {}
        for item in self.multi.document["trigger"]["events"]:
            instance = str(item["name"]).split("__", 1)[0]
            templates.setdefault(instance, item)
        if set(templates) != {TRIGGER_INSTANCE, LEVEL_INSTANCE}:
            raise TriggerNegativeError(f"unexpected trigger lanes: {sorted(templates)}")
        events: list[ExternalEvent] = []
        for instance in sorted(templates):
            key = "atrig" if instance == TRIGGER_INSTANCE else "companion"
            if key not in schedule:
                continue
            item = templates[instance]
            low, high = schedule[key]
            events.append(ExternalEvent(slot=int(item["slot"]), cycle=low, value=0))
            events.append(ExternalEvent(slot=int(item["slot"]), cycle=high,
                                        value=(1 << int(item["width"])) - 1))
        events.sort(key=lambda item: (item.cycle, item.slot))
        return RuntimeSample(request_id=request_id, raw=(0,) * CYCLES,
                             events=tuple(events))

    def _verilator(self) -> str:
        tool = shutil.which("verilator")
        if tool is None:
            raise AssertionError("Verilator is required for the real per-trigger negatives")
        flags = [f"-I{ROOT / item}" for item in self.fixture.include_roots]
        for instance in self.plan.instances:
            elaboration = getattr(instance.profile.source, "elaboration", None)
            for name, value in getattr(elaboration, "defines", ()) or ():
                flags.append(f"-D{name}={value}")
        if not flags:
            return tool
        wrapper = self.root / "verilator-with-profile-flags.sh"
        wrapper.write_text("#!/bin/sh\nexec %s %s \"$@\"\n" % (tool, " ".join(flags)),
                           encoding="utf-8")
        wrapper.chmod(0o755)
        return wrapper.as_posix()

    def _build(self, label: str, top_path: Path, image: Path, tool: str):
        last: Exception | None = None
        for attempt in (1, 2):
            output = self.root / f"build-{label}"
            if output.exists():
                shutil.rmtree(output)
            try:
                return build_profile_runtime(
                    self.plan, output_dir=output, base_dir=ROOT,
                    top_text=top_path.read_text(encoding="utf-8"),
                    sources=list(self.fixture.sources), boot_image=image,
                    verilator=tool, timeout_seconds=1800)
            except SocRuntimeError as error:
                last = error
                print("MYFUZZ_IRQ_NEG_NOTE build %s attempt %d failed: %s"
                      % (label, attempt, str(error)[:300]))
                if "runtime-build-failed" not in str(error):
                    raise
        raise last

    def _run(self, label: str, build_label: str, program_label: str, sample_label: str,
             *, request_id: int) -> ReportRun:
        program = {"multi": self.multi, "single": self.single,
                   "no_trigger": self.no_trigger}[program_label]
        build = self.builds[build_label]
        image = self.images[program_label]
        if build.boot_image != image.resolve():
            build = replace(build, boot_image=image.resolve())
        sample = self.samples[sample_label]
        started = time.monotonic()
        result = run_sample(build, sample, timeout_seconds=1800)
        print("MYFUZZ_IRQ_NEG_RUN trigger=%s case=%s status=%s cycles=%d wall_s=%.2f reason=%s"
              % (self.trigger, label, result.status, result.cycles,
                 time.monotonic() - started, result.reason))
        if result.status == "OK":
            print("MYFUZZ_IRQ_NEG_REPORT trigger=%s case=%s %s"
                  % (self.trigger, label,
                     " ".join("%s=%d" % (name, read32(
                         result, int(program.report_address) + int(self.layout[name])))
                         for name in TRAJECTORY_FIELDS)))
        return ReportRun(label=label, program=program, result=result,
                         layout=self.layout, sample=sample)

    # -- evidence ---------------------------------------------------------

    def injected_fault(self) -> str:
        """The named fault this trigger's drop injection really is."""
        if self.trigger in INTERRUPT_TRIGGERS_EDGE_DETECTED:
            return "source id 1's LATCH_MASK bit removed"
        return "source id 1's controller input pinned to zero"

    def package_for(self, run: ReportRun, *, criterion: str):
        """One composition-defect evidence package for the injected run."""
        policy = compile_input_constraints(self.plan, drive_profile="cpu_execute")
        return build_evidence_package(
            self.plan, self.builds["injected"], policy, [run.result],
            samples=[run.sample],
            kind="injected_source_specific_latch",
            criteria=[{"criterion_id": criterion,
                       "description": ("every declared interrupt source must be claimed "
                                       "by its declared id and completed")}],
            legality=applied_legality(self.builds["injected"], run.sample, run.result),
            anomaly={"present": True, "criterion": criterion,
                     "basis": "independent controller LATCH_MASK/source-input contract",
                     "basis_independent": True, "reproducible": True,
                     "expected": self.declared_sources, "observed": 0},
            attribution={"composition_findings": [
                {"fault": self.injected_fault(),
                 "source_id": 1,
                 "baseline_top_hash": self.top_hashes["baseline"],
                 "mutated_top_hash": self.top_hashes["injected"]}]})

    def close(self) -> None:
        self.temporary.cleanup()


class TriggerNegativeSuite:
    """The per-trigger real negatives; one concrete subclass per trigger.

    The mixin carries the shared machinery and the negatives every admitted
    trigger has.  A trigger whose lane needs an extra statement (``pulse``, whose
    declared moment the peripheral does not physically emit) adds its own test in
    its own subclass instead of skipping a shared one: with
    ``MYFUZZ_SOC_REAL=1`` nothing in this module may skip.
    """

    TRIGGER: str = ""
    soc: TriggerSoC | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.blocker: str | None = None
        cls.soc = None
        cls.started = time.monotonic()
        try:
            cls.soc = TriggerSoC(cls.TRIGGER)
        except Exception as error:  # noqa: BLE001 - reported by setUp
            cls.blocker = f"{type(error).__name__}: {error}"

    @classmethod
    def tearDownClass(cls) -> None:
        soc = cls.soc
        print("\nMYFUZZ_IRQ_NEG_TIMING trigger=%s wall_s=%.1f %s"
              % (cls.TRIGGER, time.monotonic() - cls.started,
                 " ".join("%s=%s" % item for item in
                          sorted((getattr(soc, "notes", {}) or {}).items()))))
        if soc is not None:
            soc.close()

    def setUp(self) -> None:
        if self.blocker is not None:
            self.fail(f"the {self.TRIGGER} trigger negatives could not be prepared: "
                      f"{self.blocker}")

    # -- helpers ----------------------------------------------------------

    def executed(self, label: str) -> ReportRun:
        """One executed run of this class's SoC, by label.

        Deliberately not named ``run``: that name belongs to ``TestCase`` and
        overriding it would break unittest's own dispatch.
        """
        assert self.soc is not None
        return self.soc.runs[label]

    def report(self, label: str, name: str) -> int:
        return self.executed(label).report(name)

    def trajectory(self, label: str) -> tuple[str, str]:
        assert self.soc is not None
        return self.executed(label).trajectory(self.soc.declared_sources)

    # -- the shared negatives ---------------------------------------------

    def test_the_injection_never_edits_the_real_rtl(self) -> None:
        """Every mutant is a temporary copy; the checked-in RTL is untouched."""
        assert self.soc is not None
        self.assertEqual(self.soc.rtl_hashes_before, _rtl_hashes())
        for label, path in self.soc.top_paths.items():
            resolved = path.resolve()
            self.assertTrue(resolved.is_file(), label)
            self.assertFalse(str(resolved).startswith(str((ROOT / "src").resolve()) + os.sep),
                             f"{label} was written inside src/: {resolved}")
        self.assertNotEqual(self.soc.top_hashes["baseline"],
                            self.soc.top_hashes["injected"])
        self.assertNotEqual(self.soc.top_hashes["baseline"],
                            self.soc.top_hashes["swapped"])

    def test_the_baseline_closes_both_sources_per_source(self) -> None:
        """The baseline is per-source evidence, not an aggregate count."""
        assert self.soc is not None
        run = self.executed("baseline")
        self.assertEqual("OK", run.result.status, run.result.reason)
        self.assertGreater(run.result.cycles, 0)
        self.assertEqual(1, self.report("baseline", "claim_id"),
                         "the first claim must be the trigger lane's declared id 1")
        self.assertEqual(bitmap_bit(1), self.report("baseline", "pending_before_claim"),
                         "the trigger lane's own pending bit before the claim")
        self.assertEqual(1, self.report("baseline", "cause_before_clear"),
                         "the trigger lane's declared peripheral cause was observed")
        self.assertEqual(0, self.report("baseline", "cause_after_clear"),
                         "the declared clear emptied the trigger lane's condition")
        self.assertEqual(1, self.report("baseline", "complete_accepted"))
        self.assertEqual(0, self.report("baseline", "final_in_service"))
        self.assertEqual(self.soc.declared_sources,
                         self.report("baseline", "interrupt_completions"))
        self.assertEqual(1, self.report("baseline", "all_sources_closed"))
        self.assertEqual(1, self.report("baseline", "loop_closed"))
        self.assertGreaterEqual(self.report("baseline", "handler_entries"),
                                self.soc.declared_sources)
        verdict, reason = self.trajectory("baseline")
        self.assertEqual(TRAJECTORY_PASS, verdict, reason)

    def test_the_source_specific_injection_drops_only_that_source(self) -> None:
        """The injected lane never closes; the companion still does."""
        assert self.soc is not None
        # The source-specific defect is the latch bit for a lane whose input is a
        # bounded moment and the connection for one whose input is a level.
        if self.TRIGGER in INTERRUPT_TRIGGERS_EDGE_DETECTED:
            self.assertEqual("source id 1's LATCH_MASK bit removed",
                             self.soc.injected_fault())
        else:
            self.assertIn("pinned", self.soc.injected_fault())
        run = self.executed("injected")
        self.assertEqual("OK", run.result.status, run.result.reason)
        self.assertEqual(self.soc.declared_sources - 1,
                         self.report("injected", "interrupt_completions"),
                         "exactly one declared source fewer must complete")
        self.assertEqual(0, self.report("injected", "all_sources_closed"))
        self.assertEqual(2, self.report("injected", "claim_id"),
                         "the only claimed id is the untouched companion's")
        self.assertEqual(1, self.report("injected", "complete_accepted"),
                         "the companion's COMPLETE was accepted")
        self.assertEqual(0, self.report("injected", "final_in_service"))
        # Per source: the companion's bit was pending before its claim and the
        # injected lane's bit was not, so the dropped lane is named rather than
        # inferred from a count.
        self.assertEqual(bitmap_bit(2),
                         self.report("injected", "pending_before_claim"))
        pending_word = self.report("injected", "pending_word_0_before_claim")
        self.assertEqual(0, pending_word & bitmap_bit(1),
                         "the injected lane must never become pending")
        self.assertEqual(bitmap_bit(2), pending_word & bitmap_bit(2),
                         "the companion really did become pending")
        verdict, reason = self.trajectory("injected")
        self.assertEqual(TRAJECTORY_INCOMPLETE, verdict, reason)

    def test_the_injected_run_is_classified_as_a_composition_defect(self) -> None:
        """A dropped source is a connection/controller finding, not a GPIO bug.

        The package carries the mutated top's hash next to the baseline's and a
        composition attribution; the boundary classifier must return
        ``composition_defect``, never a component-internal candidate, and the
        injected run must replay identically from its saved sample.
        """
        assert self.soc is not None
        package = self.soc.package_for(self.executed("injected"),
                                       criterion="all-declared-sources-complete")
        classification, reason = classify_boundary(package)
        self.assertEqual(COMPOSITION_DEFECT, classification, reason)
        self.assertNotEqual(COMPONENT_CANDIDATE, classification)
        confirmed, confirm_reason = confirm_component_defect(package, isolation={},
                                                             criterion={})
        self.assertEqual(COMPOSITION_DEFECT, confirmed, confirm_reason)
        replay = replay_package(package, self.soc.builds["injected"],
                                timeout_seconds=1800)
        self.assertEqual("agreement", replay.status, replay.reason)

    def test_a_masked_source_is_never_claimed_while_the_unmasked_one_closes(self) -> None:
        """A wrong enable mask hides a source without breaking the other lane.

        The program enables exactly the trigger lane (id 1) and the sample drives
        both lanes, so the masked companion (id 2) really becomes pending.  The
        masked lane is never claimed, the unmasked lane closes -- and the
        aggregate ``all_sources_closed`` reads 1 anyway, which is exactly why no
        assertion here accepts that counter as proof.
        """
        assert self.soc is not None
        run = self.executed("mask")
        self.assertEqual("OK", run.result.status, run.result.reason)
        self.assertEqual(bitmap_bit(1) | bitmap_bit(2),
                         self.report("mask", "pending_word_0_before_claim"),
                         "both declared lanes really arrived")
        self.assertEqual(1, self.report("mask", "claim_id"),
                         "the unmasked lane's declared id is the only claim")
        self.assertEqual(1, self.report("mask", "handler_entries"))
        self.assertEqual(1, self.report("mask", "interrupt_completions"))
        self.assertEqual(1, self.report("mask", "complete_accepted"))
        self.assertEqual(0, self.report("mask", "cause_after_clear"))
        self.assertEqual(0, self.report("mask", "unknown_claim"))
        # The masked source is still pending after the only COMPLETE: it was
        # never claimed.  This is the per-source fact the aggregate cannot show.
        after = self.report("mask", "pending_word_after_complete")
        self.assertEqual(bitmap_bit(2), after & bitmap_bit(2),
                         "the masked companion is still pending, never claimed")
        self.assertEqual(0, after & bitmap_bit(1))
        self.assertEqual(1, self.report("mask", "all_sources_closed"),
                         "the aggregate counter reads closed although the masked "
                         "source was never claimed -- it is not proof of closure")
        self.assertNotEqual(TRAJECTORY_PASS, self.trajectory("mask")[0],
                            "one of the two declared sources was never claimed")

    def test_the_permuted_id_mapping_is_caught_by_the_run_not_the_counter(self) -> None:
        """With the lanes swapped, the claimed id has no condition behind it.

        Only the companion's pin is driven, so controller bit 0 (source id 1 per
        the plan) is asserted by the *companion's* output.  The CPU still claims
        id 1 and completes it, but the instance the plan maps to id 1 -- this
        module's trigger lane -- never asserted anything: its peripheral condition
        was never observed by the ISR and the main flow's poll of it never latched.

        The closure counter is the point of this test.  The controller keeps
        claiming the same (wrong) id while the driven companion's condition stays
        set, so ``interrupt_completions`` reaches the declared source count and
        ``all_sources_closed`` reads 1 -- exactly the false closure the 2026-09-21
        report warns about.  The per-source fields contradict it: no ISR entry ever
        read a peripheral cause, so no claim ever reached the one source that had
        a condition to service.  The counter is recorded, never accepted as proof.
        """
        assert self.soc is not None
        run = self.executed("swapped")
        self.assertEqual("OK", run.result.status, run.result.reason)
        self.assertEqual(1, self.report("swapped", "claim_id"),
                         "the permuted vector still makes the CPU claim id 1")
        self.assertGreaterEqual(self.report("swapped", "handler_entries"), 1)
        self.assertGreaterEqual(self.report("swapped", "interrupt_completions"), 1,
                                "claims did happen; the counter is not the proof")
        # Per source: the plan's id-1 instance never asserted, and no claim ever
        # reached a source whose condition was set (the ISR records the first
        # non-zero cause it reads, so 0 here means the driven companion was never
        # serviced even though its condition stayed latched).
        self.assertEqual(0, self.report("swapped", "cause_before_clear"),
                         "the plan's id-1 instance never asserted its condition")
        self.assertEqual(0, self.report("swapped", "status_latched_by_poll"),
                         "the plan's id-1 instance never latched for the poll either")
        self.assertEqual(1, self.report("swapped", "all_sources_closed"),
                         "the aggregate counter reads closed although the claimed id "
                         "has no physical source behind it")
        self.assertGreaterEqual(self.report("swapped", "interrupt_completions"),
                                self.soc.declared_sources,
                                "the false closure came from repeated completions")
        self.assertNotEqual(TRAJECTORY_PASS, self.trajectory("swapped")[0],
                            "no declared source's condition was ever cleared")
        # And the structure audit refuses the same artifact by name.
        audit = self.soc.fixture.audit(self.soc.tops["swapped"])
        finding = next(item for item in audit["findings"]
                       if item["check_id"] == "interrupt_paths")
        self.assertEqual(FAIL, finding["status"], finding)

    def test_a_sample_without_the_trajectory_is_not_assessed(self) -> None:
        """A deliberately trajectory-free sample is not a pass.

        The program is generated with ``trigger_event=False`` and the sample
        applies no event at all, so no source ever notifies, pends, is claimed, is
        cleared or completed.  Every trajectory field is absent, the honest
        verdict is the project's ``not_assessed`` (never ``pass``), and the very
        same rule returns ``pass`` for the baseline run of the same build, so the
        assertion is not vacuous.
        """
        assert self.soc is not None
        run = self.executed("no_trajectory")
        self.assertEqual("OK", run.result.status, run.result.reason)
        for name in ("claim_id", "handler_entries", "pending_before_claim",
                     "pending_word_0_before_claim", "cause_before_clear",
                     "complete_accepted", "interrupt_completions",
                     "all_sources_closed", "loop_closed", "status_latched_by_poll"):
            self.assertEqual(0, self.report("no_trajectory", name),
                             f"{name} must stay absent without a trigger")
        self.assertEqual(1, self.report("no_trajectory", "main_completed"),
                         "the CPU ran: the trajectory is absent, not the program")
        verdict, reason = self.trajectory("no_trajectory")
        self.assertEqual(REPLAY_NOT_ASSESSED, verdict, reason)
        self.assertNotEqual(TRAJECTORY_PASS, verdict)
        self.assertEqual(TRAJECTORY_PASS, self.trajectory("baseline")[0])


class LevelTriggerNegatives(TriggerNegativeSuite, unittest.TestCase):
    """``level``: no latch bit exists, so its drop negative pins the input."""

    TRIGGER = "level"


class PulseTriggerNegatives(TriggerNegativeSuite, unittest.TestCase):
    """``pulse``: latched by declaration, but the peripheral holds its level."""

    TRIGGER = "pulse"

    def test_the_latch_bit_is_not_load_bearing_for_a_held_level_source(self) -> None:
        """Novagpio holds its condition, so the pulse lane's latch is not a pulse.

        ``pulse`` declares a bounded moment and the planner therefore latches its
        lane, but the peripheral used here holds ``irq_o`` high until software
        clears it: clearing that latch bit does *not* drop the event and the run
        still closes.  That is why this lane's source-specific drop negative is
        the connection injection (the shared negative above, asserted to be the
        pinned-input fault for this trigger), and why the latch semantics of a
        real bounded pulse are covered by the edge-detector lanes -- whose
        converter output is exactly one cycle wide -- and by the controller's own
        RTL verification.  The two mutants are distinct builds, so the control run
        says something about the latch bit and not about the pin.
        """
        assert self.soc is not None
        self.assertIn("pinned", self.soc.injected_fault())
        self.assertNotEqual(self.soc.top_hashes["latch_cleared"],
                            self.soc.top_hashes["baseline"])
        self.assertNotEqual(self.soc.top_hashes["latch_cleared"],
                            self.soc.top_hashes["injected"])
        self.assertNotEqual(self.soc.builds["latch_cleared"].build_hash,
                            self.soc.builds["injected"].build_hash,
                            "the two mutants are compiled from different tops")
        self.assertIn(f".LATCH_MASK({self.soc.fixture.targets.latch_width}'b0",
                      self.soc.tops["latch_cleared"])
        run = self.executed("pulse_latch")
        self.assertEqual("OK", run.result.status, run.result.reason)
        self.assertEqual(self.soc.declared_sources,
                         self.report("pulse_latch", "interrupt_completions"),
                         "a held-level source closes even with its latch bit cleared")
        self.assertEqual(1, self.report("pulse_latch", "all_sources_closed"))
        self.assertEqual(1, self.report("pulse_latch", "claim_id"))
        self.assertEqual(TRAJECTORY_PASS, self.trajectory("pulse_latch")[0])


class RisingEdgeTriggerNegatives(TriggerNegativeSuite, unittest.TestCase):
    """``rising_edge``: the converter's one-cycle pulse needs the latch."""

    TRIGGER = "rising_edge"


class FallingEdgeTriggerNegatives(TriggerNegativeSuite, unittest.TestCase):
    """``falling_edge``: the pulse fires when software clears the held condition."""

    TRIGGER = "falling_edge"


class BothEdgesTriggerNegatives(TriggerNegativeSuite, unittest.TestCase):
    """``both_edges``: both transitions of the normalized input can fire."""

    TRIGGER = "both_edges"


#: The opt-in gate sits on the concrete classes so the mixin itself is never
#: collected: with ``MYFUZZ_SOC_REAL`` unset the five real classes skip as a
#: whole, and with it set they may not skip at all.
for _class in (LevelTriggerNegatives, PulseTriggerNegatives, RisingEdgeTriggerNegatives,
               FallingEdgeTriggerNegatives, BothEdgesTriggerNegatives):
    _class.__unittest_skip__ = not OPT_IN
    _class.__unittest_skip_why__ = ("set MYFUZZ_SOC_REAL=1 for the real per-trigger "
                                    "interrupt negatives")
del _class


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
