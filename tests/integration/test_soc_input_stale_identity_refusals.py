"""Roadmap phase 1D (Task D, steps D3.1 and D3.2): the two negative classes that
must refuse a *named* thing instead of quietly doing something else.

The RFuzz input chain can only be trusted if two kinds of dishonest success are
impossible:

* **stale identity.**  A constraint policy, or a saved :class:`EvidencePackage`,
  describes the layout/plan of an *older* generation.  Applying it to the current
  build would silently reinterpret an old corpus, so ``run_sample_with_policy``
  and ``replay_package`` must refuse it before anything is executed, with the
  exact reason that names the two identities it compared.
* **an out-of-region offer.**  A candidate address that leaves its declared
  region must be refused by the layer whose policy forbids moving it, and it must
  never be "clamped" into a legal slot unless a *declared* repair policy says so
  -- in which case the move must be recorded with its before/after values.

What this file adds, and what it deliberately does not repeat
------------------------------------------------------------
``tests/integration/test_soc_dependency_replay.py`` already covers, on a real
build (gated behind ``MYFUZZ_SOC_REAL=1``) and on a hand-written two-line build
record: ``policy-layout-mismatch``, ``policy-plan-mismatch``, a policy without a
``policy_hash``, a build without a readable identity record, a package saved under
an older layout → ``REPLAY_REFUSED``, and a saved document that disagrees with
its raw archive → ``raw-input-document-mismatch``.  ``tests/composition/
test_soc_input_repair.py`` already covers ``candidate-target-outside-executable-
region``, ``candidate-target-outside-declared-program`` (with
``target_policy="strict"``), ``candidate-slot-address-misplaced`` and
``data-address-unmapped`` at the pure ``CandidateRepairer`` boundary.  Those cases
are *not* restated here.

What is genuinely missing, and is what this module proves:

1. the stale identities are *real*: the mismatching layout hash comes from a
   different real composition (``request-ibex.json``) and the mismatching plan
   hash from the ``bfm_isolated`` drive of the same ``request.json``, which shares
   the layout hash -- so the plan check is demonstrably not redundant with the
   layout check;
2. every refusal is **stable**: the exact reason string is asserted, twice in a
   row, and ``run_sample`` is mocked out to prove the refusal happens before any
   execution;
3. the check *order* is declared: policy hash, then the build record, then the
   layout, then the plan;
4. ``REPLAY_REFUSED`` for an older layout and the document/archive disagreement
   are provable with **no Verilator at all**, from a record-only build whose
   identity record is the *real* generated testbench;
5. the out-of-region offer is refused by three different layers depending on the
   policy, and this module names each one: the declared-program layer
   (``candidate-slot-address-misplaced``), the image layer
   (``instruction-candidate-rejected:instruction-address-unmapped`` and
   ``data-address-unmapped``), and the generated harness
   (``MYFUZZ_IMAGE_ERROR slot=<prefix> reason=address``, surfaced in
   ``RunResult.image_errors``);
6. the repair-vs-strict contrast is asserted on both sides with the *same* input
   word: strict refuses and moves nothing, repair moves the address into the
   declared region and records the move.  The declared-program policy
   (``CandidateProgramPolicy``) and the legacy image policy
   (``image_address_policy``) are shown to be two different knobs -- confusing
   them is exactly the failure this module exists to prevent.

``MYFUZZ_SOC_REAL=1`` gates the real-RTL half (Verilator + the example
composition), following ``tests/integration/test_soc_dependency_replay.py``: when
the flag is set nothing here skips, and a missing dependency fails naming it.  The
build is cached under ``runs/soc-input-stale-identity/<plan-prefix>/`` so a
repeated run re-executes the binary instead of recompiling it.
"""
from __future__ import annotations

import dataclasses
import functools
import json
import os
import shlex
import shutil
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from typing import Sequence

from myfuzz.composition import soc_failure_evidence, soc_runtime
from myfuzz.composition.input_constraints import compile_input_constraints
from myfuzz.composition.soc_candidate_program import (
    CandidateProgramPolicy,
    CandidateProgram,
    build_candidate_program,
    decode_word,
    encode_jal,
)
from myfuzz.composition.soc_failure_evidence import (
    REPLAY_REFUSED,
    build_evidence_package,
    identity_mismatches,
    read_evidence_package,
    recorded_build_identity,
    replay_package,
    write_evidence_package,
)
from myfuzz.composition.soc_image import (
    SocImageError,
    build_image_plan,
    combined_input_layout,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    RunResult,
    RuntimeBuild,
    RuntimeSample,
    SocRuntimeError,
    build_profile_runtime,
    render_profile_testbench,
    run_sample,
    run_sample_with_policy,
)
from myfuzz.integration.soc_builder import (
    SocBuildError,
    SocRawProjector,
    _peer_projection_slots,
    build_projection_arms,
)

from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_input_arms_projection import (
    arms_for,
    example_plan,
    field_by_role,
    ibex_plan,
    put,
    segment,
)

OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
CACHE_ROOT = ROOT / "runs/soc-input-stale-identity"

#: The declared candidate program every out-of-region case uses.  Two
#: instruction slots make "inside the region but at the *other* slot" a real
#: case, and one data slot carries the writable-region case.
INSTRUCTION_CANDIDATES = 2
DATA_CANDIDATES = 1
DATA_SLOT_OFFSET = 0x80

#: The address deliberately offered where the declared program does not live.
#: It is four-byte aligned and carries a full word, so the only thing wrong with
#: it is *where* it points: a test that failed on alignment would not prove the
#: region check at all.
OUT_OF_REGION_INSTRUCTION = 0x0001_8004


@functools.lru_cache(maxsize=1)
def ibex_plan_cached():
    """The pinned-Ibex plan, built once per process (the fixture does not cache it)."""
    return ibex_plan()


@functools.lru_cache(maxsize=1)
def bfm_plan_cached():
    """A real second plan of the *same* profile layout but a different plan hash."""
    return example_plan("bfm_isolated")


def record_only_build(directory: Path, plan, *,
                      build_hash: str = "sha256:" + "a" * 64) -> RuntimeBuild:
    """A build whose only real artifact is the identity record it wrote.

    ``RuntimeBuild`` keeps no ``layout_hash`` field: the layout arrived at by a
    build *is* the header of the generated testbench.  Writing the real
    :func:`render_profile_testbench` output therefore gives these tests a record
    that is byte-identical in form to a compiled build's, without needing
    Verilator -- which is what lets the stale-identity refusals run by default.
    """
    directory.mkdir(parents=True, exist_ok=True)
    testbench = directory / "profile_tb.sv"
    testbench.write_text(render_profile_testbench(plan), encoding="utf-8")
    return RuntimeBuild(
        output_dir=directory,
        top_path=directory / "myfuzz_soc_top.sv",
        testbench_path=testbench,
        executable=directory / "myfuzz_profile_sim",
        sources=(),
        raw_width=int(plan.raw_layout["raw_width"]),
        slots=(),
        observations=(),
        boot_image=None,
        boot_image_policy="no_preloaded_region",
        build_hash=build_hash,
        warnings=0,
    )


def declared_program(plan, *, address_policy: str = "repair",
                     target_policy: str = "repair") -> CandidateProgram:
    """The declared candidate program of one plan under an explicit policy."""
    return build_candidate_program(
        plan,
        instruction_candidates=INSTRUCTION_CANDIDATES,
        data_candidates=DATA_CANDIDATES,
        policy=CandidateProgramPolicy(address_policy=address_policy,
                                      target_policy=target_policy,
                                      data_slot_offset=DATA_SLOT_OFFSET),
    )


def declared_arm(plan, program: CandidateProgram, *,
                 image_address_policy: str = "repair"):
    """The production dependency-repair arm over one declared program.

    The arm is built by :func:`build_projection_arms` -- the same call the
    campaign path makes -- so what these tests refuse is the production arm's
    refusal and not a hand-assembled projector's.
    """
    image = program.image
    layout = combined_input_layout(plan, image)
    policy = compile_input_constraints(plan, drive_profile=plan.drive_profile)
    arms = build_projection_arms(
        layout=layout,
        constraint_hash=policy.policy_hash,
        special_width=int(plan.raw_layout["raw_width"]),
        policy=policy,
        image=image,
        image_address_policy=image_address_policy,
        candidate_program=program,
        peer_slots=_peer_projection_slots(plan, layout, base_dir=ROOT),
    )
    return layout, policy, arms["dependency_repair"]


def slot_word(layout, slot, *, address: int, value: int, be: int = 0xF) -> int:
    """One raw word offering exactly `slot` at `address` with `value`."""
    payload = "data" if slot.kind == "instruction" else "value"
    raw = 0
    raw = put(raw, field_by_role(layout, "soc_image", f"{slot.prefix}_offer"), 1)
    raw = put(raw, field_by_role(layout, "soc_image", f"{slot.prefix}_address"), address)
    raw = put(raw, field_by_role(layout, "soc_image", f"{slot.prefix}_{payload}"), value)
    raw = put(raw, field_by_role(layout, "soc_image", f"{slot.prefix}_be"), be)
    return raw


def program_words(program: CandidateProgram, layout, *,
                  override: str | None = None, **settings) -> tuple[int, ...]:
    """Every declared slot offered exactly once, with at most one override.

    The declared program requires every instruction slot to be offered once per
    test, so a refusal for an unoffered slot would be a different check.  Each
    slot is offered at its own declared address unless `override` names the slot
    whose address (or word) the test deliberately gets wrong.
    """
    words = []
    for slot in program.slots.slots():
        address = int(slot.declared_address)
        word = 0x00000013 if slot.kind == "instruction" else 0x1234ABCD
        if slot.prefix == override:
            address = int(settings.get("address", address))
            word = int(settings.get("word", word))
        words.append(slot_word(layout, slot, address=address, value=word))
    return tuple(words)


def stub_simulator(directory: Path, lines: Sequence[str]) -> Path:
    """A stand-in for the compiled harness that prints exactly these lines.

    Used for the *result* half of the harness refusal contract
    (``MYFUZZ_IMAGE_ERROR ...`` → ``RunResult.image_errors``) without Verilator.
    That the generated RTL really prints that line is asserted separately from
    the generated text and, when opted in, from a real run; this stub only proves
    the runtime does not drop the refusal on the floor.
    """
    path = directory / "stub_harness"
    body = "".join(f"printf '%s\\n' {shlex.quote(line)}\n" for line in lines)
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


# ---------------------------------------------------------------------------
# D3.1: stale layout / stale rules
# ---------------------------------------------------------------------------


class StalePolicyIdentityTests(unittest.TestCase):
    """``run_sample_with_policy`` refuses a policy that is not this build's.

    Every reason is asserted as an exact string, twice, with ``run_sample``
    patched out: a refusal that only says "something raised" cannot be told apart
    from a later failure inside the simulator, and a refusal that happens after
    the run has started is not a refusal of the input.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory(prefix=".myfuzz-soc-stale-", dir=ROOT)
        cls.addClassCleanup(cls._temporary.cleanup)
        cls.directory = Path(cls._temporary.name)
        cls.plan = example_plan()
        cls.build = record_only_build(cls.directory / "current", cls.plan)
        cls.policy = compile_input_constraints(cls.plan, drive_profile="cpu_execute")
        cls.sample = RuntimeSample(request_id=0x51A1E, raw=(0x00, 0x11, 0x22))

    # -- helpers -----------------------------------------------------------

    def refusal(self, policy) -> str:
        """The exact reason one policy is refused with, and nothing ran."""
        with unittest.mock.patch.object(soc_runtime, "run_sample") as run:
            with self.assertRaises(SocRuntimeError) as caught:
                run_sample_with_policy(self.build, self.sample, policy=policy)
        run.assert_not_called()
        return str(caught.exception)

    def assert_refused(self, policy, expected: str) -> None:
        """Assert the exact reason, and that repeating it is idempotent."""
        self.assertEqual(expected, self.refusal(policy))
        self.assertEqual(expected, self.refusal(policy),
                         "the refusal must be stable across repeated calls")

    # -- layout and plan ---------------------------------------------------

    def test_a_policy_from_an_older_layout_is_refused_by_name(self) -> None:
        """The stale hash is a *real* layout of another composition, not a fake.

        ``request-ibex.json`` declares a different set of special inputs, so its
        ``layout_hash`` is a layout this build could never have been made from.
        """
        foreign = ibex_plan_cached()
        stale = compile_input_constraints(foreign, drive_profile="cpu_execute")
        self.assertNotEqual(str(foreign.raw_layout["layout_hash"]),
                            str(self.plan.raw_layout["layout_hash"]))
        self.assertEqual(str(foreign.raw_layout["layout_hash"]), stale.layout_hash)
        self.assert_refused(
            stale,
            f"policy-layout-mismatch:policy={stale.layout_hash}:"
            f"build={self.plan.raw_layout['layout_hash']}")

    def test_a_policy_from_an_older_plan_is_refused_even_though_the_layout_matches(self) -> None:
        """The plan check is not redundant with the layout check.

        The ``bfm_isolated`` drive of the same request has the *same* profile
        layout and a different plan hash, so only the plan half can catch it.
        """
        other = bfm_plan_cached()
        stale = compile_input_constraints(other, drive_profile="bfm_isolated")
        self.assertEqual(str(other.raw_layout["layout_hash"]),
                         str(self.plan.raw_layout["layout_hash"]),
                         "this case only means something while the layouts agree")
        self.assertNotEqual(other.plan_hash, self.plan.plan_hash)
        self.assert_refused(
            stale,
            f"policy-plan-mismatch:policy={stale.plan_hash}:build={self.plan.plan_hash}")

    def test_the_layout_check_precedes_the_plan_check(self) -> None:
        """A policy stale in both halves is refused for the layout first.

        The order is part of the contract: the layout is what the raw bits mean,
        so it is reported before the plan they were projected for.
        """
        foreign = ibex_plan_cached()
        both_stale = dataclasses.replace(
            compile_input_constraints(bfm_plan_cached(), drive_profile="bfm_isolated"),
            layout_hash=str(foreign.raw_layout["layout_hash"]))
        self.assert_refused(
            both_stale,
            f"policy-layout-mismatch:policy={both_stale.layout_hash}:"
            f"build={self.plan.raw_layout['layout_hash']}")

    # -- missing identity --------------------------------------------------

    def test_a_policy_without_a_policy_hash_is_refused_by_name(self) -> None:
        self.assert_refused(
            dataclasses.replace(self.policy, policy_hash=""),
            "policy-hash-missing: the supplied policy carries no policy_hash")

    def test_a_policy_without_a_layout_hash_is_refused_by_name(self) -> None:
        """The declared layer's third named refusal, exact and stable."""
        self.assert_refused(
            dataclasses.replace(self.policy, layout_hash=""),
            "policy-layout-hash-missing: the supplied policy carries no layout_hash")

    def test_the_policy_hash_is_checked_before_the_build_record_is_read(self) -> None:
        """The cheapest, most specific refusal wins: no record is required first.

        A build whose testbench is gone cannot record its identity at all, yet a
        policy with no ``policy_hash`` is still refused for *that* -- which is the
        documented order of the checks in
        :func:`myfuzz.composition.soc_runtime.run_sample_with_policy`.
        """
        broken = dataclasses.replace(self.build,
                                     testbench_path=self.directory / "absent.sv")
        with unittest.mock.patch.object(soc_runtime, "run_sample") as run:
            with self.assertRaises(SocRuntimeError) as caught:
                run_sample_with_policy(broken, self.sample,
                                       policy=dataclasses.replace(self.policy,
                                                                  policy_hash=""))
        run.assert_not_called()
        self.assertEqual("policy-hash-missing: the supplied policy carries no policy_hash",
                         str(caught.exception))
        # The same unreadable build with a *valid* policy is refused for the
        # record instead, so the assertion above really is about the order.
        with self.assertRaises(SocRuntimeError) as caught:
            run_sample_with_policy(broken, self.sample, policy=self.policy)
        self.assertIn("runtime-build-record-unreadable", str(caught.exception))

    def test_an_intact_policy_is_not_refused(self) -> None:
        """The control: the same build and sample pass identity validation.

        Without this, every assertion above could be satisfied by a validator
        that refuses everything.  ``run_sample`` is still patched out, so the
        *validation* is what is observed, not a simulator run.
        """
        with unittest.mock.patch.object(soc_runtime, "run_sample") as run:
            run.return_value = RunResult(
                request_id=self.sample.request_id, cycles=0, status="patched",
                counters={}, observations={}, trace=(), applied=(),
                stdout="", stderr="")
            result = run_sample_with_policy(self.build, self.sample, policy=self.policy)
        run.assert_called_once()
        self.assertEqual("patched", result.status)


class StaleEvidenceIdentityTests(unittest.TestCase):
    """``replay_package``/``identity_mismatches`` refuse stale evidence, purely.

    The existing suite proves this on a real build behind ``MYFUZZ_SOC_REAL=1``.
    These cases prove it with no Verilator at all, from a record-only build, and
    add the two invariants that were missing: the refusal is *stable*, and it
    happens without calling ``run_sample`` even once.
    """

    RAW = (0x00, 0x01, 0x02)
    REQUEST_ID = 0xE71D

    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory(prefix=".myfuzz-soc-stale-", dir=ROOT)
        cls.addClassCleanup(cls._temporary.cleanup)
        cls.directory = Path(cls._temporary.name)
        cls.plan = example_plan()
        cls.build = record_only_build(cls.directory / "current", cls.plan)
        cls.policy = compile_input_constraints(cls.plan, drive_profile="cpu_execute")
        cls.sample = RuntimeSample(request_id=cls.REQUEST_ID, raw=cls.RAW)
        cls.result = RunResult(
            request_id=cls.REQUEST_ID, cycles=len(cls.RAW), status="OK",
            counters={"cycles": len(cls.RAW)},
            observations={"cpu0__status_o": 1},
            trace=tuple({"cycle": index, "raw": value}
                        for index, value in enumerate(cls.RAW)),
            applied=(), stdout="", stderr="")

    def package(self):
        return build_evidence_package(
            self.plan, self.build, self.policy, [self.result],
            kind="stale-identity-refusal", samples=[self.sample])

    def legacy_package(self):
        """The same package with the layout/rule identity of an older layout.

        The stale hash is the real ``request-ibex.json`` layout, so this is the
        shape a corpus saved before a layout change would have -- not a
        synthetically corrupted string.
        """
        package = self.package()
        stale = str(ibex_plan_cached().raw_layout["layout_hash"])
        return dataclasses.replace(package, identity=dict(
            package.identity, layout_hash=stale,
            policy=dict(package.identity["policy"], layout_hash=stale)))

    # -- the baseline ------------------------------------------------------

    def test_the_saved_package_describes_the_build_it_was_made_on(self) -> None:
        """The control that makes the refusals below attributable.

        The package is built without a compiled binary, and it says so: the
        record it really binds is the plan/layout header of the generated
        testbench, which is re-read here from the build directory.
        """
        package = self.package()
        self.assertEqual((), identity_mismatches(package, self.build))
        self.assertEqual(str(self.plan.raw_layout["layout_hash"]),
                         str(package.identity["layout_hash"]))
        self.assertEqual(recorded_build_identity(self.build),
                         {"plan_hash": self.plan.plan_hash,
                          "layout_hash": str(self.plan.raw_layout["layout_hash"])})
        self.assertTrue(package.inputs_complete)

    # -- refused replay ----------------------------------------------------

    def test_a_package_saved_under_an_older_layout_is_refused_without_a_rerun(self) -> None:
        stale = str(ibex_plan_cached().raw_layout["layout_hash"])
        legacy = self.legacy_package()
        directory = self.directory / "legacy-layout"
        write_evidence_package(legacy, directory)
        read_back = read_evidence_package(directory)
        self.assertEqual(stale, str(read_back.identity["layout_hash"]))
        with unittest.mock.patch.object(soc_failure_evidence, "run_sample") as run:
            replay = replay_package(read_back, self.build)
        run.assert_not_called()
        self.assertEqual(REPLAY_REFUSED, replay.status)
        self.assertEqual(
            ("layout_hash:saved=" + stale + ":build="
             + str(self.plan.raw_layout["layout_hash"]),),
            tuple(replay.mismatching_fields))
        self.assertEqual(
            "refused: the package identity does not describe this build: "
            "layout_hash:saved=" + stale + ":build="
            + str(self.plan.raw_layout["layout_hash"]),
            replay.reason)
        self.assertEqual((), tuple(replay.reruns))
        self.assertIsNone(replay.divergence)
        self.assertFalse(replay.agreed)

    def test_the_older_layout_refusal_is_stable_across_repeated_replays(self) -> None:
        legacy = self.legacy_package()
        first = replay_package(legacy, self.build)
        second = replay_package(legacy, self.build)
        self.assertEqual(REPLAY_REFUSED, first.status)
        self.assertEqual(first.reason, second.reason)
        self.assertEqual(tuple(first.mismatching_fields), tuple(second.mismatching_fields))

    # -- document vs its own archive ---------------------------------------

    def test_the_archive_agrees_with_its_document_before_any_tamper(self) -> None:
        directory = self.directory / "intact"
        write_evidence_package(self.package(), directory)
        read_back = read_evidence_package(directory)
        self.assertEqual(self.RAW, tuple(read_back.sample().raw))
        self.assertEqual(self.REQUEST_ID, read_back.sample().request_id)

    def test_a_document_that_disagrees_with_its_raw_archive_is_detected(self) -> None:
        """Only the document is edited; the archive file stays byte-exact.

        The archive's own hash still matches the index, so a reader that only
        verified the *file* would accept a package whose document describes
        different raw bits -- exactly the "saved input" the replay would then
        mis-report.  Reading must compare the two.
        """
        directory = self.directory / "tampered-document"
        document_path = write_evidence_package(self.package(), directory)
        document = json.loads(document_path.read_text(encoding="utf-8"))
        self.assertEqual(0x01, document["samples"][0]["raw"][1])
        document["samples"][0]["raw"][1] = 0x7F
        document_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            read_evidence_package(directory)
        message = str(caught.exception)
        self.assertIn("raw-input-document-mismatch", message)
        self.assertIn("the package document and its raw-input archive disagree", message)


# ---------------------------------------------------------------------------
# D3.2: an out-of-declared-region address is refused, not clamped
# ---------------------------------------------------------------------------


class DeclaredProgramAddressPolicyTests(unittest.TestCase):
    """The declared-program layer: ``CandidateProgramPolicy`` decides.

    ``CandidateRepairer._place`` is the layer that refuses here.  It is reached
    from the arm because ``ProfileCampaignProjector.project_records`` hands the
    whole record to the declared program's repairer
    (``_project_declared_program``) and wraps the program's own named error.  The
    region itself is *not* the criterion at this layer: the criterion is the
    slot's declared address, so an address that is inside the region but belongs
    to another slot is refused in exactly the same way.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = ibex_plan_cached()
        cls.repair_program = declared_program(cls.plan)
        cls.repair_layout = combined_input_layout(cls.plan, cls.repair_program.image)
        cls.strict_program = declared_program(cls.plan, address_policy="strict")
        cls.strict_layout = combined_input_layout(cls.plan, cls.strict_program.image)

    def setUp(self) -> None:
        # A fresh arm per test: ``repair_counts`` accumulates over the lifetime
        # of one projector, so a shared arm would make every count assertion
        # depend on which tests ran before it.
        self.repair_arm = self.arm_for(self.repair_program)
        self.strict_arm = self.arm_for(self.strict_program)

    def arm_for(self, program: CandidateProgram, *,
                image_address_policy: str = "repair"):
        return declared_arm(self.plan, program,
                            image_address_policy=image_address_policy)[2]

    # -- refused: strict ---------------------------------------------------

    def test_a_misplaced_instruction_address_is_refused_by_name_when_repair_is_forbidden(
            self) -> None:
        slot = self.repair_program.slots.instruction[0]
        offered = OUT_OF_REGION_INSTRUCTION
        self.assertFalse(self.repair_program.image.base <= offered
                         < self.repair_program.image.base + self.repair_program.image.size)
        words = program_words(self.strict_program, self.strict_layout,
                              override=slot.prefix, address=offered)
        with self.assertRaises(SocBuildError) as caught:
            self.strict_arm.project_records(words)
        self.assertEqual(
            f"candidate-slot-address-misplaced:{slot.prefix}:0x{offered:08x}:"
            f"expected-0x{slot.declared_address:08x}",
            str(caught.exception))
        self.assertIsNone(self.strict_arm.last_repaired_test,
                          "a refused test must not be published as a repaired one")

    def test_an_address_inside_the_region_but_at_another_slot_is_refused_too(self) -> None:
        """The declared slot address is the criterion, not merely the region."""
        first, second = self.repair_program.slots.instruction[0], \
            self.repair_program.slots.instruction[1]
        offered = int(second.declared_address)
        image = self.repair_program.image
        self.assertTrue(image.base <= offered < image.base + image.size)
        words = program_words(self.strict_program, self.strict_layout,
                              override=first.prefix, address=offered)
        with self.assertRaises(SocBuildError) as caught:
            self.strict_arm.project_records(words)
        self.assertEqual(
            f"candidate-slot-address-misplaced:{first.prefix}:0x{offered:08x}:"
            f"expected-0x{first.declared_address:08x}",
            str(caught.exception))

    def test_a_data_offer_outside_the_writable_region_is_refused_by_the_same_policy(self) -> None:
        slot = self.repair_program.slots.data[0]
        offered = int(self.repair_program.image.data_base
                      + self.repair_program.image.data_size + 4)
        words = program_words(self.strict_program, self.strict_layout,
                              override=slot.prefix, address=offered)
        with self.assertRaises(SocBuildError) as caught:
            self.strict_arm.project_records(words)
        self.assertEqual(
            f"candidate-slot-address-misplaced:{slot.prefix}:0x{offered:08x}:"
            f"expected-0x{slot.declared_address:08x}",
            str(caught.exception))

    def test_a_refused_offer_leaves_the_caller_record_untouched(self) -> None:
        """A refusal is not a partial application: the input word is unchanged.

        The repairer copies the words before it places anything, so a caller that
        saves its corpus around a refused projection keeps the exact bits it
        offered instead of a half-repaired record.
        """
        slot = self.repair_program.slots.instruction[0]
        words = program_words(self.strict_program, self.strict_layout,
                              override=slot.prefix, address=OUT_OF_REGION_INSTRUCTION)
        before = tuple(words)
        with self.assertRaises(SocBuildError):
            self.strict_arm.project_records(words)
        self.assertEqual(before, tuple(words))
        address_field = field_by_role(self.strict_layout, "soc_image",
                                      f"{slot.prefix}_address")
        self.assertEqual(OUT_OF_REGION_INSTRUCTION, segment(words[0], address_field))

    # -- recorded: repair --------------------------------------------------

    def test_a_declared_repair_moves_the_address_to_the_slot_and_records_it(self) -> None:
        """With the declared repair policy the offer is moved *and* recorded.

        Nothing about the move is implicit: the before/after pair is a repair
        record, the projected raw word carries the declared address, and the
        repaired test publishes the placement.
        """
        slot = self.repair_program.slots.instruction[0]
        words = program_words(self.repair_program, self.repair_layout,
                              override=slot.prefix, address=OUT_OF_REGION_INSTRUCTION)
        projected = self.repair_arm.project_records(words)
        address_field = field_by_role(self.repair_layout, "soc_image",
                                      f"{slot.prefix}_address")
        self.assertEqual(int(slot.declared_address), segment(projected[0], address_field))
        self.assertEqual(1, self.repair_arm.repair_counts["address_repair"])
        record = next(item for item in self.repair_arm.last_repaired_test.records
                      if item.kind == "address" and item.slot == slot.prefix)
        self.assertEqual(OUT_OF_REGION_INSTRUCTION, int(record.before))
        self.assertEqual(int(slot.declared_address), int(record.after))
        placement = next(item for item in self.repair_arm.last_repaired_test.placements
                         if item["slot"] == slot.prefix)
        self.assertEqual(int(slot.declared_address), int(placement["declared_address"]))

    def test_the_identity_arm_moves_nothing(self) -> None:
        """``direct_input`` has no repair policy, so the bits stay as offered.

        This matters because the identity arm is what the harness sees for a
        corpus that was never projected: the out-of-region address must reach the
        harness unchanged, where the harness's own refusal (asserted in
        :class:`HarnessOverlayRefusalTests`) is the only layer left to catch it.
        """
        _, layout, _, arms = arms_for(self.plan,
                                      instruction_candidates=INSTRUCTION_CANDIDATES,
                                      data_candidates=DATA_CANDIDATES,
                                      candidate_program=True)
        arm = arms["direct_input"]
        self.assertIsInstance(arm, SocRawProjector)
        slot = self.repair_program.slots.instruction[0]
        words = program_words(self.repair_program, layout,
                              override=slot.prefix, address=OUT_OF_REGION_INSTRUCTION)
        self.assertEqual(list(words), list(arm.project_records(words)))
        address_field = field_by_role(layout, "soc_image", f"{slot.prefix}_address")
        self.assertEqual(OUT_OF_REGION_INSTRUCTION,
                         segment(arm.project_records(words)[0], address_field))

    # -- the two knobs are not one knob ------------------------------------

    def test_the_declared_program_policy_governs_even_when_the_legacy_knob_says_strict(
            self) -> None:
        """``image_address_policy`` is not consulted on the declared-program path.

        The declared-program arm places through the plan's own candidate program,
        whose ``address_policy`` is the declaration.  A caller that sets the
        legacy image knob to ``strict`` and expects the declared program to obey
        it would get a silent repair instead of a refusal, which is why the two
        are asserted to be different knobs here rather than assumed equal.
        """
        slot = self.repair_program.slots.instruction[0]
        layout = self.repair_layout
        arm = self.arm_for(self.repair_program, image_address_policy="strict")
        self.assertEqual("strict", arm.image_address_policy)
        words = program_words(self.repair_program, layout,
                              override=slot.prefix, address=OUT_OF_REGION_INSTRUCTION)
        projected = arm.project_records(words)
        address_field = field_by_role(layout, "soc_image", f"{slot.prefix}_address")
        self.assertEqual(int(slot.declared_address), segment(projected[0], address_field))
        self.assertEqual(1, arm.repair_counts["address_repair"])

    def test_the_strict_declared_policy_refuses_even_when_the_legacy_knob_says_repair(
            self) -> None:
        slot = self.strict_program.slots.instruction[0]
        layout = self.strict_layout
        arm = self.arm_for(self.strict_program, image_address_policy="repair")
        self.assertEqual("repair", arm.image_address_policy)
        words = program_words(self.strict_program, layout,
                              override=slot.prefix, address=OUT_OF_REGION_INSTRUCTION)
        with self.assertRaises(SocBuildError) as caught:
            arm.project_records(words)
        self.assertEqual(
            f"candidate-slot-address-misplaced:{slot.prefix}:"
            f"0x{OUT_OF_REGION_INSTRUCTION:08x}:"
            f"expected-0x{slot.declared_address:08x}",
            str(caught.exception))

    def test_a_control_flow_fuzz_word_is_corrected_before_the_program_analyser(self) -> None:
        """Why ``candidate-target-*`` is not reachable through the fuzz channel.

        The reference ISA layer sits *in front of* the declared program: a raw
        word that is not an operation the declared ISA can emit is replaced by a
        legal one before the analyser sees it.  A hand-encoded ``jal`` is such a
        word, so the analyser never receives an out-of-region branch target here
        and the ``candidate-target-outside-executable-region`` /
        ``candidate-target-outside-declared-program`` refusals stay covered where
        they are reachable -- through the ``directed`` channel in
        ``tests/composition/test_soc_input_repair.py``.  What this test pins is
        the layer order that makes that true.
        """
        slot = self.repair_program.slots.instruction[0]
        # A jump whose target is far outside every executable region.
        offered = encode_jal(0, 0x2_0000 - int(slot.declared_address))
        words = program_words(self.repair_program, self.repair_layout,
                              override=slot.prefix, word=offered)
        projected = self.repair_arm.project_records(words)
        placement = next(item for item in self.repair_arm.last_repaired_test.placements
                         if item["slot"] == slot.prefix)
        self.assertNotEqual(offered, int(placement["word_value"]))
        self.assertEqual(1, self.repair_arm.repair_counts["isa_repair"])
        corrected = decode_word(int(placement["word_value"]))
        self.assertNotIn(corrected.kind, ("jal", "jalr", "branch"))
        # The corrected word is placed at the declared slot: the refusal that
        # would have fired for a target is never reached, and no target repair
        # is claimed either.
        self.assertEqual(int(slot.declared_address), int(placement["declared_address"]))
        self.assertEqual(0, self.repair_arm.repair_counts["target_repair"])
        address_field = field_by_role(self.repair_layout, "soc_image",
                                      f"{slot.prefix}_address")
        self.assertEqual(int(slot.declared_address), segment(projected[0], address_field))


class LegacyImageAddressPolicyTests(unittest.TestCase):
    """The legacy single-candidate image: ``image_address_policy`` decides.

    Without a declared candidate program the arm projects one ``init``/``data``
    offer through the image plan itself, and there the two layers that can refuse
    are the image plan's data check (``data-address-unmapped``) and the
    instruction-stimulus layer underneath it, whose
    ``instruction-address-unmapped`` is wrapped by the image as
    ``instruction-candidate-rejected:...``.  The declared repair policy here is
    the legacy region projection, which is *not* the same move as the declared
    program's projection onto a slot address.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()
        cls.image = build_image_plan(cls.plan)
        cls.layout = combined_input_layout(cls.plan, cls.image)
        cls.policy = compile_input_constraints(cls.plan, drive_profile="cpu_execute")
        cls.instruction = cls.image.candidates.instruction[0]
        cls.data = cls.image.candidates.data[0]

    def arm(self, image_address_policy: str):
        return build_projection_arms(
            layout=self.layout,
            constraint_hash=self.policy.policy_hash,
            special_width=int(self.plan.raw_layout["raw_width"]),
            policy=self.policy,
            image=self.image,
            image_address_policy=image_address_policy,
            peer_slots=_peer_projection_slots(self.plan, self.layout, base_dir=ROOT),
        )["dependency_repair"]

    def test_a_strict_image_refuses_an_out_of_region_instruction_offer(self) -> None:
        offered = int(self.image.base + self.image.size + 4)
        word = slot_word(self.layout, self.instruction, address=offered, value=0x00000013)
        arm = self.arm("strict")
        with self.assertRaises(SocImageError) as caught:
            arm.project_records((word,))
        # The reason names both layers: the image wraps the stimulus layer's
        # ``instruction-address-unmapped`` in ``instruction-candidate-rejected``.
        self.assertEqual("instruction-candidate-rejected:instruction-address-unmapped",
                         str(caught.exception))
        self.assertEqual({"address_repair": 0}, dict(arm.repair_counts),
                         "a strict policy must not have repaired anything")

    def test_a_strict_image_refuses_a_data_offer_outside_the_writable_region(self) -> None:
        offered = int(self.image.data_base + self.image.data_size + 4)
        word = slot_word(self.layout, self.data, address=offered, value=0x11223344)
        arm = self.arm("strict")
        with self.assertRaises(SocImageError) as caught:
            arm.project_records((word,))
        self.assertEqual(f"data-address-unmapped:0x{offered:x}", str(caught.exception))
        self.assertEqual({"address_repair": 0}, dict(arm.repair_counts))

    def test_the_declared_repair_moves_the_address_into_the_declared_region(self) -> None:
        """The other side of the same word: moved, in-region, and counted.

        The legacy policy projects onto a legal full word *inside the declared
        region*; it is not the declared program's projection onto a slot's
        declared address.  What both must share is that the move is declared and
        recorded.
        """
        offered = int(self.image.base + self.image.size + 4)
        word = slot_word(self.layout, self.instruction, address=offered, value=0x00000013)
        arm = self.arm("repair")
        projected = arm.project_records((word,))
        address_field = field_by_role(self.layout, "soc_image", "init_address")
        repaired = segment(projected[0], address_field)
        self.assertNotEqual(offered, repaired)
        self.assertEqual(0, repaired % 4)
        self.assertTrue(self.image.base <= repaired < self.image.base + self.image.size)
        self.assertEqual(1, arm.repair_counts["address_repair"])
        # The image layer really accepts it: the placement the stimulus froze is
        # the repaired address, so the record and the applied word agree.
        corrected = self.image.materialize_many(
            [value & ((1 << self.image.raw_width) - 1) for value in projected])
        self.assertEqual(1, corrected.accepted)
        self.assertEqual(repaired, int(corrected.initialization_records[0]
                                       ["corrected_candidate"]["address"]))

    def test_the_declared_repair_is_not_the_identity_arm(self) -> None:
        """The repair is a declared policy, not something the identity arm does."""
        offered = int(self.image.base + self.image.size + 4)
        word = slot_word(self.layout, self.instruction, address=offered, value=0x00000013)
        arms = build_projection_arms(
            layout=self.layout, constraint_hash=self.policy.policy_hash,
            special_width=int(self.plan.raw_layout["raw_width"]), policy=self.policy,
            image=self.image, image_address_policy="repair",
            peer_slots=_peer_projection_slots(self.plan, self.layout, base_dir=ROOT))
        self.assertEqual([word], list(arms["direct_input"].project_records([word])))


class HarnessOverlayRefusalTests(unittest.TestCase):
    """The generated harness refuses an out-of-region overlay by name.

    The harness is the last layer that can catch an out-of-region offer, because
    the identity arm hands it exactly the bits it was given.  Its refusal is a
    ``$display`` line it prints *instead of* writing the memory model, and
    ``run_sample`` surfaces that line in ``RunResult.image_errors``.  Both halves
    are asserted here without Verilator; the real RTL that prints the line is
    asserted by :class:`RealHarnessOverlayRefusalTests`.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = example_plan()
        cls.image = build_image_plan(cls.plan)
        cls.layout = combined_input_layout(cls.plan, cls.image)
        cls.text = render_profile_testbench(cls.plan, image_plan=cls.image)

    def test_every_declared_slot_refuses_out_of_region_then_places_in_region(self) -> None:
        """Each slot's own declared region bounds its placement, exactly.

        The guard's *then* branch is the refusal and its *else* branch is the
        memory write, so there is no third path in which an out-of-region address
        could be moved into a legal slot: a clamped placement would have to live
        in the ``then`` branch, and that branch contains only the ``$display``.
        """
        for slot in self.image.candidates.slots():
            with self.subTest(slot=slot.prefix):
                guard = (
                    f"            if ({{1'b0,image_address}} + image_lane < "
                    f"33'd{slot.region_base} || "
                    f"{{1'b0,image_address}} + image_lane >= "
                    f"33'd{slot.region_base + slot.region_size}) begin\n"
                    f'              $display("MYFUZZ_IMAGE_ERROR slot=%s reason=address", '
                    f'"{slot.prefix}");\n'
                    f"            end else begin\n")
                self.assertIn(guard, self.text)
                following = self.text.split(guard, 1)[1]
                write = following.splitlines()[0]
                self.assertIn("initial_memory[image_address - 32'd", write)
                self.assertIn("= image_value[image_lane*8 +: 8];", write)
                # The offered address is what gets recorded, never a moved one.
                self.assertIn(f"        placed_{slot.prefix}_address = image_address;",
                              self.text)
        self.assertEqual(len(self.image.candidates.slots()),
                         self.text.count("MYFUZZ_IMAGE_ERROR slot=%s reason=address"))

    def test_the_refusal_the_harness_prints_reaches_the_run_result(self) -> None:
        """``MYFUZZ_IMAGE_ERROR slot=<prefix> reason=address`` → ``image_errors``.

        The executable is a stub that prints the same line the generated harness
        prints; the point here is the runtime's *result* contract, so a refusal
        the RTL reported cannot be silently dropped before it is saved.  The
        generated text that produces the line is asserted above, and the real
        binary is exercised when ``MYFUZZ_SOC_REAL=1``.
        """
        with tempfile.TemporaryDirectory(prefix=".myfuzz-soc-harness-", dir=ROOT) as name:
            directory = Path(name)
            executable = stub_simulator(directory, (
                "MYFUZZ_IMAGE_ERROR slot=init reason=address",
                "MYFUZZ_SOC_RUN status=OK cycles=2 request=4369",
            ))
            build = dataclasses.replace(record_only_build(directory, self.plan),
                                        executable=executable)
            sample = RuntimeSample(request_id=0x1111, raw=(0, 0))
            result = run_sample(build, sample)
        self.assertEqual("OK", result.status)
        self.assertEqual(({"slot": "init", "reason": "address"},), result.image_errors)
        self.assertEqual(0, len(result.image_placements))


# ---------------------------------------------------------------------------
# the real RTL half (opt in)
# ---------------------------------------------------------------------------

_BUILD_CACHE: dict[str, RuntimeBuild] = {}


def _build_from_document(document: dict, output: Path) -> RuntimeBuild:
    boot = document.get("boot_image")
    return RuntimeBuild(
        output_dir=output,
        top_path=output / str(document["top"]),
        testbench_path=output / str(document["testbench"]),
        executable=output / str(document["executable"]),
        sources=tuple(str(item) for item in document.get("sources", ())),
        raw_width=int(document["raw_width"]),
        slots=tuple(dict(item) for item in document.get("slots", ())),
        observations=tuple(dict(item) for item in document.get("observations", ())),
        boot_image=None if boot is None else output / str(boot),
        boot_image_policy=str(document.get("boot_image_policy", "")),
        build_hash=str(document["build_hash"]),
        warnings=int(document.get("warnings", 0)),
        peer_slots=tuple(dict(item) for item in document.get("peer_slots", ())),
        peer_observations=tuple(dict(item) for item in document.get("peer_observations", ())),
        peer_wires=tuple(dict(item) for item in document.get("peer_wires", ())),
        spi_wire_contracts=dict(document.get("spi_wire_contracts", {}) or {}),
        cpu_data_sources=tuple(document.get("cpu_data_sources", ()) or ()),
        source_hashes=dict(document.get("source_hashes", {}) or {}),
    )


def _image_runtime_build(plan, image) -> RuntimeBuild:
    """The real example-plan runtime carrying the candidate image overlay.

    Cached under ``runs/soc-input-stale-identity/<plan-prefix>/``; the cached
    record is only accepted while its plan hash, the layout hash the generated
    testbench records and the image plan's own hash all still match, so a stale
    binary is rebuilt instead of being replayed against.
    """
    key = str(plan.plan_hash).split(":", 1)[-1][:12]
    if key in _BUILD_CACHE:
        return _BUILD_CACHE[key]
    directory = CACHE_ROOT / key
    record = directory / "runtime_build.json"
    if record.is_file():
        try:
            saved = json.loads(record.read_text(encoding="utf-8"))
        except ValueError:
            saved = {}
        document = saved.get("build")
        if isinstance(document, dict) and saved.get("plan_hash") == plan.plan_hash \
                and saved.get("image_hash") == image.image_hash:
            build = _build_from_document(document, directory)
            if build.executable.is_file() and build.top_path.is_file() \
                    and build.testbench_path.is_file():
                recorded = recorded_build_identity(build)
                if recorded["plan_hash"] == plan.plan_hash \
                        and recorded["layout_hash"] == str(plan.raw_layout["layout_hash"]):
                    _BUILD_CACHE[key] = build
                    return build
    if directory.exists():
        shutil.rmtree(directory)
    files = render_composition(plan)
    sources = [str(item["path"]) for item in source_list(plan)]
    build = build_profile_runtime(plan, output_dir=directory, base_dir=ROOT,
                                  top_text=files["myfuzz_soc_top.sv"], sources=sources,
                                  image_plan=image)
    record.write_text(json.dumps({"plan_hash": plan.plan_hash,
                                  "image_hash": image.image_hash,
                                  "build": build.document()},
                                 indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _BUILD_CACHE[key] = build
    return build


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real harness refusal")
class RealHarnessOverlayRefusalTests(unittest.TestCase):
    """The real harness refuses an out-of-region overlay instead of clamping it.

    One build serves all three runs, so the control, the refused offer and the
    repaired offer differ only in the raw word they drive:

    * control -- no offer at all: no placement, no refusal;
    * identity -- the out-of-region word exactly as a corpus carries it: the
      harness reports ``MYFUZZ_IMAGE_ERROR slot=init reason=address`` and the
      run's observations are *identical* to the control's, so the word was not
      moved into a legal slot anywhere;
    * repair -- the word the declared legacy repair policy projects: the address
      is inside the declared region, the run is clean, and the placement readback
      is the offered word's own first byte.
    """

    CYCLES = (0, 0, 0)

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("verilator") is None:
            raise AssertionError(
                "MYFUZZ_SOC_REAL=1 requires Verilator for the harness refusal run")
        cls.plan = example_plan()
        cls.image = build_image_plan(cls.plan)
        cls.layout = combined_input_layout(cls.plan, cls.image)
        cls.policy = compile_input_constraints(cls.plan, drive_profile="cpu_execute")
        cls.build = _image_runtime_build(cls.plan, cls.image)
        cls.slot = cls.image.candidates.instruction[0]
        cls.offered = int(cls.image.base + cls.image.size + 4)
        cls.word = slot_word(cls.layout, cls.slot, address=cls.offered, value=0x00000013)
        cls.control = run_sample(
            cls.build, RuntimeSample(request_id=0xC0, raw=cls.CYCLES))
        cls.refused = run_sample(
            cls.build, RuntimeSample(request_id=0xC1, raw=(cls.word,) + cls.CYCLES))
        arm = build_projection_arms(
            layout=cls.layout, constraint_hash=cls.policy.policy_hash,
            special_width=int(cls.plan.raw_layout["raw_width"]), policy=cls.policy,
            image=cls.image, image_address_policy="repair",
            peer_slots=_peer_projection_slots(cls.plan, cls.layout, base_dir=ROOT),
        )["dependency_repair"]
        cls.projected = tuple(arm.project_records([cls.word]))
        cls.repair_counts = dict(arm.repair_counts)
        cls.repaired = run_sample(
            cls.build, RuntimeSample(request_id=0xC2, raw=cls.projected + cls.CYCLES))

    def test_the_runs_share_one_executable_and_one_layout_identity(self) -> None:
        recorded = recorded_build_identity(self.build)
        self.assertEqual(self.plan.plan_hash, recorded["plan_hash"])
        self.assertEqual(str(self.plan.raw_layout["layout_hash"]), recorded["layout_hash"])
        self.assertTrue(self.build.executable.is_file())
        for result in (self.control, self.refused, self.repaired):
            self.assertEqual("OK", result.status, result.reason)

    def test_the_harness_refuses_the_out_of_region_offer_by_name(self) -> None:
        self.assertEqual((), tuple(self.control.image_errors))
        self.assertEqual((), tuple(self.control.image_placements))
        self.assertTrue(self.refused.image_errors, "the refusal must be reported")
        # Every reported line is the same named refusal; nothing else was reported.
        self.assertEqual({frozenset(dict(item).items())
                          for item in self.refused.image_errors},
                         {frozenset({"slot": self.slot.prefix,
                                     "reason": "address"}.items())})
        self.assertIn("MYFUZZ_IMAGE_ERROR", self.refused.stdout)

    def test_the_refused_offer_is_not_moved_into_a_legal_slot(self) -> None:
        """Nothing changed: same memory, same requests, same address record.

        The counters are not compared: the refused sample carries one more raw
        word than the control (that word *is* the offer), so its cycle count
        differs by construction.  What must not differ is any state the DUT
        reached or any bus traffic it produced.
        """
        self.assertEqual(dict(self.control.observations), dict(self.refused.observations))
        self.assertEqual(tuple(self.control.requests), tuple(self.refused.requests))
        self.assertEqual(tuple(self.control.responses), tuple(self.refused.responses))
        placements = [item for item in self.refused.image_placements
                      if item["slot"] == self.slot.prefix]
        self.assertTrue(placements)
        for item in placements:
            self.assertEqual(self.offered, int(item["addr"]),
                             "the harness recorded a different address than it was given")
            self.assertEqual(0, int(item["readback"]))

    def test_the_declared_repair_policy_moves_it_and_the_run_is_clean(self) -> None:
        address_field = field_by_role(self.layout, "soc_image",
                                      f"{self.slot.prefix}_address")
        repaired = segment(self.projected[0], address_field)
        self.assertNotEqual(self.offered, repaired)
        self.assertTrue(self.image.base <= repaired < self.image.base + self.image.size)
        self.assertEqual(1, self.repair_counts["address_repair"])
        self.assertEqual((), tuple(self.repaired.image_errors))
        placements = [item for item in self.repaired.image_placements
                      if item["slot"] == self.slot.prefix]
        self.assertEqual(1, len(placements))
        self.assertEqual(repaired, int(placements[0]["addr"]))
        self.assertEqual(0x13, int(placements[0]["readback"]))


if __name__ == "__main__":
    unittest.main()
