"""Roadmap phase 1C: one deterministic corpus through all three projection arms.

The projection tests prove what each arm does to one field; the transport and
replay tests prove that a saved raw input really re-runs.  What is still missing
is the *comparison*: the same input set driven through the three arms, on the
same executable, reported as rates, unique projected inputs, CPU/peer coverage
and a field-by-field replay comparison.

This module covers that report (``myfuzz.composition.soc_input_chain_report``)
without Verilator.  The projection half of every outcome below is the *real*
projector output over the *real* ``soc_comparison.build_seed_corpus`` corpus of a
real plan; only the "what the RTL did" half (bus requests, applied stimulus, peer
applications, coverage bits) is fixed by hand, so the report's arithmetic, its
identity checks and its divergence location can be asserted exactly.  The real
three-arm run on pinned Ibex lives in the opt-in half of this module.

Two rules this module is built around, because collapsing them is how a
comparison starts flattering an arm:

* a BFM/contention execution mode may not claim CPU requests, and its requests
  are counted in ``bfm_request_count`` only -- never in CPU coverage and never
  added to ``cpu_request_count``;
* a rejected input produced no run at all, so it may not carry applied stimulus,
  requests or peer applications.
"""
from __future__ import annotations

import json
import os
import shutil
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from myfuzz.composition.soc_input_chain_report import (
    BFM_EXECUTION_MODES,
    CPU_EXECUTION_MODES,
    REPORT_SCHEMA,
    SEEDED_CORPUS_EXECUTION_MODE,
    SocInputChainReportError,
    arm_metrics,
    build_chain_report,
    fabric_source_lanes,
)
from myfuzz.composition.soc_runtime import RuntimeBuild
from myfuzz.contracts import content_hash
from myfuzz.integration.soc_builder import SocBuildError
from myfuzz.composition.soc_candidate_program import encode_addi, encode_sw
from myfuzz.integration.soc_comparison import build_seed_corpus

from tests.integration.test_soc_input_arms_projection import (
    arms_for,
    example_plan,
    ibex_plan,
)

ROOT = Path(__file__).resolve().parents[2]
ARM_NAMES = ("direct_input", "constrained_baseline", "dependency_repair")
SEED = 20_260_922
ENTRIES = 6
CYCLES = 4
#: The real run needs enough cycles for reset, the pre-release image overlay and
#: a few executed instructions; the pure fixture above needs none of that.
REAL_CYCLES = 400
#: The RAM word the pinned store writes, so an entry's own constant is readable
#: through the memory the DUT really modified.
RAM_SCRATCH_OFFSET = 0x40
#: Declared instruction slots per test.  Slot 0 is the fuzzed candidate; the rest
#: are pinned by the boot image, so the program always ends in a store instead of
#: falling into the memory model's zero fill.
INSTRUCTION_SLOTS = 3
#: The example plan's own special-input port.  The applied trace names real ports,
#: so the replay comparison has a real field role to locate a flipped bit in.
TRACE_PORT = "gpio0__pin_mode_i"
EXECUTABLE_SHA256 = "sha256:" + "e" * 64
SOURCE_CLOSURE_HASH = "sha256:" + "a" * 64
REFUSED_REASON = "profile-dynamic-image-loading-unsupported"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def fake_build(layout, *, source_hashes=None, cpu_data_sources=(0,)) -> RuntimeBuild:
    """A build record with no files behind it.

    The report is pure: it must never read the testbench, the executable, the
    boot image or the sources.  Pointing every path at a directory that does not
    exist is how that property is enforced here rather than assumed.
    """
    missing = Path("runs/soc-input-chain-does-not-exist")
    return RuntimeBuild(
        output_dir=missing,
        top_path=missing / "myfuzz_soc_top.sv",
        testbench_path=missing / "profile_tb.sv",
        executable=missing / "myfuzz_profile_sim",
        sources=(),
        raw_width=int(layout.raw_width),
        slots=(),
        observations=(),
        boot_image=None,
        boot_image_policy="no_preloaded_region",
        build_hash="sha256:" + "b" * 64,
        warnings=0,
        cpu_data_sources=tuple(int(item) for item in cpu_data_sources),
        source_hashes=dict(
            {"src/myfuzz/protocols/rtl/soc_router.sv": "sha256:" + "1" * 64}
            if source_hashes is None else source_hashes),
    )


class ChainFixture:
    """The real projectors of one real plan plus the corpus every arm receives."""

    def __init__(self, drive_profile: str = "cpu_execute", *,
                 instruction_candidates: int = 1, data_candidates: int = 1) -> None:
        self.drive_profile = drive_profile
        self.plan = example_plan(drive_profile)
        self.image, self.layout, self.policy, self.arms = arms_for(
            self.plan, instruction_candidates=instruction_candidates,
            data_candidates=data_candidates)
        self.build = fake_build(self.layout)
        self.corpus = build_seed_corpus(
            SimpleNamespace(layout=self.layout), seed=SEED, entries=ENTRIES,
            cycles=CYCLES, image_plan=self.image.document())
        self.identity = {
            "layout_hash": str(self.layout.layout_hash),
            "policy_hash": str(self.policy.policy_hash),
            "image_hash": str(self.image.image_hash),
            "source_closure_hash": SOURCE_CLOSURE_HASH,
            "executable_sha256": EXECUTABLE_SHA256,
        }

    def indices(self, kind: str) -> tuple[int, ...]:
        return tuple(int(item["index"]) for item in self.corpus
                     if str(item["kind"]) == kind)


def run_half(arm: str, index: int, *, mode: str = "cpu_execute",
             requests: bool = True) -> dict[str, object]:
    """The hand-built "what the RTL did" half of one outcome.

    A CPU-mode run records one bus write from the CPU's own lane; a BFM-mode run
    records one write from the synthetic master's lane and no CPU request, which
    is what the execution mode means.  ``requests=False`` is the case the plan
    calls out: an executed CPU input that produced no observed request cannot be
    counted as CPU coverage.  The image placements mirror what the generated
    harness reports: the address it placed at and the value the memory model
    really held there afterwards.
    """
    applied = [{"cycle": 0, "port": TRACE_PORT, "value": index},
               {"cycle": 2, "port": TRACE_PORT, "value": index + 1}]
    peer = [{"cycle": 1, "instance": "uart0", "slot": "uart.tx_byte",
             "value": 0x31 + index}] if index == 3 else []
    counters = {"cycles": CYCLES, "observations": 3, "fabric_responses": 3}
    if mode in BFM_EXECUTION_MODES:
        bfm = [] if not requests else [
            {"cycle": 1, "addr": 0x4000_0000 + 0x10 * index, "write": 1,
             "wdata": index, "be": 0xF, "source": 1}]
        return {
            "execution_mode": mode,
            "applied": applied,
            "cpu_requests": [], "cpu_writes": [],
            "bfm_requests": bfm, "bfm_writes": [item for item in bfm if item["write"]],
            "counters": counters,
            "peer_applied": peer,
            "coverage_bits": [index, index + 8],
        }
    cpu = [] if not requests else [
        {"cycle": 1, "addr": 0x8000_0000 + 0x10 * index, "write": 1,
         "wdata": 0x13, "be": 0xF, "source": 0}]
    return {
        "execution_mode": mode,
        "applied": applied,
        "cpu_requests": cpu, "cpu_writes": [item for item in cpu if item["write"]],
        "bfm_requests": [], "bfm_writes": [],
        "counters": counters,
        "peer_applied": peer,
        "coverage_bits": [index, index + 8],
        # The identity arm carries no repair authority, so an out-of-region offer
        # is refused by the harness: that refusal is evidence, not a silent zero.
        "image_placements": [{"kind": "instruction", "slot": "init",
                              "addr": 0x1_0000 + 4 * index, "readback": 0x13,
                              "reset_held": True}],
        "image_errors": ([{"slot": "init", "reason": "address"}]
                         if (arm, index) == ("direct_input", 2) else []),
    }


def outcome(arm: str, index: int, entry, *, status: str, reason: str, projected,
            execution_mode: str = "cpu_execute", repairs=(), counters=None,
            applied=(), cpu_requests=(), cpu_writes=(), bfm_requests=(),
            bfm_writes=(), peer_applied=(), image_placements=(), image_errors=(),
            coverage_bits=(), identity=None, **overrides) -> dict[str, object]:
    """One outcome with the plan's fixed fields, plus the run half's extras."""
    record: dict[str, object] = {
        "index": int(index),
        "arm": arm,
        "status": status,
        "reason": reason,
        "raw": [int(value) for value in entry["raw"]],
        "applied": [dict(item) for item in applied],
        "projected": [int(value) for value in projected],
        "repairs": [dict(item) for item in repairs],
        "counters": dict({"cycles": CYCLES} if counters is None else counters),
        "cpu_requests": [dict(item) for item in cpu_requests],
        "cpu_writes": [dict(item) for item in cpu_writes],
        "bfm_requests": [dict(item) for item in bfm_requests],
        "bfm_writes": [dict(item) for item in bfm_writes],
        "peer_applied": [dict(item) for item in peer_applied],
        "image_placements": [dict(item) for item in image_placements],
        "image_errors": [dict(item) for item in image_errors],
        "coverage_bits": [int(item) for item in coverage_bits],
        "execution_mode": execution_mode,
    }
    record.update(identity or {})
    record.update(overrides)
    return record


def chain_outcomes(fixture: ChainFixture, *, corpus=None, modes=None, no_request=(),
                   with_replays: bool = True):
    """Every arm's outcomes over the shared corpus: real projection, fixed run.

    ``modes`` maps a corpus index to its execution mode (default ``cpu_execute``)
    and ``no_request`` names ``(arm, index)`` pairs whose run observed no bus
    request; both are what a real run would report for a different bus owner or a
    quiet test.  The replay evidence is aligned with the outcome sequence, with
    ``None`` where a rejected input has nothing to replay.
    """
    entries = fixture.corpus if corpus is None else corpus
    mode_for = dict(modes or {})
    outcomes: dict[str, list[dict[str, object]]] = {arm: [] for arm in fixture.arms}
    replays: dict[str, list[object]] = {arm: [] for arm in fixture.arms}
    for arm, projector in fixture.arms.items():
        counts = dict(getattr(projector, "repair_counts", {}) or {})
        for entry in entries:
            index = int(entry["index"])
            mode = str(mode_for.get(index, "cpu_execute"))
            try:
                projected = [int(value)
                             for value in projector.project_records(entry["raw"])]
            except SocBuildError as error:
                # A refusal is a *named* outcome of the projection: the input is
                # recorded, the reason is recorded, and nothing was driven.
                outcomes[arm].append(outcome(
                    arm, index, entry, status="rejected", reason=str(error),
                    projected=(), execution_mode=mode))
                replays[arm].append(None)
                continue
            after = dict(getattr(projector, "repair_counts", {}) or {})
            repairs = [{"kind": name, "slot": "", "field": "", "rule": "test-fixture"}
                       for name in sorted(after)
                       for _ in range(int(after[name]) - int(counts.get(name, 0)))]
            counts = after
            half = run_half(arm, index, mode=mode,
                            requests=(arm, index) not in no_request)
            outcomes[arm].append(outcome(
                arm, index, entry, status="executed", reason="", projected=projected,
                repairs=repairs, **half))
            replays[arm].append(None if not with_replays else {
                "status": "OK", "cycles": CYCLES, "request_id": index,
                "applied_trace": [dict(item) for item in half["applied"]],
            })
    return outcomes, replays


def report_for(fixture: ChainFixture, outcomes, replays=None, *, identity=None,
               corpus=None, **evidence) -> dict[str, object]:
    document: dict[str, object] = {
        "outcomes": outcomes,
        "identity": dict(fixture.identity if identity is None else identity),
    }
    if replays is not None:
        document["replays"] = replays
    document.update(evidence)
    return build_chain_report(
        plan=fixture.plan, build=fixture.build, arms=fixture.arms,
        corpus=fixture.corpus if corpus is None else corpus, evidence=document)


# ---------------------------------------------------------------------------
# the three arms over one corpus
# ---------------------------------------------------------------------------


class ArmMetricsTests(unittest.TestCase):
    """Rates, unique projections, CPU/peer coverage -- and nothing summed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = ChainFixture()
        # Two executed CPU inputs really produced no observed request, so "has a
        # request" is a measured property and not a restatement of "executed".
        cls.outcomes, cls.replays = chain_outcomes(
            cls.fixture, no_request={("direct_input", 1), ("constrained_baseline", 5)})
        cls.report = report_for(cls.fixture, cls.outcomes, cls.replays)
        cls.candidates = cls.fixture.indices("candidate")
        cls.special = cls.fixture.indices("special")

    def test_every_arm_records_one_outcome_per_corpus_entry(self) -> None:
        for arm in ARM_NAMES:
            with self.subTest(arm=arm):
                metrics = self.report["arms"][arm]
                self.assertEqual(arm, metrics["arm"])
                self.assertEqual(len(self.fixture.corpus), metrics["outcomes"])
                self.assertEqual(
                    len(self.outcomes[arm]), len(self.report["outcomes"][arm]))
                self.assertEqual(
                    sorted(int(item["index"]) for item in self.fixture.corpus),
                    sorted(int(item["index"]) for item in self.report["outcomes"][arm]))

    def test_effective_input_rate_is_the_share_status_executed(self) -> None:
        arms = self.report["arms"]
        self.assertEqual(1.0, arms["direct_input"]["effective_input_rate"])
        self.assertEqual(0.0, arms["direct_input"]["rejection_rate"])
        self.assertEqual(len(self.special), arms["constrained_baseline"]["executed"])
        self.assertAlmostEqual(
            len(self.special) / len(self.fixture.corpus),
            arms["constrained_baseline"]["effective_input_rate"])
        self.assertAlmostEqual(
            len(self.candidates) / len(self.fixture.corpus),
            arms["constrained_baseline"]["rejection_rate"])
        self.assertEqual(1.0, arms["dependency_repair"]["effective_input_rate"])
        self.assertEqual(0, arms["dependency_repair"]["rejected"])

    def test_a_rejection_is_grouped_by_its_exact_named_reason(self) -> None:
        baseline = self.report["arms"]["constrained_baseline"]
        self.assertEqual({REFUSED_REASON: len(self.candidates)},
                         baseline["rejection_counts"])
        self.assertAlmostEqual(
            len(self.candidates) / len(self.fixture.corpus),
            baseline["rejection_rates"][REFUSED_REASON])
        # The name is the projector's own, recorded verbatim: a reason rewritten
        # here would make two different refusals look like one.
        for record in self.report["outcomes"]["constrained_baseline"]:
            if record["status"] == "rejected":
                self.assertEqual(REFUSED_REASON, record["reason"])

    def test_repairs_are_counted_per_kind_over_the_effective_inputs(self) -> None:
        direct = self.report["arms"]["direct_input"]
        repair = self.report["arms"]["dependency_repair"]
        self.assertEqual({}, direct["repair_counts"])
        self.assertEqual({"address_repair": 4}, repair["repair_counts"])
        self.assertAlmostEqual(
            4 / repair["executed"], repair["repair_rates"]["address_repair"])
        recorded = sum(len(record["repairs"])
                       for record in self.report["outcomes"]["dependency_repair"])
        self.assertEqual(4, recorded)
        self.assertEqual(0, sum(len(record["repairs"]) for record in
                                self.report["outcomes"]["constrained_baseline"]))

    def test_unique_projected_inputs_are_sha256_deduplicated_and_real(self) -> None:
        arms = self.report["arms"]
        self.assertEqual(len(self.fixture.corpus),
                         arms["direct_input"]["unique_projected_inputs"]["count"])
        self.assertEqual(len(self.special),
                         arms["constrained_baseline"]["unique_projected_inputs"]["count"])
        self.assertEqual(len(self.fixture.corpus),
                         arms["dependency_repair"]["unique_projected_inputs"]["count"])
        identity = {int(item["index"]): item["projected_sha256"]
                    for item in self.report["outcomes"]["direct_input"]}
        repaired = {int(item["index"]): item["projected_sha256"]
                    for item in self.report["outcomes"]["dependency_repair"]}
        # The identity arm's first projection is reproduced verbatim by the
        # repair arm; the address-repaired entry is not.  Both halves matter: one
        # proves the two arms saw the same input, the other that they did not
        # silently become the same projector.
        self.assertEqual(identity[0], repaired[0])
        self.assertNotEqual(identity[2], repaired[2])
        self.assertEqual(sorted(set(repaired.values())),
                         arms["dependency_repair"]["unique_projected_inputs"]["hashes"])

    def test_two_corpus_entries_that_project_to_one_input_count_once(self) -> None:
        repeated = tuple({"index": index, "kind": "special", "raw": (0x2A,) * CYCLES}
                         for index in (0, 1))
        outcomes, replays = chain_outcomes(self.fixture, corpus=repeated)
        report = report_for(self.fixture, outcomes, replays, corpus=repeated)
        self.assertEqual(2, report["corpus"]["entries"])
        self.assertEqual(2, report["arms"]["direct_input"]["executed"])
        self.assertEqual(1, report["arms"]["direct_input"]["unique_projected_inputs"]["count"])
        self.assertEqual(2, report["arms"]["direct_input"]["unique_projected_inputs"]["inputs"])

    def test_cpu_coverage_counts_only_executed_cpu_outcomes_with_requests(self) -> None:
        direct = self.report["arms"]["direct_input"]["cpu_coverage"]
        self.assertEqual(list(CPU_EXECUTION_MODES), direct["execution_modes"])
        self.assertEqual(len(self.fixture.corpus), direct["outcomes"])
        self.assertEqual(5, direct["outcomes_with_requests"])
        self.assertEqual(1, direct["outcomes_without_requests"])
        self.assertEqual([0x8000_0000 + 0x10 * index for index in (0, 2, 3, 4, 5)],
                         direct["touched_addresses"])
        self.assertEqual(5, direct["touched_address_count"])
        self.assertEqual(5, direct["request_count"])
        self.assertEqual(5, direct["write_count"])
        self.assertAlmostEqual(5 / 6, direct["coverage_rate"])
        baseline = self.report["arms"]["constrained_baseline"]["cpu_coverage"]
        self.assertEqual(len(self.special), baseline["outcomes"])
        self.assertEqual(2, baseline["outcomes_with_requests"])
        self.assertEqual(1, baseline["outcomes_without_requests"])
        repair = self.report["arms"]["dependency_repair"]["cpu_coverage"]
        self.assertEqual(6, repair["outcomes_with_requests"])
        self.assertEqual(6, repair["touched_address_count"])

    def test_peer_coverage_counts_outcomes_with_applied_peer_events(self) -> None:
        for arm in ARM_NAMES:
            with self.subTest(arm=arm):
                peer = self.report["arms"][arm]["peer_coverage"]
                self.assertEqual(1, peer["outcomes_with_applied_events"])
                self.assertEqual(1, peer["applied_events"])
                self.assertEqual(["uart0"], peer["instances"])
                self.assertEqual(["uart.tx_byte"], peer["slots"])

    def test_rtl_coverage_bits_are_aggregated_when_a_run_reports_them(self) -> None:
        bits = self.report["arms"]["direct_input"]["coverage_bits"]
        self.assertEqual(len(self.fixture.corpus), bits["outcomes_recorded"])
        self.assertEqual(sorted({*range(6), *range(8, 14)}), bits["union"])

    def test_image_placements_and_run_counters_are_aggregated(self) -> None:
        placements = self.report["arms"]["direct_input"]["image_placements"]
        self.assertEqual(len(self.fixture.corpus), placements["outcomes_recorded"])
        self.assertEqual(len(self.fixture.corpus), placements["placements"])
        self.assertEqual(len(self.fixture.corpus), placements["readbacks_nonzero"])
        self.assertEqual(["init"], placements["slots"])
        self.assertEqual(["instruction"], sorted(placements["kinds"]))
        # The identity arm cannot repair an out-of-region address, so the harness
        # refused it: the refusal is counted, never smoothed into a placement.
        self.assertEqual(1, placements["errors"])
        self.assertEqual(1, placements["outcomes_with_errors"])
        counters = self.report["arms"]["direct_input"]["counter_totals"]
        self.assertEqual(3 * len(self.fixture.corpus),
                         counters["fabric_responses"]["total"])
        self.assertEqual(CYCLES * len(self.fixture.corpus), counters["cycles"]["total"])

    def test_a_rejected_input_is_not_counted_as_cpu_or_peer_coverage(self) -> None:
        baseline = self.report["arms"]["constrained_baseline"]
        rejected = [record for record in self.report["outcomes"]["constrained_baseline"]
                    if record["status"] == "rejected"]
        self.assertEqual(len(self.candidates), len(rejected))
        for record in rejected:
            self.assertEqual([], record["applied"])
            self.assertEqual([], record["cpu_requests"])
            self.assertEqual([], record["peer_applied"])
            self.assertEqual([], record["projected"])
        self.assertEqual(0, baseline["anomalies"])
        self.assertEqual(len(self.special), baseline["cpu_coverage"]["outcomes"])
        self.assertEqual(1, baseline["peer_coverage"]["outcomes_with_applied_events"])


class ArmMetricsFunctionTests(unittest.TestCase):
    """``arm_metrics`` is usable on its own: no plan, no build, no disk."""

    def test_arm_metrics_reports_one_arm_without_a_build(self) -> None:
        fixture = ChainFixture()
        outcomes, _ = chain_outcomes(fixture)
        metrics = arm_metrics("direct_input", outcomes["direct_input"])
        self.assertEqual("direct_input", metrics["arm"])
        self.assertEqual(1.0, metrics["effective_input_rate"])
        self.assertEqual(6, metrics["cpu_coverage"]["outcomes_with_requests"])

    def test_arm_metrics_refuses_an_outcome_recorded_for_another_arm(self) -> None:
        fixture = ChainFixture()
        outcomes, _ = chain_outcomes(fixture)
        with self.assertRaisesRegex(SocInputChainReportError, "outcome-arm-mismatch"):
            arm_metrics("direct_input", outcomes["dependency_repair"])


# ---------------------------------------------------------------------------
# execution modes: BFM and CPU are counted apart
# ---------------------------------------------------------------------------


class ExecutionModeSeparationTests(unittest.TestCase):
    """A BFM run's requests are never CPU coverage, and never summed with it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = ChainFixture("bfm_isolated")
        # Three entries execute under the CPU and three under the synthetic
        # master, so every arm has both halves in one report.
        cls.outcomes, cls.replays = chain_outcomes(cls.fixture, modes={
            index: ("cpu_execute" if index in (0, 1, 2) else
                    "bfm_isolated" if index == 3 else "contention")
            for index in range(ENTRIES)})
        cls.report = report_for(cls.fixture, cls.outcomes, cls.replays)

    def copy_outcomes(self):
        return {arm: [json.loads(json.dumps(record)) for record in records]
                for arm, records in self.outcomes.items()}

    def test_bfm_outcomes_never_claim_cpu_requests(self) -> None:
        for arm in ARM_NAMES:
            for record in self.report["outcomes"][arm]:
                if record["execution_mode"] in BFM_EXECUTION_MODES:
                    with self.subTest(arm=arm, index=record["index"],
                                      mode=record["execution_mode"]):
                        self.assertEqual([], record["cpu_requests"])
                        self.assertEqual([], record["cpu_writes"])

    def test_cpu_and_bfm_request_counts_are_reported_separately(self) -> None:
        accounting = self.report["request_accounting"]
        self.assertEqual(list(CPU_EXECUTION_MODES), accounting["cpu_execution_modes"])
        self.assertEqual(list(BFM_EXECUTION_MODES), accounting["bfm_execution_modes"])
        self.assertTrue(accounting["counted_separately"])
        # Three CPU entries and three non-CPU entries per arm, one request each.
        self.assertEqual(9, accounting["cpu_request_count"])
        self.assertEqual(9, accounting["bfm_request_count"])
        # There is no sum anywhere: if there were, it would read 18 and the two
        # numbers above could no longer be read as separate accountings.
        self.assertNotIn("request_count", accounting)
        self.assertNotIn("total_request_count", accounting)
        for arm in ARM_NAMES:
            metrics = self.report["arms"][arm]
            with self.subTest(arm=arm):
                self.assertEqual(3, metrics["cpu_request_count"])
                self.assertEqual(3, metrics["bfm_request_count"])
                self.assertEqual(3, metrics["cpu_coverage"]["outcomes"])
                self.assertEqual(3, metrics["cpu_coverage"]["request_count"])
                self.assertEqual(3, metrics["bfm_coverage"]["outcomes"])
                self.assertEqual(3, metrics["bfm_coverage"]["request_count"])
                self.assertFalse(metrics["bfm_coverage"]["counted_as_cpu_coverage"])
        cpu_addresses = set(
            self.report["arms"]["direct_input"]["cpu_coverage"]["touched_addresses"])
        bfm_addresses = set(
            self.report["arms"]["direct_input"]["bfm_coverage"]["touched_addresses"])
        self.assertTrue(cpu_addresses)
        self.assertTrue(bfm_addresses)
        self.assertEqual(set(), cpu_addresses & bfm_addresses)

    def test_a_bfm_outcome_that_claims_cpu_requests_is_refused(self) -> None:
        outcomes = self.copy_outcomes()
        target = next(record for record in outcomes["direct_input"]
                      if record["execution_mode"] in BFM_EXECUTION_MODES)
        target["cpu_requests"] = [{"cycle": 1, "addr": 0x0, "write": 1,
                                   "wdata": 0, "be": 0xF, "source": 0}]
        with self.assertRaisesRegex(
                SocInputChainReportError,
                "bfm-execution-mode-claims-cpu-requests:direct_input"):
            report_for(self.fixture, outcomes, self.replays)

    def test_an_unknown_execution_mode_is_refused_rather_than_guessed(self) -> None:
        outcomes = self.copy_outcomes()
        outcomes["direct_input"][0]["execution_mode"] = SEEDED_CORPUS_EXECUTION_MODE
        with self.assertRaisesRegex(SocInputChainReportError, "unknown-execution-mode"):
            report_for(self.fixture, outcomes, self.replays)

    def test_a_rejected_outcome_that_records_a_run_is_refused(self) -> None:
        fixture = ChainFixture()
        outcomes, _ = chain_outcomes(fixture)
        rejected = outcomes["constrained_baseline"][0]
        self.assertEqual("rejected", rejected["status"])
        rejected["cpu_requests"] = [{"cycle": 1, "addr": 0x0, "write": 1,
                                     "wdata": 0, "be": 0xF, "source": 0}]
        with self.assertRaisesRegex(SocInputChainReportError,
                                    "rejected-outcome-recorded-a-run"):
            report_for(fixture, outcomes, outcome_replays(fixture, outcomes))


def outcome_replays(fixture: ChainFixture, outcomes):
    """Replay evidence aligned with an outcome mapping, ``None`` where rejected."""
    return {arm: [None if record["status"] == "rejected" else
                  {"status": "OK", "cycles": CYCLES, "request_id": record["index"],
                   "applied_trace": [dict(item) for item in record["applied"]]}
                  for record in records]
            for arm, records in outcomes.items()}


# ---------------------------------------------------------------------------
# replay: field by field, located to (index, cycle, field_role, bit)
# ---------------------------------------------------------------------------


class ReplayComparisonTests(unittest.TestCase):
    """A replay that differs anywhere is located, not summarised."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = ChainFixture()
        cls.outcomes, cls.replays = chain_outcomes(cls.fixture)

    def copy_replays(self):
        return {arm: [json.loads(json.dumps(item)) for item in records]
                for arm, records in self.replays.items()}

    def test_an_identical_replay_agrees_field_by_field(self) -> None:
        report = report_for(self.fixture, self.outcomes, self.replays)
        replay = report["replay"]
        self.assertEqual("agreement", replay["status"], replay["reason"])
        self.assertIsNone(replay["divergence"])
        self.assertGreater(replay["checked_fields"], 0)
        self.assertEqual(0, replay["mismatching_fields"])
        self.assertEqual([], replay["mismatching_labels"])
        for arm in ARM_NAMES:
            self.assertEqual("agreement", replay["per_arm"][arm]["status"], arm)

    def test_a_single_flipped_bit_is_located_at_index_cycle_field_and_bit(self) -> None:
        replays = self.copy_replays()
        target = replays["dependency_repair"][0]
        self.assertEqual(2, target["applied_trace"][1]["cycle"])
        target["applied_trace"][1]["value"] ^= 0b10
        report = report_for(self.fixture, self.outcomes, replays)
        replay = report["replay"]
        self.assertEqual("divergence", replay["status"])
        divergence = replay["divergence"]
        self.assertEqual("dependency_repair", divergence["arm"])
        self.assertEqual(0, divergence["index"])
        self.assertEqual(2, divergence["cycle"])
        self.assertEqual(TRACE_PORT, divergence["field_role"])
        self.assertEqual(1, divergence["bit"])
        self.assertEqual([1], divergence["bits"])
        self.assertEqual("applied-port-value", divergence["kind"])
        self.assertIn(f"applied[2].{TRACE_PORT}", divergence["label"])
        self.assertEqual(1, replay["mismatching_fields"])
        # The arm that diverged says so, and the two that did not are not tarred
        # with it: a per-arm status is that arm's own comparison.
        self.assertEqual("divergence", replay["per_arm"]["dependency_repair"]["status"])
        for arm in ("direct_input", "constrained_baseline"):
            self.assertEqual("agreement", replay["per_arm"][arm]["status"], arm)

    def test_a_dropped_applied_cycle_is_located_at_that_cycle(self) -> None:
        replays = self.copy_replays()
        target = replays["direct_input"][3]
        self.assertEqual(2, len(target["applied_trace"]))
        target["applied_trace"] = target["applied_trace"][:1]
        report = report_for(self.fixture, self.outcomes, replays)
        divergence = report["replay"]["divergence"]
        self.assertEqual("direct_input", divergence["arm"])
        self.assertEqual(3, divergence["index"])
        self.assertEqual(2, divergence["cycle"])
        self.assertEqual(TRACE_PORT, divergence["field_role"])
        # The replayed run recorded no value at all there, so there is no bit to
        # name -- ``None`` says that instead of pretending bit 0.
        self.assertIsNone(divergence["bit"])

    def test_a_report_without_replay_evidence_does_not_claim_agreement(self) -> None:
        report = report_for(self.fixture, self.outcomes, None)
        replay = report["replay"]
        self.assertEqual("not_assessed", replay["status"])
        self.assertIsNone(replay["divergence"])
        self.assertEqual(0, replay["checked_fields"])
        self.assertIn("no replay evidence", replay["reason"])

    def test_a_partially_replayed_report_is_marked_partial(self) -> None:
        replays = self.copy_replays()
        replays["direct_input"][0] = None
        report = report_for(self.fixture, self.outcomes, replays)
        self.assertEqual("partial", report["replay"]["status"])
        self.assertGreater(report["replay"]["checked_fields"], 0)


# ---------------------------------------------------------------------------
# identity: same corpus, same executable, same layout/policy/image
# ---------------------------------------------------------------------------


class ReportIdentityTests(unittest.TestCase):
    """The report proves what it compares before it compares anything."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = ChainFixture()
        cls.outcomes, cls.replays = chain_outcomes(cls.fixture)
        cls.report = report_for(cls.fixture, cls.outcomes, cls.replays)

    def copy_outcomes(self):
        return {arm: [json.loads(json.dumps(record)) for record in records]
                for arm, records in self.outcomes.items()}

    def test_the_three_arms_share_one_corpus_and_one_executable(self) -> None:
        report = self.report
        self.assertEqual(report["corpus"]["hash"], report["shared_corpus_hash"])
        for arm in ARM_NAMES:
            with self.subTest(arm=arm):
                self.assertEqual(report["shared_corpus_hash"],
                                 report["corpus"]["arms"][arm])
        self.assertEqual(EXECUTABLE_SHA256, report["executable_sha256"])
        self.assertEqual(report["executable_sha256"],
                         report["identity"]["executable_sha256"])
        for arm in ARM_NAMES:
            for record in report["outcomes"][arm]:
                with self.subTest(arm=arm, index=record["index"]):
                    for field in ("layout_hash", "policy_hash", "image_hash",
                                  "source_closure_hash", "executable_sha256"):
                        self.assertEqual(report["identity"][field], record[field])
                    self.assertEqual(EXECUTABLE_SHA256, record["executable_sha256"])
                    self.assertTrue(record["applied"] or record["status"] == "rejected")

    def test_the_layout_policy_and_image_hash_come_from_the_arms_themselves(self) -> None:
        identity = self.report["identity"]
        self.assertEqual(str(self.fixture.layout.layout_hash), identity["layout_hash"])
        self.assertEqual(str(self.fixture.policy.policy_hash), identity["policy_hash"])
        self.assertEqual(str(self.fixture.image.image_hash), identity["image_hash"])

    def test_the_shared_corpus_hash_is_the_one_the_corpus_itself_has(self) -> None:
        expected = content_hash([
            {"index": int(item["index"]), "raw": [int(value) for value in item["raw"]]}
            for item in sorted(self.fixture.corpus,
                               key=lambda item: int(item["index"]))])
        self.assertEqual(expected, self.report["shared_corpus_hash"])

    def test_an_arm_that_saw_a_different_input_set_is_refused(self) -> None:
        outcomes = self.copy_outcomes()
        raw = list(outcomes["dependency_repair"][0]["raw"])
        raw[0] ^= 0x1
        outcomes["dependency_repair"][0]["raw"] = raw
        with self.assertRaisesRegex(
                SocInputChainReportError,
                "arm-did-not-use-the-shared-corpus:dependency_repair"):
            report_for(self.fixture, outcomes, self.replays)

    def test_an_arm_with_a_different_executable_is_refused(self) -> None:
        outcomes = self.copy_outcomes()
        outcomes["direct_input"][0]["executable_sha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(
                SocInputChainReportError, "identity-conflict:executable_sha256"):
            report_for(self.fixture, outcomes, self.replays)

    def test_a_recorded_layout_hash_the_arms_never_used_is_refused(self) -> None:
        outcomes = self.copy_outcomes()
        identity = dict(self.fixture.identity, layout_hash="sha256:" + "9" * 64)
        for records in outcomes.values():
            for record in records:
                record["layout_hash"] = identity["layout_hash"]
        with self.assertRaisesRegex(
                SocInputChainReportError, "identity-conflict-with-the-arm:layout_hash"):
            report_for(self.fixture, outcomes, self.replays, identity=identity)

    def test_an_outcome_without_the_executable_identity_is_refused_by_name(self) -> None:
        outcomes = self.copy_outcomes()
        identity = dict(self.fixture.identity)
        for records in outcomes.values():
            for record in records:
                record.pop("executable_sha256", None)
        identity.pop("executable_sha256")
        with self.assertRaisesRegex(SocInputChainReportError,
                                    "outcome-identity-missing:executable_sha256"):
            report_for(self.fixture, outcomes, self.replays, identity=identity)

    def test_the_source_closure_hash_is_derived_from_the_build_record(self) -> None:
        identity = {name: value for name, value in self.fixture.identity.items()
                    if name != "source_closure_hash"}
        report = report_for(self.fixture, self.outcomes, self.replays, identity=identity)
        self.assertEqual(content_hash(self.fixture.build.source_hashes),
                         report["identity"]["source_closure_hash"])

    def test_the_report_is_plain_json_with_a_content_hash(self) -> None:
        report = self.report
        self.assertEqual(report, json.loads(json.dumps(report)))
        self.assertEqual(REPORT_SCHEMA, report["schema_version"])
        self.assertEqual(SEEDED_CORPUS_EXECUTION_MODE, report["execution_mode"])
        self.assertIn("NOT an official RFuzz search", report["claim"])
        self.assertIn("NOT three independent searches", report["claim"])
        document = {name: value for name, value in report.items()
                    if name != "content_hash"}
        self.assertEqual(content_hash(document), report["content_hash"])
        again = report_for(self.fixture, self.outcomes, self.replays)
        self.assertEqual(report["content_hash"], again["content_hash"])

    def test_the_report_records_the_plan_and_build_it_measured(self) -> None:
        report = self.report
        self.assertEqual(str(self.fixture.plan.plan_hash), report["plan"]["plan_hash"])
        self.assertEqual(self.fixture.drive_profile, report["plan"]["drive_profile"])
        self.assertEqual(int(self.fixture.plan.raw_layout["raw_width"]),
                         report["plan"]["profile_raw_width"])
        self.assertEqual(int(self.fixture.layout.raw_width),
                         report["layout"]["raw_width"])
        self.assertEqual(self.fixture.build.build_hash, report["build"]["build_hash"])
        self.assertEqual(list(self.fixture.build.cpu_data_sources),
                         report["build"]["cpu_data_sources"])
        self.assertEqual(ENTRIES, report["corpus"]["entries"])

    def test_the_fabric_lanes_are_split_into_cpu_and_everything_else(self) -> None:
        lanes = fabric_source_lanes(self.fixture.plan)
        self.assertEqual(1, len(lanes["cpu"]))
        self.assertEqual("cpu_master0", lanes["cpu"][0]["source_id"])
        self.assertEqual("cpu_unified", lanes["cpu"][0]["kind"])
        self.assertEqual([], lanes["other"])
        # A composition with a synthetic master really has a second lane, and it
        # is the one whose transactions must never be read as CPU coverage.
        with_master = fabric_source_lanes(ChainFixture("bfm_isolated").plan)
        self.assertEqual([0], [item["index"] for item in with_master["cpu"]])
        self.assertEqual(["fuzz_mmio"],
                         [item["kind"] for item in with_master["other"]])
        self.assertEqual([1], [item["index"] for item in with_master["other"]])


# ---------------------------------------------------------------------------
# the real three-arm run: pinned Ibex, one build, the same seeded corpus
# ---------------------------------------------------------------------------


OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
OUTPUT_ROOT = ROOT / "runs/soc-input-chain"


def real_build_from_document(document: dict) -> RuntimeBuild:
    output = Path(document["output_dir"])
    boot = document.get("boot_image")
    # ``RuntimeBuild.document`` stores the executable's *name*; the compiler
    # writes it under ``obj_dir``.  Resolving it here is what lets a cached
    # record be reused instead of rebuilt on every run.
    executable = output / "obj_dir" / str(document["executable"]) if (output / "obj_dir" / str(document["executable"])).exists() else output / str(document["executable"])
    if not executable.is_file():
        candidate = output / "obj_dir" / str(document["executable"])
        if candidate.is_file():
            executable = candidate
    return RuntimeBuild(
        output_dir=output, top_path=output / str(document["top"]),
        testbench_path=output / str(document["testbench"]),
        executable=executable,
        sources=tuple(str(item) for item in document.get("sources", ())),
        raw_width=int(document["raw_width"]),
        slots=tuple(dict(item) for item in document.get("slots", ())),
        observations=tuple(dict(item) for item in document.get("observations", ())),
        boot_image=None if boot is None else output / str(boot),
        boot_image_policy=str(document.get("boot_image_policy", "")),
        build_hash=str(document["build_hash"]), warnings=int(document.get("warnings", 0)),
        peer_slots=tuple(dict(item) for item in document.get("peer_slots", ())),
        cpu_data_sources=tuple(int(item)
                               for item in document.get("cpu_data_sources", ())))


def _set_slot_field(raw: int, slot, name: str, value: int) -> int:
    """Place one value in one segment of a declared slot's raw word."""
    segment = slot.segment(name)
    mask = ((1 << segment.width) - 1) << segment.raw_lo
    return (raw & ~mask) | ((int(value) & ((1 << segment.width) - 1)) << segment.raw_lo)


def runtime_build_for(plan, image, directory: Path, *, program=None,
                      directed=None) -> RuntimeBuild:
    """Compile the pinned Ibex composition once, then reuse the executable.

    The caller's candidate image is materialised by the testbench from the sample
    words (``image_plan=image``), so all three arms drive one executable and the
    only difference between their runs is the projected input sequence.

    ``program`` is the declared candidate program the samples will be projected
    through.  Its *static* part -- the entry trampoline and the generated
    prologue -- is the fixed boot image the per-test overlay is applied on top of,
    so a build made for one program must not be reused for another: booting from
    a different program's image leaves the CPU executing that other program, and
    the candidate the arm placed is never reached.  The record therefore carries
    the program identity, and a mismatch rebuilds instead of replaying.
    """
    from myfuzz.composition.soc_profile_renderer import render_composition, source_list
    from myfuzz.composition.soc_runtime import build_profile_runtime

    program_hash = None if program is None else content_hash(
        {"static_image": program.document()["static_image"],
         "directed": {str(key): int(value) for key, value in sorted((directed or {}).items())}})
    record = directory / "runtime_build.json"
    if record.is_file():
        try:
            document = json.loads(record.read_text(encoding="utf-8"))
        except ValueError:
            document = {}
        build_document = document.get("build")
        if isinstance(build_document, dict) and document.get("plan_hash") == plan.plan_hash \
                and document.get("program_hash") == program_hash:
            build = real_build_from_document(build_document)
            if build.executable.is_file() and build.testbench_path.is_file() \
                    and build.boot_image is not None and build.boot_image.is_file():
                return build
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True, exist_ok=True)
    boot_image = None
    if program is not None:
        # The boot image is the program's *static* part with every declared slot
        # filled: the slots the caller pins get its directed word, and the slot it
        # leaves to the fuzzer gets its own declared address with a zero word, the
        # same shape the corpus will offer.  It is materialised through the
        # program's own repairer and layout, so the fixed image and the per-test
        # overlay agree bit for bit.
        #
        # Filling the pinned slots is what makes the corpus observable at all:
        # with every slot left to the fuzzer, an entry whose candidate is a no-op
        # leaves the CPU running into the memory model's zero fill (not a legal
        # instruction), so the run produces no transaction and two entries cannot
        # be compared.
        boot_image = directory / "candidate_program.hex"
        pins = dict(directed or {})
        words = []
        for slot in program.slots.slots():
            if slot.kind != "instruction" or slot.prefix in pins:
                # A pinned slot is offered by ``directed`` instead, and a slot
                # that is both offered and directed is refused by name rather
                # than silently preferring one of the two.
                continue
            raw = 0
            raw = _set_slot_field(raw, slot, "offer", 1)
            raw = _set_slot_field(raw, slot, "address", slot.declared_address)
            raw = _set_slot_field(raw, slot, "be", 0xF)
            raw = _set_slot_field(raw, slot, "data", 0)
            words.append(raw)
        repaired = program.repairer().repair_test(
            words, directed={name: int(value) for name, value in pins.items()})
        program.image.write_hex(repaired.image.image, boot_image)
    files = render_composition(plan)
    records = source_list(plan)
    sources = [item["path"] for item in records if item["role"] != "include_root"]
    build = build_profile_runtime(
        plan, output_dir=directory / "build", base_dir=ROOT,
        top_text=files["myfuzz_soc_top.sv"], sources=sources, image_plan=image,
        boot_image=boot_image)
    record.write_text(json.dumps({"plan_hash": plan.plan_hash,
                                  "program_hash": program_hash,
                                  "build": build.document()},
                                 indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return build


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real three-arm chain report")
class RealThreeArmChainTests(unittest.TestCase):
    """One deterministic corpus, three projectors, one real Ibex build.

    This is a *seeded-corpus* measurement: NOT an official RFuzz search and NOT
    three independent searches.  The three arms receive the same input set from
    the same seed and differ only in how they project it, so the report's rates
    describe the projectors, not a search that found anything.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.blocker: str | None = None
        cls.started = time.monotonic()
        try:
            cls._prepare()
        except Exception as error:                      # noqa: BLE001 - reported verbatim
            cls.blocker = f"{type(error).__name__}: {error}"

    @classmethod
    def _prepare(cls) -> None:
        from myfuzz.composition.soc_failure_evidence import (
            recorded_build_identity, tool_identity)
        from myfuzz.composition.soc_runtime import RuntimeSample, run_sample

        if shutil.which("verilator") is None:
            raise AssertionError(
                "MYFUZZ_SOC_REAL=1 requires Verilator for the real three-arm chain report")
        cls.plan = ibex_plan("cpu_execute")
        # A declared candidate program is what gives the repair arm authority to
        # place an offered word; without it every entry's instruction is written
        # by the ISA layer only and the entries are the same program, so the CPU
        # could not differ between them even in principle.
        #
        cls.image, cls.layout, cls.policy, cls.arms = arms_for(cls.plan)
        cls.prefix = str(cls.plan.plan_hash).split(":", 1)[-1][:12]
        cls.directory = OUTPUT_ROOT / cls.prefix
        cls.build = runtime_build_for(cls.plan, cls.image, cls.directory)
        cls.recorded = recorded_build_identity(cls.build)
        cls.corpus = build_seed_corpus(
            SimpleNamespace(layout=cls.layout), seed=SEED, entries=ENTRIES,
            cycles=REAL_CYCLES, image_plan=cls.image.document())
        cls.identity = {
            "layout_hash": str(cls.layout.layout_hash),
            "policy_hash": str(cls.policy.policy_hash),
            "image_hash": str(cls.image.image_hash),
            "source_closure_hash": content_hash(dict(cls.build.source_hashes)),
            "executable_sha256": str(
                tool_identity(cls.build, probe=False)["executable_hash"]),
        }
        outcomes: dict[str, list[dict[str, object]]] = {arm: [] for arm in cls.arms}
        replays: dict[str, list[object]] = {arm: [] for arm in cls.arms}
        cpu_lanes = {int(item["index"])
                     for item in fabric_source_lanes(cls.plan)["cpu"]}
        if not cpu_lanes:
            raise AssertionError("the composed plan declares no CPU fabric lane")
        for arm, projector in cls.arms.items():
            counts = dict(getattr(projector, "repair_counts", {}) or {})
            for entry in cls.corpus:
                index = int(entry["index"])
                try:
                    projected = [int(value)
                                 for value in projector.project_records(entry["raw"])]
                except SocBuildError as error:
                    outcomes[arm].append(outcome(
                        arm, index, entry, status="rejected", reason=str(error),
                        projected=(), execution_mode=str(cls.plan.drive_profile),
                        identity=cls.identity))
                    replays[arm].append(None)
                    continue
                after = dict(getattr(projector, "repair_counts", {}) or {})
                repairs = [{"kind": name, "slot": "", "field": "",
                            "rule": "seeded-corpus"}
                           for name in sorted(after)
                           for _ in range(int(after[name]) - int(counts.get(name, 0)))]
                counts = after
                sample = RuntimeSample(request_id=0x1000 + index, raw=tuple(projected))
                result = run_sample(cls.build, sample, timeout_seconds=600)
                # The same projected sequence is driven a second time; the saved
                # and the replayed applied stimulus are compared field by field
                # by the report itself, not by this test.
                replay = run_sample(cls.build, sample, timeout_seconds=600)
                requests = [dict(item) for item in result.requests]
                counters = dict(result.counters)
                # The CPU's own lanes (instruction fetch and data): completions
                # there are evidence that the CPU really reached the fabric,
                # kept apart from the write-request capture
                # (``RunResult.requests``) instead of being renamed a request.
                counters["cpu_attributed_responses"] = sum(
                    1 for response in result.responses
                    if int(response["source"]) in cpu_lanes)
                status = "executed" if result.status == "OK" else "anomaly"
                reason = "" if result.status == "OK" else \
                    f"{result.status}:{result.reason}"
                outcomes[arm].append(outcome(
                    arm, index, entry, status=status, reason=reason,
                    projected=projected, execution_mode=str(cls.plan.drive_profile),
                    repairs=repairs, counters=counters,
                    applied=[dict(item) for item in result.applied],
                    cpu_requests=requests,
                    cpu_writes=[item for item in requests if int(item["write"])],
                    peer_applied=[dict(item) for item in result.peer_applied],
                    image_placements=[dict(item) for item in result.image_placements],
                    image_errors=[dict(item) for item in result.image_errors],
                    coverage_bits=[], identity=cls.identity))
                replays[arm].append(None if status != "executed" else {
                    "status": result.status, "cycles": result.cycles,
                    "request_id": sample.request_id,
                    "applied_trace": [dict(item) for item in replay.applied]})
        cls.outcomes = outcomes
        cls.replays = replays
        cls.report = build_chain_report(
            plan=cls.plan, build=cls.build, arms=cls.arms, corpus=cls.corpus,
            evidence={"outcomes": outcomes, "replays": replays,
                      "identity": cls.identity})
        cls.report_path = cls.directory / "report.json"
        cls.report_path.write_text(
            json.dumps(cls.report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.blocker is None:
            print("\nMYFUZZ_SOC_INPUT_CHAIN_TIMING wall_s=%.1f report=%s"
                  % (time.monotonic() - cls.started, cls.report_path))
            for arm, metrics in cls.report["arms"].items():
                print("MYFUZZ_SOC_INPUT_CHAIN_ARM arm=%s effective=%.3f repairs=%s "
                      "rejections=%s unique=%d cpu_requests=%d cpu_addr=%d "
                      "peer=%d bfm_requests=%d"
                      % (arm, metrics["effective_input_rate"],
                         metrics["repair_counts"], metrics["rejection_counts"],
                         metrics["unique_projected_inputs"]["count"],
                         metrics["cpu_request_count"],
                         metrics["cpu_coverage"]["touched_address_count"],
                         metrics["peer_coverage"]["outcomes_with_applied_events"],
                         metrics["bfm_request_count"]))

    def setUp(self) -> None:
        if self.blocker is not None:
            self.fail("the real three-arm chain run could not be prepared: %s" % self.blocker)

    def test_the_three_arms_share_the_corpus_the_build_and_the_executable(self) -> None:
        report = self.report
        self.assertEqual(REPORT_SCHEMA, report["schema_version"])
        self.assertEqual(SEEDED_CORPUS_EXECUTION_MODE, report["execution_mode"])
        self.assertEqual(ENTRIES, report["corpus"]["entries"])
        for arm in ARM_NAMES:
            self.assertEqual(report["shared_corpus_hash"], report["corpus"]["arms"][arm])
        self.assertEqual(report["executable_sha256"], self.identity["executable_sha256"])
        self.assertTrue(self.build.executable.is_file())
        self.assertEqual(str(self.plan.plan_hash), self.recorded["plan_hash"])
        self.assertEqual(str(self.plan.plan_hash), report["plan"]["plan_hash"])

    def test_every_arm_reports_effective_repair_and_rejection_rates(self) -> None:
        for arm in ARM_NAMES:
            metrics = self.report["arms"][arm]
            with self.subTest(arm=arm):
                self.assertEqual(ENTRIES, metrics["outcomes"])
                self.assertGreater(metrics["effective_input_rate"], 0.0)
                self.assertEqual(metrics["executed"] + metrics["rejected"]
                                 + metrics["anomalies"], metrics["outcomes"])
                # The Ibex plan has no synthetic master, so no BFM request can
                # exist and every request this run observed came from the CPU.
                self.assertEqual(0, metrics["bfm_request_count"])

    def test_the_report_replays_every_effective_input_field_by_field(self) -> None:
        replay = self.report["replay"]
        self.assertEqual("agreement", replay["status"], replay["reason"])
        # 400 cycles of applied stimulus per effective input: the comparison is
        # field by field over real traces, not over an empty pair of lists.
        self.assertGreater(replay["checked_fields"], 100)
        self.assertEqual(0, replay["mismatching_fields"])
        self.assertEqual(0, replay["not_assessed_outcomes"])

    def test_cpu_and_bfm_accounting_stay_separate_in_the_real_report(self) -> None:
        for arm in ARM_NAMES:
            metrics = self.report["arms"][arm]
            with self.subTest(arm=arm):
                # The Ibex plan composes no synthetic master, so no transaction
                # this run observed can be a BFM request.
                self.assertEqual(0, metrics["bfm_request_count"])
                self.assertEqual(metrics["cpu_request_count"],
                                 metrics["cpu_coverage"]["request_count"])
                # A BFM transaction is never relabelled a CPU one, and the BFM
                # bucket is explicitly marked as not counting toward CPU
                # coverage.
                self.assertFalse(self.report["coverage"]["bfm"]
                                 ["counted_as_cpu_coverage"])
                self.assertEqual(metrics["bfm_request_count"],
                                 self.report["coverage"]["bfm"]["request_count"])
        # The seeded corpus's instruction payload is the same legal no-op in every
        # entry, so this corpus cannot make two entries differ in the CPU's own
        # transactions; the real write A/B is measured directly (and with real
        # candidates) in ``test_soc_input_transport_ab`` and
        # ``test_soc_input_real_rtl_gate``.  When the corpus produces no write the
        # report records the named gap instead of dressing empty coverage up as a
        # measurement.
        if self.report["coverage"]["cpu"]["request_count"] == 0:
            self.assertTrue(any(gap.startswith("cpu-coverage-gap")
                                for gap in self.report["gaps"]), self.report["gaps"])

    def test_the_report_is_written_under_the_plan_prefix(self) -> None:
        self.assertEqual(self.directory.name, self.prefix)
        self.assertTrue(self.report_path.is_file())
        written = json.loads(self.report_path.read_text(encoding="utf-8"))
        self.assertEqual(self.report, written)
        self.assertEqual(REPORT_SCHEMA, written["schema_version"])
        self.assertEqual(self.report["shared_corpus_hash"], written["shared_corpus_hash"])


if __name__ == "__main__":                              # pragma: no cover
    unittest.main()
