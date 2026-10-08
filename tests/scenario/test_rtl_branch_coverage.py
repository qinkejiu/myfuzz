"""Instrumented-RTL branch coverage kept apart from port semantic hits.

The only data this module may report as *internal branch coverage* is a
coverage vector whose provenance is proven: a named instrumenter version, the
instrumented RTL files with their digests, the exposed coverage-port list with
its width, and the aggregate digest of the whole instrumented tree. Every case
below therefore builds a real (temporary) instrumented tree and derives the
aggregate with the frozen production enumerator
:func:`myfuzz.integration.soc_builder._instrumented_output_sha256`, so the
positive cases exercise the same identity arithmetic the campaign uses.

Fail-closed is the point of the negative cases: a missing, forged, mismatched or
out-of-range identity must be *rejected*, never silently downgraded into
"the port semantics looked right". Port semantic hits (``feedback.py``
``CoverageTarget`` predicates over observed outputs) are counted in a separate
field of the same document and are never added to, or substituted for, the
branch count.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from myfuzz.integration.soc_builder import _instrumented_output_sha256
from myfuzz.scenario.feedback import CoverageTarget, observed_targets
from myfuzz.scenario.rtl_branch_coverage import (
    BRANCH_POINT_KINDS,
    COVERAGE_PORT,
    ENCODING_BIT,
    ENCODING_COUNTER,
    MAX_PORTS,
    MAX_REJECTIONS,
    REJECTED,
    SCHEMA_VERSION,
    VERIFIED,
    RtlBranchCoverage,
)


INSTRUMENTER_SCHEMA = "source_branch_instrumenter.v1"
RUN_IDENTITY = {
    "run_id": "run-branch-0001",
    "harness_top": "myfuzz_live_tb",
    "build_hash": "sha256:" + "b" * 64,
}
INSTRUMENTER_SOURCE = (
    '"""Synthetic stand-in for scripts/source_branch_instrumenter.py."""\n'
    "MARKER = 'myfuzz coverage begin'\n"
)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class Case:
    """One complete, otherwise-valid instrumented-coverage case."""

    def __init__(self, tmp_path: Path, **overrides: object) -> None:
        self.root = tmp_path / "instrumented"
        sources = {
            "myfuzz_soc_top.sv": (
                "module myfuzz_soc_top;\n"
                "  // myfuzz coverage begin\n"
                "  reg __vi_branch_cov_0;\n"
                "endmodule\n"
            ),
            "src/myfuzz/spi.sv": (
                "module spi;\n"
                "  // myfuzz coverage begin\n"
                "  reg __vi_branch_cov_1;\n"
                "endmodule\n"
            ),
        }
        for relative, text in sources.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.flist = self.root / "instrumented_sources.f"
        self.flist.write_text(
            "".join(f"{self.root / name}\n" for name in sorted(sources))
        )
        self.width = 9
        self.port = COVERAGE_PORT
        # Bits 2, 5 and 7 are real instrumented branch points; the rest of the
        # vector belongs to other port classes (checker/opcode) and is declared
        # so the identity check can insist the exposed list matches.
        self.branch_bits = (2, 5, 7)
        self.port_vector = [
            [COVERAGE_PORT, 0],
            [COVERAGE_PORT, 1],
            [COVERAGE_PORT, 2],
            [COVERAGE_PORT, 3],
            [COVERAGE_PORT, 4],
            [COVERAGE_PORT, 5],
            [COVERAGE_PORT, 6],
            [COVERAGE_PORT, 7],
            [COVERAGE_PORT, 8],
            ["checker_eval_o", 0],
            ["checker_fail_o", 1],
            ["rvfi_opcode_coverage_o", 4],
        ]
        manifest = {
            "coverage_port": COVERAGE_PORT,
            "coverage_point_count": 5,
            "coverage_vector_width": self.width,
            "signal_prefix": "__vi_branch_cov",
            "coverage_bits": [
                {"bit": 0, "kind": "statement"},
                {"bit": 1, "kind": "statement"},
                {"bit": 2, "kind": "if"},
                {"bit": 3, "kind": "case"},
                {"bit": 4, "kind": "if"},
                {"bit": 5, "kind": "case"},
                {"bit": 6, "kind": "statement"},
                {"bit": 7, "kind": "if"},
                {"bit": 8, "kind": "case"},
            ],
        }
        self.manifest_path = self.root / "instrumentation.json"
        self.manifest_path.write_text(json.dumps(manifest, indent=1) + "\n")
        self.manifest = manifest
        self.manifest_sha256 = _digest(self.manifest_path.read_bytes())
        self.instrumenter_source = tmp_path / "scripts" / "source_branch_instrumenter.py"
        self.instrumenter_source.parent.mkdir(parents=True, exist_ok=True)
        self.instrumenter_source.write_text(INSTRUMENTER_SOURCE)
        self.aggregate = _instrumented_output_sha256(
            self.root, self.flist, path_aliases=(self.root.as_posix(),)
        )
        self.rtl_files = [
            {"path": path.relative_to(self.root).as_posix(),
             "sha256": _digest(path.read_bytes())}
            for path in sorted(self.root.rglob("*"))
            if path.is_file() and path.name != "instrumentation.json"
        ]
        # Every branch bit lit, one counter class with a different value so the
        # saturation encoding is exercised rather than a plain 0/1 flag.
        # ``observation`` is the single source of truth: ``counters`` and
        # ``first_seen`` are views on it, so a test that changes the vector also
        # changes what the evaluator reads.
        self.observation = {
            "coverage_port": COVERAGE_PORT,
            "coverage_ports": self.port_vector,
            "counters": [0, 0, 3, 0, 0, 1, 0, 4, 0, 9, 0, 7],
            # First-seen evidence exists exactly for the points that are lit; a
            # sighting claimed for a dark point is a contradiction (see below).
            "first_seen": [None] * len(self.port_vector),
        }
        self.observation["first_seen"][2] = {"event": "case_0001", "time": 0.5}
        self.observation["first_seen"][5] = {"event": "case_0004", "time": 1.1}
        self.observation["first_seen"][7] = {"event": "case_0007", "time": 1.5}
        self.attribution = {
            "instrumenter": {
                "schema_version": INSTRUMENTER_SCHEMA,
                "source_sha256": _digest(INSTRUMENTER_SOURCE.encode()),
            },
            "instrumented_root": str(self.root),
            "instrumented_flist": str(self.flist),
            "instrumented_output_sha256": self.aggregate,
            "rtl_files": self.rtl_files,
            "coverage_port": COVERAGE_PORT,
            "coverage_vector_width": self.width,
            "coverage_ports": self.port_vector,
            "branch_coverage_ports": [[COVERAGE_PORT, bit] for bit in self.branch_bits],
            "encoding": ENCODING_COUNTER,
            "counter_max": 255,
            "harness": dict(RUN_IDENTITY),
            "instrumentation_manifest_sha256": self.manifest_sha256,
        }
        self.observation = {
            "coverage_port": COVERAGE_PORT,
            "coverage_ports": self.port_vector,
            "counters": [0, 0, 3, 0, 0, 1, 0, 4, 0, 9, 0, 7],
            # First-seen evidence exists exactly for the points that are lit; a
            # sighting claimed for a dark point is a contradiction (see below).
            "first_seen": [None] * len(self.port_vector),
        }
        self.observation["first_seen"][2] = {"event": "case_0001", "time": 0.5}
        self.observation["first_seen"][5] = {"event": "case_0004", "time": 1.1}
        self.observation["first_seen"][7] = {"event": "case_0007", "time": 1.5}
        for name, value in overrides.items():
            setattr(self, name, value)

    @property
    def counters(self) -> list:
        return self.observation["counters"]

    @counters.setter
    def counters(self, value) -> None:
        self.observation["counters"] = list(value)

    @property
    def first_seen(self):
        return self.observation["first_seen"]

    @first_seen.setter
    def first_seen(self, value) -> None:
        self.observation["first_seen"] = value

    def evaluate(self, **kwargs: object) -> dict:
        options = {
            "attribution": self.attribution,
            "harness_identity": RUN_IDENTITY,
            "observation": self.observation,
            "instrumented_root": self.root,
            "instrumenter_source_path": self.instrumenter_source,
            "instrumentation_manifest": self.manifest,
            "manifest_sha256": self.manifest_sha256,
        }
        options.update(kwargs)
        return RtlBranchCoverage(**options).evaluate()


@pytest.fixture
def case(tmp_path: Path) -> Case:
    return Case(tmp_path)


def reasons(document: dict) -> list[str]:
    return [item["reason"] for item in document["rejections"]]


# --------------------------------------------------------------------------
# Positive: a proven instrumented vector lights exactly the expected points.
# --------------------------------------------------------------------------


def test_proven_instrumented_vector_counts_exactly_the_lit_bits(case: Case) -> None:
    document = case.evaluate()

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["status"] == VERIFIED
    assert document["rejections"] == []
    assert document["branch_points"]["declared_points"] == 3
    assert document["branch_points"]["declared_width"] == case.width
    assert document["branch_points"]["instrumented_source_points"] == 5
    assert document["branch_points"]["kinds"] == {"case": 1, "if": 2}
    observed = document["observed_branches"]
    assert observed["observed_points"] == 3
    assert observed["total_points"] == 3
    assert observed["ratio"] == 1.0
    assert observed["bit_indices"] == [2, 5, 7]


def test_partially_lit_vector_reports_the_exact_fraction(case: Case) -> None:
    case.counters = [0, 0, 3, 0, 0, 0, 0, 4, 0, 9, 0, 7]
    case.first_seen = [None] * len(case.port_vector)
    case.first_seen[2] = {"event": "case_0001", "time": 0.5}
    case.first_seen[7] = {"event": "case_0007", "time": 1.5}
    document = case.evaluate()

    assert document["status"] == VERIFIED
    observed = document["observed_branches"]
    assert observed["observed_points"] == 2
    assert observed["total_points"] == 3
    assert observed["bit_indices"] == [2, 7]
    assert observed["ratio"] == pytest.approx(2 / 3, abs=1e-6)


def test_first_seen_is_reported_per_lit_point(case: Case) -> None:
    case.counters = [0, 0, 3, 0, 0, 0, 0, 4, 0, 9, 0, 7]
    case.first_seen = [None] * len(case.port_vector)
    case.first_seen[2] = {"event": "case_0001", "time": 0.5}
    case.first_seen[7] = {"event": "case_0007", "time": 1.5}
    document = case.evaluate()

    first_seen = document["observed_branches"]["first_seen"]
    assert first_seen["available"] is True
    assert first_seen["points"] == 2
    assert first_seen["earliest"] == {"bit": 2, "port": COVERAGE_PORT,
                                      "event": "case_0001", "time": 0.5}
    assert {entry["bit"]: entry["event"] for entry in first_seen["entries"]} == {
        2: "case_0001", 7: "case_0007"}


def test_first_seen_is_declared_unavailable_when_the_artifact_omits_it(case: Case) -> None:
    case.observation = {key: value for key, value in case.observation.items()
                        if key != "first_seen"}
    document = case.evaluate()

    assert document["status"] == VERIFIED
    first_seen = document["observed_branches"]["first_seen"]
    assert first_seen["available"] is False
    assert first_seen["entries"] == []
    assert first_seen["reason"]


def test_bit_encoding_accepts_strict_zero_one_values(case: Case) -> None:
    case.attribution = dict(case.attribution, encoding=ENCODING_BIT)
    case.counters = [0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1]
    case.first_seen = [None] * len(case.port_vector)
    case.first_seen[2] = {"event": "case_0001", "time": 0.5}
    case.first_seen[7] = {"event": "case_0007", "time": 1.5}
    document = case.evaluate()

    assert document["status"] == VERIFIED
    assert document["observed_branches"]["bit_indices"] == [2, 7]


def test_evaluation_is_deterministic(case: Case) -> None:
    first = json.dumps(case.evaluate(), sort_keys=True, separators=(",", ":"))
    second = json.dumps(case.evaluate(), sort_keys=True, separators=(",", ":"))

    assert first == second


# --------------------------------------------------------------------------
# Negative: fail-closed on missing, forged or mismatched identity.
# --------------------------------------------------------------------------


def test_missing_attribution_is_rejected_not_downgraded(case: Case) -> None:
    document = case.evaluate(attribution=None)

    assert document["status"] == REJECTED
    assert "instrumentation-attribution-missing" in reasons(document)
    assert document["branch_points"] is None
    assert document["observed_branches"] is None


def test_missing_instrumenter_identity_is_rejected(case: Case) -> None:
    case.attribution = {key: value for key, value in case.attribution.items()
                        if key != "instrumenter"}
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "instrumenter-identity-missing" in reasons(document)
    assert document["observed_branches"] is None


def test_unknown_instrumenter_version_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution, instrumenter={
        "schema_version": "totally_other_instrumenter.v9",
        "source_sha256": case.attribution["instrumenter"]["source_sha256"],
    })
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "instrumenter-version-unsupported" in reasons(document)
    assert document["observed_branches"] is None


def test_forged_instrumenter_source_digest_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution, instrumenter={
        "schema_version": INSTRUMENTER_SCHEMA,
        "source_sha256": "sha256:" + "0" * 64,
    })
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "instrumenter-source-mismatch" in reasons(document)
    assert document["observed_branches"] is None


def test_unavailable_instrumenter_source_is_rejected(case: Case) -> None:
    document = case.evaluate(
        instrumenter_source_path=case.instrumenter_source.parent / "absent.py")

    assert document["status"] == REJECTED
    assert "instrumenter-source-unavailable" in reasons(document)


def test_missing_rtl_file_digests_are_rejected(case: Case) -> None:
    case.attribution = {key: value for key, value in case.attribution.items()
                        if key != "rtl_files"}
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "rtl-file-digests-missing" in reasons(document)
    assert document["observed_branches"] is None


def test_forged_rtl_file_digest_is_rejected(case: Case) -> None:
    tampered = [dict(entry) for entry in case.rtl_files]
    tampered[0] = {"path": tampered[0]["path"], "sha256": "sha256:" + "1" * 64}
    case.attribution = dict(case.attribution, rtl_files=tampered)
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "rtl-file-digest-mismatch" in reasons(document)
    assert document["observed_branches"] is None


def test_rtl_file_digest_for_an_absent_file_is_rejected(case: Case) -> None:
    tampered = [dict(entry) for entry in case.rtl_files]
    tampered.append({"path": "src/myfuzz/invented.sv", "sha256": "sha256:" + "2" * 64})
    case.attribution = dict(case.attribution, rtl_files=tampered)
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "rtl-file-missing" in reasons(document)


def test_forged_instrumented_output_digest_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution,
                            instrumented_output_sha256="sha256:" + "3" * 64)
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "instrumented-output-sha256-mismatch" in reasons(document)
    assert document["observed_branches"] is None


def test_incomplete_rtl_file_closure_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution, rtl_files=case.rtl_files[:1])
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "rtl-file-closure-incomplete" in reasons(document)


def test_harness_identity_mismatch_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution, harness=dict(RUN_IDENTITY,
                                                           run_id="other-run"))
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "harness-identity-mismatch" in reasons(document)
    assert document["observed_branches"] is None


def test_missing_harness_identity_is_rejected(case: Case) -> None:
    case.attribution = {key: value for key, value in case.attribution.items()
                        if key != "harness"}
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "harness-identity-missing" in reasons(document)


# --------------------------------------------------------------------------
# Negative: the vector itself must obey its declared width and bit indices.
# --------------------------------------------------------------------------


def test_port_width_mismatch_is_rejected(case: Case) -> None:
    case.observation = dict(case.observation, counters=case.counters[:-1])
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "coverage-vector-width-mismatch" in reasons(document)
    assert document["observed_branches"] is None


def test_declared_width_mismatch_against_the_manifest_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution, coverage_vector_width=case.width + 3)
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "instrumentation-manifest-width-mismatch" in reasons(document)


def test_out_of_range_branch_bit_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution,
                            branch_coverage_ports=[[COVERAGE_PORT, 12]])
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "branch-bit-out-of-range" in reasons(document)
    assert document["observed_branches"] is None


def test_non_binary_value_under_bit_encoding_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution, encoding=ENCODING_BIT)
    case.counters = [0, 0, 2, 0, 0, 0, 0, 1, 0, 1, 0, 1]
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "coverage-value-not-binary" in reasons(document)
    assert document["observed_branches"] is None


def test_counter_above_the_declared_maximum_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution, counter_max=2)
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "coverage-value-out-of-range" in reasons(document)
    assert document["observed_branches"] is None


def test_branch_bit_on_a_non_branch_instrumentation_point_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution,
                            branch_coverage_ports=[[COVERAGE_PORT, 0]])
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "branch-bit-not-branch-kind" in reasons(document)
    assert document["observed_branches"] is None


def test_branch_port_absent_from_the_observed_vector_is_rejected(case: Case) -> None:
    observed = [entry for entry in case.port_vector
                if entry != [COVERAGE_PORT, 5]]
    case.observation = dict(case.observation, coverage_ports=observed,
                            counters=[0, 0, 3, 0, 0, 0, 0, 4, 0, 9, 0, 7])
    document = case.evaluate()

    assert document["status"] == REJECTED
    # The vector no longer matches the exposed list, and the check names the
    # specific instrumented point that went missing rather than only the drift.
    assert "coverage-port-observed-mismatch" in reasons(document)
    assert "branch-port-observed-missing" in reasons(document)
    assert document["observed_branches"] is None


def test_observed_vector_that_disagrees_with_the_declared_list_is_rejected(case: Case) -> None:
    observed = list(case.port_vector)
    observed[9] = ["checker_eval_o", 3]
    case.observation = dict(case.observation, coverage_ports=observed)
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "coverage-port-observed-mismatch" in reasons(document)


def test_branch_port_outside_the_exposed_coverage_ports_is_rejected(case: Case) -> None:
    exposed = [entry for entry in case.port_vector if entry != [COVERAGE_PORT, 4]]
    case.attribution = dict(case.attribution, coverage_ports=exposed,
                            branch_coverage_ports=[[COVERAGE_PORT, 2],
                                                   [COVERAGE_PORT, 4]])
    case.observation = dict(case.observation, coverage_ports=exposed,
                            counters=[0, 0, 3, 0, 0, 1, 0, 4, 0, 9, 0])
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert set(reasons(document)) == {"branch-port-not-in-coverage-ports",
                                      "branch-port-observed-missing"}


def test_forged_manifest_digest_in_the_attestation_is_rejected(case: Case) -> None:
    case.attribution = dict(case.attribution,
                            instrumentation_manifest_sha256="sha256:" + "4" * 64)
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "instrumentation-manifest-digest-mismatch" in reasons(document)
    assert document["instrumentation"]["level"] == "none"
    assert document["observed_branches"] is None


def test_tampered_manifest_bytes_beat_a_caller_supplied_digest(case: Case) -> None:
    """The manifest on disk is authoritative: a caller cannot vouch for bytes
    that do not match it."""
    case.manifest_path.write_text(json.dumps(dict(case.manifest,
                                                  coverage_vector_width=99)) + "\n")
    document = case.evaluate(manifest_sha256=case.manifest_sha256)

    assert document["status"] == REJECTED
    assert "instrumentation-manifest-digest-mismatch" in reasons(document)
    assert document["observed_branches"] is None


def test_manifest_without_a_declared_digest_is_rejected(case: Case) -> None:
    case.attribution = {key: value for key, value in case.attribution.items()
                        if key != "instrumentation_manifest_sha256"}
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "instrumentation-manifest-unattested" in reasons(document)
    assert document["observed_branches"] is None


def test_first_seen_claim_without_an_observation_is_rejected(case: Case) -> None:
    case.counters = [0, 0, 0, 0, 0, 0, 0, 4, 0, 9, 0, 7]
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "first-seen-without-observation" in reasons(document)


def test_oversized_vector_is_rejected_by_bound(case: Case) -> None:
    width = MAX_PORTS + 1
    case.attribution = dict(case.attribution, coverage_vector_width=width,
                            coverage_ports=[], branch_coverage_ports=[])
    case.observation = dict(case.observation, coverage_ports=[],
                            counters=[0] * width)
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "coverage-vector-too-wide" in reasons(document)


def test_rejection_list_is_bounded(case: Case) -> None:
    width = 200
    vector = [[COVERAGE_PORT, bit] for bit in range(width)]
    case.attribution = dict(case.attribution, encoding=ENCODING_BIT,
                            coverage_vector_width=width, coverage_ports=vector,
                            branch_coverage_ports=[[COVERAGE_PORT, bit]
                                                   for bit in (2, 5, 7)])
    case.observation = {"coverage_port": COVERAGE_PORT, "coverage_ports": vector,
                        "counters": [7] * width}
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert len(document["rejections"]) == MAX_REJECTIONS
    counts = document["rejection_counts"]
    assert counts["total"] > MAX_REJECTIONS
    assert counts["recorded"] == MAX_REJECTIONS
    assert counts["overflow"] == counts["total"] - MAX_REJECTIONS


def test_non_integer_counter_is_rejected(case: Case) -> None:
    counters = list(case.counters)
    counters[2] = True
    case.observation = dict(case.observation, counters=counters)
    document = case.evaluate()

    assert document["status"] == REJECTED
    assert "coverage-value-not-integer" in reasons(document)


# --------------------------------------------------------------------------
# Separation: branch coverage and port semantic hits are counted apart.
# --------------------------------------------------------------------------


def _semantic_targets() -> tuple[CoverageTarget, ...]:
    return (
        CoverageTarget(target_id="gpio-ready", component="myfuzz_soc_top",
                       port="gpio_ready_o", mask=0x1, value=0x1),
        CoverageTarget(target_id="spi-done", component="myfuzz_soc_top",
                       port="spi_done_o", mask=0x4, value=0x4),
    )


def _semantic_events() -> tuple[dict, ...]:
    return (
        {"component": "myfuzz_soc_top", "outputs": {"gpio_ready_o": 1,
                                                    "spi_done_o": 0}},
        {"component": "myfuzz_soc_top", "outputs": {"gpio_ready_o": 0,
                                                    "spi_done_o": 4}},
    )


def test_branch_coverage_and_port_semantic_hits_are_counted_separately(case: Case) -> None:
    targets = _semantic_targets()
    events = _semantic_events()
    document = case.evaluate(port_semantic_targets=targets,
                             port_semantic_events=events)

    assert document["status"] == VERIFIED
    assert document["observed_branches"]["observed_points"] == 3
    hits = document["port_semantic_hits"]
    assert hits["total_targets"] == 2
    assert hits["observed_targets"] == len(observed_targets(events, targets)) == 2
    separation = document["separation"]
    assert separation["branch_coverage"] == 3
    assert separation["port_semantic_hits"] == 2
    assert separation["combined"] is None
    assert separation["sum_forbidden"] is True


def test_non_branch_ports_lit_in_the_same_vector_are_not_branch_coverage(case: Case) -> None:
    case.counters = [0, 0, 3, 0, 0, 1, 0, 4, 0, 9, 5, 7]
    document = case.evaluate()

    # Bits 9..11 belong to checker/opcode port classes and are all lit here.
    assert document["observed_branches"]["observed_points"] == 3
    assert document["port_semantic_hits"]["non_branch_lit_ports"] == 3
    assert document["port_semantic_hits"]["observed_lit_ports_by_class"] == {
        "checker_eval_o": 1, "checker_fail_o": 1, "rvfi_opcode_coverage_o": 1}
    assert document["separation"]["branch_coverage"] == 3
    assert document["separation"]["non_branch_lit_ports"] == 3
    assert document["separation"]["combined"] is None


def test_a_run_with_only_port_semantic_hits_reports_zero_branches(case: Case) -> None:
    case.counters = [0] * 9 + [9, 9, 9]
    case.first_seen = [None] * len(case.port_vector)
    document = case.evaluate(port_semantic_targets=_semantic_targets(),
                             port_semantic_events=_semantic_events())

    assert document["status"] == VERIFIED
    assert document["observed_branches"]["observed_points"] == 0
    assert document["observed_branches"]["ratio"] == 0.0
    assert document["port_semantic_hits"]["observed_targets"] == 2
    assert document["port_semantic_hits"]["non_branch_lit_ports"] == 3
    assert document["separation"]["branch_coverage"] == 0
    assert document["separation"]["port_semantic_hits"] == 2
    assert document["separation"]["non_branch_lit_ports"] == 3


def test_a_semantic_target_on_a_branch_port_cannot_launder_branch_coverage(case: Case) -> None:
    targets = (CoverageTarget(target_id="laundered", component="myfuzz_soc_top",
                              port=COVERAGE_PORT, mask=0x1, value=0x1),)
    events = ({"component": "myfuzz_soc_top", "outputs": {COVERAGE_PORT: 1}},)
    document = case.evaluate(port_semantic_targets=targets,
                             port_semantic_events=events)

    assert document["status"] == REJECTED
    assert "port-semantic-target-on-branch-port" in reasons(document)
    assert document["observed_branches"] is None
    assert document["separation"]["branch_coverage"] is None


def test_branch_bits_are_never_derived_from_port_semantics(case: Case) -> None:
    """A branch bit with no real observation stays dark even if a semantic
    predicate over the same run would have matched."""
    case.counters = [0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    case.first_seen = [None] * len(case.port_vector)
    case.first_seen[2] = {"event": "case_0001", "time": 0.5}
    document = case.evaluate(port_semantic_targets=_semantic_targets(),
                             port_semantic_events=_semantic_events())

    assert document["observed_branches"]["observed_points"] == 1
    assert document["observed_branches"]["bit_indices"] == [2]
    assert document["port_semantic_hits"]["observed_targets"] == 2
    assert document["separation"]["branch_coverage"] == 1


def test_rejected_document_still_separates_and_never_merges(case: Case) -> None:
    case.attribution = None
    document = case.evaluate(port_semantic_targets=_semantic_targets(),
                             port_semantic_events=_semantic_events())

    assert document["status"] == REJECTED
    assert document["observed_branches"] is None
    assert document["separation"]["branch_coverage"] is None
    assert document["separation"]["port_semantic_hits"] == 2
    assert document["separation"]["combined"] is None


def test_branch_point_kinds_are_the_instrumenter_branch_kinds() -> None:
    assert set(BRANCH_POINT_KINDS) == {"if", "case"}
