"""Per-point first-seen evidence for the instrumented coverage vector.

The shipped checker (:mod:`myfuzz.scenario.rtl_branch_coverage`) already reads an
``observation["first_seen"]`` array, but nothing ever *recorded* one, so every
real run reported ``first_seen.available=false``.  The evidence this file pins is
the one the run genuinely owns: the **per-test counter readback**.

Every test is a counter vector, not a self-description:

* ``RtlSimulator.run_test`` reads the whole instrumented counter vector back once
  per test (simulator protocol v2, ``RFUZZ_COUNTERS <request id>``).  The first
  test whose readback shows a point non-zero is that point's first sighting, and
  the protocol request id is its event identity.  No timestamp is invented: the
  ``time`` field is the measured monotonic offset of that very readback.
* The readback owner is :mod:`myfuzz.integration.rfuzz_simulator` (a ``soc_*``
  path file), so the ledger can be written without touching the Rust client, the
  simulator protocol, the harness rendering, or the online runner.
* The ledger is written into the run's own build directory and declared by
  :mod:`myfuzz.integration.soc_builder`, so the saved artifact - not a reader's
  guess - says whether per-point first-seen evidence exists.
* ``scripts/report_rtl_branch_coverage.py`` joins the ledger to the plan by
  identity and passes the positional array the checker expects.  Anything that
  cannot be joined exactly is reported as ``available=false`` with a reason, and
  a malformed list is refused by the checker with its own precise reason.

All tests are software only: no harness is rendered, no Verilator runs, and the
RTL campaign paths are never executed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.integration import rfuzz_simulator, soc_builder, soc_coverage
from myfuzz.integration.soc_builder import _instrumented_output_sha256
from myfuzz.scenario import rtl_branch_coverage as checker
from myfuzz.scenario.rtl_branch_coverage import (
    COVERAGE_PORT,
    REJECTED,
    VERIFIED,
)
from scripts import report_rtl_branch_coverage as report_cli


ROOT = Path(__file__).resolve().parents[2]
REAL_INSTRUMENTER_SOURCE = ROOT / "scripts" / "source_branch_instrumenter.py"
RUN_ID = "first-seen-run"
INSTRUMENTER_SCHEMA = "source_branch_instrumenter.v1"
COVERAGE_KIND = "source-instrumented-rtl-branch-u8-saturating"
OBSERVED_BITS = (2, 5, 7)
VECTOR_WIDTH = 9
#: Three tests, one counter vector read back each: point 0 first goes non-zero in
#: test 2, point 1 in test 3, point 3 never.  ``MAXIMA`` is what the live runner
#: accumulates from exactly these readbacks.
READBACKS = ((0, 0, 0), (3, 0, 0), (3, 5, 0))
MAXIMA = [3, 5, 0]

#: ``available=false`` with a reason is the only honest answer when the evidence
#: is absent; a fabricated ``points: 0`` verdict is not.
NO_EVIDENCE_REASON = ("the artifact preserves no per-point first-seen "
                      "evidence")


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class _Clock:
    """A deterministic monotonic clock so ledger times are assertable."""

    def __init__(self, values) -> None:
        self._values = list(values)
        self._last = self._values[-1] if self._values else 0.0

    def __call__(self) -> float:
        if self._values:
            self._last = self._values.pop(0)
        return self._last


def _ports(bits=OBSERVED_BITS) -> tuple[tuple[str, int], ...]:
    return tuple((COVERAGE_PORT, bit) for bit in bits)


def _aligned_ledger(path: Path, *, readbacks=READBACKS, bits=OBSERVED_BITS,
                    clock_values=(100.0, 100.5, 101.0, 101.5)) -> dict:
    """Write the ledger with the shipped writer and return its document."""
    ledger = rfuzz_simulator.CoverageFirstSeenLedger(
        path, _ports(bits), coverage_kind=COVERAGE_KIND,
        session="test-session", clock=_Clock(clock_values))
    for order, counters in enumerate(readbacks, start=1):
        ledger.observe(counters, event=order)
    assert ledger.write() == ""
    return json.loads(path.read_text())


def _mutated_ledger(base: dict, kind: str) -> dict:
    """The aligned ledger, damaged exactly the way ``kind`` names."""
    document = json.loads(json.dumps(base))
    entries = document["entries"]
    if kind == "short":
        document["entries"] = entries[:-1]
    elif kind == "oversized":
        document["entries"] = list(entries) + [None] * (
            soc_coverage.MAX_FIRST_SEEN_ENTRIES + 1)
    elif kind == "oversized-file":
        return {"__oversized__": True}
    elif kind == "bad-entry":
        entries[0] = {"point": [COVERAGE_PORT, 2], "event": ["not", "a", "scalar"],
                      "time": 1.0}
    elif kind == "dark-claim":
        entries[2] = {"point": [COVERAGE_PORT, 7], "event": 9, "time": 1.0}
    elif kind == "misnamed-entry":
        entries[0] = {"point": [COVERAGE_PORT, 7], "event": 2, "time": 1.0}
    elif kind == "overrun-entry":
        document["entries"] = list(entries) + [
            {"point": [COVERAGE_PORT, 2], "event": 4, "time": 2.0}]
    elif kind == "omit-lit":
        entries[1] = None
    elif kind == "foreign-points":
        document["points"] = [[COVERAGE_PORT, bit] for bit in (5, 2, 7)]
    elif kind == "truncated":
        document["truncated"] = True
        entries[1] = None
    elif kind == "other-schema":
        document["schema_version"] = "soc_coverage_first_seen.v99"
    elif kind == "wrong-count":
        document["counter_count"] = 4
    elif kind == "unreadable":
        return {"__unreadable__": True}
    else:  # pragma: no cover - the test asks for a kind that does not exist
        raise AssertionError(f"unknown ledger kind: {kind}")
    return document


def _build_run(tmp_path: Path, *, ledger: str | None = "aligned",
               declaration: object = "default", maxima=MAXIMA,
               readbacks=READBACKS) -> Path:
    """A synthetic saved run whose coverage identity the shipped CLI verifies."""
    run = tmp_path / RUN_ID
    build = run / "build"
    root = build / "instrumentation" / "instrumented"
    root.mkdir(parents=True)
    (root / "myfuzz_soc_top.sv").write_text(
        "module myfuzz_soc_top;\n"
        "  // myfuzz coverage begin\n"
        "  reg __vi_branch_cov_0;\n"
        "endmodule\n",
        encoding="utf-8",
    )
    (root / "spi.sv").write_text(
        "module spi;\n"
        "  // myfuzz coverage begin\n"
        "  reg __vi_branch_cov_1;\n"
        "endmodule\n",
        encoding="utf-8",
    )
    flist = root / "instrumented_sources.f"
    flist.write_text(
        "".join(f"{root / name}\n" for name in
                ("myfuzz_soc_top.sv", "spi.sv")),
        encoding="utf-8",
    )
    manifest = {
        "coverage_port": COVERAGE_PORT,
        "coverage_point_count": len(OBSERVED_BITS),
        "coverage_vector_width": VECTOR_WIDTH,
        "signal_prefix": "__vi_branch_cov",
        "coverage_bits": [
            {"bit": bit,
             "kind": "if" if bit in OBSERVED_BITS else "statement"}
            for bit in range(VECTOR_WIDTH)
        ],
    }
    manifest_path = root / "instrumentation.json"
    manifest_path.write_text(json.dumps(manifest, indent=1) + "\n",
                             encoding="utf-8")
    aggregate = _instrumented_output_sha256(root, flist)
    coverage = {
        "kind": COVERAGE_KIND,
        "signal": COVERAGE_PORT,
        "observation_plan": "soc_coverage_plan.json",
        "observations": [[COVERAGE_PORT, bit] for bit in OBSERVED_BITS],
        "counter_count": len(OBSERVED_BITS),
        "instrumenter": {
            "schema_version": INSTRUMENTER_SCHEMA,
            "source_sha256": _digest(REAL_INSTRUMENTER_SOURCE.read_bytes()),
        },
        "instrumented_root": root.resolve().as_posix(),
        "instrumented_flist": flist.resolve().as_posix(),
        "instrumented_output_sha256": aggregate,
    }
    if declaration == "default":
        coverage["first_seen"] = soc_builder.coverage_first_seen_evidence(_ports())
    elif declaration is not None:
        coverage["first_seen"] = declaration
    provenance = {
        "schema_version": "soc_campaign_build.v1",
        "build_hash": _digest(b"first-seen-run"),
        "coverage": coverage,
        "executable": {"path": "obj_dir/Vmyfuzz_live_tb",
                       "sha256": _digest(b"executable")},
        "sources": {"harness_top": "myfuzz_soc_top"},
    }
    (build / "artifact_provenance.json").write_text(
        json.dumps(provenance, indent=1) + "\n", encoding="utf-8")
    (build / "soc_coverage_plan.json").write_text(
        json.dumps({"observed": [
            {"bit": bit, "point_id": f"myfuzz_soc_top:__vi_branch_cov_{bit}",
             "category": "cpu", "instance_id": "myfuzz_soc_top",
             "module": "myfuzz_soc_top"}
            for bit in OBSERVED_BITS]}), encoding="utf-8")
    (run / "report.json").write_text(json.dumps({
        "client_result": {
            "artifact_provenance": provenance,
            "coverage_maxima": list(maxima),
        },
    }), encoding="utf-8")
    if ledger == "aligned":
        _aligned_ledger(build / soc_coverage.FIRST_SEEN_LEDGER_NAME,
                        readbacks=readbacks)
    elif isinstance(ledger, str):
        base = _aligned_ledger(build / soc_coverage.FIRST_SEEN_LEDGER_NAME,
                               readbacks=readbacks)
        document = _mutated_ledger(base, ledger)
        target = build / soc_coverage.FIRST_SEEN_LEDGER_NAME
        if "__unreadable__" in document:
            target.write_text("{not json", encoding="utf-8")
        elif "__oversized__" in document:
            target.write_bytes(b"x" * (soc_coverage.MAX_FIRST_SEEN_LEDGER_BYTES + 1))
        else:
            target.write_text(json.dumps(document), encoding="utf-8")
    # The builder decides the path; the reader resolves the same one.  A
    # document that declares nothing resolves to nothing (older artifacts).
    resolved = soc_builder.first_seen_ledger_path(build, provenance)
    if coverage.get("first_seen") is None:
        assert resolved is None
    else:
        assert resolved == build / soc_coverage.FIRST_SEEN_LEDGER_NAME
    return run


def _cli_json(capsys, run: Path) -> tuple[int, dict]:
    code = report_cli.main(["--run", run.as_posix(), "--json", "--quiet"])
    return code, json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------------------
# The ledger records the first readback that lit each point.
# ---------------------------------------------------------------------------


def test_ledger_records_the_first_readback_that_lit_each_point(tmp_path: Path) -> None:
    path = tmp_path / soc_coverage.FIRST_SEEN_LEDGER_NAME
    ledger = rfuzz_simulator.CoverageFirstSeenLedger(
        path, _ports(), coverage_kind=COVERAGE_KIND, session="s",
        clock=_Clock((100.0, 100.5, 101.0, 101.5)))
    for order, counters in enumerate(READBACKS, start=1):
        ledger.observe(counters, event=order)

    document = ledger.document()
    assert ledger.valid is True
    assert ledger.reason == ""
    assert document["schema_version"] == soc_coverage.FIRST_SEEN_SCHEMA
    assert document["points"] == [[COVERAGE_PORT, bit] for bit in OBSERVED_BITS]
    assert document["counter_count"] == len(OBSERVED_BITS)
    assert document["readbacks"] == 3
    assert document["observed_points"] == 2
    # Point 0 lit in test 2, point 1 in test 3; the undriven point stays null
    # rather than being given a fabricated sighting, and each entry names its
    # own point so a reader joins by identity, not by position.
    assert document["entries"][0] == {"point": [COVERAGE_PORT, 2],
                                      "event": 2, "time": 1.0}
    assert document["entries"][1] == {"point": [COVERAGE_PORT, 5],
                                      "event": 3, "time": 1.5}
    assert document["entries"][2] is None
    assert document["bound"] == soc_coverage.MAX_FIRST_SEEN_ENTRIES


def test_ledger_accepts_the_counter_readback_exactly_as_the_simulator_returns_it(
        tmp_path: Path) -> None:
    """``RtlSimulator.run_test`` returns ``bytes``, so the ledger must too."""
    ledger = rfuzz_simulator.CoverageFirstSeenLedger(
        tmp_path / "ledger.json", _ports(), session="s")
    ledger.observe(bytes((7, 0, 1)), event=11)
    document = ledger.document()
    assert document["entries"][0]["event"] == 11
    assert document["entries"][2]["event"] == 11


def test_ledger_refuses_a_counter_vector_that_is_not_the_declared_width(
        tmp_path: Path) -> None:
    """A misaligned readback must never be joined positionally."""
    path = tmp_path / "ledger.json"
    ledger = rfuzz_simulator.CoverageFirstSeenLedger(path, _ports(), session="s")
    ledger.observe((1, 0), event=1)

    document = ledger.document()
    assert ledger.valid is False
    assert ledger.reason == ("the readback carries 2 counters for 3 declared "
                             "points")
    assert document["entries"] == [None, None, None]
    assert document["observed_points"] == 0
    assert ledger.write() != ""
    assert not path.exists()


def test_ledger_refuses_a_port_list_beyond_the_checkers_bound(tmp_path: Path) -> None:
    ledger = rfuzz_simulator.CoverageFirstSeenLedger(
        tmp_path / "ledger.json", _ports(), bound=2, session="s")
    assert ledger.valid is False
    assert "bound" in ledger.reason
    assert ledger.write() != ""


def test_ledger_bound_is_the_shipped_checkers_bound() -> None:
    assert (soc_coverage.MAX_FIRST_SEEN_ENTRIES
            == checker.MAX_FIRST_SEEN_ENTRIES)


def test_ledger_flushes_on_the_first_sighting_and_then_on_its_interval(
        tmp_path: Path) -> None:
    ledger = rfuzz_simulator.CoverageFirstSeenLedger(
        tmp_path / "ledger.json", _ports(), session="s",
        clock=_Clock((0.0, 1.0, 2.0, 30.0, 31.0)), flush_seconds=5.0)
    # No sighting yet: nothing to write.
    assert ledger.observe((0, 0, 0), event=1) is False
    # The first sighting is always flushed, so a short run still leaves evidence.
    assert ledger.observe((1, 0, 0), event=2) is True
    # Inside the interval a new sighting stays in memory.
    assert ledger.observe((1, 0, 0), event=3) is False
    # Past the interval the new sighting is flushed again.
    assert ledger.observe((1, 1, 0), event=4) is True


def test_ledger_write_is_owned_by_one_session(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    owner = rfuzz_simulator.CoverageFirstSeenLedger(path, _ports(), session="owner")
    owner.observe((1, 0, 0), event=1)
    assert owner.write() == ""
    owner.observe((1, 1, 0), event=2)
    assert owner.write() == ""
    assert json.loads(path.read_text())["observed_points"] == 2

    other = rfuzz_simulator.CoverageFirstSeenLedger(path, _ports(), session="other")
    other.observe((0, 0, 1), event=7)
    assert other.write() != ""
    retained = json.loads(path.read_text())
    assert retained["session"] == "owner"
    assert retained["entries"][2] is None


def test_ledger_never_clobbers_an_unreadable_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    path.write_text("{truncated", encoding="utf-8")
    ledger = rfuzz_simulator.CoverageFirstSeenLedger(path, _ports(), session="s")
    ledger.observe((1, 0, 0), event=1)
    assert ledger.write() != ""
    assert path.read_text() == "{truncated"


def test_ledger_write_failure_is_reported_never_raised(tmp_path: Path) -> None:
    """A ledger that cannot be persisted must not fail the RTL test."""
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    ledger = rfuzz_simulator.CoverageFirstSeenLedger(
        blocked / "ledger.json", _ports(), session="s")
    ledger.observe((1, 0, 0), event=1)
    assert ledger.write() != ""


def test_ledger_document_is_deterministic_for_a_fixed_readback_sequence(
        tmp_path: Path) -> None:
    def build() -> dict:
        ledger = rfuzz_simulator.CoverageFirstSeenLedger(
            tmp_path / "ledger.json", _ports(), coverage_kind=COVERAGE_KIND,
            session="fixed", clock=_Clock((0.0, 1.0, 2.0, 3.0)))
        for order, counters in enumerate(READBACKS, start=1):
            ledger.observe(counters, event=order)
        return ledger.document()

    first, second = build(), build()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_simulator_records_the_request_id_of_the_readback_that_lit_a_point(
        tmp_path: Path) -> None:
    """The readback owner, not a reader, decides what an entry's event is.

    ``RtlSimulator`` is instantiated without its child process here on purpose:
    this pins the recording call itself (request id plus the flush cadence), not
    the simulator IO that other suites already cover.
    """
    path = tmp_path / soc_coverage.FIRST_SEEN_LEDGER_NAME
    artifact = SimpleNamespace(coverage_first_seen_ledger=path,
                               coverage_ports=_ports(),
                               coverage_kind=COVERAGE_KIND)
    simulator = rfuzz_simulator.RtlSimulator.__new__(rfuzz_simulator.RtlSimulator)
    simulator.artifact = artifact
    simulator.first_seen = rfuzz_simulator.first_seen_ledger_for_artifact(
        artifact, session="s", clock=_Clock((0.0, 1.0, 2.0)))
    simulator._executions = 41
    simulator._record_first_seen(bytes((1, 0, 0)))
    written = json.loads(path.read_text())
    assert written["entries"][0] == {"point": [COVERAGE_PORT, 2], "event": 41,
                                     "time": 1.0}
    assert written["entries"][1] is None

    # A later sighting inside the flush interval stays in memory until close().
    simulator._executions = 42
    simulator._record_first_seen(bytes((1, 1, 0)))
    assert json.loads(path.read_text())["entries"][1] is None
    simulator.first_seen.write()
    assert json.loads(path.read_text())["entries"][1] == {
        "point": [COVERAGE_PORT, 5], "event": 42, "time": 2.0}


def test_simulator_never_fails_a_test_for_a_ledger_problem(tmp_path: Path) -> None:
    class Broken:
        def observe(self, counters, *, event=None):
            raise RuntimeError("ledger exploded")

        def write(self):
            raise RuntimeError("ledger exploded")

    simulator = rfuzz_simulator.RtlSimulator.__new__(rfuzz_simulator.RtlSimulator)
    simulator.artifact = SimpleNamespace()
    simulator.first_seen = Broken()
    simulator._executions = 1
    simulator._record_first_seen(bytes((1, 0, 0)))
    assert simulator.first_seen is None
    assert isinstance(simulator.first_seen_error, str)


# ---------------------------------------------------------------------------
# The artifact decides whether the readback evidence exists at all.
# ---------------------------------------------------------------------------


def test_artifact_without_the_declared_ledger_records_nothing(tmp_path: Path) -> None:
    """The online/other simulator users keep their exact behaviour."""
    artifact = SimpleNamespace(coverage_ports=_ports(), coverage_kind=COVERAGE_KIND)
    assert rfuzz_simulator.first_seen_ledger_for_artifact(artifact) is None


def test_artifact_declaring_a_ledger_binds_it_to_its_own_port_list(
        tmp_path: Path) -> None:
    path = tmp_path / soc_coverage.FIRST_SEEN_LEDGER_NAME
    artifact = SimpleNamespace(coverage_first_seen_ledger=path,
                               coverage_ports=_ports(),
                               coverage_kind=COVERAGE_KIND)
    ledger = rfuzz_simulator.first_seen_ledger_for_artifact(artifact,
                                                            session="s")
    assert ledger is not None
    assert ledger.path == path
    assert ledger.document()["points"] == [[COVERAGE_PORT, bit]
                                           for bit in OBSERVED_BITS]
    assert ledger.document()["coverage_kind"] == COVERAGE_KIND


def test_simulator_artifact_declares_the_ledger_field_for_the_soc_path() -> None:
    """The field exists on the artifact contract with a safe default."""
    artifact = rfuzz_simulator.SimulatorArtifact(
        layout=None, transport=None, executable=Path("exe"),
        coverage_ports=_ports(), projector=None)
    assert artifact.coverage_first_seen_ledger is None


def test_build_declaration_names_the_ledger_and_the_readback_evidence() -> None:
    declaration = soc_builder.coverage_first_seen_evidence(_ports())
    assert declaration["evidence"] == soc_coverage.FIRST_SEEN_EVIDENCE
    assert declaration["event"] == soc_coverage.FIRST_SEEN_EVENT
    assert declaration["schema_version"] == soc_coverage.FIRST_SEEN_SCHEMA
    assert declaration["ledger"] == soc_coverage.FIRST_SEEN_LEDGER_NAME
    assert Path(declaration["ledger"]).name == declaration["ledger"]
    assert declaration["counter_count"] == len(OBSERVED_BITS)
    assert declaration["bound"] == checker.MAX_FIRST_SEEN_ENTRIES


def test_build_resolves_the_ledger_path_from_its_own_document(tmp_path: Path) -> None:
    build = tmp_path / "build"
    nested = {"coverage": {"first_seen": soc_builder.coverage_first_seen_evidence(_ports())}}
    flat = {"coverage_instrumentation": {
        "first_seen": soc_builder.coverage_first_seen_evidence(_ports())}}
    assert soc_builder.first_seen_ledger_path(
        build, nested) == build / soc_coverage.FIRST_SEEN_LEDGER_NAME
    assert soc_builder.first_seen_ledger_path(
        build, flat) == build / soc_coverage.FIRST_SEEN_LEDGER_NAME
    # An older artifact makes no claim, so no ledger is written for it.
    assert soc_builder.first_seen_ledger_path(build, {"coverage": {}}) is None
    assert soc_builder.first_seen_ledger_path(build, {}) is None


def test_build_refuses_a_ledger_declaration_that_is_not_a_bare_file_name(
        tmp_path: Path) -> None:
    build = tmp_path / "build"
    for name in ("/etc/passwd", "../escape.json", "sub/dir.json", "", None):
        document = {"coverage": {"first_seen": {
            **soc_builder.coverage_first_seen_evidence(_ports()),
            "ledger": name}}}
        assert soc_builder.first_seen_ledger_path(build, document) is None


def test_build_paths_wire_the_declaration_and_the_ledger_field() -> None:
    """The shipped builders must actually publish what the helpers describe."""
    import inspect

    for function in (soc_builder.build_soc_campaign_artifact,
                     soc_builder._build_profile_campaign_artifact):
        source = inspect.getsource(function)
        assert "coverage_first_seen_evidence(" in source, function.__name__
        assert "first_seen_ledger_path(" in source, function.__name__


# ---------------------------------------------------------------------------
# The report CLI joins the ledger to the plan by identity.
# ---------------------------------------------------------------------------


def test_cli_accepts_a_run_whose_ledger_matches_the_plan(tmp_path: Path,
                                                         capsys) -> None:
    run = _build_run(tmp_path)
    code, document = _cli_json(capsys, run)
    assert code == 0
    assert document["status"] == VERIFIED
    assert document["coverage_kind"] == "source-instrumented-rtl-branch"
    first_seen = document["observed_branches"]["first_seen"]
    assert first_seen["available"] is True
    assert first_seen["points"] == 2
    assert first_seen["entries"] == [
        {"bit": 2, "port": COVERAGE_PORT, "event": 2, "time": 1.0},
        {"bit": 5, "port": COVERAGE_PORT, "event": 3, "time": 1.5},
    ]
    assert first_seen["earliest"] == first_seen["entries"][0]
    source = document["first_seen_source"]
    assert source["available"] is True
    assert source["reason"] is None
    assert Path(source["ledger"]).name == soc_coverage.FIRST_SEEN_LEDGER_NAME
    # The builder's own path resolution and the reader's agree exactly.
    provenance = json.loads(
        (run / "report.json").read_text())["client_result"]["artifact_provenance"]
    assert soc_builder.first_seen_ledger_path(
        run / "build", provenance) == Path(source["ledger"])


def test_cli_prints_the_first_seen_verdict(tmp_path: Path, capsys) -> None:
    run = _build_run(tmp_path)
    assert report_cli.main(["--run", run.as_posix()]) == 0
    printed = capsys.readouterr().out
    assert "first_seen=yes" in printed
    assert "points=2" in printed
    assert "earliest=bit:2" in printed

    plain = _build_run(tmp_path / "older", ledger=None, declaration=None)
    assert report_cli.main(["--run", plain.as_posix()]) == 0
    printed = capsys.readouterr().out
    assert "first_seen=no" in printed
    assert NO_EVIDENCE_REASON in printed


def test_cli_reports_an_older_artifact_as_unavailable_with_a_reason(
        tmp_path: Path, capsys) -> None:
    """Compatibility: a run that carries no ledger keeps the old verdict."""
    run = _build_run(tmp_path, ledger=None, declaration=None)
    code, document = _cli_json(capsys, run)
    assert code == 0
    assert document["status"] == VERIFIED
    first_seen = document["observed_branches"]["first_seen"]
    assert first_seen["available"] is False
    assert first_seen["points"] == 0
    assert first_seen["entries"] == []
    assert first_seen["reason"] == NO_EVIDENCE_REASON
    assert "declares no" in document["first_seen_source"]["reason"]


def test_cli_ignores_a_stray_ledger_the_artifact_never_declared(
        tmp_path: Path, capsys) -> None:
    """Evidence is only read where the artifact says it wrote it."""
    run = _build_run(tmp_path, declaration=None)
    code, document = _cli_json(capsys, run)
    assert code == 0
    assert document["observed_branches"]["first_seen"]["available"] is False


def test_cli_reports_a_missing_declared_ledger_as_unavailable(tmp_path: Path,
                                                              capsys) -> None:
    run = _build_run(tmp_path, ledger=None)
    code, document = _cli_json(capsys, run)
    assert code == 0
    assert document["status"] == VERIFIED
    first_seen = document["observed_branches"]["first_seen"]
    assert first_seen["available"] is False
    assert first_seen["reason"] == NO_EVIDENCE_REASON
    assert "missing" in document["first_seen_source"]["reason"]


def test_cli_reports_an_unreadable_ledger_as_unavailable(tmp_path: Path,
                                                         capsys) -> None:
    run = _build_run(tmp_path, ledger="unreadable")
    code, document = _cli_json(capsys, run)
    assert code == 0
    assert document["observed_branches"]["first_seen"]["available"] is False
    assert "unreadable" in document["first_seen_source"]["reason"]


@pytest.mark.parametrize("kind, fragment", [
    ("other-schema", "schema"),
    ("wrong-count", "counter"),
    ("foreign-points", "points"),
    ("misnamed-entry", "name its own point"),
    ("overrun-entry", "name its own point"),
    ("truncated", "truncated"),
    ("omit-lit", "omits"),
    ("oversized-file", "bound"),
])
def test_cli_refuses_a_ledger_it_cannot_join_exactly(tmp_path: Path, capsys,
                                                     kind: str,
                                                     fragment: str) -> None:
    run = _build_run(tmp_path, ledger=kind)
    code, document = _cli_json(capsys, run)
    # The run's own branch coverage is still verified; only the first-seen
    # evidence is unavailable, and it is never fabricated from a bad join.
    assert code == 0
    assert document["status"] == VERIFIED
    assert document["observed_branches"]["first_seen"]["available"] is False
    source = document["first_seen_source"]
    assert source["available"] is False
    assert fragment in source["reason"]


@pytest.mark.parametrize("kind, reason", [
    ("short", "first-seen-length-mismatch"),
    ("oversized", "first-seen-invalid"),
    ("bad-entry", "first-seen-entry-invalid"),
    ("dark-claim", "first-seen-without-observation"),
])
def test_cli_refuses_a_malformed_list_with_the_checkers_precise_reason(
        tmp_path: Path, capsys, kind: str, reason: str) -> None:
    """A future artifact with a malformed list must be refused, never guessed.

    A refused document reports no branch numbers at all - not a smaller number
    and certainly not a first-seen count derived from the malformed list.
    """
    run = _build_run(tmp_path, ledger=kind)
    code, document = _cli_json(capsys, run)
    assert code == 1
    assert document["status"] == REJECTED
    assert reason in [item["reason"] for item in document["rejections"]]
    assert document["observed_branches"] is None
    assert document["branch_points"] is None


def test_cli_verdict_is_deterministic(tmp_path: Path, capsys) -> None:
    run = _build_run(tmp_path)
    first = report_cli._run_document(run)
    code, second = _cli_json(capsys, run)
    assert code == 0
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert (first["observed_branches"]["first_seen"]
            == second["observed_branches"]["first_seen"])
    assert first["observed_branches"]["first_seen"]["entries"] == [
        {"bit": 2, "port": COVERAGE_PORT, "event": 2, "time": 1.0},
        {"bit": 5, "port": COVERAGE_PORT, "event": 3, "time": 1.5},
    ]


@pytest.mark.skipif(not (ROOT / "runs/p4-cpu-side-coverage-20261008-online").is_dir(),
                    reason="the saved instrumented run is not present")
def test_saved_instrumented_run_still_reports_unavailable_with_a_reason(
        capsys) -> None:
    """The real P4 run predates the ledger: absence stays unavailable."""
    run = ROOT / "runs/p4-cpu-side-coverage-20261008-online"
    code, document = _cli_json(capsys, run)
    assert code == 0
    assert document["status"] == VERIFIED
    first_seen = document["observed_branches"]["first_seen"]
    assert first_seen["available"] is False
    assert first_seen["entries"] == []
    assert first_seen["reason"] == NO_EVIDENCE_REASON
