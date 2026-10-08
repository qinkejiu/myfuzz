"""P4 slot immutability sweep over a declared list of saved runs (read-only).

Specification pinned here, before the implementation:

* the sweep runs the **shipped** per-run verdict
  (``myfuzz.scenario.slot_immutability``) over every declared run directory and
  aggregates immutable / violated / insufficient_evidence / unavailable;
* an ``unavailable`` run is reported with a precise reason, ``null`` slot counts
  and a non-zero sweep exit -- never as ``immutable`` and never as ``0 slots``;
* the versioned document is deterministic: the same declared runs and the same
  frozen artifacts produce byte-identical JSON (no clock, no host, no cwd);
* real saved runs are read read-only, and the sweep must not modify them.

Nothing here compiles, renders or starts RTL/Verilator, and no fuzz job runs:
synthetic runs are hand-written records with the shipped shapes, and the real
runs are streamed with the shipped readers (``report_for_run`` for ``jsonl.v1``,
``TraceEventStream`` for the monolithic ``json.v1`` artifact).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from myfuzz.scenario.slot_immutability import (
    ARGUMENT_ERROR_EXIT_CODE, EXIT_CODES, main as shipped_main)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "report_p4_slot_immutability_sweep.py"

RUN_REAL_SEQUENCE_EDIT = "runs/p4-sequence-edit-insert-20261008-online"
RUN_REAL_JSONL = "runs/current-dataflow-p5-streamed-short-20261007-online"

RESERVATION = (0x1000, 0x1020)
WORD_A = bytes.fromhex("13000000")
#: A word that differs from WORD_A in *every* byte, so every lane is a conflict.
WORD_B = bytes.fromhex("b7010111")


@pytest.fixture(scope="module")
def sweep():
    """Load the sweep script by path: it is a script, not a package module."""
    assert SCRIPT.is_file(), f"missing sweep script {SCRIPT}"
    spec = importlib.util.spec_from_file_location("p4_slot_immutability_sweep",
                                                  SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# synthetic runs with the shipped record shapes
# ---------------------------------------------------------------------------

def write_manifest(directory: Path, start: int = RESERVATION[0],
                   end: int = RESERVATION[1]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "decoder_manifest.json").write_text(
        json.dumps({"instruction_start": start, "instruction_end": end}),
        encoding="utf-8")
    return directory


def program_instruction(event_id: int, address: int, data: bytes) -> dict:
    return {"event_id": event_id, "kind": "instruction_source", "component": "cpu",
            "address": address, "data_hex": data.hex(), "generation": 0}


def memory_read(event_id: int, address: int, data: bytes) -> dict:
    return {"event_id": event_id, "kind": "memory_read", "component": "cpu",
            "memory_id": "ram", "address": address,
            "byte_offset": address - 0x10000, "data_hex": data.hex(),
            "value": int.from_bytes(data, "little"), "width_bytes": len(data),
            "versions": [], "writer_event_ids": [], "writer_kinds": []}


def run_with_jsonl(directory: Path, events) -> Path:
    write_manifest(directory)
    with open(directory / "online_events.jsonl", "w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
    return directory


def run_with_monolithic(directory: Path, events) -> Path:
    """A ``json.v1`` run: one ``online_final_trace.json``, no JSONL at all."""
    write_manifest(directory)
    (directory / "online_final_trace.json").write_text(
        json.dumps({"events": list(events)}), encoding="utf-8")
    return directory


class SyntheticRuns:
    """One directory per verdict, all four in the same sweep declaration."""

    def __init__(self, root: Path) -> None:
        self.immutable = run_with_jsonl(root / "immutable", [
            program_instruction(1, 0x1000, WORD_A),
            memory_read(2, 0x1000, WORD_A)])
        self.violated = run_with_jsonl(root / "violated", [
            program_instruction(1, 0x1000, WORD_A),
            program_instruction(2, 0x1000, WORD_B)])
        self.insufficient = run_with_jsonl(root / "insufficient", [
            memory_read(1, 0x1000, WORD_A)])
        self.unavailable = write_manifest(root / "unavailable")  # no trace at all

    @property
    def directories(self) -> list[str]:
        return [str(self.immutable), str(self.violated),
                str(self.insufficient), str(self.unavailable)]

    def verdicts(self, document: dict) -> dict:
        return {row["run_directory"]: row["verdict"]
                for row in document["runs"]}

    def row(self, document: dict, directory: Path) -> dict:
        return next(row for row in document["runs"]
                    if row["run_directory"] == str(directory))


@pytest.fixture
def synthetic(tmp_path, sweep) -> SyntheticRuns:
    return SyntheticRuns(tmp_path)


def run_sweep(sweep, declaration, json_out: Path, *args: str) -> int:
    return sweep.main([*map(str, declaration), "--json-out", str(json_out),
                       *args])


# ---------------------------------------------------------------------------
# aggregation of the four per-run verdicts
# ---------------------------------------------------------------------------

def test_sweep_aggregates_the_four_synthetic_verdicts(sweep, synthetic, tmp_path):
    out = tmp_path / "sweep.json"
    # Severity: one violated run outranks the unavailable one, exactly like the
    # shipped CLI's conclusion order (violated > insufficient/unavailable).
    assert run_sweep(sweep, synthetic.directories, out) == 1
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["schema_version"] == sweep.SWEEP_SCHEMA_VERSION == (
        "p4_slot_immutability_sweep.v1")
    assert document["declaration"]["run_directories"] == synthetic.directories
    assert synthetic.verdicts(document) == {
        str(synthetic.immutable): "immutable",
        str(synthetic.violated): "violated",
        str(synthetic.insufficient): "insufficient_evidence",
        str(synthetic.unavailable): "unavailable",
    }
    assert document["totals"]["verdicts"] == {
        "immutable": 1, "violated": 1, "insufficient_evidence": 1,
        "unavailable": 1}
    # Every judged run carries the shipped verdict fields.
    immutable = synthetic.row(document, synthetic.immutable)
    assert immutable["verdict_reader"] == "shipped_cli_path"
    assert (immutable["slot_count"], immutable["immutable"]) == (4, 4)
    assert immutable["violated"] == 0
    assert immutable["insufficient_evidence"] == 0
    assert immutable["proof_scope"]["rtl_executed_by_checker"] is False
    assert immutable["gate_line"].startswith(
        f"{sweep.SHIPPED_GATE_SCHEMA_VERSION} ")
    # The sweep never claims a pass while a declared run has no verdict.
    assert document["sweep_conclusion"] == "violated"
    assert document["sweep_exit_code"] == 1


def test_sweep_names_the_violated_slot_and_event(sweep, synthetic, tmp_path):
    out = tmp_path / "sweep.json"
    run_sweep(sweep, synthetic.directories, out)
    document = json.loads(out.read_text(encoding="utf-8"))
    row = synthetic.row(document, synthetic.violated)
    assert (row["slot_count"], row["immutable"], row["violated"],
            row["insufficient_evidence"]) == (4, 0, 4, 0)
    assert row["conflicts_by_kind"] == {
        "later_materialization_different_value": 4,
        "later_read_different_value": 0}
    assert [(slot["address"], slot["conflict_kind"],
             slot["conflicting_event_id"], slot["materialized_value"],
             slot["conflicting_value"])
            for slot in row["violated_slots"]] == [
        (0x1000, "later_materialization_different_value", 2, 0x13, 0xb7),
        (0x1001, "later_materialization_different_value", 2, 0x00, 0x01),
        (0x1002, "later_materialization_different_value", 2, 0x00, 0x01),
        (0x1003, "later_materialization_different_value", 2, 0x00, 0x11)]


def test_sweep_keeps_the_shipped_reassertion_rule(sweep, tmp_path):
    """Materializing the *same* value again is a reassertion, not a violation."""
    directory = run_with_jsonl(tmp_path / "reasserted", [
        program_instruction(1, 0x1000, WORD_A),
        program_instruction(2, 0x1000, WORD_A)])
    out = tmp_path / "sweep.json"
    assert run_sweep(sweep, [directory], out) == 0
    row = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    assert (row["verdict"], row["slot_count"], row["violated"]) == (
        "immutable", 4, 0)
    assert row["reassertion_count"] == 4
    assert row["violated_slots"] == []


def test_sweep_names_each_insufficient_reason(sweep, synthetic, tmp_path):
    out = tmp_path / "sweep.json"
    run_sweep(sweep, synthetic.directories, out)
    document = json.loads(out.read_text(encoding="utf-8"))
    row = synthetic.row(document, synthetic.insufficient)
    assert (row["slot_count"], row["immutable"], row["violated"],
            row["insufficient_evidence"]) == (4, 0, 0, 4)
    assert row["insufficient_by_reason"] == {"read_before_materialization": 4}
    assert [(slot["address"], slot["reason"], slot["early_read_event_id"])
            for slot in row["insufficient_slots"]] == [
        (0x1000, "read_before_materialization", 1),
        (0x1001, "read_before_materialization", 1),
        (0x1002, "read_before_materialization", 1),
        (0x1003, "read_before_materialization", 1)]


# ---------------------------------------------------------------------------
# an unavailable run is never a pass and never "0 slots"
# ---------------------------------------------------------------------------

def test_unavailable_run_is_never_counted_as_immutable(sweep, tmp_path):
    only = write_manifest(tmp_path / "no-trace")
    out = tmp_path / "sweep.json"
    assert run_sweep(sweep, [only], out) == 2
    document = json.loads(out.read_text(encoding="utf-8"))
    row = document["runs"][0]
    assert row["verdict"] == "unavailable"
    assert row["run_conclusion"] is None
    assert row["verdict_reader"] is None
    for field in ("slot_count", "immutable", "violated", "insufficient_evidence",
                  "proof_scope", "gate_line"):
        assert row[field] is None, field
    assert row["null_counts_reason"]
    assert row["unavailable_reasons"], "an unavailable run must name its reasons"
    assert document["sweep_conclusion"] == "unavailable"
    assert document["sweep_exit_code"] == sweep.SWEEP_EXIT_CODES["unavailable"] == 2
    totals = document["totals"]
    assert totals["verdicts"]["unavailable"] == 1
    assert totals["verdicts"]["immutable"] == 0
    assert totals["runs_with_a_shipped_verdict"] == 0
    assert totals["slot_count"] is None, "no judged run: no slot count to add"
    assert totals["immutable_slots"] is None


def test_unavailable_reason_names_the_missing_artifact(sweep, tmp_path):
    only = write_manifest(tmp_path / "no-trace")
    out = tmp_path / "sweep.json"
    run_sweep(sweep, [only], out)
    row = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    reasons = {item["stage"]: item["reason"] for item in row["unavailable_reasons"]}
    assert "no online_events.jsonl" in reasons["shipped_cli_path"]
    assert "no online_final_trace.meta.json" in reasons["shipped_stream_path"]
    assert row["shipped_cli_path"]["verdict"] == "unavailable"
    assert row["shipped_cli_path"]["reason"] == reasons["shipped_cli_path"]


def test_unavailable_reason_names_every_blocking_declaration(sweep, tmp_path):
    """No manifest *and* no trace: both blockers are named, not just the first."""
    empty = tmp_path / "no-manifest-no-trace"
    empty.mkdir()
    out = tmp_path / "sweep.json"
    assert run_sweep(sweep, [empty], out) == 2
    row = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    assert row["verdict"] == "unavailable"
    stages = [item["stage"] for item in
              row["shipped_stream_path"]["blocking_reasons"]]
    assert stages == ["trace_artifact", "program_range"]
    combined = row["shipped_stream_path"]["reason"]
    assert "no online_final_trace.meta.json" in combined
    assert "no decoder_manifest.json" in combined
    assert row["identity"]["trace"]["stream_reader_declares_no_artifact"]


def test_missing_declared_run_directory_is_unavailable(sweep, tmp_path):
    missing = tmp_path / "never-created"
    out = tmp_path / "sweep.json"
    assert run_sweep(sweep, [missing], out) == 2
    row = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    assert row["verdict"] == "unavailable"
    assert row["slot_count"] is None
    assert row["unavailable_reasons"][0]["stage"] == "declaration"
    assert "does not exist" in row["unavailable_reasons"][0]["reason"]


def test_sweep_without_a_declaration_is_an_argument_error(sweep):
    assert sweep.main([]) == ARGUMENT_ERROR_EXIT_CODE == 3


# ---------------------------------------------------------------------------
# the verdict is the shipped one, and the monolithic reader is labelled
# ---------------------------------------------------------------------------

def test_sweep_verdict_agrees_with_the_shipped_cli_exit_code(sweep, synthetic,
                                                             tmp_path, capsys):
    out = tmp_path / "sweep.json"
    run_sweep(sweep, synthetic.directories, out)
    document = json.loads(out.read_text(encoding="utf-8"))
    capsys.readouterr()
    for directory in (synthetic.immutable, synthetic.violated,
                      synthetic.insufficient):
        row = synthetic.row(document, directory)
        assert row["verdict"] == row["run_conclusion"]
        assert row["exit_code"]["shipped_gate_conclusion"] == EXIT_CODES[
            row["run_conclusion"]]
        assert row["exit_code"]["sweep_per_run"] == sweep.SWEEP_EXIT_CODES[
            row["verdict"]]
        assert shipped_main([str(directory)]) == EXIT_CODES[row["run_conclusion"]]
        capsys.readouterr()
    # The shipped CLI refuses the whole invocation (exit 3) for a run it cannot
    # read; the sweep records that run as unavailable instead of losing the
    # other verdicts, and still never lets it pass.
    assert shipped_main([str(synthetic.unavailable)]) == ARGUMENT_ERROR_EXIT_CODE
    capsys.readouterr()
    row = synthetic.row(document, synthetic.unavailable)
    assert row["exit_code"]["shipped_gate_conclusion"] is None
    assert row["exit_code"]["shipped_cli_default_invocation"] == (
        ARGUMENT_ERROR_EXIT_CODE)


def test_monolithic_trace_is_judged_through_the_shipped_stream_reader(
        sweep, tmp_path):
    directory = run_with_monolithic(tmp_path / "monolithic", [
        program_instruction(1, 0x1000, WORD_A),
        memory_read(2, 0x1000, WORD_A)])
    out = tmp_path / "sweep.json"
    assert run_sweep(sweep, [directory], out) == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    row = document["runs"][0]
    assert row["verdict"] == "immutable"
    assert row["verdict_reader"] == "shipped_stream_path"
    assert (row["slot_count"], row["immutable"]) == (4, 4)
    assert row["identity"]["trace"]["events_file"] == "online_final_trace.json"
    assert row["identity"]["trace"]["format"] == "json.v1"
    # The default shipped CLI path cannot read this run, and the document says
    # so instead of pretending the CLI judged it.
    assert row["shipped_cli_path"]["verdict"] == "unavailable"
    assert "no online_events.jsonl" in row["shipped_cli_path"]["reason"]
    # ... and with the stream reader disabled the same run is unavailable.
    out_disabled = tmp_path / "sweep_disabled.json"
    assert run_sweep(sweep, [directory], out_disabled,
                     "--no-stream-reader") == 2
    disabled = json.loads(out_disabled.read_text(encoding="utf-8"))["runs"][0]
    assert disabled["verdict"] == "unavailable"
    assert disabled["slot_count"] is None
    assert disabled["shipped_stream_path"]["attempted"] is False


def test_sweep_does_not_fall_back_for_a_broken_jsonl_trace(sweep, tmp_path):
    """A present-but-malformed JSONL must fail closed, never re-read elsewhere."""
    directory = run_with_jsonl(tmp_path / "broken", [
        program_instruction(1, 0x1000, WORD_A)])
    run_with_monolithic(directory, [program_instruction(1, 0x1000, WORD_A)])
    with open(directory / "online_events.jsonl", "a", encoding="utf-8") as handle:
        handle.write("{not json}\n")
    out = tmp_path / "sweep.json"
    assert run_sweep(sweep, [directory], out) == 2
    row = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    assert row["verdict"] == "unavailable"
    assert row["shipped_stream_path"]["attempted"] is False
    assert "is not JSON" in row["shipped_cli_path"]["reason"]


# ---------------------------------------------------------------------------
# trace integrity: the verdict may only stand on the trace it declares
# ---------------------------------------------------------------------------

def write_trace_meta(directory: Path, events, *, event_count=None,
                     semantic_sha256=None) -> Path:
    meta = {
        "schema_version": "online_trace_jsonl.v1",
        "events_file": "online_events.jsonl",
        "event_count": len(events) if event_count is None else event_count,
        "local_ticks": {"cpu": 1},
        "status": "complete",
    }
    if semantic_sha256 is not None:
        meta["semantic_sha256"] = semantic_sha256
    (directory / "online_final_trace.meta.json").write_text(
        json.dumps(meta), encoding="utf-8")
    return directory


def shipped_canonical_digest(events, local_ticks, status) -> str:
    """The frozen writer rule, recomputed with the shipped canonical encoder."""
    from myfuzz.scenario.acceptance_metrics import _canonical_bytes
    digest = hashlib.sha256(b'{"events":[')
    for index, event in enumerate(events):
        if index:
            digest.update(b",")
        digest.update(_canonical_bytes(event))
    digest.update(b'],"local_ticks":')
    digest.update(_canonical_bytes(local_ticks))
    digest.update(b',"status":')
    digest.update(_canonical_bytes(status))
    digest.update(b"}")
    return digest.hexdigest()


def test_trace_integrity_refuses_a_mismatched_declared_event_count(sweep, tmp_path):
    events = [program_instruction(1, 0x1000, WORD_A),
              memory_read(2, 0x1000, WORD_A)]
    directory = write_trace_meta(
        run_with_jsonl(tmp_path / "count-mismatch", events),
        events, event_count=len(events) + 7)
    out = tmp_path / "sweep.json"
    assert run_sweep(sweep, [directory], out) == 2
    row = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    assert row["verdict"] == "unavailable"
    assert row["slot_count"] is None
    assert row["shipped_cli_path"]["verdict"] == "immutable"
    assert row["shipped_cli_path"]["refused_by_trace_integrity"] is True
    assert row["trace_integrity"]["status"] == "failed"
    assert any("event count mismatch" in item["reason"]
               for item in row["unavailable_reasons"])


def test_trace_integrity_refuses_a_wrong_semantic_digest(sweep, tmp_path):
    events = [program_instruction(1, 0x1000, WORD_A)]
    directory = write_trace_meta(
        run_with_jsonl(tmp_path / "digest-mismatch", events), events,
        semantic_sha256="00" * 32)
    out = tmp_path / "sweep.json"
    assert run_sweep(sweep, [directory], out) == 2
    row = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    assert row["verdict"] == "unavailable"
    assert row["trace_integrity"]["status"] == "verified"
    assert row["trace_integrity"]["semantic_sha256_verified"] is False
    assert any("semantic_sha256_mismatch" in item["reason"]
               for item in row["unavailable_reasons"])


def test_trace_integrity_accepts_a_matching_digest_and_a_missing_one(sweep, tmp_path):
    events = [program_instruction(1, 0x1000, WORD_A),
              memory_read(2, 0x1000, WORD_A)]
    # A declared digest that the shipped reader recomputes: verified, immutable.
    local_ticks, status = {"cpu": 1}, "complete"
    verified_dir = write_trace_meta(
        run_with_jsonl(tmp_path / "digest-ok", events), events,
        semantic_sha256=shipped_canonical_digest(events, local_ticks, status))
    # No declared digest at all: recorded as missing, not as a failure.
    plain_dir = write_trace_meta(
        run_with_jsonl(tmp_path / "no-digest", events), events)
    out = tmp_path / "sweep.json"
    assert run_sweep(sweep, [verified_dir, plain_dir], out) == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    verified = document["runs"][0]
    assert verified["verdict"] == "immutable"
    assert verified["trace_integrity"]["semantic_sha256_verified"] is True
    assert verified["trace_integrity"]["event_count_matches_declared"] is True
    assert verified["trace_integrity"]["event_count_matches_judged"] is True
    plain = document["runs"][1]
    assert plain["verdict"] == "immutable"
    assert plain["trace_integrity"]["semantic_sha256_verified"] is None
    assert plain["trace_integrity"]["declared_semantic_sha256"] is None
    assert document["totals"]["runs_with_verified_trace_semantic_sha256"] == 1
    assert document["totals"]["runs_without_declared_trace_digest"] == 1


# ---------------------------------------------------------------------------
# identity evidence and determinism
# ---------------------------------------------------------------------------

def test_sweep_records_identity_evidence_and_exit_code_semantics(
        sweep, synthetic, tmp_path):
    manifest = synthetic.immutable / "decoder_manifest.json"
    out = tmp_path / "sweep.json"
    run_sweep(sweep, synthetic.directories, out)
    document = json.loads(out.read_text(encoding="utf-8"))
    row = synthetic.row(document, synthetic.immutable)
    identity = row["identity"]
    assert identity["decoder_manifest"]["sha256"] == hashlib.sha256(
        manifest.read_bytes()).hexdigest()
    assert identity["decoder_manifest"]["bytes"] == manifest.stat().st_size
    assert identity["session_manifest"]["present"] is False
    assert identity["session_manifest"]["sha256"] is None
    trace = identity["trace"]
    assert trace["present"] is True
    assert trace["sha256"] == hashlib.sha256(
        (synthetic.immutable / "online_events.jsonl").read_bytes()).hexdigest()
    semantics = document["exit_code_semantics"]
    assert semantics["shipped_gate"] == dict(EXIT_CODES)
    assert semantics["shipped_gate_argument_error"] == ARGUMENT_ERROR_EXIT_CODE
    assert semantics["sweep"]["unavailable"] == 2
    assert document["shipped_gate_schema_version"] == (
        sweep.SHIPPED_GATE_SCHEMA_VERSION)
    assert "真实 Store/取指后的程序字节不能被后例变异" in document["requirement"]
    # What the sweep does *not* prove is recorded with the document itself.
    assert any("does not" in item or "不" in item for item in document["limits"])


def test_sweep_json_is_byte_identical_for_repeated_runs(sweep, synthetic,
                                                        tmp_path):
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    run_sweep(sweep, synthetic.directories, first)
    run_sweep(sweep, synthetic.directories, second)
    assert first.read_bytes() == second.read_bytes()


# ---------------------------------------------------------------------------
# real saved runs, read-only
# ---------------------------------------------------------------------------

def _tree_snapshot(directory: Path) -> dict:
    return {str(path.relative_to(directory)): (path.stat().st_size,
                                               path.stat().st_mtime_ns)
            for path in sorted(directory.rglob("*")) if path.is_file()}


@pytest.mark.parametrize("run_directory", [RUN_REAL_SEQUENCE_EDIT, RUN_REAL_JSONL])
def test_real_run_is_immutable_and_left_untouched(sweep, run_directory, tmp_path):
    directory = REPO_ROOT / run_directory
    if not directory.is_dir():
        pytest.skip(f"{run_directory} is not present in this workspace")
    before = _tree_snapshot(directory)
    out = tmp_path / "real.json"
    assert sweep.main([str(directory), "--json-out", str(out)]) == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    row = document["runs"][0]
    assert row["verdict"] == "immutable"
    assert row["run_conclusion"] == "immutable"
    assert row["violated"] == 0
    assert row["insufficient_evidence"] == 0
    assert row["slot_count"] > 0
    assert row["immutable"] == row["slot_count"]
    assert row["proof_scope"]["rtl_executed_by_checker"] is False
    assert row["identity"]["decoder_manifest"]["sha256"]
    assert row["identity"]["session_manifest"]["sha256"]
    # The verdict stands on the trace the run declares: the shipped reader
    # recomputed the declared canonical digest and the declared event count.
    assert row["trace_integrity"]["status"] == "verified"
    assert row["trace_integrity"]["semantic_sha256_verified"] is True
    assert row["trace_integrity"]["event_count_matches_judged"] is True
    assert _tree_snapshot(directory) == before, "the sweep must be read-only"
    # Determinism on real artifacts: the same declared run twice is byte-identical.
    again = tmp_path / "real_again.json"
    assert sweep.main([str(directory), "--json-out", str(again)]) == 0
    assert again.read_bytes() == out.read_bytes()
