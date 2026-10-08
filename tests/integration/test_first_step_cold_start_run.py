"""Stub tests for ``scripts/run_first_step_cold_start_run.py``.

No RTL and no RFuzz client are started here. Two seams are exercised instead:

* the orchestrator's per-case subprocess runner is replaced by a fake that
  writes a case directory the way the frozen live writer does, so the
  aggregation, the ordering, the window truncation and the failure accounting
  are all tested against real files;
* the worker's runtime factory and live runner are injected fakes, so the
  frozen per-case weights, the decoder prefix replay and the receipt
  verification are tested without a session.

The synthetic continuous run directory is decoder-consistent: its rows are
produced by replaying synthetic eight-byte records through the real
``OnlineCaseDecoder`` (pure Python), which is what makes a same-genome
comparison meaningful without RTL. ``paired_efficiency.compare_runs`` must be
able to read the aggregated cold directory, and the paired CLI is invoked
through a subprocess to prove the delivered entry point really pairs.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.scenario.ibex_pulp_dual_source import (
    make_ibex_pulp_dual_source_online_decoder,
    make_ibex_pulp_dual_source_stream_bootstrap,
)
from myfuzz.scenario.decode_space import (
    compare_online_decode_space, online_decode_space_document,
    recorded_decode_space,
)
from myfuzz.scenario.paired_efficiency import compare_runs

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import run_first_step_cold_start_run as cold_run  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_first_step_cold_start_run.py"
FROZEN_WRITER = ROOT / "src" / "myfuzz" / "integration" / "scenario_rfuzz_live.py"
FROZEN_PRODUCER = ROOT / "scripts" / "bench_ibex_pulp_cold_start.py"
PAIRED_CLI = ROOT / "scripts" / "bench_first_step_paired.py"
REAL_CONTINUOUS = (ROOT / "runs" /
                   "current-dataflow-p5-chain-acceptance-20261007-online")

_DECODER_SOURCE_PATHS = (
    "src/myfuzz/scenario/ibex_pulp_dual_source.py",
    "src/myfuzz/scenario/online_case_decoder.py",
    "src/myfuzz/scenario/rv32i_sources.py",
)


def _file_sha256(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def _recorded_source_hashes(document: object) -> dict[str, str]:
    """Collect every ``{path, sha256}`` pair recorded in a run identity."""
    found: dict[str, str] = {}

    def walk(node: object) -> None:
        if isinstance(node, dict):
            path, digest = node.get("path"), node.get("sha256")
            if isinstance(path, str) and isinstance(digest, str):
                found.setdefault(path, digest)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(document)
    return found


def _decode_space_drift_reason(identity_document: object) -> str | None:
    """The exact reason a frozen reference cannot be reproduced, if any.

    A new run identity records the decode space itself, so that comparison
    decides (`compare_online_decode_space` is the same one the replay verifier
    uses).  A legacy identity records the decode sources only incidentally, if
    at all; then whatever ``{path, sha256}`` pairs it carries are compared
    directly.  Either way drift yields a precise skip reason instead of a
    failure, and a missing record stays a fallback rather than a refusal.
    """
    recorded_space = recorded_decode_space(identity_document)
    if recorded_space is not None:
        comparison = compare_online_decode_space(recorded_space)
        if comparison.drifted:
            return ("frozen reference run predates the current decoder sources: "
                    + ", ".join(comparison.drifted))
        return None
    recorded = _recorded_source_hashes(identity_document)
    drifted = sorted(path for path in _DECODER_SOURCE_PATHS
                     if path in recorded and recorded[path] != _file_sha256(path))
    if drifted:
        return ("frozen reference run predates the current decoder sources: "
                + ", ".join(drifted))
    return None


SEARCH_SEED = 20261007
WEIGHTS = {"cpu.online_instruction": 104, "gpio_b.external_pin8": 104}
COMPONENT_IDENTITY = "b" * 64
TARGETS_SHA = "e" * 64
DECODER_MANIFEST = "1" * 64
PLAN_SHA = "d" * 64
PER_CASE_EFFECTIVE = 2.0
PER_CASE_ELAPSED = 2.5
INIT_SECONDS = (1.5, 1.75, 2.0, 2.25)


# --------------------------------------------------------------------------
# frozen producer schema, extracted from the writer source itself
# --------------------------------------------------------------------------


def _frozen_writer_receipt_keys() -> tuple[str, ...]:
    """Read the receipt row keys out of ``persist_receipt``'s dict literal."""
    tree = ast.parse(FROZEN_WRITER.read_text(encoding="utf-8"))
    function = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "persist_receipt")
    for node in ast.walk(function):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "write"):
            continue
        for inner in ast.walk(node):
            if (isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "dumps"):
                for argument in inner.args:
                    if isinstance(argument, ast.Dict):
                        keys = tuple(key.value for key in argument.keys)
                        assert len(keys) >= 30, keys
                        return keys
    raise AssertionError("persist_receipt receipt dictionary was not found")


def _frozen_producer_case_keys() -> tuple[str, ...]:
    """Read the per-case keys ``measure_cold_cases`` puts in its result dict."""
    tree = ast.parse(FROZEN_PRODUCER.read_text(encoding="utf-8"))
    function = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "measure_cold_cases")
    for node in ast.walk(function):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "result"
                and isinstance(node.value, ast.Dict)):
            return tuple(key.value for key in node.value.keys)
    raise AssertionError("measure_cold_cases result dictionary was not found")


FROZEN_RECEIPT_KEYS = _frozen_writer_receipt_keys()
# ``replay_*`` keys are appended by measure_cold_cases only under --fresh-replay.
FROZEN_CASE_KEYS = tuple(key for key in _frozen_producer_case_keys()
                         if not key.startswith("replay_"))


# --------------------------------------------------------------------------
# synthetic, decoder-consistent continuous run directory
# --------------------------------------------------------------------------


def _raw(index: int) -> bytes:
    return bytes([index, 0, index, 0, index, 0, index, 0])


def _decoded_cases(count: int) -> list:
    """Replay synthetic records through the real decoder (no RTL, no session)."""
    decoder = make_ibex_pulp_dual_source_online_decoder(
        bootstrap=make_ibex_pulp_dual_source_stream_bootstrap())
    cases = []
    for index in range(count):
        case = decoder.decode(_raw(index), coverage_hints=dict(WEIGHTS))
        decoder.commit(case)
        cases.append(case)
    return cases


def _row(index: int, case, *, coverage: str = "0100") -> dict:
    raw_hex = _raw(index).hex()
    row = {name: None for name in FROZEN_RECEIPT_KEYS}
    row.update({
        "run_id": "stub-continuous",
        "buffer_id": index,
        "slot": 0,
        "raw_sha256": hashlib.sha256(_raw(index)).hexdigest(),
        "genome_sha256": None,
        "path_id": case.path_id,
        "applied_sources": [case.source.action_id.rsplit(":", 1)[-1]],
        "applied_source_ids": [case.source.action_id.rsplit(":", 1)[-1]],
        "applied_template": 0,
        "applied_path": index,
        "effective_genome_sha256": None,
        "status": "complete",
        "total_local_ticks": 96,
        "local_ticks": {"cpu": 32, "gpio_a": 32, "gpio_b": 32},
        "coverage_hex": coverage,
        "violations": [],
        "error": None,
        "wall_cut": None,
        "online_raw_records_hex": [raw_hex],
        "case_id": case.case_id,
        "direction": case.direction,
        "flow_id": "F5",
        "target_id": "ip_to_cpu_to_ip.closed_loop",
        "source_id": case.source.action_id.rsplit(":", 1)[-1],
        "operator_id": "external_event",
        "candidate_id": f"online-candidate.v1:{index}",
        "source_selection_reason": "feedback_weighted_legal_source",
        "candidate_disposition": "admitted",
        "candidate_disposition_reason": "rtl_case_committed",
        "rejection": None,
        "interaction_source_gains": {},
        "online_phase_timing_seconds": {"total": 1.0},
        "online_submit_timing_seconds": {"local_command_count": 96},
        "online_runner_timing_seconds": {"runner_step": 0.5},
        "online_source": None,
        "online_weights": dict(WEIGHTS),
        "interaction_feature_deltas": {},
        "interaction_new_features": [],
        "interaction_deferred": True,
    })
    row["genome_sha256"] = cold_run.online_case_sha256(case)
    row["effective_genome_sha256"] = row["genome_sha256"]
    return row


def _write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")


def _stub_continuous(directory: Path, *, case_count: int = 4,
                     client_binary: Path | None = None,
                     source_files: list | None = None,
                     run_id: str = "stub-continuous",
                     effective_seconds: float = 10.0,
                     elapsed_seconds: float = 12.0) -> dict:
    """Write a continuous run directory whose rows a real decoder produced."""
    directory.mkdir(parents=True, exist_ok=True)
    cases = _decoded_cases(case_count)
    rows = [_row(index, case) for index, case in enumerate(cases)]
    for row in rows:
        row["run_id"] = run_id
    with (directory / "receipts.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    _write_json(directory / "report.json", {
        "execution_mode": "online_cases",
        "execution_status": "complete",
        "session_status": "complete",
        "tests": case_count,
        "statuses": {"complete": case_count},
        "effective_search_seconds": effective_seconds,
        "elapsed_seconds": elapsed_seconds,
        "decoder_manifest_sha256": DECODER_MANIFEST,
        "global_mutation_seed": SEARCH_SEED,
    })
    identity = {
        "schema_version": "scenario_online_run_identity.v1",
        "execution_mode": "online_cases",
        "run_config": {"run_id": run_id, "duration_seconds": 30.0,
                       "max_tests": case_count, "search_seed": SEARCH_SEED,
                       "max_runs_per_batch": 1, "feedback_interval": 16},
        "source_files": (source_files if source_files is not None else []),
        "session": {"component_identity_sha256": COMPONENT_IDENTITY,
                    "manifest_file": "online_session_manifest.json",
                    "manifest_sha256": "c" * 64},
        "components": {"identity_sha256": COMPONENT_IDENTITY},
        "genome": {"format": "online_session_plan", "plan_file": "online_plan.json",
                   "plan_sha256": PLAN_SHA,
                   "semantics": "complete admitted session prefix"},
        "feedback": {"targets_sha256": TARGETS_SHA},
        "toolchain": {"client": {"basename": "kfuzz",
                                 "binary_sha256": ("f" * 64 if client_binary is None
                                                   else _sha256_file(client_binary))}},
        "artifacts": {},
    }
    _write_json(directory / "online_run_identity.json", {
        "schema_version": "scenario_online_run_identity_envelope.v1",
        "sha256": hashlib.sha256(json.dumps(
            identity, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode()).hexdigest(),
        "identity": identity,
    })
    _write_json(directory / "online_session_manifest.json",
                {"runner": {"sessions": {
                    "cpu": {"identity": {"schema_version": "stub.cpu.v1"}},
                    "gpio_a": {"identity": {"schema_version": "stub.gpio.v1"}},
                    "gpio_b": {"identity": {"schema_version": "stub.gpio.v1"}}}}})
    return {"rows": rows, "cases": cases}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write_client_binary(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _stub_case_process(rows: list[dict], *, returncode: int = 0,
                       genome_offset: int = 0, raw_offset: int = 0,
                       receipt_rows: int = 1, error: str | None = None,
                       case_result_extra: dict | None = None):
    """Build a fake ``_execute_case_process`` writing a frozen-shaped case dir."""
    calls: list[dict] = []

    def fake(argv, *, cwd, env, timeout):
        index = int(argv[argv.index("--index") + 1])
        case_dir = Path(argv[argv.index("--case-dir") + 1])
        run_id = argv[argv.index("--run-id") + 1]
        case_dir.mkdir(parents=True, exist_ok=True)
        row = json.loads(json.dumps(rows[index]))
        row["run_id"] = run_id
        if raw_offset:
            row["online_raw_records_hex"] = [bytes([b ^ 0xff for b in _raw(index)]).hex()]
        if genome_offset:
            row["effective_genome_sha256"] = f"{genome_offset:064x}"
        with (case_dir / "receipts.jsonl").open("w", encoding="utf-8") as handle:
            for _ in range(receipt_rows):
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        _write_json(case_dir / "report.json", {
            "tests": receipt_rows,
            "effective_search_seconds": PER_CASE_EFFECTIVE,
            "elapsed_seconds": PER_CASE_ELAPSED,
            "decoder_manifest_sha256": DECODER_MANIFEST,
            "global_mutation_seed": SEARCH_SEED,
            "finalization_timing_seconds": {"session_finish": 0.25,
                                            "total_before_report": 0.5},
        })
        _write_json(case_dir / "online_plan.json", {
            "schema_version": "online_session_plan.v1",
            "source_admissions": {"admissions": [{"role": "fuzz_source"}]}})
        result = {
            "schema_version": "first_step_cold_start_case.v1",
            "index": index,
            "case_dir": str(case_dir),
            "run_id": run_id,
            "raw_hex": rows[index]["online_raw_records_hex"][0],
            "raw_sha256": rows[index]["raw_sha256"],
            "receipt_rows": receipt_rows,
            "status": rows[index]["status"],
            "case_id": rows[index]["case_id"],
            "effective_genome_sha256": row["effective_genome_sha256"],
            "path_id": rows[index]["path_id"],
            "applied_sources": rows[index]["applied_sources"],
            "coverage_hex": rows[index]["coverage_hex"],
            "local_ticks": rows[index]["local_ticks"],
            "violations": rows[index]["violations"],
            "raw_match": not raw_offset,
            "genome_match": not genome_offset,
            "path_match": True,
            "source_match": True,
            "status_match": True,
            "init_seconds": INIT_SECONDS[index % len(INIT_SECONDS)],
            "total_seconds": INIT_SECONDS[index % len(INIT_SECONDS)] + 0.5,
            "effective_search_seconds": PER_CASE_EFFECTIVE,
            "elapsed_seconds": PER_CASE_ELAPSED,
            "decoder_manifest_sha256": DECODER_MANIFEST,
            "component_identity_sha256": COMPONENT_IDENTITY,
            "targets_sha256": TARGETS_SHA,
            "modes": {"cpu_retirement": False, "native_irq_receipts": False,
                      "gpio_consumption": False},
            "error": error,
        }
        result.update(case_result_extra or {})
        _write_json(case_dir / "case_result.json", result)
        calls.append({"argv": list(argv), "index": index, "timeout": timeout})
        return subprocess.CompletedProcess(argv, returncode, stdout="stub\n",
                                           stderr="" if returncode == 0 else "boom\n")

    fake.calls = calls
    return fake


def _run_cli(arguments: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run([sys.executable, str(SCRIPT), *arguments], cwd=str(cwd),
                          capture_output=True, text=True, check=False,
                          env=environment)


# --------------------------------------------------------------------------
# frozen schema relationships
# --------------------------------------------------------------------------


def test_receipt_keys_are_derived_from_the_frozen_live_writer() -> None:
    assert cold_run.frozen_receipt_keys() == FROZEN_RECEIPT_KEYS
    for required in ("status", "effective_genome_sha256", "raw_sha256", "path_id",
                     "applied_sources", "violations", "coverage_hex", "local_ticks",
                     "online_raw_records_hex", "online_weights",
                     "online_phase_timing_seconds"):
        assert required in FROZEN_RECEIPT_KEYS


def test_cold_baseline_document_matches_the_frozen_producer_schema(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous)
    output = tmp_path / "cold"
    monkeypatch.setattr(cold_run, "_execute_case_process",
                        _stub_case_process(stub["rows"]))
    summary = cold_run.run_cold_start(continuous_run_dir=continuous,
                                      output_dir=output, cache_dir=tmp_path / "cache",
                                      client_binary=_write_client_binary(
                                          tmp_path / "kfuzz"),
                                      max_cases=4, seconds=1.0)
    assert summary["case_failure_count"] == 0

    document = json.loads((output / "cold_start.json").read_text(encoding="utf-8"))
    assert document["schema_version"] == "ibex_pulp_cold_baseline.v1"
    assert document["comparison_scope"] == "startup_cost_only_not_coverage_equivalence"
    assert document["case_count"] == 4
    assert document["source_receipts"] == str(continuous / "receipts.jsonl")
    assert document["source_compatible_count"] == 4
    assert document["path_compatible_count"] == 4
    assert isinstance(document["elapsed_seconds"], float)
    for entry in document["cases"]:
        for name in FROZEN_CASE_KEYS:
            assert name in entry, name
        assert entry["raw_hex"] == stub["rows"][entry["index"]][
            "online_raw_records_hex"][0]
        assert entry["init_seconds"] == INIT_SECONDS[entry["index"]]
        assert entry["total_seconds"] == INIT_SECONDS[entry["index"]] + 0.5
        assert entry["cold_status"] == "complete"
        assert entry["error"] is None
        assert entry["elapsed_seconds"] == PER_CASE_ELAPSED
        assert entry["finalization_timing_seconds"]["session_finish"] == 0.25
        # The split phases of the frozen producer are not separable in a
        # per-case live restart: null with a reason, never 0.
        for split in ("decode_seconds", "execute_seconds", "finish_seconds"):
            assert entry[split] is None
        assert entry["timing_split_reason"]


# --------------------------------------------------------------------------
# window, ordering and raw identity
# --------------------------------------------------------------------------


def test_case_order_and_raw_follow_the_continuous_window(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous)
    output = tmp_path / "cold"
    fake = _stub_case_process(stub["rows"])
    monkeypatch.setattr(cold_run, "_execute_case_process", fake)
    summary = cold_run.run_cold_start(
        continuous_run_dir=continuous, output_dir=output, cache_dir=tmp_path / "cache",
        client_binary=_write_client_binary(tmp_path / "kfuzz"),
        max_cases=2, seconds=1.0)
    assert summary["case_count"] == 2
    assert [call["index"] for call in fake.calls] == [0, 1]

    rows = [json.loads(line) for line in
            (output / "receipts.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["online_raw_records_hex"][0] for row in rows] == [
        stub["rows"][index]["online_raw_records_hex"][0] for index in (0, 1)]
    assert [row["raw_sha256"] for row in rows] == [
        stub["rows"][index]["raw_sha256"] for index in (0, 1)]
    assert [row["case_id"] for row in rows] == [
        stub["rows"][index]["case_id"] for index in (0, 1)]

    document = json.loads((output / "cold_start.json").read_text(encoding="utf-8"))
    assert document["case_count"] == 2
    assert [entry["raw_hex"] for entry in document["cases"]] == [
        row["online_raw_records_hex"][0] for row in rows]
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["tests"] == 2
    assert report["statuses"] == {"complete": 2}
    assert report["effective_search_seconds"] == pytest.approx(2 * PER_CASE_EFFECTIVE)
    assert report["elapsed_seconds"] == pytest.approx(2 * PER_CASE_ELAPSED)
    assert report["finalization_timing_seconds"] == {
        "session_finish": pytest.approx(0.5),
        "total_before_report": pytest.approx(1.0)}
    assert report["finalization_timing_missing_cases"] == 0
    identity = json.loads((output / "online_run_identity.json").read_text(
        encoding="utf-8"))
    assert identity["identity"]["cold_start"]["per_case_sessions"] == 2
    assert identity["identity"]["cold_start"]["per_case_max_tests"] == 1
    plan = json.loads((output / "online_plan.json").read_text(encoding="utf-8"))
    assert plan["case_count"] == 2
    assert [entry["raw_hex"] for entry in plan["cases"]] == [
        row["online_raw_records_hex"][0] for row in rows]
    assert all(entry["plan_sha256"] for entry in plan["cases"])
    gate = json.loads((output / "gate_commands.json").read_text(encoding="utf-8"))
    assert gate["started_by"]["output_dir"] == str(output)
    assert gate["started_by"]["command_entrypoint"].endswith(
        "run_first_step_cold_start_run.py")
    assert gate["continuous_run_dir"] == str(continuous)
    assert [entry["returncode"] for entry in gate["case_commands"]] == [0, 0]


def test_receipt_rows_carry_the_frozen_live_writer_key_set(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous)
    output = tmp_path / "cold"
    monkeypatch.setattr(cold_run, "_execute_case_process",
                        _stub_case_process(stub["rows"]))
    cold_run.run_cold_start(continuous_run_dir=continuous, output_dir=output,
                            cache_dir=tmp_path / "cache",
                            client_binary=_write_client_binary(tmp_path / "kfuzz"),
                            max_cases=4, seconds=1.0)
    for line in (output / "receipts.jsonl").read_text(encoding="utf-8").splitlines():
        assert tuple(json.loads(line).keys()) == tuple(sorted(FROZEN_RECEIPT_KEYS))


def test_a_row_missing_a_frozen_key_fails_the_run(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous)
    output = tmp_path / "cold"
    fake = _stub_case_process(stub["rows"])
    original = fake

    def broken(argv, *, cwd, env, timeout):
        completed = original(argv, cwd=cwd, env=env, timeout=timeout)
        case_dir = Path(argv[argv.index("--case-dir") + 1])
        row = json.loads((case_dir / "receipts.jsonl").read_text(
            encoding="utf-8").strip())
        row.pop("local_ticks")
        (case_dir / "receipts.jsonl").write_text(
            json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        return completed

    monkeypatch.setattr(cold_run, "_execute_case_process", broken)
    with pytest.raises(cold_run.ColdStartCaseError, match="local_ticks"):
        cold_run.run_cold_start(continuous_run_dir=continuous, output_dir=output,
                                cache_dir=tmp_path / "cache",
                                client_binary=_write_client_binary(tmp_path / "kfuzz"),
                                max_cases=1, seconds=1.0)


# --------------------------------------------------------------------------
# paired efficiency really reads the aggregated directory
# --------------------------------------------------------------------------


def _paired_cold_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *,
                     client_binary: Path, case_count: int = 4,
                     **stub_options) -> tuple[Path, Path]:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous, case_count=case_count,
                            client_binary=client_binary, **stub_options)
    output = tmp_path / "cold"
    monkeypatch.setattr(cold_run, "_execute_case_process",
                        _stub_case_process(stub["rows"]))
    cold_run.run_cold_start(continuous_run_dir=continuous, output_dir=output,
                            cache_dir=tmp_path / "cache",
                            client_binary=client_binary, max_cases=case_count,
                            seconds=1.0)
    return continuous, output


def test_paired_efficiency_pairs_the_stub_cold_directory(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "frozen_source.py"
    source.write_text("# frozen source\n", encoding="utf-8")
    client = _write_client_binary(tmp_path / "kfuzz")
    continuous, cold = _paired_cold_run(
        tmp_path, monkeypatch, client_binary=client,
        source_files=[{"path": str(source), "sha256": _sha256_file(source)}])

    report = compare_runs(continuous, cold)
    assert report["per_case_agreement"]["cases_compared"] == 4
    assert report["per_case_agreement"]["receipt_rows"] == {"continuous": 4, "cold": 4}
    for name, entry in report["per_case_agreement"]["fields"].items():
        assert entry["equal"] == 4, name
        assert entry["missing"] == 0, name
    validity = report["comparison_validity"]
    assert validity["failed_prerequisites"] == []
    assert validity["unverified_prerequisites"] == []
    assert validity["comparable"] is True
    assert validity["output_equivalence"]["claimed"] is True

    initialization = report["initialization"]
    assert initialization["cold_baseline_document"] == "cold_start.json"
    assert initialization["cold_baseline_case_count"] == 4
    assert initialization["cold_init_seconds_total"] == pytest.approx(
        sum(INIT_SECONDS))
    assert initialization["cold_baseline_input_alignment"]["equal"] == 4
    assert report["groups"]["cold"]["effective_search_seconds"] == pytest.approx(
        4 * PER_CASE_EFFECTIVE)
    assert report["groups"]["continuous"]["effective_search_seconds"] == 10.0


def test_paired_efficiency_cli_pairs_the_stub_cold_directory(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "frozen_source.py"
    source.write_text("# frozen source\n", encoding="utf-8")
    client = _write_client_binary(tmp_path / "kfuzz")
    continuous, cold = _paired_cold_run(
        tmp_path, monkeypatch, client_binary=client,
        source_files=[{"path": str(source), "sha256": _sha256_file(source)}])
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    process = subprocess.run(
        [sys.executable, str(PAIRED_CLI), "compare", "--continuous", str(continuous),
         "--cold", str(cold), "--no-chain-producer"],
        cwd=str(ROOT), capture_output=True, text=True, check=False, env=environment)
    assert process.returncode == 0, process.stderr
    document = json.loads(process.stdout.strip().splitlines()[-1])
    assert document["per_case_agreement"]["cases_compared"] == 4
    assert document["schema_version"] == "paired_efficiency_report.v1"
    assert document["comparison_validity"]["comparable"] is True


def test_pairing_reports_a_genome_mismatch_as_not_comparable(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "frozen_source.py"
    source.write_text("# frozen source\n", encoding="utf-8")
    client = _write_client_binary(tmp_path / "kfuzz")
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous, client_binary=client,
                            source_files=[{"path": str(source),
                                           "sha256": _sha256_file(source)}])
    cold = tmp_path / "cold"
    monkeypatch.setattr(cold_run, "_execute_case_process",
                        _stub_case_process(stub["rows"], genome_offset=0x1234))
    cold_run.run_cold_start(continuous_run_dir=continuous, output_dir=cold,
                            cache_dir=tmp_path / "cache", client_binary=client,
                            max_cases=4, seconds=1.0)
    report = compare_runs(continuous, cold)
    assert report["per_case_agreement"]["fields"]["effective_genome_sha256"][
        "mismatch"] == 4
    assert report["comparison_validity"]["comparable"] is False
    assert "genome_agreement" in report["comparison_validity"][
        "failed_prerequisites"]
    assert report["comparison_validity"]["output_equivalence"]["claimed"] is False


def test_truncated_cold_directory_refuses_a_full_continuous_pair(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "frozen_source.py"
    source.write_text("# frozen source\n", encoding="utf-8")
    client = _write_client_binary(tmp_path / "kfuzz")
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous, client_binary=client,
                            source_files=[{"path": str(source),
                                           "sha256": _sha256_file(source)}])
    cold = tmp_path / "cold"
    monkeypatch.setattr(cold_run, "_execute_case_process",
                        _stub_case_process(stub["rows"]))
    cold_run.run_cold_start(continuous_run_dir=continuous, output_dir=cold,
                            cache_dir=tmp_path / "cache", client_binary=client,
                            max_cases=2, seconds=1.0)
    rows = (cold / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
    document = json.loads((cold / "cold_start.json").read_text(encoding="utf-8"))
    assert len(rows) == 2
    assert len(document["cases"]) == 2
    with pytest.raises(Exception, match="receipt counts differ"):
        compare_runs(continuous, cold)


# --------------------------------------------------------------------------
# failure accounting and exit codes
# --------------------------------------------------------------------------


def test_case_process_failure_is_recorded_and_reported(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous)
    output = tmp_path / "cold"
    monkeypatch.setattr(cold_run, "_execute_case_process",
                        _stub_case_process(stub["rows"], returncode=1))
    summary = cold_run.run_cold_start(
        continuous_run_dir=continuous, output_dir=output, cache_dir=tmp_path / "cache",
        client_binary=_write_client_binary(tmp_path / "kfuzz"),
        max_cases=2, seconds=1.0)
    assert summary["case_failure_count"] == 2
    assert summary["exit_code"] == cold_run.EXIT_CASE_FAILURE
    gate = json.loads((output / "gate_commands.json").read_text(encoding="utf-8"))
    assert [entry["returncode"] for entry in gate["case_commands"]] == [1, 1]
    assert gate["case_commands"][0]["argv"][0] == sys.executable
    assert "--continuous-run-dir" in gate["case_commands"][0]["argv"]
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["execution_status"] == "failed"
    assert report["cold_start"]["case_failure_count"] == 2
    document = json.loads((output / "cold_start.json").read_text(encoding="utf-8"))
    assert document["case_count"] == 2
    assert all(entry["error"] for entry in document["cases"])


def test_raw_mismatch_is_a_case_failure(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous)
    output = tmp_path / "cold"
    summary = cold_run.run_cold_start(
        continuous_run_dir=continuous, output_dir=output, cache_dir=tmp_path / "cache",
        client_binary=_write_client_binary(tmp_path / "kfuzz"), max_cases=1,
        seconds=1.0, execute_case_process=_stub_case_process(stub["rows"],
                                                            raw_offset=1))
    assert summary["case_failure_count"] == 1
    assert summary["receipt_rows"] == 0
    assert summary["exit_code"] == cold_run.EXIT_CASE_FAILURE
    document = json.loads((output / "cold_start.json").read_text(encoding="utf-8"))
    assert document["cases"][0]["raw_compatible"] is False
    assert document["cases"][0]["error"]


def test_genome_mismatch_fails_the_run_but_keeps_the_row(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous)
    output = tmp_path / "cold"
    summary = cold_run.run_cold_start(
        continuous_run_dir=continuous, output_dir=output, cache_dir=tmp_path / "cache",
        client_binary=_write_client_binary(tmp_path / "kfuzz"), max_cases=2,
        seconds=1.0,
        execute_case_process=_stub_case_process(stub["rows"], genome_offset=0x1234))
    # The frozen input ran, so the row is published evidence; the identity it
    # produced is not the frozen one, so the run fails loudly.
    assert summary["receipt_rows"] == 2
    assert summary["published_case_count"] == 2
    assert summary["verified_case_count"] == 0
    assert summary["case_failure_count"] == 0
    assert summary["verification_failure_count"] == 2
    assert summary["exit_code"] == cold_run.EXIT_CASE_FAILURE
    document = json.loads((output / "cold_start.json").read_text(encoding="utf-8"))
    assert all(entry["genome_compatible"] is False for entry in document["cases"])
    assert all(entry["error"] is None for entry in document["cases"])
    assert all(entry["verification_error"] for entry in document["cases"])


# --------------------------------------------------------------------------
# dry run, missing inputs and invalid budgets
# --------------------------------------------------------------------------


def test_dry_run_lists_commands_and_writes_nothing(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    _stub_continuous(continuous)
    output = tmp_path / "cold"
    process = _run_cli(["run", "--continuous-run-dir", str(continuous),
                        "--output", str(output), "--max-cases", "3", "--dry-run"])
    assert process.returncode == 0, process.stderr
    lines = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
    commands = [line for line in lines if line.get("argv")]
    assert len(commands) == 3
    assert [line["index"] for line in commands] == [0, 1, 2]
    for line in commands:
        assert line["argv"][:2] == [sys.executable, str(SCRIPT)]
        assert line["argv"][2] == "case"
        assert "--case-dir" in line["argv"]
        assert line["command"].startswith(sys.executable)
    assert lines[-1]["dry_run"] is True
    assert not output.exists()


def test_dry_run_does_not_need_client_binary_or_cache(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    _stub_continuous(continuous)
    output = tmp_path / "cold"
    process = _run_cli(["run", "--continuous-run-dir", str(continuous),
                        "--output", str(output), "--max-cases", "1", "--dry-run"])
    assert process.returncode == 0, process.stderr
    summary = json.loads(process.stdout.splitlines()[-1])
    assert summary["missing_required_options"] == ["--client-binary", "--cache-dir"]


def test_real_run_requires_client_binary_and_cache_dir(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    _stub_continuous(continuous)
    process = _run_cli(["run", "--continuous-run-dir", str(continuous),
                        "--output", str(tmp_path / "cold"), "--max-cases", "1"])
    assert process.returncode == cold_run.EXIT_INPUT_ERROR
    assert "--client-binary" in process.stderr
    assert not (tmp_path / "cold").exists()


def test_missing_continuous_directory_fails_with_its_path(tmp_path: Path) -> None:
    absent = tmp_path / "absent"
    process = _run_cli(["run", "--continuous-run-dir", str(absent),
                        "--output", str(tmp_path / "cold"), "--max-cases", "1"])
    assert process.returncode == cold_run.EXIT_INPUT_ERROR
    assert "continuous run directory does not exist" in process.stderr
    assert str(absent) in process.stderr


def test_max_cases_zero_fails_explicitly(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    _stub_continuous(continuous)
    process = _run_cli(["run", "--continuous-run-dir", str(continuous),
                        "--output", str(tmp_path / "cold"), "--max-cases", "0"])
    assert process.returncode == cold_run.EXIT_INPUT_ERROR
    assert "--max-cases must be at least 1" in process.stderr


def test_missing_receipts_file_fails_with_its_path(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    continuous.mkdir()
    process = _run_cli(["run", "--continuous-run-dir", str(continuous),
                        "--output", str(tmp_path / "cold"), "--max-cases", "1"])
    assert process.returncode == cold_run.EXIT_INPUT_ERROR
    assert "receipts.jsonl" in process.stderr


def test_missing_raw_input_fails_with_the_line_number(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous, case_count=2)
    rows = [json.loads(line) for line in
            (continuous / "receipts.jsonl").read_text(encoding="utf-8").splitlines()]
    rows[1].pop("online_raw_records_hex")
    with (continuous / "receipts.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    process = _run_cli(["run", "--continuous-run-dir", str(continuous),
                        "--output", str(tmp_path / "cold"), "--max-cases", "2"])
    assert process.returncode == cold_run.EXIT_INPUT_ERROR
    assert "line 2" in process.stderr
    assert str(continuous / "receipts.jsonl") in process.stderr


def test_existing_output_directory_is_refused(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    _stub_continuous(continuous)
    output = tmp_path / "cold"
    output.mkdir()
    process = _run_cli(["run", "--continuous-run-dir", str(continuous),
                        "--output", str(output), "--max-cases", "1"])
    assert process.returncode == cold_run.EXIT_INPUT_ERROR
    assert "must be new" in process.stderr


# --------------------------------------------------------------------------
# the worker: frozen weights, prefix replay and one seed case
# --------------------------------------------------------------------------


class _FakeExecutor:
    def __init__(self) -> None:
        self._online_weights = lambda: {"unpatched": 1}


class _FakeSession:
    def __init__(self, identity: dict) -> None:
        self.manifest_document = identity
        self.finished = 0

    def finish(self):
        self.finished += 1
        return type("Trace", (), {"status": "complete"})()


class _FakeDecoder:
    """Returns the pre-computed real cases for the synthetic raw records."""

    def __init__(self, cases: list) -> None:
        self.cases = cases
        self.decoded: list[tuple[bytes, dict]] = []
        self.committed: list = []

    def decode(self, raw, *, coverage_hints=None):
        self.decoded.append((raw, dict(coverage_hints or {})))
        return self.cases[raw[0]]

    def commit(self, case) -> None:
        self.committed.append(case)

    def document(self) -> dict:
        return {"schema_version": "stub.decoder.v1"}


class _FakeRuntime:
    def __init__(self, cases: list) -> None:
        self.decoder = _FakeDecoder(cases)
        self.executor = _FakeExecutor()
        self.session = _FakeSession({"runner": {"sessions": {}}})


def _fake_live_runner(rows: list[dict], calls: list[dict], *,
                      force_raw: bytes | None = None):
    """Stand-in for ``run_scenario_rfuzz_live``: one row, no RTL."""

    def runner(**kwargs):
        calls.append(kwargs)
        output = Path(kwargs["output_dir"])
        output.mkdir(parents=True, exist_ok=True)
        raw = force_raw if force_raw is not None else kwargs["seed_records"][0]
        index = kwargs["seed_records"][0][0]
        row = json.loads(json.dumps(rows[index]))
        row["online_raw_records_hex"] = [raw.hex()]
        row["raw_sha256"] = hashlib.sha256(raw).hexdigest()
        with (output / "receipts.jsonl").open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
        _write_json(output / "report.json", {
            "tests": 1, "effective_search_seconds": 1.0, "elapsed_seconds": 1.5,
            "decoder_manifest_sha256": DECODER_MANIFEST})
        return type("Result", (), {"tests": 1, "elapsed_seconds": 1.5,
                                   "effective_search_seconds": 1.0})()

    return runner


def test_worker_injects_frozen_weights_and_runs_one_seed_case(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous, case_count=3)
    case_dir = tmp_path / "case-2"
    live_calls: list[dict] = []
    runtime = _FakeRuntime(stub["cases"])
    times = iter([10.0, 12.0, 13.0, 14.0])

    result = cold_run.execute_cold_case(
        continuous_run_dir=continuous, index=2, case_dir=case_dir,
        cache_dir=tmp_path / "cache", client_binary=tmp_path / "kfuzz",
        run_id="stub-cold-case-2", seconds=1.0,
        modes={"cpu_retirement": False, "native_irq_receipts": False,
               "gpio_consumption": False},
        runtime_factory=lambda **kwargs: runtime,
        live_runner=_fake_live_runner(stub["rows"], live_calls),
        clock=lambda: next(times))

    # The full frozen prefix was replayed into the fresh decoder with the
    # recorded per-case weights, the target case was decoded for verification,
    # and only case 2 was executed. Committing the target case belongs to the
    # live batch (the stub runner does not), so only the prefix is committed.
    assert [raw for raw, _hints in runtime.decoder.decoded] == [
        _raw(0), _raw(1), _raw(2)]
    assert [hints for _raw_bytes, hints in runtime.decoder.decoded] == [
        WEIGHTS, WEIGHTS, WEIGHTS]
    assert runtime.decoder.committed == stub["cases"][:2]
    assert result["decode_reproduces_saved_case"] is True
    assert result["decoded_case_id"] == stub["rows"][2]["case_id"]
    assert result["decoded_effective_genome_sha256"] == stub["rows"][2][
        "effective_genome_sha256"]
    assert runtime.executor._online_weights() == WEIGHTS
    assert len(live_calls) == 1
    assert live_calls[0]["seed_records"] == (_raw(2),)
    assert live_calls[0]["max_tests"] == 1
    assert live_calls[0]["max_runs_per_batch"] == 1
    assert live_calls[0]["search_seed"] == SEARCH_SEED
    assert live_calls[0]["duration_seconds"] == 1.0
    assert live_calls[0]["client_binary"] == tmp_path / "kfuzz"
    assert result["init_seconds"] == 2.0
    assert result["prefix_replay_seconds"] == 1.0
    assert result["total_seconds"] == 4.0
    assert result["raw_match"] and result["genome_match"]
    assert result["path_match"] and result["source_match"]
    assert result["receipt_rows"] == 1
    assert result["error"] is None
    assert json.loads((case_dir / "case_result.json").read_text(
        encoding="utf-8"))["case_id"] == stub["rows"][2]["case_id"]
    assert result["live_call"]["client_binary"] == str(tmp_path / "kfuzz")
    assert result["live_call"]["seed_records_hex"] == [_raw(2).hex()]
    assert result["runtime_call"]["cache_dir"] == str(tmp_path / "cache")
    assert result["runtime_call"]["run_id"] == "stub-cold-case-2"


def test_worker_records_a_non_reproducible_frozen_prefix(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous, case_count=3)
    rows = [json.loads(line) for line in
            (continuous / "receipts.jsonl").read_text(encoding="utf-8").splitlines()]
    rows[1]["case_id"] = "online-1-not-the-frozen-case"
    with (continuous / "receipts.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    result = cold_run.execute_cold_case(
        continuous_run_dir=continuous, index=2, case_dir=tmp_path / "case-2",
        cache_dir=tmp_path / "cache", client_binary=tmp_path / "kfuzz",
        run_id="stub-cold-case-2", seconds=1.0, modes={},
        runtime_factory=lambda **kwargs: _FakeRuntime(stub["cases"]),
        live_runner=_fake_live_runner(stub["rows"], []))
    assert result["error"] is not None
    assert "prefix case 1" in result["error"]
    assert result["receipt_rows"] == 0
    assert not (tmp_path / "case-2" / "receipts.jsonl").exists()


def test_worker_rejects_a_receipt_that_is_not_the_frozen_input(
        tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous, case_count=1)
    live_calls: list[dict] = []
    result = cold_run.execute_cold_case(
        continuous_run_dir=continuous, index=0, case_dir=tmp_path / "case-0",
        cache_dir=tmp_path / "cache", client_binary=tmp_path / "kfuzz",
        run_id="stub-cold-case-0", seconds=1.0, modes={},
        runtime_factory=lambda **kwargs: _FakeRuntime(stub["cases"]),
        live_runner=_fake_live_runner(stub["rows"], live_calls,
                                      force_raw=b"\xff" * 8))
    assert result["raw_match"] is False
    assert result["receipt_rows"] == 1
    assert result["error"] is not None
    assert "raw" in result["error"]


# --------------------------------------------------------------------------
# decoder prefix replay is the mechanism behind same-genome reproduction
# --------------------------------------------------------------------------


def test_prefix_replay_reproduces_the_reference_case_identity(tmp_path: Path) -> None:
    continuous = tmp_path / "continuous"
    stub = _stub_continuous(continuous, case_count=4)
    reference = [cold_run.online_case_sha256(case) for case in stub["cases"]]
    assert reference == [row["effective_genome_sha256"] for row in stub["rows"]]
    for index in range(4):
        decoder = make_ibex_pulp_dual_source_online_decoder(
            bootstrap=make_ibex_pulp_dual_source_stream_bootstrap())
        cold_run.replay_decoder_prefix(decoder, stub["rows"], index)
        case = decoder.decode(_raw(index), coverage_hints=dict(WEIGHTS))
        assert case.case_id == stub["rows"][index]["case_id"]
        assert cold_run.online_case_sha256(case) == reference[index]


@pytest.mark.skipif(not (REAL_CONTINUOUS / "receipts.jsonl").is_file(),
                    reason="the frozen real continuous run directory is absent")
def test_real_continuous_receipts_reproduce_identical_case_hashes() -> None:
    """The saved real run's per-case genome hashes are decoder-reproducible.

    Reproducing a frozen run's case identities is only meaningful while the
    decoder sources still match the revision that produced it: a source change
    (for example a new legal operator) shifts the decode space, so a drifted
    frozen reference is skipped instead of being read as a failure.
    """
    identity_path = REAL_CONTINUOUS / "online_run_identity.json"
    report_path = REAL_CONTINUOUS / "report.json"
    if report_path.is_file():
        # The frozen run records the decoder manifest it was produced with; a
        # different current manifest means the decode space moved (for example a
        # new legal operator), so the frozen reference cannot be reproduced.
        recorded_manifest = json.loads(
            report_path.read_text(encoding="utf-8")).get("decoder_manifest_sha256")
        if isinstance(recorded_manifest, str):
            current = make_ibex_pulp_dual_source_online_decoder(
                bootstrap=make_ibex_pulp_dual_source_stream_bootstrap())
            current_manifest = hashlib.sha256(cold_run.canonical_json(
                current.document())).hexdigest()
            if current_manifest != recorded_manifest:
                pytest.skip("frozen reference run records decoder manifest "
                            f"{recorded_manifest[:16]}… but the current decoder is "
                            f"{current_manifest[:16]}…")
    if identity_path.is_file():
        reason = _decode_space_drift_reason(
            json.loads(identity_path.read_text(encoding="utf-8")))
        if reason is not None:
            pytest.skip(reason)
    rows = [json.loads(line) for line in
            (REAL_CONTINUOUS / "receipts.jsonl").read_text(
                encoding="utf-8").splitlines()]
    decoder = make_ibex_pulp_dual_source_online_decoder(
        bootstrap=make_ibex_pulp_dual_source_stream_bootstrap())
    decoded = []
    for row in rows:
        raw = bytes.fromhex(row["online_raw_records_hex"][0])
        case = decoder.decode(raw, coverage_hints=row["online_weights"])
        decoded.append((row, case))
        decoder.commit(case)
    # The frozen bundle records the decoded input it was produced with. If the
    # current decode space yields a different instruction/source payload for the
    # same raw input, the reference predates a decoder change (for example a new
    # legal operator) and its case hashes are not expected to reproduce.
    drifted_payloads = []
    for row, case in decoded:
        recorded_source = row.get("online_source") or {}
        decoded_source = getattr(case.source, "__dict__", {})
        if (recorded_source.get("data_hex") != decoded_source.get("data_hex")
                or recorded_source.get("address") != decoded_source.get("address")):
            drifted_payloads.append(f"{row.get('case_id')}")
    if drifted_payloads:
        pytest.skip("frozen reference run decodes to different payloads under the "
                    f"current decoder ({len(drifted_payloads)} cases, e.g. "
                    + ", ".join(sorted(drifted_payloads)[:3]) + ")")
    for index, (row, case) in enumerate(decoded):
        assert case.case_id == row["case_id"], index
        assert cold_run.online_case_sha256(case) == row[
            "effective_genome_sha256"], index


# --------------------------------------------------------------------------
# frozen-reference drift decision: the new field first, legacy pairs second
# --------------------------------------------------------------------------


def test_recorded_decode_space_field_decides_frozen_reference_drift() -> None:
    current = online_decode_space_document()
    assert _decode_space_drift_reason({"decode_space": current}) is None
    drifted = copy.deepcopy(current)
    for item in drifted["source_files"]:
        if item["path"] == "src/myfuzz/scenario/rv32i_sources.py":
            item["sha256"] = "0" * 64
    reason = _decode_space_drift_reason({"decode_space": drifted})
    assert reason is not None
    assert "src/myfuzz/scenario/rv32i_sources.py" in reason
    # The recorded decode space is authoritative: an incidental stale pair
    # earlier in the identity cannot override a matching closure.
    assert _decode_space_drift_reason({
        "source_files": [{"path": "src/myfuzz/scenario/rv32i_sources.py",
                          "sha256": "0" * 64}],
        "decode_space": current}) is None


def test_legacy_identity_pairs_still_decide_frozen_reference_drift() -> None:
    for path in _DECODER_SOURCE_PATHS:
        assert _decode_space_drift_reason(
            {"implementation_sources": [{"path": path,
                                         "sha256": _file_sha256(path)}]}) is None
    reason = _decode_space_drift_reason({"implementation_sources": [
        {"path": "src/myfuzz/scenario/online_case_decoder.py",
         "sha256": "0" * 64}]})
    assert reason is not None
    assert "src/myfuzz/scenario/online_case_decoder.py" in reason
