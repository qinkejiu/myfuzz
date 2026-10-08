#!/usr/bin/env python3
"""Run one fresh Ibex + dual PULP GPIO session per frozen continuous case.

Why this exists
---------------
``scripts/bench_ibex_pulp_cold_start.py`` measures startup cost, but it writes a
single ``ibex_pulp_cold_baseline.v1`` document and no run directory, so
``myfuzz.scenario.paired_efficiency.compare_runs`` cannot pair it with the
continuous campaign directory. This entry point produces that run directory:

* for every saved case of the continuous run, in the saved order, it starts a
  **fresh process, fresh runtime and fresh RTL session** and feeds exactly that
  case's frozen eight-byte record as the RFuzz seed input, so the per-case
  receipt is written by the frozen live writer
  (``myfuzz.integration.scenario_rfuzz_live``) with the same row schema;
* the recorded ``online_weights`` of that case are injected as the decode hints,
  and the frozen input prefix (cases ``0..index-1``) is replayed through the
  fresh decoder before the case runs. Both are required for the same
  ``case_id``/``effective_genome_sha256``: the decoder's case sequence number and
  CPU instruction cursor are derived from that prefix, and the path/source
  selection is weighted by the recorded hints;
* the case's own produced receipt is compared against the saved row, and every
  comparison result is recorded instead of assumed.

Artifacts written to ``--output``
---------------------------------
``receipts.jsonl``
    One row per verified case, copied verbatim from the per-case run directory,
    in the continuous run's order.
``report.json``
    Aggregate with ``effective_search_seconds`` and ``elapsed_seconds`` summed
    over the per-case sessions, plus the measured decoder manifest digest and the
    inherited global mutation seed.
``online_plan.json``
    A per-case plan **index** (hashes of each case's frozen session plan). It is
    deliberately not a single session plan: every case ran in its own session.
``online_run_identity.json``
    The comparison-relevant identity envelope. Source files, decoder manifest,
    component identity and targets digest are measured on this machine right
    now; the campaign budget/seed and the frozen plan identity are inherited from
    the continuous run and flagged as such inside ``cold_start``.
``cold_start.json``
    ``ibex_pulp_cold_baseline.v1`` with per-case ``init_seconds``,
    ``total_seconds`` and ``raw_hex``, the same document schema the frozen
    producer writes.
``gate_commands.json``
    Every command actually executed, its return code and its captured output
    tail, plus the in-process API call recorded by each case worker.
``cases/<index>/``
    The frozen per-case run directory (receipts, report, plan, trace, identity,
    ``case_result.json``, ``case_process.log``). Add ``--discard-case-dirs`` to
    drop verified case directories after aggregation; failed cases are always
    kept.

Exit codes
----------
``0``  every requested case ran and its receipt verified;
``2``  unusable input (missing directory/receipts/identity/raw input, bad budget);
``3``  at least one case failed, or an aggregated artifact was malformed;
``1``  any other error.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import asdict
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
for entry in (SRC.as_posix(), SCRIPTS.as_posix()):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from bench_ibex_pulp_cold_start import load_records  # noqa: E402


SCHEMA_VERSION = "first_step_cold_start_run_report.v1"
CASE_SCHEMA_VERSION = "first_step_cold_start_case.v1"
GATE_SCHEMA_VERSION = "first_step_cold_start_gate_commands.v1"
PLAN_INDEX_SCHEMA_VERSION = "first_step_cold_start_plan_index.v1"
COLD_BASELINE_SCHEMA_VERSION = "ibex_pulp_cold_baseline.v1"
COLD_BASELINE_SCOPE = "startup_cost_only_not_coverage_equivalence"
EXECUTION_MODE = "online_cases_per_case_cold_start"

RECEIPTS_NAME = "receipts.jsonl"
REPORT_NAME = "report.json"
IDENTITY_NAME = "online_run_identity.json"
SESSION_MANIFEST_NAME = "online_session_manifest.json"
PLAN_NAME = "online_plan.json"
COLD_BASELINE_NAME = "cold_start.json"
GATE_COMMANDS_NAME = "gate_commands.json"
CASE_RESULT_NAME = "case_result.json"
CASE_PROCESS_LOG_NAME = "case_process.log"
CASE_DIRECTORY_NAME = "cases"

PER_CASE_MAX_TESTS = 1
DEFAULT_MAX_CASES = 30
DEFAULT_SECONDS = 5.0
DEFAULT_CASE_TIMEOUT_SECONDS = 1800.0
MAX_SECONDS = 3600.0
OUTPUT_TAIL_CHARS = 4000

MODE_FLAGS = ("cpu_retirement", "native_irq_receipts", "gpio_consumption")
TIMING_SPLIT_REASON = (
    "a per-case live restart does not separate decode, submit and finish into the "
    "frozen cold baseline's three phases; the frozen per-case "
    "online_phase_timing_seconds is copied verbatim into each case entry instead, "
    "so these three stay null rather than 0")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INPUT_ERROR = 2
EXIT_CASE_FAILURE = 3


class ColdStartRunError(RuntimeError):
    """Base class for this entry point's failures."""


class ColdStartInputError(ColdStartRunError):
    """The continuous run directory or the budget cannot be used."""


class ColdStartCaseError(ColdStartRunError):
    """A produced per-case artifact cannot be trusted."""


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def canonical_json(value: object) -> bytes:
    """Byte-identical to the frozen writers' canonical JSON encoding."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, document: object) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True, allow_nan=False) + "\n",
                    encoding="utf-8")
    return path


def _read_json_object(path: Path) -> dict | None:
    path = Path(path)
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ColdStartInputError(f"invalid JSON in {path}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise ColdStartInputError(f"{path} is not a JSON object")
    return document


def _finite_non_negative(value: object) -> float | None:
    if type(value) is int or type(value) is float:
        number = float(value)
        if math.isfinite(number) and number >= 0:
            return number
    return None


def _sum_or_none(values: list[float | None]) -> float | None:
    """Sum the measured samples; ``None`` when nothing was measured."""
    measured = [value for value in values if value is not None]
    return sum(measured) if measured else None


def _tail(text: str | None, limit: int = OUTPUT_TAIL_CHARS) -> str | None:
    if text is None:
        return None
    return text[-limit:]


def frozen_receipt_keys() -> tuple[str, ...]:
    """The exact ``receipts.jsonl`` row keys of the frozen live writer.

    The keys are read from ``persist_receipt`` in
    ``myfuzz.integration.scenario_rfuzz_live`` instead of being duplicated here,
    so a schema change in the writer is picked up (or fails loudly) rather than
    silently producing a cold directory that cannot be paired.
    """
    from myfuzz.integration import scenario_rfuzz_live

    source = Path(scenario_rfuzz_live.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next((node for node in ast.walk(tree)
                     if isinstance(node, ast.FunctionDef)
                     and node.name == "persist_receipt"), None)
    if function is None:
        raise ColdStartRunError(
            "the frozen live writer has no persist_receipt function, so the "
            "receipt row schema cannot be pinned")
    for node in ast.walk(function):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "write"):
            continue
        for inner in ast.walk(node):
            if not (isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "dumps"):
                continue
            for argument in inner.args:
                if not isinstance(argument, ast.Dict):
                    continue
                keys = tuple(key.value for key in argument.keys)
                if keys and all(isinstance(key, str) for key in keys):
                    return keys
    raise ColdStartRunError(
        "the frozen live writer's receipt dictionary was not found, so the "
        "receipt row schema cannot be pinned")


def online_case_sha256(case: object) -> str:
    """The frozen effective-genome digest of one decoded online case."""
    from myfuzz.scenario.session_runtime import OnlineInstruction

    document = asdict(case)
    source = document.get("source")
    if not isinstance(source, dict):
        raise ColdStartRunError("decoded case has no source document")
    source["kind"] = ("instruction" if isinstance(case.source, OnlineInstruction)
                      else "source_event")
    return _sha256_bytes(json.dumps(document, sort_keys=True,
                                    separators=(",", ":"), ensure_ascii=False,
                                    allow_nan=False).encode("utf-8"))


def _decode_position(decoder: object, row: dict) -> object:
    raw = bytes.fromhex(row["online_raw_records_hex"][0])
    return decoder.decode(raw, coverage_hints=dict(row["online_weights"]))


def replay_decoder_prefix(decoder: object, cases: list[dict], index: int) -> None:
    """Advance a fresh decoder to the frozen pre-state of case ``index``.

    The decoder state that determines ``case_id`` (its sequence number), the
    CPU instruction cursor and therefore the effective genome digest is a pure
    function of the recorded ``(raw, online_weights)`` prefix. Replaying it
    touches no RTL and no session.
    """
    if type(index) is not int or index < 0:
        raise ColdStartInputError("case index must be a non-negative integer")
    for position in range(index):
        decoder.commit(_decode_position(decoder, cases[position]))


def _replay_prefix_verified(decoder: object, cases: list[dict], index: int) -> None:
    """Replay the prefix and prove it reproduces the saved per-case identity."""
    for position in range(index):
        row = cases[position]
        case = _decode_position(decoder, row)
        digest = online_case_sha256(case)
        if (case.case_id != row.get("case_id")
                or digest != row.get("effective_genome_sha256")):
            raise ColdStartCaseError(
                f"prefix case {position} is not reproducible from the saved "
                f"inputs: decoded case_id {case.case_id!r} vs saved "
                f"{row.get('case_id')!r}, decoded effective_genome_sha256 "
                f"{digest} vs saved {row.get('effective_genome_sha256')!r}")
        decoder.commit(case)


# --------------------------------------------------------------------------
# continuous run directory reading
# --------------------------------------------------------------------------


def _continuous_identity(continuous_run_dir: Path) -> dict:
    document = _read_json_object(Path(continuous_run_dir) / IDENTITY_NAME)
    if document is None:
        raise ColdStartInputError(
            f"continuous run directory has no {IDENTITY_NAME}: "
            f"{Path(continuous_run_dir) / IDENTITY_NAME}")
    identity = document.get("identity")
    if not isinstance(identity, dict):
        raise ColdStartInputError(
            f"{Path(continuous_run_dir) / IDENTITY_NAME} has no identity object")
    return document


def _run_config(identity_document: dict) -> dict:
    identity = identity_document.get("identity") or {}
    config = identity.get("run_config")
    return config if isinstance(config, dict) else {}


def _search_seed(continuous_run_dir: Path, identity_document: dict) -> int | None:
    seed = _run_config(identity_document).get("search_seed")
    if type(seed) is int and 0 <= seed < 2 ** 64:
        return seed
    report = _read_json_object(Path(continuous_run_dir) / REPORT_NAME) or {}
    seed = report.get("global_mutation_seed")
    return seed if type(seed) is int and 0 <= seed < 2 ** 64 else None


def _detect_modes(continuous_run_dir: Path) -> dict:
    """Read the continuous session's observation modes from its manifest.

    The manifest keys are the declaration of what the continuous session
    observed; a cold session without the same modes would not produce comparable
    checker evidence.
    """
    path = Path(continuous_run_dir) / SESSION_MANIFEST_NAME
    document = _read_json_object(path)
    if document is None:
        return {"modes": {name: False for name in MODE_FLAGS},
                "source": None,
                "reason": f"{SESSION_MANIFEST_NAME} is absent, so every optional "
                          "observation mode stays off"}
    sessions = ((document.get("runner") or {}).get("sessions")
                if isinstance(document.get("runner"), dict) else None)
    if not isinstance(sessions, dict) or "cpu" not in sessions:
        raise ColdStartInputError(
            f"{path} has no runner.sessions.cpu identity, so the observation "
            "modes of the continuous session cannot be read")
    cpu = (sessions.get("cpu") or {}).get("identity") or {}
    gpio_modes = []
    for component in ("gpio_a", "gpio_b"):
        identity = (sessions.get(component) or {}).get("identity") or {}
        gpio_modes.append("gpio_observation_contract" in identity)
    modes = {
        "cpu_retirement": "cpu_observation_schema_version" in cpu,
        "native_irq_receipts": "cpu_native_irq_receipt_contract" in cpu,
        "gpio_consumption": bool(gpio_modes) and all(gpio_modes),
    }
    if modes["native_irq_receipts"] and not modes["cpu_retirement"]:
        raise ColdStartInputError(
            f"{path} declares native IRQ receipts without an RVFI observation "
            "schema, so the continuous session modes are inconsistent")
    return {"modes": modes, "source": SESSION_MANIFEST_NAME,
            "evidence": {
                "cpu_observation_schema_version":
                    cpu.get("cpu_observation_schema_version"),
                "cpu_native_irq_receipt_contract":
                    "cpu_native_irq_receipt_contract" in cpu,
                "gpio_observation_contracts": gpio_modes,
            },
            "reason": None}


def _load_continuous_window(continuous_run_dir: Path, max_cases: int) -> list[dict]:
    receipts = Path(continuous_run_dir) / RECEIPTS_NAME
    if not receipts.is_file():
        raise ColdStartInputError(
            f"continuous run directory has no {RECEIPTS_NAME}: {receipts}")
    try:
        rows = load_records(receipts, max_cases, allow_short=True)
    except ValueError as exc:
        raise ColdStartInputError(str(exc)) from exc
    if not rows:
        raise ColdStartInputError(f"{receipts} holds no case")
    for index, row in enumerate(rows):
        raw = bytes.fromhex(row["online_raw_records_hex"][0])
        declared = row.get("raw_sha256")
        if declared is not None and declared != _sha256_bytes(raw):
            raise ColdStartInputError(
                f"{receipts}: line {index + 1}: raw_sha256 {declared!r} does not "
                f"match online_raw_records_hex {raw.hex()!r}")
    return rows


def _source_identity_verification(identity_document: dict) -> dict:
    declared = (identity_document.get("identity") or {}).get("source_files")
    declared = declared if isinstance(declared, list) else []
    entries: list[dict] = []
    for entry in declared:
        path = entry.get("path") if isinstance(entry, dict) else None
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not isinstance(digest, str):
            continue
        resolved = Path(path)
        if not resolved.is_absolute():
            resolved = ROOT / path
        current = sha256_file(resolved) if resolved.is_file() else None
        entries.append({"path": path, "declared_sha256": digest,
                        "current_sha256": current,
                        "matches": current == digest})
    drifted = [entry for entry in entries if not entry["matches"]]
    return {
        "declared_count": len(entries),
        "matching_count": len(entries) - len(drifted),
        "drifted": drifted,
        "current_source_files": [{"path": entry["path"],
                                  "sha256": entry["current_sha256"]}
                                 for entry in entries],
    }


# --------------------------------------------------------------------------
# per-case command planning and execution
# --------------------------------------------------------------------------


def planned_case_argv(*, index: int, continuous_run_dir: Path, case_dir: Path,
                      cache_dir: Path | str, client_binary: Path | str,
                      run_id: str, seconds: float, modes: dict,
                      python: str | None = None,
                      script: Path | None = None) -> list[str]:
    argv = [python or sys.executable,
            str(Path(script) if script is not None else Path(__file__).resolve()),
            "case",
            "--continuous-run-dir", str(continuous_run_dir),
            "--index", str(index),
            "--case-dir", str(case_dir),
            "--cache-dir", str(cache_dir),
            "--client-binary", str(client_binary),
            "--run-id", run_id,
            "--seconds", repr(float(seconds))]
    for name in MODE_FLAGS:
        if modes.get(name):
            argv.append("--" + name.replace("_", "-"))
    return argv


def _execute_case_process(argv: list[str], *, cwd: Path, env: dict,
                          timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True,
                          text=True, timeout=timeout, check=False)


def _runtime_measurements(runtime: object) -> dict:
    decoder_document = runtime.decoder.document()
    manifest = runtime.session.manifest_document
    runner = manifest.get("runner") if isinstance(manifest, dict) else None
    targets = [asdict(target) for target in getattr(runtime.executor, "targets", ())]
    return {
        "decoder_manifest_sha256": _sha256_bytes(canonical_json(decoder_document)),
        "component_identity_sha256": (_sha256_bytes(canonical_json(runner))
                                      if isinstance(runner, dict) else None),
        "targets_sha256": (_sha256_bytes(canonical_json(targets))
                           if targets else None),
        "session_manifest_sha256": (_sha256_bytes(canonical_json(manifest))
                                    if isinstance(manifest, dict) else None),
    }


def _default_runtime_factory(**kwargs: object) -> object:
    from myfuzz.integration.ibex_pulp_online import make_ibex_pulp_online_runtime
    return make_ibex_pulp_online_runtime(**kwargs)


def _default_live_runner(**kwargs: object) -> object:
    from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live
    return run_scenario_rfuzz_live(**kwargs)


def _write_case_result(case_dir: Path, document: dict) -> Path:
    """Persist one case result; the directory is only created when needed.

    The frozen live writer owns the creation of a *new* run directory, so this
    must never run before the live call. It is called after the live call or on
    a path where the live call will not happen at all.
    """
    return _write_json(Path(case_dir) / CASE_RESULT_NAME, document)


def _receipt_rows(case_dir: Path, keys: tuple[str, ...]) -> list[dict]:
    path = Path(case_dir) / RECEIPTS_NAME
    if not path.is_file():
        return []
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ColdStartCaseError(
                f"{path}: line {number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(row, dict):
            raise ColdStartCaseError(f"{path}: line {number}: not a JSON object")
        missing = [name for name in keys if name not in row]
        extra = [name for name in row if name not in keys]
        if missing or extra:
            raise ColdStartCaseError(
                f"{path}: line {number}: receipt row schema differs from the frozen "
                f"live writer: missing={missing} unexpected={extra}")
        rows.append(row)
    return rows


def execute_cold_case(*, continuous_run_dir: Path, index: int, case_dir: Path,
                      cache_dir: Path, client_binary: Path, run_id: str,
                      seconds: float, modes: dict | None = None,
                      runtime_factory=None, live_runner=None,
                      clock=time.monotonic) -> dict:
    """Run exactly one frozen case in a brand new session.

    Returns the case result document; failures are recorded in its ``error``
    field with ``exit_code`` 3 instead of being raised, so the produced evidence
    always survives. Unusable input raises :class:`ColdStartInputError`.
    """
    continuous_run_dir = Path(continuous_run_dir)
    case_dir = Path(case_dir)
    cache_dir = Path(cache_dir)
    client_binary = Path(client_binary)
    modes = {name: bool((modes or {}).get(name)) for name in MODE_FLAGS}
    if type(index) is not int or index < 0:
        raise ColdStartInputError("case index must be a non-negative integer")
    if type(seconds) is not float and type(seconds) is not int:
        raise ColdStartInputError("--seconds must be a number")
    if not 0 < float(seconds) <= MAX_SECONDS:
        raise ColdStartInputError(
            f"--seconds must be in (0, {MAX_SECONDS:g}]")
    identity_document = _continuous_identity(continuous_run_dir)
    cases = _load_continuous_window(continuous_run_dir, index + 1)
    if len(cases) <= index:
        raise ColdStartInputError(
            f"continuous run {continuous_run_dir} has only {len(cases)} saved "
            f"cases, so case index {index} cannot be replayed")
    frozen = cases[index]
    raw = bytes.fromhex(frozen["online_raw_records_hex"][0])
    weights = dict(frozen["online_weights"])
    search_seed = _search_seed(continuous_run_dir, identity_document)
    client_sha256 = sha256_file(client_binary) if client_binary.is_file() else None
    runtime_factory = runtime_factory or _default_runtime_factory
    live_runner = live_runner or _default_live_runner

    result: dict = {
        "schema_version": CASE_SCHEMA_VERSION,
        "index": index,
        "case_dir": str(case_dir),
        "run_id": run_id,
        "raw_hex": raw.hex(),
        "raw_sha256": _sha256_bytes(raw),
        "saved_case_id": frozen.get("case_id"),
        "saved_effective_genome_sha256": frozen.get("effective_genome_sha256"),
        "saved_path_id": frozen.get("path_id"),
        "saved_applied_sources": frozen.get("applied_sources"),
        "saved_status": frozen.get("status"),
        "saved_online_weights": weights,
        "search_seed": search_seed,
        "client_binary": {"path": str(client_binary), "sha256": client_sha256},
        "modes": modes,
        "receipt_keys": None,
        "receipt_rows": 0,
        "receipt_schema_matches_frozen_writer": None,
        "case_id": None,
        "effective_genome_sha256": None,
        "path_id": None,
        "applied_sources": None,
        "status": None,
        "coverage_hex": None,
        "local_ticks": None,
        "violations": None,
        "online_phase_timing_seconds": None,
        "raw_match": None,
        "genome_match": None,
        "path_match": None,
        "source_match": None,
        "status_match": None,
        "decoder_manifest_sha256": None,
        "component_identity_sha256": None,
        "targets_sha256": None,
        "session_manifest_sha256": None,
        "init_seconds": None,
        "prefix_replay_seconds": None,
        "run_seconds": None,
        "total_seconds": None,
        "effective_search_seconds": None,
        "elapsed_seconds": None,
        "runtime_call": {"cache_dir": str(cache_dir), "run_id": run_id,
                         "modes": modes},
        "live_call": None,
        "timing_split_reason": TIMING_SPLIT_REASON,
        "error": None,
        "exit_code": EXIT_OK,
    }
    started = clock()
    runtime = None
    live_called = False
    try:
        runtime = runtime_factory(cache_dir=cache_dir, run_id=run_id, **modes)
        after_init = clock()
        result.update(_runtime_measurements(runtime))
        _replay_prefix_verified(runtime.decoder, cases, index)
        # Decoding the target case before the live call proves that this fresh
        # decoder still reproduces the saved case identity, and fails before RTL
        # time is spent when it does not. Decoding is pure; re-decoding the same
        # raw inside the live batch yields an equal case.
        target_case = _decode_position(runtime.decoder, frozen)
        target_digest = online_case_sha256(target_case)
        result["decoded_case_id"] = target_case.case_id
        result["decoded_effective_genome_sha256"] = target_digest
        result["decode_reproduces_saved_case"] = (
            target_case.case_id == frozen.get("case_id")
            and target_digest == frozen.get("effective_genome_sha256"))
        if not result["decode_reproduces_saved_case"]:
            raise ColdStartCaseError(
                f"the fresh decoder does not reproduce the saved case: decoded "
                f"{target_case.case_id!r}/{target_digest} vs saved "
                f"{frozen.get('case_id')!r}/{frozen.get('effective_genome_sha256')!r}")
        after_prefix = clock()
        # The recorded per-case weights are the decode hints the continuous
        # session used for this case; without them the path/source selection
        # would follow this fresh session's default weights and decode a
        # different genome.
        runtime.executor._online_weights = lambda: dict(weights)
        live_kwargs = {"executor": runtime.executor, "client_binary": client_binary,
                       "output_dir": case_dir, "duration_seconds": float(seconds),
                       "seed_records": (raw,), "max_tests": PER_CASE_MAX_TESTS,
                       "search_seed": search_seed, "max_runs_per_batch": 1}
        live_called = True
        live_result = live_runner(**live_kwargs)
        after_run = clock()
        result["live_call"] = {
            "entrypoint": "myfuzz.integration.scenario_rfuzz_live."
                          "run_scenario_rfuzz_live",
            "client_binary": str(client_binary),
            "output_dir": str(case_dir),
            "duration_seconds": float(seconds),
            "seed_records_hex": [raw.hex()],
            "max_tests": PER_CASE_MAX_TESTS,
            "search_seed": search_seed,
            "max_runs_per_batch": 1,
            "tests": getattr(live_result, "tests", None),
            "elapsed_seconds": _finite_non_negative(
                getattr(live_result, "elapsed_seconds", None)),
            "effective_search_seconds": _finite_non_negative(
                getattr(live_result, "effective_search_seconds", None)),
        }
        result["init_seconds"] = after_init - started
        result["prefix_replay_seconds"] = after_prefix - after_init
        result["run_seconds"] = after_run - after_prefix
        result["total_seconds"] = after_run - started
        result["effective_search_seconds"] = result["live_call"][
            "effective_search_seconds"]
        result["elapsed_seconds"] = result["live_call"]["elapsed_seconds"]
        keys = frozen_receipt_keys()
        result["receipt_keys"] = list(keys)
        rows = _receipt_rows(case_dir, keys)
        result["receipt_rows"] = len(rows)
        result["receipt_schema_matches_frozen_writer"] = True
        if len(rows) != PER_CASE_MAX_TESTS:
            raise ColdStartCaseError(
                f"the per-case session wrote {len(rows)} receipt rows, expected "
                f"{PER_CASE_MAX_TESTS}; the frozen seed case was not the only case")
        produced = rows[0]
        result.update({
            "case_id": produced.get("case_id"),
            "effective_genome_sha256": produced.get("effective_genome_sha256"),
            "path_id": produced.get("path_id"),
            "applied_sources": produced.get("applied_sources"),
            "status": produced.get("status"),
            "coverage_hex": produced.get("coverage_hex"),
            "local_ticks": produced.get("local_ticks"),
            "violations": produced.get("violations"),
            "online_phase_timing_seconds":
                produced.get("online_phase_timing_seconds"),
            "raw_match": produced.get("raw_sha256") == _sha256_bytes(raw),
            "genome_match": produced.get("effective_genome_sha256")
                            == frozen.get("effective_genome_sha256"),
            "path_match": produced.get("path_id") == frozen.get("path_id"),
            "source_match": produced.get("applied_sources")
                            == frozen.get("applied_sources"),
            "status_match": produced.get("status") == frozen.get("status"),
        })
        if result["raw_match"] is not True:
            # The frozen input was not the input that ran: the row cannot be
            # published as a paired case at all.
            raise ColdStartCaseError(
                f"the cold session receipt raw_sha256 {produced.get('raw_sha256')!r} "
                f"is not the frozen continuous input {result['raw_sha256']!r}")
        mismatches = [name for name in ("genome_match", "path_match", "source_match")
                      if result[name] is not True]
        if mismatches:
            # Same input, different case identity: the row is still evidence of
            # the frozen input and is published, but the run fails loudly and the
            # mismatch is recorded for the paired report.
            result["verification_error"] = (
                "the cold session did not reproduce the frozen case: "
                + ", ".join(
                    f"{name}={result[name]!r} (produced {result.get(name[:-6])!r} "
                    f"vs saved {frozen.get(_saved_field(name))!r})"
                    for name in mismatches))
            result["exit_code"] = EXIT_CASE_FAILURE
        elif result["status_match"] is not True:
            result["status_observation"] = (
                f"the frozen input ran to status {result['status']!r} instead of "
                f"{frozen.get('status')!r}; this is an observed outcome difference, "
                "not a broken case artifact")
    except ColdStartInputError:
        if runtime is not None and not live_called:
            try:
                runtime.session.finish()
            except Exception:
                pass
        raise
    except BaseException as exc:  # noqa: BLE001 - recorded, never swallowed
        if runtime is not None and not live_called:
            try:
                runtime.session.finish()
            except Exception:
                pass
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["exit_code"] = EXIT_CASE_FAILURE
    _write_case_result(case_dir, result)
    return result


def _saved_field(verdict: str) -> str:
    return {"raw_match": "raw_sha256", "genome_match": "effective_genome_sha256",
            "path_match": "path_id", "source_match": "applied_sources"}[verdict]


# --------------------------------------------------------------------------
# aggregation
# --------------------------------------------------------------------------


def _aggregate_case_rows(case_index: int, case_dir: Path,
                         keys: tuple[str, ...]) -> list[dict]:
    rows = _receipt_rows(case_dir, keys)
    if len(rows) != 1:
        raise ColdStartCaseError(
            f"case {case_index} directory {case_dir} holds {len(rows)} receipt "
            f"rows, expected 1")
    return rows


def _cold_baseline_case(result: dict, frozen: dict) -> dict:
    return {
        "index": result["index"],
        "raw_hex": result["raw_hex"],
        "original_status": frozen.get("status"),
        "cold_status": ("error" if result.get("error") is not None
                        else result.get("status")),
        "original_source": (frozen.get("applied_sources") or [None])[0],
        "cold_source": (result.get("applied_sources") or [None])[0],
        "source_compatible": result.get("source_match") is True,
        "original_path": frozen.get("path_id"),
        "cold_path": result.get("path_id"),
        "path_compatible": result.get("path_match") is True,
        "init_seconds": result.get("init_seconds"),
        "decode_seconds": None,
        "execute_seconds": None,
        "finish_seconds": None,
        "total_seconds": result.get("total_seconds"),
        "error": result.get("error"),
        "verification_error": result.get("verification_error"),
        "timing_split_reason": TIMING_SPLIT_REASON,
        "original_raw_sha256": frozen.get("raw_sha256"),
        "cold_raw_sha256": result.get("raw_sha256"),
        "raw_compatible": result.get("raw_match") is True,
        "original_effective_genome_sha256": frozen.get("effective_genome_sha256"),
        "cold_effective_genome_sha256": result.get("effective_genome_sha256"),
        "genome_compatible": result.get("genome_match") is True,
        "status_compatible": result.get("status_match") is True,
        "case_id": result.get("case_id"),
        "case_dir": result.get("case_dir"),
        "case_command_returncode": result.get("case_command_returncode"),
        "prefix_replay_seconds": result.get("prefix_replay_seconds"),
        "run_seconds": result.get("run_seconds"),
        "effective_search_seconds": result.get("effective_search_seconds"),
        "elapsed_seconds": result.get("elapsed_seconds"),
        "case_report_effective_search_seconds":
            result.get("case_report_effective_search_seconds"),
        "case_report_elapsed_seconds": result.get("case_report_elapsed_seconds"),
        "finalization_timing_seconds": result.get("finalization_timing_seconds"),
        "online_phase_timing_seconds": result.get("online_phase_timing_seconds"),
    }


def _common_measurement(results: list[dict], name: str) -> tuple[object, list[dict]]:
    """One value shared by every case, else null plus the conflicts."""
    values = [result.get(name) for result in results if result.get(name) is not None]
    conflicts = []
    if not values:
        return None, conflicts
    first = values[0]
    for result in results:
        value = result.get(name)
        if value is not None and canonical_json(value) != canonical_json(first):
            conflicts.append({"index": result.get("index"), "value": value})
    if conflicts:
        return None, conflicts
    return first, conflicts


def _build_cold_identity(*, continuous_run_dir: Path, identity_document: dict,
                         run_id: str, measurement: dict, search_seed: int | None,
                         client_binary: Path, client_sha256: str | None,
                         source_verification: dict, case_count: int,
                         verified_count: int, mode_detection: dict) -> dict:
    inherited = identity_document.get("identity") or {}
    inherited_config = dict(_run_config(identity_document))
    inherited_config["run_id"] = run_id
    inherited_genome = (inherited.get("genome")
                        if isinstance(inherited.get("genome"), dict) else {})
    inherited_toolchain = (inherited.get("toolchain")
                           if isinstance(inherited.get("toolchain"), dict) else {})
    measured_source_files = source_verification["current_source_files"]
    identity = {
        "schema_version": "scenario_online_run_identity.v1",
        "execution_mode": EXECUTION_MODE,
        "run_config": inherited_config,
        "source_files": measured_source_files,
        "session": {"component_identity_sha256":
                    measurement.get("component_identity_sha256"),
                    "manifest_file": None, "manifest_sha256": None},
        "components": {"identity_sha256":
                       measurement.get("component_identity_sha256")},
        "genome": {
            "format": "frozen_continuous_session_plan",
            "plan_file": PLAN_NAME,
            "plan_sha256": inherited_genome.get("plan_sha256"),
            "plan_identity_source": f"{IDENTITY_NAME}:identity.genome.plan_sha256",
            "semantics": ("the frozen continuous admitted prefix declared by "
                          f"{continuous_run_dir}, re-executed one case per fresh "
                          "session; the aggregate plan file is a per-case index"),
        },
        "feedback": {"interaction_schema": "interaction_feedback.v1",
                     "coverage_semantics": "observed real RTL output predicates",
                     "targets_file": "targets.json",
                     "targets_sha256": measurement.get("targets_sha256"),
                     "targets_sha256_source": "measured from the fresh executor"},
        "decoder_manifest_sha256": measurement.get("decoder_manifest_sha256"),
        "toolchain": {
            "client": {"basename": Path(client_binary).name,
                       "binary_sha256": client_sha256,
                       "sha256_source": "measured from --client-binary"},
            "inherited_client": inherited_toolchain.get("client"),
        },
        "cold_start": {
            "per_case_sessions": case_count,
            "verified_case_sessions": verified_count,
            "per_case_max_tests": PER_CASE_MAX_TESTS,
            "continuous_run_dir": str(continuous_run_dir),
            "continuous_identity_sha256": identity_document.get("sha256"),
            "inherited_declarations": ["run_config", "genome.plan_sha256"],
            "measured_declarations": ["source_files", "decoder_manifest_sha256",
                                      "session.component_identity_sha256",
                                      "feedback.targets_sha256",
                                      "toolchain.client.binary_sha256"],
            "mode_detection": mode_detection,
            "search_seed": search_seed,
            "source_identity_verification": {
                "declared_count": source_verification["declared_count"],
                "matching_count": source_verification["matching_count"],
                "drifted_paths": [entry["path"] for entry
                                  in source_verification["drifted"]],
            },
        },
    }
    return {"schema_version": "scenario_online_run_identity_envelope.v1",
            "sha256": _sha256_bytes(canonical_json(identity)),
            "identity": identity}


def run_cold_start(*, continuous_run_dir: Path, output_dir: Path,
                   cache_dir: Path | None = None,
                   client_binary: Path | None = None, max_cases: int,
                   seconds: float = DEFAULT_SECONDS, run_id: str | None = None,
                   modes: dict | None = None, dry_run: bool = False,
                   keep_case_dirs: bool = True,
                   case_timeout_seconds: float = DEFAULT_CASE_TIMEOUT_SECONDS,
                   execute_case_process=None, clock=time.monotonic,
                   parent_argv: list[str] | None = None) -> dict:
    """Execute one fresh session per frozen case and aggregate the artifacts."""
    continuous_run_dir = Path(continuous_run_dir)
    output_dir = Path(output_dir)
    if type(max_cases) is not int or max_cases < 1:
        raise ColdStartInputError("--max-cases must be at least 1")
    if type(seconds) is not float and type(seconds) is not int:
        raise ColdStartInputError("--seconds must be a number")
    if not 0 < float(seconds) <= MAX_SECONDS:
        raise ColdStartInputError(f"--seconds must be in (0, {MAX_SECONDS:g}]")
    if not continuous_run_dir.is_dir():
        raise ColdStartInputError(
            f"continuous run directory does not exist: {continuous_run_dir}")
    window = _load_continuous_window(continuous_run_dir, max_cases)
    identity_document = _continuous_identity(continuous_run_dir)
    detected = _detect_modes(continuous_run_dir)
    forced = {name: bool((modes or {}).get(name, False)) for name in MODE_FLAGS}
    effective_modes = {name: bool(detected["modes"][name] or forced[name])
                       for name in MODE_FLAGS}
    detected = dict(detected, forced_flags=forced, modes=effective_modes)
    search_seed = _search_seed(continuous_run_dir, identity_document)
    continuous_config = _run_config(identity_document)
    if run_id is None:
        base = continuous_config.get("run_id")
        run_id = f"{base}-cold-start" if isinstance(base, str) and base else \
            "first-step-cold-start"

    missing_options = [name for name, value in (("--client-binary", client_binary),
                                                ("--cache-dir", cache_dir))
                       if value is None]
    case_commands = []
    for index in range(len(window)):
        case_dir = output_dir / CASE_DIRECTORY_NAME / f"{index:04d}"
        case_commands.append(planned_case_argv(
            index=index, continuous_run_dir=continuous_run_dir, case_dir=case_dir,
            cache_dir=(cache_dir if cache_dir is not None else "<cache-dir>"),
            client_binary=(client_binary if client_binary is not None
                           else "<client-binary>"),
            run_id=f"{run_id}-case-{index}", seconds=seconds,
            modes=effective_modes))

    if dry_run:
        for index, argv in enumerate(case_commands):
            print(json.dumps({"index": index, "argv": argv,
                              "command": shlex.join(argv)}, sort_keys=True))
        return {
            "dry_run": True,
            "case_count": len(window),
            "window_case_count": len(window),
            "requested_max_cases": max_cases,
            "output_dir": str(output_dir),
            "created": False,
            "run_id": run_id,
            "modes": effective_modes,
            "client_binary": None if client_binary is None else str(client_binary),
            "cache_dir": None if cache_dir is None else str(cache_dir),
            "missing_required_options": missing_options,
            "output_dir_exists_at_plan_time": (output_dir.exists()
                                               or output_dir.is_symlink()),
            "exit_code": EXIT_OK,
        }
    if output_dir.exists() or output_dir.is_symlink():
        raise ColdStartInputError(f"output directory must be new: {output_dir}")
    if missing_options:
        raise ColdStartInputError(
            "a real cold-start run requires " + " and ".join(missing_options)
            + "; only --dry-run can plan without them")
    if not Path(client_binary).is_file():
        raise ColdStartInputError(
            f"--client-binary is not a file: {client_binary}")
    # The RTL factory creates its build cache on demand, exactly as the frozen
    # campaign entry point allows; whether it existed is recorded instead of
    # being enforced.
    cache_dir_existed = Path(cache_dir).is_dir()

    started = clock()
    output_dir.mkdir(parents=True)
    keys = frozen_receipt_keys()
    client_sha256 = sha256_file(client_binary)
    source_verification = _source_identity_verification(identity_document)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [SRC.as_posix(), environment["PYTHONPATH"]] if environment.get("PYTHONPATH")
        else [SRC.as_posix()])
    runner = execute_case_process or _execute_case_process
    gate_commands: list[dict] = []
    results: list[dict] = []
    receipt_lines: list[str] = []
    published_statuses: dict[str, int] = {}

    def write_gate() -> None:
        _write_json(output_dir / GATE_COMMANDS_NAME, {
            "schema_version": GATE_SCHEMA_VERSION,
            "started_by": {
                "tool": "scripts/run_first_step_cold_start_run.py",
                "command_entrypoint": str(Path(__file__).resolve()),
                "parent_argv": list(parent_argv or sys.argv),
                "python": sys.executable,
                "cwd": str(Path.cwd()),
                "case_command_cwd": str(ROOT),
                "output_dir": str(output_dir),
                "run_id": run_id,
                "executed_entrypoints": [
                    "myfuzz.integration.ibex_pulp_online.make_ibex_pulp_online_runtime",
                    "myfuzz.integration.scenario_rfuzz_live.run_scenario_rfuzz_live"],
            },
            "continuous_run_dir": str(continuous_run_dir),
            "cache_dir": str(cache_dir),
            "cache_dir_existed_at_plan_time": cache_dir_existed,
            "client_binary": {"path": str(client_binary), "sha256": client_sha256},
            "modes": effective_modes,
            "case_commands": list(gate_commands),
            "case_failure_count": sum(1 for result in results
                                      if result.get("error") is not None),
        })

    for index, argv in enumerate(case_commands):
        case_dir = output_dir / CASE_DIRECTORY_NAME / f"{index:04d}"
        case_started = clock()
        returncode = None
        timed_out = False
        stdout = stderr = ""
        try:
            completed = runner(argv, cwd=ROOT, env=environment,
                               timeout=case_timeout_seconds)
            returncode = completed.returncode
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (
                exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (
                exc.stderr or "")
        except OSError as exc:
            stderr = f"{type(exc).__name__}: {exc}"
        case_ended = clock()
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / CASE_PROCESS_LOG_NAME).write_text(
            (stdout or "") + "\n--- stderr ---\n" + (stderr or ""),
            encoding="utf-8")
        result = None
        result_path = case_dir / CASE_RESULT_NAME
        if result_path.is_file():
            try:
                result = json.loads(result_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ColdStartCaseError(
                    f"case {index} wrote an invalid {CASE_RESULT_NAME}: "
                    f"{exc.msg}") from exc
        if not isinstance(result, dict):
            result = {"schema_version": CASE_SCHEMA_VERSION, "index": index,
                      "case_dir": str(case_dir), "receipt_rows": 0,
                      "error": (f"case worker wrote no {CASE_RESULT_NAME} "
                                f"(returncode {returncode})"),
                      "exit_code": EXIT_CASE_FAILURE}
        result["case_command_returncode"] = returncode
        result["case_command_timed_out"] = timed_out
        if timed_out:
            result["error"] = (f"case command timed out after "
                               f"{case_timeout_seconds:g}s")
            result["exit_code"] = EXIT_CASE_FAILURE
        elif returncode != 0 and not result.get("error"):
            result["error"] = (f"case command exited {returncode}: "
                               + (stderr.strip().splitlines()[-1] if stderr.strip()
                                  else "no stderr"))
            result["exit_code"] = EXIT_CASE_FAILURE
        results.append(result)
        if result.get("error") is None and result.get("raw_match") is not True:
            # A published row must be the frozen input. The worker reports the
            # comparison, but the aggregator re-enforces it so a worker change
            # cannot silently publish a different input.
            result["error"] = (
                "case result does not prove the frozen raw input ran "
                f"(raw_match={result.get('raw_match')!r})")
            result["exit_code"] = EXIT_CASE_FAILURE
        identity_mismatch = [name for name in ("genome_match", "path_match",
                                               "source_match")
                             if result.get(name) is False]
        if result.get("error") is None and identity_mismatch:
            # The row stays published: it is real evidence of the frozen input
            # and the paired report counts the mismatch per field.
            result.setdefault(
                "verification_error",
                "the case result does not reproduce the frozen case identity: "
                + ", ".join(identity_mismatch))
            result["exit_code"] = EXIT_CASE_FAILURE
        published = result.get("error") is None
        rows: list[dict] = []
        if published:
            lines = [line for line in
                     (case_dir / RECEIPTS_NAME).read_text(
                         encoding="utf-8").splitlines() if line.strip()]
            rows = _aggregate_case_rows(index, case_dir, keys)
            receipt_lines.extend(lines)
            for row in rows:
                if row.get("raw_sha256") != _sha256_bytes(
                        bytes.fromhex(window[index]["online_raw_records_hex"][0])):
                    raise ColdStartCaseError(
                        f"case {index} receipt raw_sha256 {row.get('raw_sha256')!r} "
                        "is not the frozen continuous input")
                status = row.get("status")
                if not isinstance(status, str):
                    raise ColdStartCaseError(
                        f"case {index} receipt row has no string status: "
                        f"{status!r}")
                published_statuses[status] = published_statuses.get(status, 0) + 1
            case_report = _read_json_object(case_dir / REPORT_NAME) or {}
            result["case_report_effective_search_seconds"] = _finite_non_negative(
                case_report.get("effective_search_seconds"))
            result["case_report_elapsed_seconds"] = _finite_non_negative(
                case_report.get("elapsed_seconds"))
            timing = case_report.get("finalization_timing_seconds")
            if isinstance(timing, dict) and timing and all(
                    _finite_non_negative(value) is not None
                    for value in timing.values()):
                result["finalization_timing_seconds"] = {
                    name: float(value) for name, value in timing.items()}
        gate_commands.append({
            "index": index,
            "argv": list(argv),
            "command": shlex.join(argv),
            "case_dir": str(case_dir),
            "returncode": returncode,
            "timed_out": timed_out,
            "duration_seconds": case_ended - case_started,
            "published_receipt_rows": len(rows),
            "raw_hex": window[index]["online_raw_records_hex"][0],
            "raw_match": result.get("raw_match"),
            "genome_match": result.get("genome_match"),
            "path_match": result.get("path_match"),
            "source_match": result.get("source_match"),
            "status_match": result.get("status_match"),
            "init_seconds": result.get("init_seconds"),
            "total_seconds": result.get("total_seconds"),
            "error": result.get("error"),
            "verification_error": result.get("verification_error"),
            "stdout_tail": _tail(stdout),
            "stderr_tail": _tail(stderr),
        })
        write_gate()

    (output_dir / RECEIPTS_NAME).write_text(
        "".join(line + "\n" for line in receipt_lines), encoding="utf-8")

    published_results = [result for result in results
                         if result.get("error") is None]
    verified_results = [result for result in published_results
                        if result.get("verification_error") is None]
    for result in published_results:
        result["verified"] = result.get("verification_error") is None
    measurement = {}
    conflicts = {}
    for name in ("decoder_manifest_sha256", "component_identity_sha256",
                 "targets_sha256"):
        value, mismatches = _common_measurement(published_results, name)
        measurement[name] = value
        if mismatches:
            conflicts[name] = mismatches
    measurement["source_verification"] = source_verification
    measurement["decoder_manifest_matches_continuous"] = (
        measurement["decoder_manifest_sha256"] is not None
        and measurement["decoder_manifest_sha256"]
        == (_read_json_object(continuous_run_dir / REPORT_NAME) or {}).get(
            "decoder_manifest_sha256"))

    baseline_cases = [_cold_baseline_case(result, window[result["index"]])
                      for result in results]
    baseline = {
        "schema_version": COLD_BASELINE_SCHEMA_VERSION,
        "comparison_scope": COLD_BASELINE_SCOPE,
        "source_receipts": str(continuous_run_dir / RECEIPTS_NAME),
        "case_count": len(baseline_cases),
        "published_case_count": len(published_results),
        "verified_case_count": len(verified_results),
        "elapsed_seconds": clock() - started,
        "source_compatible_count": sum(entry["source_compatible"]
                                       for entry in baseline_cases),
        "path_compatible_count": sum(entry["path_compatible"]
                                     for entry in baseline_cases),
        "raw_compatible_count": sum(entry["raw_compatible"]
                                    for entry in baseline_cases),
        "genome_compatible_count": sum(entry["genome_compatible"]
                                       for entry in baseline_cases),
        "status_compatible_count": sum(entry["status_compatible"]
                                       for entry in baseline_cases),
        "init_seconds_total": _sum_or_none([entry["init_seconds"]
                                            for entry in baseline_cases]),
        "total_seconds_total": _sum_or_none([entry["total_seconds"]
                                             for entry in baseline_cases]),
        "cases": baseline_cases,
    }
    _write_json(output_dir / COLD_BASELINE_NAME, baseline)

    plan_cases = []
    for result in results:
        case_dir = Path(result.get("case_dir") or "")
        plan_path = case_dir / PLAN_NAME
        plan_cases.append({
            "index": result["index"],
            "raw_hex": result.get("raw_hex"),
            "case_id": result.get("case_id"),
            "plan_file": (str(plan_path.relative_to(output_dir))
                          if plan_path.is_file() else None),
            "plan_sha256": sha256_file(plan_path) if plan_path.is_file() else None,
        })
    _write_json(output_dir / PLAN_NAME, {
        "schema_version": PLAN_INDEX_SCHEMA_VERSION,
        "semantics": ("per-case fresh online session plans over the frozen "
                      "continuous admitted prefix; every case ran in its own "
                      "session, so this is an index rather than a single session "
                      "plan and it declares no source_admissions list"),
        "continuous_run_dir": str(continuous_run_dir),
        "continuous_identity_sha256": identity_document.get("sha256"),
        "continuous_plan_sha256": (((identity_document.get("identity") or {})
                                    .get("genome") or {}).get("plan_sha256")),
        "case_count": len(plan_cases),
        "verified_case_count": len(verified_results),
        "cases": plan_cases,
    })

    cold_identity = _build_cold_identity(
        continuous_run_dir=continuous_run_dir, identity_document=identity_document,
        run_id=run_id, measurement=measurement, search_seed=search_seed,
        client_binary=Path(client_binary), client_sha256=client_sha256,
        source_verification=source_verification, case_count=len(results),
        verified_count=len(verified_results), mode_detection=detected)
    _write_json(output_dir / IDENTITY_NAME, cold_identity)

    # Status counts come from the published receipt rows, which is exactly the
    # stream acceptance_metrics.analyze_run counts, so report.json and
    # receipts.jsonl can never disagree.
    statuses = dict(sorted(published_statuses.items()))
    finalization: dict[str, float] = {}
    finalization_missing = 0
    for result in published_results:
        timing = result.get("finalization_timing_seconds")
        if not isinstance(timing, dict):
            finalization_missing += 1
            continue
        for name, value in timing.items():
            finalization[name] = finalization.get(name, 0.0) + float(value)
    failure_count = len(results) - len(published_results)
    verification_failure_count = len(published_results) - len(verified_results)
    status_mismatch_count = sum(1 for result in published_results
                                if result.get("status_match") is False)
    report = {
        "schema_version": SCHEMA_VERSION,
        "execution_mode": EXECUTION_MODE,
        "execution_status": ("complete" if failure_count == 0
                             and verification_failure_count == 0 else "failed"),
        "tests": len(published_results),
        "case_count": len(results),
        "published_case_count": len(published_results),
        "verified_case_count": len(verified_results),
        "case_failure_count": failure_count,
        "verification_failure_count": verification_failure_count,
        "status_mismatch_count": status_mismatch_count,
        "statuses": statuses,
        "effective_search_seconds": _sum_or_none(
            [result.get("effective_search_seconds")
             for result in published_results]),
        "elapsed_seconds": _sum_or_none([result.get("elapsed_seconds")
                                         for result in published_results]),
        "wall_clock_seconds": clock() - started,
        "finalization_timing_seconds": finalization or None,
        "finalization_timing_scope": (
            "sum over the verified per-case sessions of each session's own "
            "report.json finalization_timing_seconds; a cold group pays this cost "
            "once per case"),
        "finalization_timing_missing_cases": finalization_missing,
        "total_local_ticks_semantics": "sum_of_independent_local_ticks_cost_only",
        "clock_model": "independent_local_ticks_and_causal_order",
        "record_semantics": "mutation_decisions_not_dut_cycles",
        "decoder_manifest_sha256": measurement["decoder_manifest_sha256"],
        "decoder_manifest_matches_continuous":
            measurement["decoder_manifest_matches_continuous"],
        "global_mutation_seed": search_seed,
        "global_mutation_seed_status": ("supported" if search_seed is not None
                                        else "not_requested"),
        "continuous_run_dir": str(continuous_run_dir),
        "continuous_identity_sha256": identity_document.get("sha256"),
        "identity_declaration": ("source files, decoder manifest, component "
                                 "identity, targets digest and client binary are "
                                 "measured by this run; the campaign run_config and "
                                 "the frozen plan identity are inherited from the "
                                 "continuous run and named in "
                                 "online_run_identity.json:cold_start"),
        "measurement_conflicts": conflicts,
        "source_identity_verification": {
            "declared_count": source_verification["declared_count"],
            "matching_count": source_verification["matching_count"],
            "drifted_paths": [entry["path"] for entry
                              in source_verification["drifted"]],
        },
        "modes": effective_modes,
        "mode_detection": detected,
        "cold_start": {
            "per_case_sessions": len(results),
            "published_case_sessions": len(published_results),
            "verified_case_sessions": len(verified_results),
            "per_case_max_tests": PER_CASE_MAX_TESTS,
            "seconds_per_case": float(seconds),
            "case_failure_count": failure_count,
            "verification_failure_count": verification_failure_count,
            "status_mismatch_count": status_mismatch_count,
            "init_seconds_total": baseline["init_seconds_total"],
            "total_seconds_total": baseline["total_seconds_total"],
            "prefix_replay_seconds_total": _sum_or_none(
                [result.get("prefix_replay_seconds") for result in results]),
            "cases": [{"index": result["index"],
                       "case_dir": result.get("case_dir"),
                       "init_seconds": result.get("init_seconds"),
                       "total_seconds": result.get("total_seconds"),
                       "prefix_replay_seconds":
                           result.get("prefix_replay_seconds"),
                       "error": result.get("error"),
                       "verification_error": result.get("verification_error")}
                      for result in results],
        },
        "client_binary": {"path": str(client_binary), "sha256": client_sha256},
        "gate_commands": GATE_COMMANDS_NAME,
        "cold_start_document": COLD_BASELINE_NAME,
    }
    _write_json(output_dir / REPORT_NAME, report)

    discarded: list[int] = []
    if not keep_case_dirs:
        for result in verified_results:
            case_dir = Path(result.get("case_dir") or "")
            if case_dir.is_dir():
                for path in sorted(case_dir.rglob("*"), reverse=True):
                    if path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        path.rmdir()
                case_dir.rmdir()
                discarded.append(result["index"])
        report["discarded_case_dirs"] = discarded
        _write_json(output_dir / REPORT_NAME, report)

    write_gate()
    return {
        "output_dir": str(output_dir),
        "run_id": run_id,
        "case_count": len(results),
        "published_case_count": len(published_results),
        "verified_case_count": len(verified_results),
        "case_failure_count": failure_count,
        "verification_failure_count": verification_failure_count,
        "status_mismatch_count": status_mismatch_count,
        "init_seconds_total": baseline["init_seconds_total"],
        "total_seconds_total": baseline["total_seconds_total"],
        "effective_search_seconds": report["effective_search_seconds"],
        "elapsed_seconds": report["elapsed_seconds"],
        "wall_clock_seconds": report["wall_clock_seconds"],
        "receipt_rows": len(receipt_lines),
        "exit_code": (EXIT_OK if failure_count == 0 and verification_failure_count == 0
                      else EXIT_CASE_FAILURE),
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _add_mode_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cpu-retirement", action="store_true",
                        help="force RVFI retirement observation on")
    parser.add_argument("--native-irq-receipts", action="store_true",
                        help="force native IRQ receipts on (requires RVFI)")
    parser.add_argument("--gpio-consumption", action="store_true",
                        help="force GPIO consumption observation on")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser(
        "run", help="one fresh session per frozen continuous case, then aggregate",
        description=__doc__.splitlines()[0])
    run.add_argument("--continuous-run-dir", type=Path, required=True,
                     help="run directory of the continuous session to replay")
    run.add_argument("--output", type=Path, required=True,
                     help="new directory for the aggregated cold run")
    run.add_argument("--client-binary", type=Path,
                     help="RFuzz client binary used for every case session")
    run.add_argument("--cache-dir", type=Path,
                     help="RTL build cache directory used for every case session")
    run.add_argument("--max-cases", type=int, default=DEFAULT_MAX_CASES,
                     help="how many leading continuous cases to replay")
    run.add_argument("--seconds", type=float, default=DEFAULT_SECONDS,
                     help="per-case duration budget of the fresh session")
    run.add_argument("--run-id")
    run.add_argument("--dry-run", action="store_true",
                     help="print the commands that would run and exit 0")
    run.add_argument("--discard-case-dirs", action="store_true",
                     help="delete verified per-case run directories after "
                          "aggregation (failed cases are always kept)")
    run.add_argument("--case-timeout-seconds", type=float,
                     default=DEFAULT_CASE_TIMEOUT_SECONDS)
    _add_mode_flags(run)

    case = commands.add_parser(
        "case", help="worker: run exactly one frozen case in a fresh session",
        description="Run one frozen continuous case in a brand new session.")
    case.add_argument("--continuous-run-dir", type=Path, required=True)
    case.add_argument("--index", type=int, required=True)
    case.add_argument("--case-dir", type=Path, required=True)
    case.add_argument("--cache-dir", type=Path, required=True)
    case.add_argument("--client-binary", type=Path, required=True)
    case.add_argument("--run-id", required=True)
    case.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    _add_mode_flags(case)

    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            summary = run_cold_start(
                continuous_run_dir=args.continuous_run_dir, output_dir=args.output,
                cache_dir=args.cache_dir, client_binary=args.client_binary,
                max_cases=args.max_cases, seconds=args.seconds, run_id=args.run_id,
                modes={"cpu_retirement": args.cpu_retirement,
                       "native_irq_receipts": args.native_irq_receipts,
                       "gpio_consumption": args.gpio_consumption},
                dry_run=args.dry_run, keep_case_dirs=not args.discard_case_dirs,
                case_timeout_seconds=args.case_timeout_seconds,
                parent_argv=[sys.executable, str(Path(__file__).resolve()),
                             *list(argv if argv is not None else sys.argv[1:])])
            print(json.dumps(summary, sort_keys=True))
            return summary["exit_code"]
        result = execute_cold_case(
            continuous_run_dir=args.continuous_run_dir, index=args.index,
            case_dir=args.case_dir, cache_dir=args.cache_dir,
            client_binary=args.client_binary, run_id=args.run_id,
            seconds=args.seconds,
            modes={"cpu_retirement": args.cpu_retirement,
                   "native_irq_receipts": args.native_irq_receipts,
                   "gpio_consumption": args.gpio_consumption})
        print(json.dumps(result, sort_keys=True))
        return result["exit_code"]
    except ColdStartInputError as exc:
        print(f"first-step-cold-start-input-error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except ColdStartCaseError as exc:
        print(f"first-step-cold-start-case-error: {exc}", file=sys.stderr)
        return EXIT_CASE_FAILURE
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"first-step-cold-start-error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
