"""Opt-in live Rust RFuzz client for independent persistent RTL scenarios."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

from myfuzz.scenario.feedback import CoverageTarget

from .rfuzz_fifo import FifoEndpoint
from .scenario_rfuzz import ScenarioRfuzzExecutor


_DECISION_FIELDS = ("template", "path", "source", "bit_low",
                    "action", "operator", "delay", "bit_high")


def render_scenario_rfuzz_config(targets: tuple[CoverageTarget, ...]) -> str:
    if not targets or len(targets) > 4096:
        raise ValueError("scenario RFuzz needs 1..4096 coverage targets")
    lines = ['[general]', 'filename = "scenario_genome.v2"',
             'instrumented = "independent_local_rtl"',
             'top = "myfuzz_scenario"',
             'timestamp = 2026-09-27T00:00:00Z']
    for field in _DECISION_FIELDS:
        lines.extend(('[[input]]', f'name = {json.dumps(field)}', 'width = 8'))
    for index, target in enumerate(targets):
        name = json.dumps(target.target_id)
        lines.extend(('[[coverage]]', f'port = {json.dumps(target.port)}',
                      f'name = {name}', f'index = {index}',
                      'filename = "scenario_target"', 'line = 0',
                      'column = 0',
                      'human = "observed real RTL output predicate"',
                      '[[counter]]', f'name = {name}', 'width = 8',
                      'max = 1', 'scale = false', f'index = {index}',
                      f'signal = {index}', 'fail = false'))
    return "\n".join(lines) + "\n"


def _drain_idle_timeout_reached(*, stop_requested_at: float | None,
                                last_progress_at: float, now: float,
                                idle_limit_seconds: float) -> bool:
    """Count only time without a completed candidate or host feedback."""
    return (stop_requested_at is not None
            and now - max(stop_requested_at, last_progress_at)
            > idle_limit_seconds)


@dataclass(frozen=True)
class ScenarioLiveResult:
    output_dir: Path
    tests: int
    completed_feedback_exchanges: int
    statuses: dict[str, int]
    client_returncode: int
    elapsed_seconds: float
    effective_search_seconds: float = 0.0


def run_scenario_rfuzz_live(*, executor: ScenarioRfuzzExecutor,
                            client_binary: Path, output_dir: Path,
                            duration_seconds: float,
                            seed_records: tuple[bytes, ...] = (bytes(8),),
                            max_tests: int = 10000,
                            search_seed: int | None = None,
                            max_runs_per_batch: int = 8) -> ScenarioLiveResult:
    """Launch a bounded RFuzz run; each client test starts a fresh RTL scenario."""
    if not isinstance(executor, ScenarioRfuzzExecutor):
        raise ValueError("scenario executor is required")
    if executor.receipts:
        raise ValueError("live scenario executor must start without receipts")
    if not 0 < duration_seconds <= 3600 or not 1 <= max_tests <= 100000:
        raise ValueError("live scenario budget is invalid")
    if search_seed is not None and (type(search_seed) is not int
                                    or not 0 <= search_seed < 2 ** 64):
        raise ValueError("scenario search seed must be a u64")
    if type(max_runs_per_batch) is not int or not 1 <= max_runs_per_batch <= 8:
        raise ValueError("scenario RFuzz batch size must be in 1..8")
    if (not seed_records or len(seed_records) > executor.decoder.max_records
            or any(not isinstance(record, bytes) or len(record) != 8
                   for record in seed_records)):
        raise ValueError("seed must contain complete eight byte records")
    binary = Path(client_binary).resolve(strict=True)
    output = Path(output_dir).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("scenario live output directory must be new")
    output.mkdir(parents=True)
    (output / "rfuzz.toml").write_text(
        render_scenario_rfuzz_config(executor.targets), encoding="utf-8")
    decoder_manifest = json.dumps(executor.decoder.document(), sort_keys=True,
                                  separators=(",", ":"), ensure_ascii=False)
    (output / "decoder_manifest.json").write_text(decoder_manifest + "\n",
                                                    encoding="utf-8")
    (output / "targets.json").write_text(json.dumps(
        [asdict(target) for target in executor.targets],
        sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    decoder_manifest_sha256 = hashlib.sha256(decoder_manifest.encode("utf-8")).hexdigest()
    (output / "seed.bin").write_bytes(b"".join(seed_records))
    if executor.evidence_dir is None:
        executor.evidence_dir = output / "failures"
        executor.evidence_dir.mkdir()
    hint_path = output / "mutation_hint.json"

    def write_hint() -> None:
        hint = executor.mutation_hint()
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False,
                                             dir=output, prefix=".hint-") as handle:
                temporary_path = Path(handle.name)
                handle.write(json.dumps(hint, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, hint_path)
            executor.note_published_hint(hint)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    write_hint()
    statuses: dict[str, int] = {}
    exchanges = 0
    started = time.monotonic()
    effective_started: float | None = None
    effective_ended: float | None = None
    last_progress_at = started
    client = None
    environment = dict(os.environ)
    environment["MYFUZZ_RFUZZ_SCENARIO_MODE"] = "1"
    environment["MYFUZZ_RFUZZ_TEST_BUFFER_KIB"] = "64"
    environment["MYFUZZ_RFUZZ_MAX_RUNS_PER_BATCH"] = str(max_runs_per_batch)
    environment["MYFUZZ_SCENARIO_HINT_FILE"] = str(hint_path)
    environment["MYFUZZ_SCENARIO_RUN_ID"] = executor.run_id
    with FifoEndpoint() as endpoint, (output / "client.log").open("wb") as log, \
            (output / "receipts.jsonl").open("w", encoding="utf-8") as receipt_file:
        command = (str(binary), str(output / "rfuzz.toml"),
                   "--server-id", endpoint.directory.name,
                   "--output-directory", str(output / "corpus"),
                   "--seed-cycles", str(len(seed_records)),
                   "--seed-input", str(output / "seed.bin"))
        if search_seed is not None:
            command += ("--search-seed", str(search_seed))
        try:
            def persist_receipt(receipt) -> None:
                nonlocal last_progress_at
                statuses[receipt.status] = statuses.get(receipt.status, 0) + 1
                receipt_file.write(json.dumps({
                    "run_id": receipt.run_id,
                    "buffer_id": receipt.buffer_id, "slot": receipt.slot,
                    "raw_sha256": receipt.raw_sha256,
                    "genome_sha256": receipt.genome_sha256,
                    "path_id": receipt.path_id,
                    "applied_sources": receipt.applied_sources,
                    "applied_source_ids": receipt.applied_source_ids,
                    "applied_template": receipt.applied_template,
                    "applied_path": receipt.applied_path,
                    "applied_hint_sequence": receipt.applied_hint_sequence,
                    "effective_genome_sha256": receipt.effective_genome_sha256,
                    "manifest_sha256": receipt.manifest_sha256,
                    "semantic_sha256": receipt.semantic_sha256,
                    "status": receipt.status,
                    "total_local_ticks": receipt.total_local_ticks,
                    "local_ticks": receipt.local_ticks,
                    "coverage_hex": receipt.coverage_hex,
                    "violations": receipt.violations,
                    "error": receipt.error,
                    "wall_cut": receipt.wall_cut}, sort_keys=True) + "\n")
                receipt_file.flush()
                last_progress_at = time.monotonic()

            client = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                      start_new_session=True, env=environment)
            stop_requested = False
            while client.poll() is None:
                now = time.monotonic()
                if effective_started is None and now - started > 30:
                    raise TimeoutError("RFuzz client did not start search")
                if (effective_started is not None
                        and now - effective_started >= duration_seconds
                        or len(executor.receipts) >= max_tests):
                    if not stop_requested:
                        effective_ended = now
                        client.send_signal(signal.SIGINT)
                        stop_requested = True
                if _drain_idle_timeout_reached(
                        stop_requested_at=effective_ended if stop_requested else None,
                        last_progress_at=last_progress_at, now=now,
                        idle_limit_seconds=30):
                    raise TimeoutError("RFuzz client did not drain its active batch")
                token = endpoint.receive(timeout=0.02)
                if token is None:
                    continue
                reply = executor.process_owned_pair(
                    *token, creator_pid=client.pid,
                    on_receipt=persist_receipt)
                if effective_started is None:
                    # The seed can share a FIFO batch with mutations. Capture
                    # the time immediately after its receipt inside executor.
                    effective_started = executor.first_receipt_completed_at
                write_hint()
                endpoint.reply(reply)
                last_progress_at = time.monotonic()
                exchanges += 1
        finally:
            if client is not None:
                try:
                    os.killpg(client.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    client.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(client.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    client.wait(timeout=2)
    if effective_started is not None and effective_ended is None:
        effective_ended = time.monotonic()
    effective_seconds = (max(0.0, effective_ended - effective_started)
                         if effective_started is not None and effective_ended is not None
                         else 0.0)
    result = ScenarioLiveResult(output, len(executor.receipts), exchanges,
                                statuses, client.returncode,
                                time.monotonic() - started, effective_seconds)
    (output / "report.json").write_text(json.dumps({
        "tests": result.tests,
        "completed_feedback_exchanges": result.completed_feedback_exchanges,
        "statuses": result.statuses,
        "client_returncode": result.client_returncode,
        "elapsed_seconds": result.elapsed_seconds,
        "effective_search_seconds": result.effective_search_seconds,
        "total_local_ticks_semantics": "sum_of_independent_local_ticks_cost_only",
        "clock_model": "independent_local_ticks_and_causal_order",
        "record_semantics": "mutation_decisions_not_dut_cycles",
        "decoder_manifest_sha256": decoder_manifest_sha256,
        "mutation_hint_schema": "scenario_mutation_hint.v1",
        "mutation_hint_updates": executor._hint_sequence,
        "global_mutation_seed": search_seed,
        "global_mutation_seed_status": (
            "supported" if search_seed is not None else "not_requested"),
    }, sort_keys=True) + "\n", encoding="utf-8")
    return result
