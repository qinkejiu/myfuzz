"""Opt-in live Rust RFuzz client for independent persistent RTL scenarios."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.event_journal import (canonical_json_chunks,
                                            write_zlib_chunk_events)
from myfuzz.scenario.replay import ScenarioTrace
from myfuzz.scenario.decode_space import (ONLINE_DECODE_SPACE_PATHS,
                                          ONLINE_DECODE_SPACE_SCHEMA_VERSION,
                                          compare_online_decode_space,
                                          online_decode_space_document,
                                          recorded_decode_space)

from .rfuzz_fifo import FifoEndpoint
from .scenario_rfuzz import ScenarioRfuzzExecutor


_DECISION_FIELDS = ("template", "path", "source", "bit_low",
                    "action", "operator", "delay", "bit_high")
_JSONL_TRACE_EVENT_THRESHOLD = 100000
_ROOT = Path(__file__).resolve().parents[3]


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


def _online_decision_for_receipt(executor: ScenarioRfuzzExecutor, receipt):
    decision = executor._online_decisions_by_slot.get((receipt.buffer_id, receipt.slot))
    if decision is not None and decision["raw_sha256"] != receipt.raw_sha256:
        raise ValueError("online receipt and raw decision identity differ")
    return decision


def _source_action_gate_record(executor: ScenarioRfuzzExecutor) -> dict | None:
    """Record the opt-in source-action gate and its bounded tracker state.

    The gate's own document is run state (admitted action ids, tracker cursor,
    counters and bounds), not construction identity, so it is reported here
    instead of being folded into the frozen session manifest.
    """
    gate = getattr(executor, "source_action_gate", None)
    if gate is None:
        return None
    document = gate.document() if callable(getattr(gate, "document", None)) else None
    return {"schema_version": "online_source_action_gate_report.v1",
            "enforce": bool(getattr(gate, "enforce", True)),
            "action_ids": list(getattr(gate, "action_ids", ())),
            "gate": document}


def _source_target_transactions_record(executor: ScenarioRfuzzExecutor) -> dict | None:
    """Record the opt-in per-case routing / target-consumption witness table.

    Only a session that declared a case witness recorder gets the key: a run
    without one keeps its previous report bytes exactly, so an absent key is
    never presented as a measured zero.  The witness table is run state -- what
    the run really routed and consumed -- so it belongs in the report rather
    than in the frozen session manifest, and its own ``schema_version`` travels
    with it.
    """
    recorder = getattr(executor, "case_witness_recorder", None)
    if recorder is None:
        return None
    document = getattr(recorder, "document", None)
    if not callable(document):
        return None
    return document(gate=getattr(executor, "source_action_gate", None))


def _closed_loop_energy_record(executor: ScenarioRfuzzExecutor) -> dict | None:
    """Record the opt-in closed-loop certificate switch and its retained state.

    Even a disabled run reports the switch, so an A/B pair can be told apart by
    its own record.  This is run state, not construction identity, so it is
    reported here instead of inside the frozen session manifest.
    """
    state = getattr(executor, "closed_loop_state", None)
    return state() if callable(state) else None


def _initial_ram_data_record(executor: ScenarioRfuzzExecutor) -> dict | None:
    """Record the opt-in pre-session initial RAM data operator's own state.

    Reported by a run that declared the operator -- enabled or explicitly
    disabled -- so an A/B pair is told apart by its own document instead of an
    absent key.  A run that never declared it keeps its previous report bytes
    exactly: this is run state, not construction identity, and the operator
    never enters the session manifest.
    """
    session = getattr(executor, "session", None)
    state = getattr(session, "initial_ram_data_state", None)
    return state() if callable(state) else None


def _path_switch_record(executor: ScenarioRfuzzExecutor) -> dict | None:
    """Record the opt-in live path switch and its retained state.

    Reported by every run, enabled or not, so the run's own document states
    which search behaviour produced it instead of leaving an off switch to be
    inferred from an absent key.  This is run state, not construction identity.
    """
    state = getattr(executor, "path_switch_state", None)
    return state() if callable(state) else None


def _run_scenario_rfuzz_live(*, executor: ScenarioRfuzzExecutor,
                             client_binary: Path, output_dir: Path,
                             duration_seconds: float,
                             seed_records: tuple[bytes, ...],
                             max_tests: int,
                             search_seed: int | None,
                             max_runs_per_batch: int,
                             compressed_trace: bool = False) -> ScenarioLiveResult:
    """Run the shared RFuzz transport after the public lifecycle guard."""
    if not isinstance(executor, ScenarioRfuzzExecutor):
        raise ValueError("scenario executor is required")
    online = executor.online_decoder is not None
    if type(compressed_trace) is not bool or (compressed_trace and executor.session is None):
        raise ValueError("compressed trace requires an online session")
    if executor.receipts:
        raise ValueError("live scenario executor must start without receipts")
    checker_identity = (_fresh_checker_identity(
        executor.checker, config=executor.checker_config,
        identity_target=executor.checker_identity_target))
    collector_identity = (_fresh_checker_identity(executor.checker, config={})
                          if executor.checker is not None else None)
    if not 0 < duration_seconds <= 3600 or not 1 <= max_tests <= 100000:
        raise ValueError("live scenario budget is invalid")
    if search_seed is not None and (type(search_seed) is not int
                                    or not 0 <= search_seed < 2 ** 64):
        raise ValueError("scenario search seed must be a u64")
    if type(max_runs_per_batch) is not int or not 1 <= max_runs_per_batch <= 8:
        raise ValueError("scenario RFuzz batch size must be in 1..8")
    max_records = (executor.decoder.max_records if executor.decoder is not None else
                   executor.online_decoder.max_input_bytes // 8)
    if (not seed_records or len(seed_records) > max_records
            or any(not isinstance(record, bytes) or len(record) != 8
                   for record in seed_records)):
        raise ValueError("seed must contain complete eight byte records")
    binary = Path(client_binary).resolve(strict=True)
    output = Path(output_dir).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("scenario live output directory must be new")
    continuous = not online and executor.session is not None
    if continuous:
        from myfuzz.scenario.session_runtime import ScenarioSession
        if not isinstance(executor.session, ScenarioSession):
            raise ValueError("live continuous identity requires ScenarioSession; record-only sessions are unsupported")
    frozen_inputs = {
            "source_files": [{"path": name, "sha256": _sha256_file(_ROOT / name)}
                             for name in _FRESH_RUNTIME_SOURCES],
            "client": _rfuzz_client_identity(binary),
            "collector": collector_identity,
    }
    decoder = executor.decoder if executor.decoder is not None else executor.online_decoder
    decoder_manifest = json.dumps(decoder.document(), sort_keys=True,
                                  separators=(",", ":"), ensure_ascii=False)
    config_text = render_scenario_rfuzz_config(executor.targets)
    target_text = json.dumps([asdict(target) for target in executor.targets],
                            sort_keys=True, separators=(",", ":")) + "\n"
    output.mkdir(parents=True)
    executor._live_context = {
        "output": output, "frozen_inputs": frozen_inputs,
        "checker_identity": checker_identity, "binary": binary,
        "decoder_manifest_sha256": hashlib.sha256(decoder_manifest.encode("utf-8")).hexdigest(),
        "started": time.monotonic(), "exchanges": 0, "client_returncode": None,
        "effective_search_seconds": 0.0,
    }
    (output / "rfuzz.toml").write_text(config_text, encoding="utf-8")
    (output / "decoder_manifest.json").write_text(decoder_manifest + "\n",
                                                    encoding="utf-8")
    (output / "targets.json").write_text(target_text, encoding="utf-8")
    decoder_manifest_sha256 = hashlib.sha256(decoder_manifest.encode("utf-8")).hexdigest()
    (output / "seed.bin").write_bytes(b"".join(seed_records))
    if online:
        manifest_bytes = json.dumps(
            executor.session.manifest_document, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8") + b"\n"
        _write_online_artifact(output / "online_session_manifest.json",
                               manifest_bytes)
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
            persisted_receipts: set[tuple[str, int, int, str]] = set()

            def persist_receipt(receipt) -> None:
                nonlocal last_progress_at
                identity = (receipt.run_id, receipt.buffer_id, receipt.slot,
                            receipt.raw_sha256)
                if identity in persisted_receipts:
                    return
                decision = (_online_decision_for_receipt(executor, receipt)
                            if online else None)
                interaction = receipt.interaction_feedback or {}
                closed_loop = (receipt.closed_loop_feedback
                               or (decision or {}).get("closed_loop_feedback")
                               or {})
                closed_loop_counts = closed_loop.get("counts") or {}
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
                    "wall_cut": receipt.wall_cut,
                    "online_raw_records_hex": (decision.get("raw_records_hex")
                                               if decision is not None else None),
                    "case_id": decision.get("case_id") if decision is not None else None,
                    "direction": decision.get("direction") if decision is not None else None,
                    "flow_id": decision.get("flow_id") if decision is not None else None,
                    "target_id": decision.get("target_id") if decision is not None else None,
                    "source_id": decision.get("source_id") if decision is not None else None,
                    "operator_id": decision.get("operator_id") if decision is not None else None,
                    "candidate_id": decision.get("candidate_id") if decision is not None else None,
                    "source_selection_reason": (decision.get("source_selection_reason")
                                                if decision is not None else None),
                    "candidate_disposition": (decision.get("candidate_disposition")
                                              if decision is not None else None),
                    "candidate_disposition_reason": (
                        decision.get("candidate_disposition_reason")
                        if decision is not None else None),
                    "rejection": (decision.get("rejection")
                                  if decision is not None else None),
                    "source_action": (decision.get("source_action")
                                      if decision is not None else None),
                    "interaction_source_gains": (
                        decision.get("interaction_source_gains", {})
                        if decision is not None else None),
                    "online_phase_timing_seconds": (
                        decision.get("phase_timing_seconds")
                        if decision is not None else None),
                    "online_submit_timing_seconds": (
                        decision.get("submit_timing_seconds")
                        if decision is not None else None),
                    "online_runner_timing_seconds": (
                        decision.get("runner_timing_seconds")
                        if decision is not None else None),
                    "online_source": (receipt.online_case.get("source")
                                      if receipt.online_case is not None else None),
                    "online_weights": receipt.online_weights,
                    "interaction_feature_deltas": interaction.get("feature_deltas"),
                    "interaction_new_features": interaction.get("new_features"),
                    "interaction_deferred": interaction.get("deferred"),
                    "closed_loop_enabled": closed_loop.get("enabled"),
                    "closed_loop_status": closed_loop.get("status"),
                    "closed_loop_delta_counts": closed_loop_counts,
                    "closed_loop_certificate_ids": [
                        entry.get("certificate_id")
                        for entry in closed_loop.get("certificates", ())],
                    "closed_loop_source_credit": closed_loop.get("credited"),
                    "closed_loop_credit_totals": closed_loop.get("credit_totals"),
                    "closed_loop_source_weights": closed_loop.get("source_weights"),
                    "closed_loop_refusals": closed_loop.get("refusals"),
                    }, sort_keys=True) + "\n")
                receipt_file.flush()
                persisted_receipts.add(identity)
                statuses[receipt.status] = statuses.get(receipt.status, 0) + 1
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
                        or len(executor.receipts) >= max_tests
                        or executor._session_stop_reason is not None
                        and (online or executor.runtime_contract is not None)):
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
                executor._live_context["exchanges"] = exchanges
        finally:
            active_error = sys.exc_info()[1]
            try:
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
                    executor._live_context["client_returncode"] = client.returncode
            except BaseException as exc:
                executor._live_context["transport_cleanup_errors"] = [
                    f"{type(exc).__name__}: {exc}"]
                if active_error is None:
                    raise
            finally:
                ended = effective_ended if effective_ended is not None else time.monotonic()
                executor._live_context["effective_search_seconds"] = (
                    max(0.0, ended - effective_started) if effective_started is not None else 0.0)
    if effective_started is not None and effective_ended is None:
        effective_ended = time.monotonic()
    effective_seconds = (max(0.0, effective_ended - effective_started)
                         if effective_started is not None and effective_ended is not None
                         else 0.0)
    result = ScenarioLiveResult(output, len(executor.receipts), exchanges,
                                statuses, client.returncode,
                                time.monotonic() - started, effective_seconds)
    report = {
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
        "source_action_gate": _source_action_gate_record(executor),
        "closed_loop_energy": _closed_loop_energy_record(executor),
        "path_switch": _path_switch_record(executor),
    }
    initial_ram_data = _initial_ram_data_record(executor)
    if initial_ram_data is not None:
        report["initial_ram_data"] = initial_ram_data
    source_target_transactions = _source_target_transactions_record(executor)
    if source_target_transactions is not None:
        report["source_target_transactions"] = source_target_transactions
    (output / "report.json").write_text(json.dumps(
        report, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _fresh_checker_identity(checker, *, config=None, identity_target=None):
    """Bind checker semantics; collectors can declare stable config explicitly."""
    from myfuzz.scenario.session_runtime import _checker_identity

    target = identity_target if identity_target is not None else checker
    if target is None:
        if config is not None:
            raise ValueError("checker configuration requires a callable identity")
        return None
    if config is None:
        if identity_target is not None and identity_target is not checker:
            raise ValueError("separate checker identity requires explicit configuration")
        return _checker_identity(target)
    if not isinstance(config, dict):
        raise ValueError("checker configuration must be a JSON object")
    declared_config = json.loads(_canonical_json(config))
    named = target if hasattr(target, "__qualname__") else type(target)
    source = inspect.getsourcefile(named)
    if source is None or not Path(source).is_file():
        raise ValueError("checker source is unavailable")
    resolved = Path(source).resolve()
    source_name = (resolved.relative_to(_ROOT).as_posix()
                   if resolved.is_relative_to(_ROOT) else str(resolved))
    return {"module": named.__module__, "qualname": named.__qualname__,
            "source": {"path": source_name, "sha256": _sha256_file(resolved)},
            "configuration_mode": "explicit_stable_declaration",
            "config": declared_config}


_FRESH_RUNTIME_SOURCES = (
    'src/myfuzz/scenario/uart_retired_read.py',
    'src/myfuzz/scenario/uart_operand_seed.py',
    'src/myfuzz/scenario/uart_operand_use.py',
    'src/myfuzz/scenario/memory_service.py',
    'src/myfuzz/local_harness/cpu_session.py',
    'src/myfuzz/local_harness/session.py',
    'src/myfuzz/scenario/memory_commit_authority.py',
    'src/myfuzz/scenario/memory_read_authority.py',
    'src/myfuzz/scenario/uart_ram_commit_join.py',
    'src/myfuzz/scenario/uart_store_memory.py',
    'src/myfuzz/scenario/uart_memory_readback.py',
    'src/myfuzz/scenario/uart_irq_entry.py',
    'src/myfuzz/local_harness/uart_controlled_irq_contract.py',
    "src/myfuzz/scenario/uart_irq_consumption.py",
    "src/myfuzz/local_harness/ibex_irq_receipt_contract.py",
    "src/myfuzz/scenario/uart_consumption.py",
    "src/myfuzz/local_harness/opentitan_uart_fifo_contract.py",
    "src/myfuzz/local_harness/opentitan_uart_session.py",
    "src/myfuzz/scenario/ibex_uart_online.py",
    "src/myfuzz/scenario/ibex_uart_online_checker.py",
    "src/myfuzz/integration/ibex_uart_online.py",
    "scripts/run_ibex_uart_online.py",
    "src/myfuzz/integration/scenario_rfuzz.py",
    "src/myfuzz/integration/scenario_rfuzz_live.py",
    "src/myfuzz/integration/scenario_rfuzz_replay.py",
    "src/myfuzz/integration/rfuzz_fifo.py",
    "src/myfuzz/integration/rfuzz_shmem.py",
    "src/myfuzz/integration/rfuzz_wire.py",
    "src/myfuzz/scenario/interaction_feedback.py",
    "src/myfuzz/scenario/runtime_path_contract.py",
    "src/myfuzz/scenario/event_provenance.py",
    "src/myfuzz/scenario/cpu_retirement.py",
    "src/myfuzz/scenario/retirement_delivery.py",
    "src/myfuzz/scenario/gpio_consumption.py",
    "src/myfuzz/local_harness/pulp_gpio_probe_contract.py",
    "src/myfuzz/scenario/runtime_edge_index.py",
    "src/myfuzz/scenario/source_provenance.py",
)


def _fresh_artifact_names(output: Path) -> set[str]:
    names = {"runner_manifest.json", "decoder_manifest.json", "targets.json",
             "seed.bin", "rfuzz.toml", "receipts.jsonl"}
    for directory in ("corpus", "failures"):
        names.update(path.relative_to(output).as_posix()
                     for path in (output / directory).rglob("*") if path.is_file())
    return names


def _verify_runtime_path_material(record: dict | None, decoder: dict, *,
                                  session: bool = False) -> None:
    """Check saved graph/contract/path/topology bytes without constructing RTL."""
    contract = decoder.get("runtime_contract")
    if contract is None:
        if record is not None and record != {"status": "legacy_unchecked",
                                             "declaration": None, "compiled": {}}:
            raise ValueError("legacy decoder cannot claim runtime path preflight")
        return
    if (not isinstance(record, dict) or set(record) != {"status", "declaration", "compiled"}
            or record["status"] != "contract_preflight"
            or not isinstance(record["compiled"], dict)):
        raise ValueError("runtime path identity is missing or invalid")
    declaration = record["declaration"]
    if (not isinstance(declaration, dict)
            or set(declaration) != {"schema_version", "graph", "contract", "selections"}
            or declaration["schema_version"] != "prepared_runtime_paths.v1"
            or declaration["graph"] != decoder.get("graph")
            or declaration["contract"] != contract
            or declaration["selections"] != decoder.get("path_mapping")):
        raise ValueError("runtime path saved declaration mismatch")
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    parsed = RuntimePathContract.from_document(contract)
    if parsed.graph_sha256 != hashlib.sha256(_canonical_json(decoder["graph"])).hexdigest():
        raise ValueError("runtime path graph digest mismatch")
    selections = {row["path_id"]: {"direction": row["direction"],
                  "path_id": row["path_id"], "target": row["target"]}
                  for row in decoder["path_mapping"]}
    if len(selections) != len(decoder["path_mapping"]):
        raise ValueError("runtime path selected identity is duplicated")
    if session and set(record["compiled"]) != {"session"}:
        raise ValueError("runtime session topology identity is missing")
    for path_id, document in record["compiled"].items():
        expected_paths = list(selections.values()) if session else [selections.get(path_id)]
        if (not isinstance(document, dict)
                or document.get("schema_version") != "runtime_path_compilation.v1"
                or document.get("graph_sha256") != parsed.graph_sha256
                or document.get("contract_sha256") != parsed.identity_sha256
                or document.get("declaration") != declaration
                or None in expected_paths or document.get("paths") != expected_paths
                or document.get("topology_sha256") != hashlib.sha256(
                    _canonical_json(document.get("topology"))).hexdigest()):
            raise ValueError("runtime path compiled topology identity mismatch")


def _write_fresh_run_identity(output: Path, *, executor: ScenarioRfuzzExecutor,
                              checker_identity: dict | None,
                              client_binary: Path, run_config: dict,
                              frozen_inputs: dict | None = None) -> str:
    """Capture one actual runner and reference full decoder and evidence bodies."""
    runner = executor.fresh_manifest_document
    source_files = [{"path": name, "sha256": _sha256_file(_ROOT / name)}
                    for name in _FRESH_RUNTIME_SOURCES]
    if frozen_inputs is not None:
        if (frozen_inputs["source_files"] != source_files
                or frozen_inputs["client"]["binary_sha256"] != _sha256_file(client_binary)):
            raise ValueError("fresh RFuzz runtime or client source identity changed during run")
        source_files = frozen_inputs["source_files"]
    _write_online_artifact(output / "runner_manifest.json", _canonical_json(runner) + b"\n")
    decoder = json.loads((output / "decoder_manifest.json").read_bytes())
    runtime_material = {"status": executor.runtime_path_status,
                        "declaration": executor._runtime_declaration_document,
                        "compiled": executor.fresh_runtime_path_documents}
    _verify_runtime_path_material(runtime_material, decoder)
    identity = {
        "schema_version": "scenario_fresh_run_identity.v1",
        "runner": {"manifest_file": "runner_manifest.json",
                   "manifest_sha256": executor.fresh_manifest_sha256,
                   "status": "observed" if runner is not None else "no_runner_observed"},
        "dependency_graph": {"manifest_file": "decoder_manifest.json",
                             "sha256": _document_sha256(output / "decoder_manifest.json"),
                             "schema_version": decoder["schema_version"],
                             "semantics": "declared_decoder_rules"},
        "genome_templates": [{"index": index, "target_id": item["target_id"],
                              "genome_sha256": hashlib.sha256(
                                  _canonical_json(item["genome"])).hexdigest()}
                             for index, item in enumerate(decoder["templates"])],
        "harness_templates": _selected_templates(runner or {}),
        "checker": checker_identity,
        "runtime_paths": runtime_material,
        "checker_collector": (frozen_inputs["collector"] if frozen_inputs is not None
                              else _fresh_checker_identity(executor.checker, config={})
                              if executor.checker is not None else None),
        "feedback": {"targets_file": "targets.json",
                     "targets_sha256": _document_sha256(output / "targets.json"),
                     "coverage_semantics": "observed real RTL output predicates",
                     "interaction_schema": "interaction_feedback.v1"},
        "source_files": source_files,
        "toolchain": {"client": (frozen_inputs["client"] if frozen_inputs is not None
                                  else _rfuzz_client_identity(client_binary)),
                      "runner_manifest_file": "runner_manifest.json"},
        "run_config": run_config,
        "artifacts": {name: _sha256_file(output / name)
                      for name in sorted(_fresh_artifact_names(output))},
    }
    digest = hashlib.sha256(_canonical_json(identity)).hexdigest()
    _write_online_artifact(output / "run_identity.json", _canonical_json({
        "schema_version": "scenario_fresh_run_identity_envelope.v1",
        "sha256": digest, "identity": identity}) + b"\n")
    return digest


def _verify_fresh_run_identity(output: Path, *, checker=None, checker_config=None,
                               checker_identity_target=None) -> dict | None:
    """Verify versioned fresh evidence before any factory or RTL operation."""
    output = Path(output)
    report = json.loads((output / "report.json").read_bytes())
    path = output / "run_identity.json"
    if not path.is_file():
        if "run_identity_schema" in report or (output / "runner_manifest.json").exists():
            raise ValueError("fresh run identity is missing from a versioned bundle")
        return None
    envelope = json.loads(path.read_bytes())
    identity = envelope.get("identity")
    if (envelope.get("schema_version") != "scenario_fresh_run_identity_envelope.v1"
            or not isinstance(identity, dict)
            or identity.get("schema_version") != "scenario_fresh_run_identity.v1"
            or hashlib.sha256(_canonical_json(identity)).hexdigest() != envelope.get("sha256")
            or report.get("run_identity_sha256") != envelope.get("sha256")
            or report.get("run_identity_schema") != identity["schema_version"]):
        raise ValueError("fresh run identity digest or schema mismatch")
    artifacts = identity.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != _fresh_artifact_names(output):
        raise ValueError("fresh run identity artifact list mismatch")
    for name, digest in artifacts.items():
        artifact = output / name
        if (artifact.is_symlink() or not artifact.resolve().is_relative_to(output.resolve())
                or not artifact.is_file() or _sha256_file(artifact) != digest):
            raise ValueError("fresh run identity artifact mismatch: " + name)
    runner = json.loads((output / "runner_manifest.json").read_bytes())
    decoder = json.loads((output / "decoder_manifest.json").read_bytes())
    _verify_runtime_path_material(identity.get("runtime_paths"), decoder)
    genome_templates = [{"index": index, "target_id": item["target_id"],
                         "genome_sha256": hashlib.sha256(
                             _canonical_json(item["genome"])).hexdigest()}
                        for index, item in enumerate(decoder["templates"])]
    runner_record = identity.get("runner", {})
    if (runner is None or runner_record.get("status") != "observed"
            or runner_record.get("manifest_file") != "runner_manifest.json"
            or runner_record.get("manifest_sha256") != hashlib.sha256(_canonical_json(runner)).hexdigest()
            or identity.get("dependency_graph", {}).get("sha256") != _document_sha256(output / "decoder_manifest.json")
            or identity.get("feedback", {}).get("targets_sha256") != _document_sha256(output / "targets.json")
            or identity.get("genome_templates") != genome_templates
            or identity.get("harness_templates") != _selected_templates(runner or {})):
        raise ValueError("fresh run identity declarations mismatch")
    from myfuzz.scenario.evidence import _verify_evidence_host_identity
    _verify_evidence_host_identity(runner)
    sources = identity.get("source_files")
    if (not isinstance(sources, list) or [item.get("path") for item in sources] != list(_FRESH_RUNTIME_SOURCES)
            or any(item.get("sha256") != _sha256_file(_ROOT / item["path"]) for item in sources)):
        raise ValueError("fresh run runtime source identity mismatch")
    if identity.get("checker") != _fresh_checker_identity(
            checker, config=checker_config, identity_target=checker_identity_target):
        raise ValueError("fresh run checker identity mismatch")
    collector = identity.get("checker_collector")
    if collector is not None:
        source = collector.get("source", {})
        source_path = Path(source.get("path", ""))
        source_path = source_path if source_path.is_absolute() else _ROOT / source_path
        if not source_path.is_file() or source.get("sha256") != _sha256_file(source_path):
            raise ValueError("fresh run checker collector source identity mismatch")
    with (output / "receipts.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("manifest_sha256") is not None and row["manifest_sha256"] != runner_record["manifest_sha256"]:
                raise ValueError("fresh run receipt manifest mismatch")
            if (decoder.get("runtime_contract") is not None
                    and row.get("manifest_sha256") is not None
                    and row.get("path_id") not in identity["runtime_paths"]["compiled"]):
                raise ValueError("runtime path successful receipt topology identity is missing")
    return identity


def _write_online_artifact(path: Path, payload: bytes) -> None:
    """Replace one terminal evidence file after flushing its complete payload."""
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=path.parent,
                                         prefix=".online-final-") as handle:
            temporary_path = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _write_incomplete_run_identity(output: Path, context: dict, *, report: dict) -> str:
    """Bind retained bytes when a terminal trace or normal identity is unavailable."""
    artifacts = {path.relative_to(output).as_posix(): _sha256_file(path)
                 for path in output.rglob("*")
                 if path.is_file() and not path.is_symlink()
                 and path.name not in {"report.json", "incomplete_run_identity.json"}
                 and not path.name.startswith(".online-final-")}
    identity = {"schema_version": "scenario_incomplete_run_identity.v1",
                "execution_mode": report["execution_mode"],
                "execution_status": "incomplete",
                "replay_status": "terminal_identity_unavailable",
                "toolchain": {"client": context["frozen_inputs"]["client"]},
                "source_files": context["frozen_inputs"]["source_files"],
                "checker": context["checker_identity"], "artifacts": artifacts,
                "runtime_paths": context.get("runtime_paths"),
                "run_config": context.get("run_config"),
                "runner": context.get("runner_manifest"),
                "session": context.get("session_manifest")}
    digest = hashlib.sha256(_canonical_json(identity)).hexdigest()
    _write_online_artifact(output / "incomplete_run_identity.json", _canonical_json({
        "schema_version": "scenario_incomplete_run_identity_envelope.v1",
        "sha256": digest, "identity": identity}) + b"\n")
    return digest


def _write_online_trace(path: Path, trace: ScenarioTrace) -> None:
    """Stream the terminal trace without cloning or encoding it all at once."""
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False,
                                         dir=path.parent, prefix=".online-final-") as handle:
            temporary_path = Path(handle.name)
            for fragment in canonical_json_chunks(trace):
                handle.write(fragment)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _write_online_trace_jsonl(output: Path, trace: ScenarioTrace) -> ScenarioTrace:
    """Stream events and their canonical semantic SHA in one traversal."""
    events_path = output / "online_events.jsonl"
    temporary_path = None
    digest = hashlib.sha256()
    digest.update(b'{"events":[')
    try:
        with tempfile.NamedTemporaryFile("wb", delete=False,
                                         dir=output, prefix=".online-events-") as handle:
            temporary_path = Path(handle.name)
            for index, event in enumerate(trace.events):
                encoded = json.dumps(event, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode("utf-8")
                if index:
                    digest.update(b",")
                digest.update(encoded)
                handle.write(encoded)
                handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        digest.update(b'],"local_ticks":')
        digest.update(_canonical_json(trace.local_ticks))
        digest.update(b',"status":')
        digest.update(_canonical_json(trace.status))
        digest.update(b"}")
        semantic_sha256 = digest.hexdigest()
        if trace.semantic_sha256 and trace.semantic_sha256 != semantic_sha256:
            raise ValueError("online trace semantic SHA mismatch")
        os.replace(temporary_path, events_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    complete_trace = replace(trace, semantic_sha256=semantic_sha256)
    metadata = {"schema_version": "online_trace_jsonl.v1",
                "events_file": events_path.name, "event_count": len(trace.events),
                "genome_sha256": trace.genome_sha256,
                "status": trace.status, "local_ticks": trace.local_ticks,
                "semantic_sha256": complete_trace.semantic_sha256,
                "manifest_sha256": trace.manifest_sha256}
    payload = json.dumps(metadata, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    _write_online_artifact(output / "online_final_trace.meta.json", payload)
    return complete_trace


def _write_online_trace_zlib(output: Path, trace: ScenarioTrace, *,
                             chunk_events: int = 256) -> ScenarioTrace:
    """Save independently addressable compressed event blocks and full SHA."""
    events_path = output / "online_events.zlib"
    temporary_path = None
    digest = hashlib.sha256(b'{"events":[')
    try:
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=output,
                                         prefix=".online-events-") as handle:
            temporary_path = Path(handle.name)
        count = write_zlib_chunk_events(temporary_path, trace.events,
                                        chunk_events=chunk_events,
                                        semantic_digest=digest)
        digest.update(b'],"local_ticks":')
        digest.update(_canonical_json(trace.local_ticks))
        digest.update(b',"status":')
        digest.update(_canonical_json(trace.status))
        digest.update(b"}")
        semantic_sha256 = digest.hexdigest()
        if trace.semantic_sha256 and trace.semantic_sha256 != semantic_sha256:
            raise ValueError("online trace semantic SHA mismatch")
        os.replace(temporary_path, events_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    complete_trace = replace(trace, semantic_sha256=semantic_sha256)
    metadata = {"schema_version": "online_trace_zlib_chunks.v1",
                "events_file": events_path.name, "event_count": count,
                "genome_sha256": trace.genome_sha256,
                "status": trace.status, "local_ticks": trace.local_ticks,
                "semantic_sha256": semantic_sha256,
                "manifest_sha256": trace.manifest_sha256}
    _write_online_artifact(output / "online_final_trace.meta.json",
                           _canonical_json(metadata) + b"\n")
    return complete_trace


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _document_sha256(path: Path) -> str:
    return hashlib.sha256(_canonical_json(json.loads(path.read_bytes()))).hexdigest()


def _command_version(name: str) -> dict | None:
    executable = shutil.which(name)
    if executable is None:
        return None
    resolved = Path(executable).resolve()
    try:
        completed = subprocess.run([str(resolved), "--version"],
                                   capture_output=True, text=True,
                                   timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"path": str(resolved), "version": None,
                "size_bytes": resolved.stat().st_size if resolved.is_file() else None,
                "binary_sha256": _sha256_file(resolved) if resolved.is_file() else None}
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return {"path": str(resolved),
            "size_bytes": resolved.stat().st_size if resolved.is_file() else None,
            "binary_sha256": _sha256_file(resolved) if resolved.is_file() else None,
            "version": output[0] if completed.returncode == 0 and output else None}


def _rfuzz_client_identity(binary: Path) -> dict:
    resolved = Path(binary).resolve(strict=True)
    identity = {"basename": resolved.name, "size_bytes": resolved.stat().st_size,
                "binary_sha256": _sha256_file(resolved)}
    project = _ROOT / "third_party/rfuzz/upstream/rfuzz_reference/fuzzer"
    release = (project / "target/release").resolve()
    try:
        resolved.relative_to(release)
    except ValueError:
        identity["build_source_status"] = "external_binary_only"
        identity["build_source"] = None
        return identity
    source_paths = [project / "Cargo.toml", project / "Cargo.lock",
                    project / "build.rs", project / "rust-toolchain",
                    project / "rust-toolchain.toml", project / ".cargo/config",
                    project / ".cargo/config.toml"]
    source_paths.extend((project / "src").rglob("*.rs"))
    files = []
    for path in sorted(set(source_paths), key=lambda item: item.relative_to(project).as_posix()):
        if path.is_file():
            files.append({"path": path.relative_to(_ROOT).as_posix(),
                          "sha256": _sha256_file(path)})
    source_document = {"files": files}
    rustc = _command_version("rustc")
    cargo = _command_version("cargo")
    identity["build_source"] = {
        "sha256": hashlib.sha256(_canonical_json(source_document)).hexdigest(),
        "files": files,
        "rustc": rustc,
        "cargo": cargo,
    }
    toolchain_bound = all(
        isinstance(tool, dict) and isinstance(tool.get("binary_sha256"), str)
        for tool in (rustc, cargo))
    identity["build_source_status"] = (
        "source_and_toolchain_binary_bound" if toolchain_bound
        else "source_bound_toolchain_partial")
    return identity


def _selected_templates(runner_identity: dict) -> list[dict]:
    selected = []

    def visit(value, component: str, location: tuple[str, ...] = ()) -> None:
        if isinstance(value, dict):
            template = value.get("selected_template")
            if isinstance(template, dict):
                selected.append({"component": component,
                                 "location": ".".join(location),
                                 **template})
            for key, child in value.items():
                visit(child, component, (*location, str(key)))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, component, (*location, str(index)))

    sessions = runner_identity.get("sessions", {})
    if isinstance(sessions, dict):
        for component, identity in sorted(sessions.items()):
            visit(identity, component)
    return selected


def _online_artifact_names(output: Path, trace_format: str) -> set[str]:
    names = {"online_session_manifest.json", "decoder_manifest.json", "targets.json",
             "rfuzz.toml", "seed.bin", "online_plan.json"}
    if trace_format == "json.v1":
        names.add("online_final_trace.json")
    elif trace_format == "jsonl.v1":
        names.update(("online_final_trace.meta.json", "online_events.jsonl"))
    elif trace_format == "zlib_chunks.v1":
        names.update(("online_final_trace.meta.json", "online_events.zlib"))
    else:
        raise ValueError("unsupported online run identity trace format")
    if (output / "receipts.jsonl").exists():
        names.add("receipts.jsonl")
    for directory in ("corpus", "failures"):
        names.update(path.relative_to(output).as_posix()
                     for path in (output / directory).rglob("*") if path.is_file())
    return names


def _write_online_run_identity(output: Path, *, session_manifest: dict,
                               plan_bytes: bytes, trace: ScenarioTrace,
                               client_binary: Path,
                               run_config: dict, frozen_inputs: dict | None = None,
                               execution_mode: str = "online_cases",
                               decoder_checker: dict | None = None) -> str:
    """Persist a canonical run identity and all evidence file digests."""
    output = Path(output)
    manifest_bytes = _canonical_json(session_manifest) + b"\n"
    _write_online_artifact(output / "online_session_manifest.json", manifest_bytes)
    if hashlib.sha256(_canonical_json(session_manifest)).hexdigest() != trace.manifest_sha256:
        raise ValueError("online session manifest does not match final trace")
    plan_path = output / "online_plan.json"
    if not plan_path.is_file() or plan_path.read_bytes() != plan_bytes:
        raise ValueError("online run plan was not saved exactly")
    if hashlib.sha256(plan_bytes).hexdigest() != trace.genome_sha256:
        raise ValueError("online run plan does not match final trace")
    full_trace = output / "online_final_trace.json"
    trace_metadata = output / "online_final_trace.meta.json"
    trace_events = output / "online_events.jsonl"
    compressed_events = output / "online_events.zlib"
    if (full_trace.is_file() and not trace_metadata.exists()
            and not trace_events.exists() and not compressed_events.exists()):
        trace_format = "json.v1"
    elif (not full_trace.exists() and trace_metadata.is_file()
          and trace_events.is_file() and not compressed_events.exists()):
        trace_format = "jsonl.v1"
    elif (not full_trace.exists() and trace_metadata.is_file()
          and compressed_events.is_file() and not trace_events.exists()):
        trace_format = "zlib_chunks.v1"
    else:
        raise ValueError("online run trace artifacts are missing or ambiguous")
    artifacts = {name: _sha256_file(output / name)
                 for name in sorted(_online_artifact_names(output, trace_format))}
    runner_identity = session_manifest.get("runner")
    if not isinstance(runner_identity, dict):
        raise ValueError("online session manifest has no runner identity")
    decoder_document = json.loads((output / "decoder_manifest.json").read_bytes())
    target_document = json.loads((output / "targets.json").read_bytes())
    runtime_document = session_manifest.get("runtime_paths")
    runtime_material = ({"status": "contract_preflight",
                         "declaration": runtime_document["declaration"],
                         "compiled": {"session": runtime_document}}
                        if runtime_document is not None else
                        {"status": "legacy_unchecked", "declaration": None, "compiled": {}})
    _verify_runtime_path_material(runtime_material, decoder_document, session=True)
    component_identity_sha256 = hashlib.sha256(
        _canonical_json(runner_identity)).hexdigest()
    run_identity = {
        "schema_version": "scenario_online_run_identity.v1",
        "artifacts": artifacts,
        "session": {
            "manifest_file": "online_session_manifest.json",
            "manifest_sha256": trace.manifest_sha256,
            "component_identity_sha256": component_identity_sha256,
        },
        "components": {"identity_file": "online_session_manifest.json",
                       "identity_sha256": component_identity_sha256},
        "templates": _selected_templates(runner_identity),
        "template_status": ("declared" if _selected_templates(runner_identity)
                            else "runtime_artifact_identity_only"),
        "genome": {"format": "online_session_plan",
                   "semantics": "complete admitted session prefix",
                   "plan_file": "online_plan.json",
                   "plan_sha256": trace.genome_sha256},
        "dependency_graph": {
            "manifest_file": "decoder_manifest.json",
            "schema_version": decoder_document.get("schema_version"),
            "sha256": _document_sha256(output / "decoder_manifest.json"),
        },
        # The sources that decide how raw records become admitted cases.  They
        # are hashed independently of the session manifest so a decode-space
        # change is visible in the identity itself (and named on replay).
        "decode_space": online_decode_space_document(),
        "checker": session_manifest.get("checker"),
        "execution_mode": execution_mode,
        "decoder_checker": decoder_checker,
        "runtime_paths": runtime_material,
        "decoder_checker_collector": (frozen_inputs["collector"] if frozen_inputs else None),
        "source_files": (frozen_inputs["source_files"] if frozen_inputs else []),
        "feedback": {
            "interaction_schema": "interaction_feedback.v1",
            "coverage_semantics": "observed real RTL output predicates",
            "targets_file": "targets.json",
            "targets_sha256": hashlib.sha256(
                _canonical_json(target_document)).hexdigest(),
        },
        "toolchain": {
            "runner_identity_sha256": component_identity_sha256,
            "client": (frozen_inputs["client"] if frozen_inputs
                       else _rfuzz_client_identity(client_binary)),
        },
        "run_config": run_config,
        "trace_format": trace_format,
        "trace_file": ("online_final_trace.json" if trace_format == "json.v1"
                       else "online_final_trace.meta.json"),
        "trace": {"status": trace.status,
                  "local_ticks": trace.local_ticks,
                  "semantic_sha256": trace.semantic_sha256,
                  "manifest_sha256": trace.manifest_sha256,
                  "genome_sha256": trace.genome_sha256},
    }
    identity_sha256 = hashlib.sha256(_canonical_json(run_identity)).hexdigest()
    envelope = {"schema_version": "scenario_online_run_identity_envelope.v1",
                "sha256": identity_sha256, "identity": run_identity}
    _write_online_artifact(output / "online_run_identity.json",
                           _canonical_json(envelope) + b"\n")
    return identity_sha256


def _recorded_session_decode_space(output: Path) -> dict | None:
    """Legacy fallback: the session manifest may already record decode sources.

    Bundles produced after the decode sources joined ``_ONLINE_SOURCE_PATHS``
    but before the identity carried a ``decode_space`` member still record each
    of those files in ``online_source_files``.  Those entries are a real,
    two-sided claim about the decode space, so they are used for comparison;
    paths the manifest does not record stay ``unknown`` instead of being read
    as a mismatch.  A manifest that is missing, symlinked or unreadable yields
    no record at all (the identity checks refuse it later on their own).
    """
    path = Path(output) / "online_session_manifest.json"
    if path.is_symlink() or not path.is_file():
        return None
    try:
        document = json.loads(path.read_bytes())
    except ValueError:
        return None
    files = document.get("online_source_files") if isinstance(document, dict) else None
    if not isinstance(files, list):
        return None
    decode_paths = frozenset(ONLINE_DECODE_SPACE_PATHS)
    recorded = []
    for item in files:
        if (isinstance(item, dict) and isinstance(item.get("path"), str)
                and isinstance(item.get("sha256"), str)
                and item["path"] in decode_paths):
            recorded.append({"path": item["path"], "sha256": item["sha256"]})
    if not recorded:
        return None
    return {"schema_version": ONLINE_DECODE_SPACE_SCHEMA_VERSION,
            "source_files": recorded}


def _verify_online_run_identity(output: Path, *, plan_path: Path,
                                trace_path: Path,
                                trace: ScenarioTrace, decoder_checker=None,
                                checker_config=None,
                                checker_identity_target=None) -> dict | None:
    """Check saved live run identity before starting replay RTL.

    Missing sidecars are accepted for pre-v1 historical bundles. New live
    bundles always write the versioned envelope.

    The decode space is checked first and refused by file name when a source
    recorded by both the bundle and this tree changed: that drift moves the
    decoded payload while every saved digest still matches.  A bundle that does
    not record a path (an older identity, or a session manifest written before
    the path joined the closure) reports it as unknown instead of a mismatch.
    The returned identity carries the verdict as ``decode_space_status``; the
    saved document itself is unchanged.
    """
    path = Path(output) / "online_run_identity.json"
    if not path.exists():
        report_path = Path(output) / "report.json"
        if ((Path(output) / "online_session_manifest.json").exists()
                or report_path.is_file()
                and "online_run_identity_sha256" in json.loads(report_path.read_bytes())):
            raise ValueError("online run identity is missing from a versioned bundle")
        return None
    document = json.loads(path.read_bytes())
    if (not isinstance(document, dict)
            or set(document) != {"schema_version", "sha256", "identity"}
            or document["schema_version"] != "scenario_online_run_identity_envelope.v1"
            or not isinstance(document["identity"], dict)):
        raise ValueError("invalid online run identity envelope")
    identity = document["identity"]
    if hashlib.sha256(_canonical_json(identity)).hexdigest() != document["sha256"]:
        raise ValueError("online run identity digest mismatch")
    report_path = Path(output) / "report.json"
    if report_path.is_file():
        report = json.loads(report_path.read_bytes())
        if report.get("online_run_identity_sha256") != document["sha256"]:
            raise ValueError("online run report identity mismatch")
    if identity.get("schema_version") != "scenario_online_run_identity.v1":
        raise ValueError("unsupported online run identity schema")
    # Decode space first: a changed decode source is exactly the drift every
    # saved artifact digest still accepts, so it is refused by name before a
    # later check can mask it behind a generic message.  A bundle that predates
    # the record (or records only part of the closure) is reported as unknown,
    # never as a mismatch: missing evidence must not refuse older runs.
    recorded_space = recorded_decode_space(identity)
    if recorded_space is None:
        recorded_space = _recorded_session_decode_space(output)
    decode_space = compare_online_decode_space(recorded_space)
    decode_space.raise_for_drift()
    identity = {**identity, "decode_space_status": decode_space.document()}
    if identity.get("decoder_checker") != _fresh_checker_identity(
            decoder_checker, config=checker_config,
            identity_target=checker_identity_target):
        raise ValueError("online decoder checker identity mismatch")
    for checker_record in (identity.get("checker"), identity.get("decoder_checker_collector")):
        if isinstance(checker_record, dict) and isinstance(checker_record.get("source"), dict):
            source_record = checker_record["source"]
            source = Path(source_record.get("path", ""))
            source = source if source.is_absolute() else _ROOT / source
            if not source.is_file() or _sha256_file(source) != source_record.get("sha256"):
                raise ValueError("online checker source identity mismatch")
    expected_trace_name = ("online_final_trace.json"
                           if identity.get("trace_format") == "json.v1"
                           else "online_final_trace.meta.json"
                           if identity.get("trace_format") in
                           ("jsonl.v1", "zlib_chunks.v1")
                           else None)
    expected_trace_path = (Path(output) / expected_trace_name
                           if expected_trace_name is not None else None)
    try:
        supplied_trace_path = Path(trace_path).resolve(strict=True)
        declared_trace_path = (expected_trace_path.resolve(strict=True)
                               if expected_trace_path is not None else None)
    except OSError as exc:
        raise ValueError("online run identity trace path is missing") from exc
    if (identity.get("trace_file") != expected_trace_name
            or supplied_trace_path != declared_trace_path):
        raise ValueError("online run identity trace path mismatch")
    artifacts = identity.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("invalid online run identity artifact list")
    if set(artifacts) != _online_artifact_names(Path(output), identity.get("trace_format")):
        raise ValueError("online run identity artifact list mismatch")
    for name, expected in artifacts.items():
        if not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("invalid online run identity artifact name")
        artifact = Path(output) / name
        if (artifact.is_symlink() or not artifact.resolve().is_relative_to(Path(output).resolve())
                or not artifact.is_file() or not isinstance(expected, str)
                or _sha256_file(artifact) != expected):
            raise ValueError(f"online run identity artifact mismatch: {name}")
    plan_hash = _sha256_file(Path(plan_path))
    if (plan_hash != trace.genome_sha256
            or plan_hash != identity.get("genome", {}).get("plan_sha256")):
        raise ValueError("online run identity plan mismatch")
    manifest_path = Path(output) / "online_session_manifest.json"
    manifest_document = json.loads(manifest_path.read_bytes())
    manifest_hash = hashlib.sha256(_canonical_json(manifest_document)).hexdigest()
    runner_identity = manifest_document.get("runner")
    if isinstance(runner_identity, dict) and "host_sources" in runner_identity:
        from myfuzz.scenario.evidence import _verify_evidence_host_identity
        _verify_evidence_host_identity(runner_identity)
    drifted_sources = []
    for item in manifest_document.get("online_source_files", []):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            drifted_sources.append(repr(item))
            continue
        source = _ROOT / item["path"]
        if not source.is_file() or _sha256_file(source) != item.get("sha256"):
            drifted_sources.append(item["path"])
    if drifted_sources:
        raise ValueError("online runtime source identity mismatch: "
                         + ", ".join(drifted_sources))
    sources = identity.get("source_files", [])
    if sources and (not isinstance(sources, list)
                   or [item.get("path") for item in sources] != list(_FRESH_RUNTIME_SOURCES)
                   or any(item.get("sha256") != _sha256_file(_ROOT / item["path"])
                          for item in sources)):
        raise ValueError("online transport source identity mismatch")
    decoder_path = Path(output) / "decoder_manifest.json"
    targets_path = Path(output) / "targets.json"
    decoder_document = json.loads(decoder_path.read_bytes())
    _verify_runtime_path_material(identity.get("runtime_paths"), decoder_document, session=True)
    runtime_document = manifest_document.get("runtime_paths")
    if runtime_document is not None and identity.get("runtime_paths", {}).get("compiled") != {
            "session": runtime_document}:
        raise ValueError("runtime session manifest topology mismatch")
    if (not isinstance(runner_identity, dict)
            or identity.get("components", {}).get("identity_file")
            != "online_session_manifest.json"
            or identity.get("components", {}).get("identity_sha256")
            != hashlib.sha256(_canonical_json(runner_identity)).hexdigest()
            or identity.get("toolchain", {}).get("runner_identity_sha256")
            != hashlib.sha256(_canonical_json(runner_identity)).hexdigest()
            or identity.get("session", {}).get("component_identity_sha256")
            != hashlib.sha256(_canonical_json(runner_identity)).hexdigest()
            or identity.get("dependency_graph", {}).get("sha256")
            != _document_sha256(decoder_path)
            or identity.get("feedback", {}).get("targets_sha256")
            != _document_sha256(targets_path)
            or identity.get("checker") != manifest_document.get("checker")):
        raise ValueError("online run identity declarations mismatch")
    saved_plan_hash = _sha256_file(Path(output) / "online_plan.json")
    supplied_plan_hash = _sha256_file(Path(plan_path))
    if identity.get("trace_format") == "json.v1":
        if not (Path(output) / "online_final_trace.json").is_file():
            raise ValueError("online run identity trace artifact is missing")
    elif identity.get("trace_format") in ("jsonl.v1", "zlib_chunks.v1"):
        metadata_path = Path(output) / "online_final_trace.meta.json"
        metadata = json.loads(metadata_path.read_bytes())
        compressed = identity.get("trace_format") == "zlib_chunks.v1"
        if (set(metadata) != {"schema_version", "events_file", "event_count",
                              "genome_sha256", "status", "local_ticks",
                              "semantic_sha256", "manifest_sha256"}
                or metadata.get("schema_version") != (
                    "online_trace_zlib_chunks.v1" if compressed else "online_trace_jsonl.v1")
                or metadata.get("events_file") != (
                    "online_events.zlib" if compressed else "online_events.jsonl")
                or metadata.get("event_count") != len(trace.events)
                or metadata.get("genome_sha256") != trace.genome_sha256
                or metadata.get("status") != trace.status
                or metadata.get("local_ticks") != trace.local_ticks
                or metadata.get("semantic_sha256") != trace.semantic_sha256
                or metadata.get("manifest_sha256") != trace.manifest_sha256):
            raise ValueError("online run identity trace metadata mismatch")
    else:
        raise ValueError("unsupported online run identity trace format")
    trace_identity = identity.get("trace", {})
    if (saved_plan_hash != supplied_plan_hash
            or manifest_hash != trace.manifest_sha256
            or identity.get("session", {}).get("manifest_sha256") != trace.manifest_sha256
            or trace_identity.get("manifest_sha256") != trace.manifest_sha256
            or trace_identity.get("genome_sha256") != trace.genome_sha256
            or trace_identity.get("semantic_sha256") != trace.semantic_sha256
            or trace_identity.get("status") != trace.status
            or trace_identity.get("local_ticks") != trace.local_ticks):
        raise ValueError("online run identity trace mismatch")
    return identity


def run_scenario_rfuzz_live(*, executor: ScenarioRfuzzExecutor,
                            client_binary: Path, output_dir: Path,
                            duration_seconds: float,
                            seed_records: tuple[bytes, ...] = (bytes(8),),
                            max_tests: int = 10000,
                            search_seed: int | None = None,
                            max_runs_per_batch: int = 8,
                            compressed_trace: bool = False) -> ScenarioLiveResult:
    """Run transport and persist the actual owned prefix on every exit."""
    online = (isinstance(executor, ScenarioRfuzzExecutor)
              and executor.online_decoder is not None)
    if online:
        executor._online_live_max_tests = max_tests
        executor._online_live_duration_seconds = duration_seconds
    # Ownership is established by mkdir inside _run, never inferred from a
    # directory appearing during failed preflight.
    if isinstance(executor, ScenarioRfuzzExecutor):
        executor._live_context = None
    run_error = None
    try:
        return _run_scenario_rfuzz_live(
            executor=executor, client_binary=client_binary, output_dir=output_dir,
            duration_seconds=duration_seconds, seed_records=seed_records,
            max_tests=max_tests, search_seed=search_seed,
            max_runs_per_batch=max_runs_per_batch,
            compressed_trace=compressed_trace)
    except BaseException as exc:
        run_error = exc
        raise
    finally:
        context = getattr(executor, "_live_context", None)
        if context is None and online:
            # The caller supplied an already live session. Preflight owns no
            # output, but must still release that supplied RTL exactly once.
            try:
                executor._finish_online_session()
            except BaseException:
                if run_error is None:
                    raise
        if context is not None:
            finalization_started = time.monotonic()
            finalization_timing = {name: 0.0 for name in (
                "session_finish", "plan_write", "trace_write", "identity_write")}
            output = context["output"]
            errors = []
            report_path = output / "report.json"
            report = {}
            if report_path.is_file():
                try:
                    report = json.loads(report_path.read_bytes())
                except (OSError, ValueError) as exc:
                    errors.append(exc)
            statuses = {}
            for receipt in executor.receipts:
                statuses[receipt.status] = statuses.get(receipt.status, 0) + 1
            report.update(
                tests=len(executor.receipts), statuses=statuses,
                completed_feedback_exchanges=context["exchanges"],
                client_returncode=context["client_returncode"],
                elapsed_seconds=time.monotonic() - context["started"],
                effective_search_seconds=context["effective_search_seconds"],
                decoder_manifest_sha256=context["decoder_manifest_sha256"],
                execution_status=("failed" if run_error is not None
                                  or context["client_returncode"] not in (0, None)
                                  else "complete"),
                execution_mode=("online_cases" if online else "continuous_decoder"
                                if executor.session is not None else "fresh_genomes"))
            report["runtime_path_status"] = executor.runtime_path_status
            # Refreshed after the terminal settlement, which can only add
            # evidence: a chain settled at the end of the journal never scores.
            report["closed_loop_energy"] = _closed_loop_energy_record(executor)
            # The live switch counters only grow, so the terminal refresh states
            # the whole run rather than the last feedback interval.
            report["path_switch"] = _path_switch_record(executor)
            initial_ram_data = _initial_ram_data_record(executor)
            if initial_ram_data is not None:
                # Only a run that declared the operator states it, so an
                # undeclared run's report is byte-identical to before.
                report["initial_ram_data"] = initial_ram_data
            if run_error is not None:
                report["error"] = f"{type(run_error).__name__}: {run_error}"
            if "transport_cleanup_errors" in context:
                report["transport_cleanup_errors"] = context["transport_cleanup_errors"]
            config = {"run_id": executor.run_id, "duration_seconds": duration_seconds,
                      "max_tests": max_tests, "search_seed": search_seed,
                      "max_runs_per_batch": max_runs_per_batch,
                      "feedback_interval": executor.feedback_interval}
            if isinstance(executor, ScenarioRfuzzExecutor):
                # The switch belongs to the run identity: an A/B pair with the
                # same seed and test budget is only readable if each arm says
                # which search behaviour produced it.
                config["closed_loop_energy"] = bool(executor.closed_loop_energy)
                config["closed_loop_energy_source"] = executor.closed_loop_energy_source
                config["path_switch"] = bool(executor.path_switch)
                config["path_switch_source"] = executor.path_switch_source
                if initial_ram_data is not None:
                    config["initial_ram_data"] = bool(initial_ram_data["enabled"])
                    config["initial_ram_data_source"] = initial_ram_data["source"]
            if compressed_trace:
                config["compressed_trace"] = "zlib_chunks.v1"
            context["run_config"] = config
            if executor.session is None:
                context["runner_manifest"] = executor.fresh_manifest_document
                context["runtime_paths"] = {"status": executor.runtime_path_status,
                    "declaration": executor._runtime_declaration_document,
                    "compiled": executor.fresh_runtime_path_documents}
            else:
                try:
                    context["session_manifest"] = executor.session.manifest_document
                    context["runtime_paths"] = context["session_manifest"].get("runtime_paths")
                except RuntimeError:
                    pass
            try:
                if executor.session is None:
                    report["run_identity_schema"] = "scenario_fresh_run_identity.v1"
                    report["run_identity_sha256"] = _write_fresh_run_identity(
                        output, executor=executor,
                        checker_identity=context["checker_identity"],
                        client_binary=context["binary"],
                        frozen_inputs=context["frozen_inputs"], run_config=config)
                else:
                    finish_error = None
                    phase_started = time.monotonic()
                    try:
                        defer_semantic_hash = (
                            compressed_trace or len(executor.session.runner.events)
                            >= _JSONL_TRACE_EVENT_THRESHOLD)
                        trace, plan_hex = executor._finish_online_session(
                            defer_semantic_hash=defer_semantic_hash)
                    except BaseException as exc:
                        finish_error = exc
                        trace = executor._online_final_trace
                        plan_hex = executor._online_final_plan_hex
                    finally:
                        finalization_timing["session_finish"] = (
                            time.monotonic() - phase_started)
                    if plan_hex is not None:
                        phase_started = time.monotonic()
                        plan_bytes = bytes.fromhex(plan_hex)
                        _write_online_artifact(output / "online_plan.json", plan_bytes)
                        finalization_timing["plan_write"] = (
                            time.monotonic() - phase_started)
                    if trace is not None:
                        phase_started = time.monotonic()
                        try:
                            if compressed_trace:
                                trace = _write_online_trace_zlib(output, trace)
                                executor._online_final_trace = trace
                            elif len(trace.events) >= _JSONL_TRACE_EVENT_THRESHOLD:
                                trace = _write_online_trace_jsonl(output, trace)
                                executor._online_final_trace = trace
                            else:
                                _write_online_trace(output / "online_final_trace.json", trace)
                        finally:
                            finalization_timing["trace_write"] = (
                                time.monotonic() - phase_started)
                    report["run_identity_schema"] = "scenario_online_run_identity.v1"
                    report["session_status"] = trace.status if trace is not None else "not_started"
                    if trace is not None and plan_hex is not None:
                        phase_started = time.monotonic()
                        report["online_run_identity_sha256"] = _write_online_run_identity(
                            output, session_manifest=executor.session.manifest_document,
                            plan_bytes=plan_bytes, trace=trace,
                            client_binary=context["binary"], run_config=config,
                            frozen_inputs=context["frozen_inputs"],
                            execution_mode=report["execution_mode"],
                            decoder_checker=context["checker_identity"])
                        finalization_timing["identity_write"] = (
                            time.monotonic() - phase_started)
                    if finish_error is not None:
                        raise finish_error
            except BaseException as exc:
                errors.append(exc)
            if errors:
                report["execution_status"] = "failed"
                report["finalization_errors"] = [f"{type(exc).__name__}: {exc}" for exc in errors]
            if ("run_identity_sha256" not in report
                    and "online_run_identity_sha256" not in report):
                try:
                    report["incomplete_run_identity_sha256"] = _write_incomplete_run_identity(
                        output, context, report=report)
                    report["run_identity_schema"] = "scenario_incomplete_run_identity.v1"
                    report["execution_status"] = "incomplete"
                except BaseException as exc:
                    errors.append(exc)
            if online:
                finalization_timing["total_before_report"] = (
                    time.monotonic() - finalization_started)
                report["finalization_timing_seconds"] = finalization_timing
            try:
                _write_online_artifact(report_path, _canonical_json(report) + b"\n")
            except BaseException as exc:
                errors.append(exc)
            if errors and run_error is None:
                raise errors[0]
