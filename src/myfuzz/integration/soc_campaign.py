"""Fail-closed orchestration for source-backed SoC RFuzz campaigns.

The existing :mod:`rfuzz_live` runner owns the official FIFO/shared-memory
exchange and the RTL child process.  This module is the SoC-specific evidence
boundary around it: it validates the opt-in, records transport and receipt
identities, keeps source/target execution separate from sampled coverage, and
publishes a bounded ``soc_result.v1`` report even when build or client startup
fails.

This is intentionally usable in preflight mode without a client binary.  A
real mutation campaign never silently falls back to a Python or all-zero probe;
it requires ``MYFUZZ_SOC_REAL=1`` and an explicit official RFuzz client.

Interrupted-run policy (interrupted-run-policy.v1)
--------------------------------------------------
The pinned official client predates the local SIGINT-at-Yield patch and cannot
exit rc=0: it drains for minutes after SIGINT and then panics in queue.rs.  A
campaign whose client was ended by *our* bounded drain is therefore classified
as the distinguishable terminal state completed_with_client_termination instead
of a plain failure, but only when the run retained positive evidence:

* at least one FIFO reply receipt (real shared-memory request/response),
* a non-empty retained corpus, and
* a recorded RFuzz input transport identity,

plus a clean owned-process-group/shared-memory cleanup and no evidence error.
The report keeps the retained evidence and the exact termination reason: the
bounded-drain kind, the deadline SIGINT time, the supervisor signal (if any),
the client's own exit status and its stderr tail.

The policy is fail-closed in every other direction.  It is only reachable from
the client phase, so a build/compile/transport failure can never be masked; it
requires the deadline SIGINT to have been sent, so a spontaneous client crash
stays a failure; it requires receipts, a corpus and the transport identity, so a
zero-input probe (already rejected before any output directory exists) or an
empty run can never reach it.  The replay step still runs for an accepted
interrupted run: the retained corpus is rebuilt with a fresh binary and its
coverage identity is verified.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import signal

from myfuzz.contracts import content_hash

from .rfuzz_live import build_corpus_manifest, replay_corpus, run_live
from .rfuzz_simulator import probe_soc_dependencies, real_soc_opt_in


SOC_RESULT_SCHEMA = "soc_result.v1"
_MODES = frozenset({"cpu_only", "mmio_only", "mixed"})
_RECEIPT_LIMIT = 4096

#: Distinguishable terminal state for a run ended by our own bounded drain.
CLIENT_TERMINATED_STATUS = "completed_with_client_termination"
CLIENT_TERMINATED_FINAL_STATUS = "passed_with_client_termination"
_STDERR_TAIL_LINES = 20
_STDERR_TAIL_CHARS = 8192

INTERRUPTED_RUN_POLICY = {
    "name": "interrupted-run-policy.v1",
    "terminal_state": CLIENT_TERMINATED_STATUS,
    "final_status": CLIENT_TERMINATED_FINAL_STATUS,
    "evidence_rule": (
        "at least one FIFO reply receipt AND a non-empty corpus AND a recorded "
        "input transport identity AND clean cleanup AND no evidence error"),
    "termination_sources": [
        "bounded-drain-timeout: the deadline SIGINT was sent and the drain limit expired",
        "bounded-drain-client-signal: the client exited with a negative status after the deadline SIGINT (our drain signal)",
        "bounded-drain-client-exit: the client exited non-zero on its own after the deadline SIGINT (for example the queue.rs panic)",
    ],
    "still_failure": [
        "build/compile/transport failure (the client phase is never reached)",
        "client failure before the deadline SIGINT (spontaneous crash or startup failure)",
        "termination without a FIFO reply receipt, a retained corpus or the input transport identity",
        "leaked owned shared-memory segments or malformed receipt evidence",
        "a signal delivered to the harness itself, which stays an operator abort",
        "zero-input probe (rejected before any output directory is created)",
    ],
    "replay": (
        "an accepted interrupted run still rebuilds the retained corpus with a "
        "fresh binary and verifies the coverage identity"),
}


class SocCampaignError(RuntimeError):
    """A campaign could not reach a trustworthy acceptance state."""


class SocCampaignProtocolError(SocCampaignError):
    """A protocol/model or reset-contract violation, not a software trap."""


class SocCampaignSoftwareTrap(SocCampaignError):
    """A legal software trap observed by a source-backed CPU."""


def _hash(value: object) -> str:
    return content_hash(value)


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _write_report(path: Path, report: Mapping[str, object]) -> None:
    """Publish a small deterministic report, replacing only this run's file."""
    payload = (json.dumps(_plain(report), ensure_ascii=True, sort_keys=True,
                          indent=2, allow_nan=False) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def _string(value: object, label: str, *, default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}:nonempty-string-required")
    return value


def _nonnegative_int(value: object, label: str, *, default: int | None = None) -> int:
    if value is None and default is not None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label}:nonnegative-integer-required")
    return value


def _positive_duration(value: object, label: str, *, default: float = 30.0) -> float:
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label}:finite-positive-required")
    if not math.isfinite(value) or value <= 0 or value > 86400:
        raise ValueError(f"{label}:finite-positive-required")
    return float(value)


def _cpu_id(value: object) -> str:
    if isinstance(value, Mapping):
        value = value.get("id", value.get("name", value.get("top_module")))
    return _string(value, "cpu")


def _peripheral_ids(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("peripherals:array-required")
    result: list[str] = []
    for item in value:
        if isinstance(item, Mapping):
            item = item.get("id", item.get("component", item.get("name")))
        item = _string(item, "peripheral")
        if item in result:
            raise ValueError("peripherals:duplicate")
        result.append(item)
    return result


def _source_paths(config: Mapping[str, object]) -> tuple[str, ...]:
    value = config.get("source_paths", ())
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("source_paths:array-required")
    paths: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or item.startswith("/"):
            raise ValueError("source_paths:relative-path-required")
        if any(part in {"", ".", ".."} for part in item.split("/")):
            raise ValueError("source_paths:path-escape")
        paths.append(item)
    return tuple(paths)


def _normalise_config(config: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(config, Mapping):
        raise ValueError("config:mapping-required")
    config_id = _string(config.get("config_id", config.get("cell_id")), "config_id")
    mode = _string(config.get("mode"), "mode", default="mixed")
    if mode not in _MODES:
        raise ValueError("mode:unsupported")
    cpu = _cpu_id(config.get("cpu"))
    peripherals = _peripheral_ids(config.get("peripherals", config.get("components", ())))
    families = config.get("families", ())
    if isinstance(families, (str, bytes)) or not isinstance(families, Sequence):
        raise ValueError("families:array-required")
    family_ids = [_string(item, "family") for item in families]
    if len(set(family_ids)) != len(family_ids):
        raise ValueError("families:duplicate")
    seed = _nonnegative_int(config.get("seed"), "seed", default=0)
    duration = _positive_duration(config.get("duration_seconds"), "duration_seconds")
    simulator = _string(config.get("simulator"), "simulator", default="verilator")
    if simulator not in {"verilator", "icarus"}:
        raise ValueError("simulator:unsupported")
    mutation_mode = _string(config.get("mutation_mode"), "mutation_mode", default="official_rfuzz")
    if mutation_mode != "official_rfuzz":
        raise ValueError("mutation_mode:official-rfuzz-required")
    if config.get("zero_input_probe") is True or config.get("probe_only") is True:
        raise ValueError("zero-input-probe-cannot-substitute-for-rfuzz")
    seed_cycles = _nonnegative_int(config.get("seed_cycles"), "seed_cycles", default=5)
    if not 1 <= seed_cycles <= 200:
        raise ValueError("seed_cycles:positive-bounded-required")
    return {
        "config_id": config_id,
        "cell_id": _string(config.get("cell_id"), "cell_id", default=config_id),
        "cpu": cpu,
        "peripherals": peripherals,
        "families": family_ids,
        "mode": mode,
        "seed": seed,
        "duration_seconds": duration,
        "simulator": simulator,
        "mutation_mode": mutation_mode,
        "source_paths": _source_paths(config),
        "client_binary": config.get("client_binary", config.get("client")),
        "seed_cycles": seed_cycles,
        "reset_contract": config.get("reset_contract", {}),
        "source_target_transactions": config.get("source_target_transactions"),
        "coverage_universe": config.get("coverage_universe"),
        "raw": dict(config),
    }


def _reset_document(value: object) -> dict[str, object]:
    required = ("driver", "memory", "cpu", "peripherals", "irq", "coverage")
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        raise ValueError("reset_contract:mapping-required")
    fields: dict[str, object] = {}
    for name in required:
        current = value.get(name, False)
        if not isinstance(current, bool):
            raise ValueError(f"reset_contract:{name}:boolean-required")
        fields[name] = current
    return {
        "sample_reset": fields,
        "all_state_domains_declared": all(fields.values()),
        "policy": "reset at every RFuzz sample; no state carried across samples",
    }


def _resolve_path(root: Path, value: object) -> Path | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("client_binary:path-required")
    path = Path(value)
    return path if path.is_absolute() else root / path


def _client_probe(root: Path, value: object) -> dict[str, object]:
    path = _resolve_path(root, value)
    if path is None:
        return {"requested": False, "path": None, "ready": False, "status": "not-configured"}
    resolved = path.resolve()
    ready = resolved.is_file() and os.access(resolved, os.X_OK)
    return {
        "requested": True,
        "path": str(resolved),
        "ready": ready,
        "status": "ready" if ready else "missing-or-not-executable",
    }


def preflight_soc_campaign(
    config: Mapping[str, object], *, root: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Return a machine-readable preflight without launching RFuzz."""
    normal = _normalise_config(config)
    root = Path(root or config.get("root") or Path.cwd()).resolve()
    opt_in = real_soc_opt_in(environment)
    try:
        dependencies = probe_soc_dependencies(
            root, source_paths=normal["source_paths"],
            simulator=normal["simulator"], require_real=False,
        )
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        dependencies = {
            "schema_version": "soc_dependency_probe.v1",
            "ready": False, "status": "error",
            "error": f"{type(error).__name__}: {error}",
        }
    client = _client_probe(root, normal["client_binary"])
    reset = _reset_document(normal["reset_contract"])
    # ``probe_soc_dependencies`` intentionally reads the process environment
    # for its own strict boundary.  This API also accepts an injected mapping
    # for tests and supervisors, so reflect that effective opt-in explicitly.
    dependencies["opt_in"] = opt_in
    ready = bool(dependencies.get("ready")) and (
        not client["requested"] or bool(client["ready"])
    )
    return {
        "schema_version": "soc_preflight.v1",
        "config_id": normal["config_id"],
        "cell_id": normal["cell_id"],
        "cpu": normal["cpu"],
        "peripherals": normal["peripherals"],
        "families": normal["families"],
        "mode": normal["mode"],
        "simulator": normal["simulator"],
        "root": str(root),
        "opt_in": opt_in,
        "dependencies": dependencies,
        "client": client,
        "reset": reset,
        "ready": ready,
        "unsupported": [],
        "policy": "preflight never launches a client; real run requires MYFUZZ_SOC_REAL=1",
    }


def _call_forms(hook: Callable[..., object], forms: Sequence[tuple[object, ...]]) -> object:
    """Invoke a hook using an explicitly supported positional form.

    Build hooks commonly accept ``(config, directory)`` while small tests and
    adapters often accept only ``(directory,)``.  Selecting among declared
    forms avoids passing a config object into an artifact-only hook and avoids
    catching a ``TypeError`` raised inside the hook itself.
    """
    try:
        signature = inspect.signature(hook)
    except (TypeError, ValueError):
        return hook(*forms[0])
    parameters = tuple(signature.parameters.values())
    if any(item.kind == item.VAR_POSITIONAL for item in parameters):
        return hook(*forms[0])
    positional = tuple(item for item in parameters
                       if item.kind in (item.POSITIONAL_ONLY, item.POSITIONAL_OR_KEYWORD))
    required = sum(item.default is item.empty for item in positional)
    for form in forms:
        if required <= len(form) <= len(positional):
            return hook(*form)
    raise TypeError("campaign hook has incompatible signature")


def _error_category(error: BaseException, phase: str) -> str:
    if isinstance(error, SocCampaignSoftwareTrap):
        return "software_trap"
    if isinstance(error, SocCampaignProtocolError):
        return "protocol_or_model"
    if isinstance(error, KeyboardInterrupt):
        return "interrupted"
    if isinstance(error, TimeoutError) or phase == "timeout":
        return "timeout"
    if phase in {"build", "compile"}:
        return "compile"
    if phase == "client":
        return "client"
    if isinstance(error, ValueError):
        return "protocol_or_model"
    text = str(error).lower()
    if "software trap" in text or "legal trap" in text:
        return "software_trap"
    if "simulator" in text or "protocol" in text or "model" in text:
        return "protocol_or_model"
    if "rfuzz client" in text or "client exited" in text:
        return "client"
    return "runtime"


def _error_record(error: BaseException, phase: str) -> dict[str, object]:
    return {
        "category": _error_category(error, phase),
        "phase": phase,
        "type": type(error).__name__,
        "message": str(error)[:4096],
    }


def _transport_document(artifact: object) -> dict[str, object] | None:
    transport = getattr(artifact, "transport", None)
    if transport is None:
        return None
    document = transport.document() if callable(getattr(transport, "document", None)) else transport
    if not isinstance(document, Mapping):
        return None
    plain = _plain(document)
    return plain if isinstance(plain, dict) else None


def _receipt_document(value: object) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if value is None:
        return [], []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return [], [{"category": "evidence", "message": "fifo receipts are not an array"}]
    rows: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            errors.append({"category": "evidence", "message": f"receipt {index} is not an object"})
            continue
        raw = item.get("input_sha256")
        coverage = item.get("coverage_sha256")
        if not isinstance(raw, str) or not raw or not isinstance(coverage, str) or not coverage:
            errors.append({"category": "evidence", "message": f"receipt {index} lacks input/coverage identity"})
            continue
        if item.get("status") != "fifo_reply_and_rtl_completed":
            errors.append({"category": "evidence", "message": f"receipt {index} is not a completed FIFO/RTL exchange"})
            continue
        if item.get("transport") != "sysv-shared-memory-rfuzz-coverage-buffer":
            errors.append({"category": "evidence", "message": f"receipt {index} has the wrong transport"})
            continue
        rows.append({
            "input_sha256": raw,
            "coverage_sha256": coverage,
            "status": item["status"],
            "transport": item["transport"],
        })
        if len(rows) >= _RECEIPT_LIMIT:
            break
    return rows, errors


def _positive_count(value: object) -> bool:
    """Return true when a nested evidence document contains a positive count."""
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return math.isfinite(value) and value > 0
    if isinstance(value, Mapping):
        return any(_positive_count(item) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(_positive_count(item) for item in value)
    return False


def _measured_fuzz_seconds(run_result: Mapping[str, object]) -> float:
    """Measure fuzz time before client drain, falling back to total run time."""
    value = run_result.get("interrupt_elapsed_seconds",
                           run_result.get("duration_seconds", 0))
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value) if math.isfinite(value) and value >= 0 else 0.0


def _campaign_evidence_gaps(
    normal: Mapping[str, object], report: Mapping[str, object],
    run_result: Mapping[str, object], receipt_errors: Sequence[object],
) -> list[str]:
    """List every unmet acceptance fact; callers use one gate for all exits."""
    gaps: list[str] = []
    receipts = report.get("fifo_reply_receipts", [])
    if not receipts:
        gaps.extend(("fifo_reply_receipt", "completed_fifo_receipt"))
    if receipt_errors:
        gaps.append("malformed_fifo_receipt")
    if _measured_fuzz_seconds(run_result) < float(normal["duration_seconds"]):
        gaps.append("requested_fuzz_duration")
    execution = report.get("rtl_execution", {})
    if not isinstance(execution, Mapping) or not _positive_count(
            execution.get("coverage_records", 0)):
        gaps.append("rtl_coverage")
    transactions = report.get("source_target_transactions", {})
    if (not isinstance(transactions, Mapping)
            or transactions.get("status") != "observed"
            or not _positive_count(
                transactions.get("source", {}))):
        gaps.append("source_transactions")
    if (not isinstance(transactions, Mapping)
            or transactions.get("status") != "observed"
            or not _positive_count(
                transactions.get("target", {}))):
        gaps.append("target_transactions")
    corpus = report.get("corpus", {})
    if (not isinstance(corpus, Mapping) or corpus.get("status") != "verified"
            or not _positive_count(corpus.get("entries", 0))):
        gaps.append("verified_corpus")
    transport = report.get("input_transport", {})
    if not isinstance(transport, Mapping) or transport.get("status") != "observed":
        gaps.append("input_transport_identity")
    cleanup = report.get("cleanup", {})
    if not isinstance(cleanup, Mapping) or cleanup.get("status") != "clean":
        gaps.append("clean_cleanup")
    replay = report.get("replay", {})
    if (not isinstance(replay, Mapping) or replay.get("status") != "passed"
            or not _positive_count(replay.get("entries", 0))):
        gaps.append("rebuild_replay")
    return sorted(set(gaps))


def _live_report(live_dir: Path) -> dict[str, object] | None:
    """Read the runner-owned live report retained before it raised."""
    path = Path(live_dir) / "report.json"
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def _client_exit_description(returncode: object) -> str:
    if returncode is None:
        return "not-reaped"
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        return "unknown"
    if returncode < 0:
        try:
            return "terminated-by-signal:" + signal.Signals(-returncode).name
        except ValueError:
            return "terminated-by-signal:%d" % returncode
    return "exited-%d" % returncode


def _stderr_tail(live_dir: Path) -> list[str]:
    """Retain a bounded tail of the client's own stdout/stderr log."""
    path = Path(live_dir) / "client.log"
    if not path.is_file():
        return []
    try:
        data = path.read_bytes()[-_STDERR_TAIL_CHARS:]
    except OSError:
        return []
    text = data.decode("utf-8", "replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return [line[:512] for line in lines[-_STDERR_TAIL_LINES:]]


def _client_termination_document(
    error: BaseException, live: object, live_dir: Path,
) -> dict[str, object] | None:
    """Record the exact reason our bounded drain ended the client.

    The deadline SIGINT is what makes the termination ours.  Without it the
    client failed on its own, which must stay a plain failure; a signal
    delivered to the harness itself also stays an operator abort.
    """
    if not isinstance(live, Mapping):
        return None
    interrupted_at = live.get("interrupt_elapsed_seconds")
    returncode = live.get("returncode")
    if interrupted_at is None:
        return None
    if isinstance(error, TimeoutError):
        kind, trigger = "bounded-drain-timeout", "timeout"
    elif (isinstance(error, RuntimeError)
          and str(error).startswith("RFuzz client exited")
          and isinstance(returncode, int) and not isinstance(returncode, bool)
          and returncode != 0):
        if returncode < 0:
            kind, trigger = "bounded-drain-client-signal", "signal"
        else:
            kind, trigger = "bounded-drain-client-exit", "client-exit"
    else:
        return None
    supervisor_signal = live.get("termination_signal")
    return {
        "status": "bounded-drain-termination",
        "kind": kind,
        "trigger": trigger,
        "supervisor_signal": (supervisor_signal
                              if isinstance(supervisor_signal, str) else None),
        "client_returncode": returncode if isinstance(returncode, int) else None,
        "client_exit": _client_exit_description(returncode),
        "bounded_drain": {
            "sent_sigint_after_seconds": interrupted_at,
            "drain_limit_seconds": live.get("drain_limit_seconds"),
            "drain_seconds": live.get("drain_seconds"),
        },
        "client_stderr_tail": _stderr_tail(live_dir),
        "client_log": str(Path(live_dir) / "client.log"),
        "error": {"type": type(error).__name__, "message": str(error)[:4096]},
    }


def _recover_terminated_client_run(
    error: BaseException, artifact: object, live_dir: Path,
    report: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]] | None:
    """Recover retained evidence for a bounded-drain client termination.

    Returns ``(live_result, termination)`` only when the failure was caused by
    our bounded drain and the run retained at least one FIFO reply receipt, a
    non-empty corpus and the input transport identity.  Otherwise the caller
    re-raises the original error: an unevidenced termination stays a failure.
    """
    if report.get("mutation", {}).get("zero_input_probe") is not False:
        return None
    live = _live_report(live_dir)
    termination = _client_termination_document(error, live, live_dir)
    if termination is None:
        return None
    receipts, receipt_errors = _receipt_document(live.get("fifo_reply_receipts"))
    corpus_dir = Path(live_dir) / "corpus"
    corpus_entries = (len(tuple(corpus_dir.glob("entry_*.json")))
                      if corpus_dir.is_dir() else 0)
    missing: list[str] = []
    if not receipts:
        missing.append("fifo_reply_receipt")
    if corpus_entries < 1:
        missing.append("retained_corpus")
    if report.get("input_transport", {}).get("status") != "observed":
        missing.append("input_transport_identity")
    if receipt_errors:
        missing.append("malformed_fifo_receipt")
    termination["retained_evidence"] = {
        "fifo_reply_receipts": len(receipts),
        "fifo_reply_receipt_count": live.get("fifo_reply_receipt_count"),
        "corpus_entries": corpus_entries,
        "input_transport_status": report.get("input_transport", {}).get("status"),
        "input_transport_hash": report.get("input_transport", {}).get("transport_hash"),
    }
    termination["policy"] = {
        "name": INTERRUPTED_RUN_POLICY["name"],
        "applied": not missing,
        "evidence_rule": INTERRUPTED_RUN_POLICY["evidence_rule"],
        "missing": missing,
        "zero_input_probe": False,
        "phases_allowed": ["client"],
    }
    report["client_termination"] = termination
    if missing:
        return None
    result = dict(live)
    result["corpus_manifest"] = None
    result["corpus_manifest_error"] = None
    try:
        # The live report only samples the receipt identities (bounded), so a
        # per-entry receipt binding is claimed only when the sample is complete.
        retained_count = live.get("fifo_reply_receipt_count")
        complete_sample = (isinstance(retained_count, int)
                           and not isinstance(retained_count, bool)
                           and retained_count == len(receipts))
        if complete_sample:
            feedback = {(row["input_sha256"], row["coverage_sha256"])
                        for row in receipts}
            manifest = build_corpus_manifest(artifact, corpus_dir,
                                             feedback_receipts=feedback)
            termination["corpus_receipt_binding"] = "complete-receipt-sample"
        else:
            manifest = build_corpus_manifest(artifact, corpus_dir)
            termination["corpus_receipt_binding"] = (
                "receipt-sample-bounded; per-entry receipt binding not claimed")
        manifest_path = Path(live_dir) / "corpus_manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        result["corpus_manifest"] = manifest
        result["corpus_manifest_sha256"] = (
            "sha256:" + hashlib.sha256(manifest_path.read_bytes()).hexdigest())
    except Exception as manifest_error:  # auxiliary evidence, never the run gate
        result["corpus_manifest_error"] = "%s: %s" % (
            type(manifest_error).__name__, manifest_error)
    return result, termination


def _execution_document(run_result: Mapping[str, object]) -> dict[str, object]:
    execution = run_result.get("actual_rtl_execution")
    if not isinstance(execution, Mapping):
        execution = {
            "tests": run_result.get("tests", 0),
            "execution_totals": run_result.get("execution_totals", {}),
            "coverage_records": run_result.get("completed_feedback_exchanges", 0),
        }
    totals = execution.get("execution_totals", {})
    return {
        "tests": execution.get("tests", 0),
        "coverage_records": execution.get("coverage_records", 0),
        "execution_totals": _plain(totals) if isinstance(totals, Mapping) else {},
        "status": "observed" if execution.get("tests", 0) else "not-observed",
    }


def _transactions_document(config: Mapping[str, object], run_result: Mapping[str, object]) -> dict[str, object]:
    observed = run_result.get("source_target_transactions")
    if observed is None:
        observed = run_result.get("transactions")
    if observed is None:
        totals = run_result.get("execution_totals")
        if isinstance(totals, Mapping) and any(
                key in totals for key in ("source_transactions", "target_transactions")):
            observed = {
                "source": {"transactions": totals.get("source_transactions", 0)},
                "target": {"transactions": totals.get("target_transactions", 0)},
            }
        elif isinstance(totals, Mapping) and any(
                key in totals for key in ("requests", "completions")):
            # The generic RTL monitor observes the CPU/fabric boundary.  Keep
            # this separate from per-target counts: it is source/target
            # transaction evidence, not a claim that every peripheral saw a
            # transaction.
            observed = {
                "source": {"backend_requests": totals.get("requests", 0)},
                "target": {"backend_completions": totals.get("completions", 0)},
                "all": dict(totals),
                "observation_boundary": "cpu-backend-fabric",
            }
    declared = config.get("source_target_transactions")
    if isinstance(observed, Mapping):
        return {"status": "observed", "source": _plain(observed.get("source", {})),
                "target": _plain(observed.get("target", {})),
                "all": _plain(observed)}
    if isinstance(declared, Mapping):
        return {"status": "declared-not-observed", "source": _plain(declared.get("source", {})),
                "target": _plain(declared.get("target", {})), "all": _plain(declared)}
    return {"status": "not-reported", "source": {}, "target": {}, "all": {}}


def _valid_corpus_manifest(manifest: object) -> bool:
    if not isinstance(manifest, Mapping):
        return False
    entries = manifest.get("entries")
    replays = manifest.get("replays")
    if (manifest.get("schema_version") != "rfuzz_corpus_manifest.v1"
            or manifest.get("coverage_transport")
            != "sysv-shared-memory-rfuzz-coverage-buffer"
            or isinstance(entries, bool) or not isinstance(entries, int) or entries < 1
            or not isinstance(replays, list) or len(replays) != entries):
        return False
    return all(
        isinstance(item, Mapping)
        and item.get("coverage_verified") is True
        and isinstance(item.get("file"), str) and bool(item["file"])
        and isinstance(item.get("input_sha256"), str) and bool(item["input_sha256"])
        and isinstance(item.get("coverage_sha256"), str) and bool(item["coverage_sha256"])
        for item in replays
    )


def _corpus_document(live_dir: Path, run_result: Mapping[str, object]) -> dict[str, object]:
    manifest = run_result.get("corpus_manifest")
    manifest_path = live_dir / "corpus_manifest.json"
    if manifest is None and manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError):
            manifest = None
    entries = run_result.get("corpus_entries", 0)
    if _valid_corpus_manifest(manifest):
        entries = manifest.get("entries", entries)
        return {
            "status": "verified",
            "entries": entries,
            "manifest_sha256": _hash(manifest),
            "manifest": _plain(manifest),
        }
    return {"status": "not-verified", "entries": entries, "manifest": None}


def _base_report(normal: Mapping[str, object], preflight: Mapping[str, object],
                 reset: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_version": SOC_RESULT_SCHEMA,
        "status": "starting",
        "config_id": normal["config_id"],
        "cell_id": normal["cell_id"],
        "cpu": normal["cpu"],
        "peripherals": normal["peripherals"],
        "families": normal["families"],
        "mode": normal["mode"],
        "seed": normal["seed"],
        "requested_duration_seconds": normal["duration_seconds"],
        "execution_kind": "official_rfuzz_source_backed_soc",
        "mutation": {
            "mode": "official_rfuzz",
            "zero_input_probe": False,
            "seed_cycles": normal["seed_cycles"],
        },
        "preflight": _plain(preflight),
        "reset": _plain(reset),
        "errors": [],
        "fifo_reply_receipts": [],
        "rtl_execution": {"status": "not-started", "tests": 0, "coverage_records": 0,
                           "execution_totals": {}},
        "source_target_transactions": {"status": "not-reported", "source": {}, "target": {}, "all": {}},
        "corpus": {"status": "not-started", "entries": 0},
        "replay": {"status": "not-requested"},
        "cleanup": {"status": "not-started"},
        "input_transport": {"status": "not-observed"},
        "client_termination": {
            "status": "not-applicable",
            "policy": {"name": INTERRUPTED_RUN_POLICY["name"], "applied": False,
                       "evidence_rule": INTERRUPTED_RUN_POLICY["evidence_rule"]},
        },
        "terminal_state_policy": _plain(INTERRUPTED_RUN_POLICY),
    }


def run_soc_campaign(
    config: Mapping[str, object], output: Path, *, root: Path | None = None,
    environment: Mapping[str, str] | None = None, preflight_only: bool = False,
    builder: Callable[..., object] | None = None,
    runner: Callable[..., Mapping[str, object]] | None = None,
    rebuilder: Callable[..., object] | None = None,
) -> dict[str, object]:
    """Build/run/replay one SoC campaign and always retain bounded evidence.

    ``builder`` and ``runner`` are injectable so contract tests can exercise
    failure/cleanup paths without launching a client.  A production run uses
    ``run_live`` and therefore the pinned RFuzz FIFO/shared-memory protocol.
    """
    normal = _normalise_config(config)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("campaign output must be new")
    output.mkdir(parents=True)
    root = Path(root or config.get("root") or Path.cwd()).resolve()
    preflight = preflight_soc_campaign(config, root=root, environment=environment)
    reset = _reset_document(normal["reset_contract"])
    report = _base_report(normal, preflight, reset)
    report_path = output / "report.json"
    _write_report(report_path, report)

    opt_in = real_soc_opt_in(environment)
    if preflight_only:
        report.update(status="preflight-only", final_status="not-executed")
        _write_report(report_path, report)
        return report
    if not opt_in:
        report.update(status="opt-in-required", final_status="not-executed")
        report["errors"] = [{"category": "configuration", "phase": "opt-in",
                              "type": "SocCampaignError",
                              "message": "MYFUZZ_SOC_REAL=1 is required for a real RFuzz campaign"}]
        _write_report(report_path, report)
        return report
    if not preflight.get("dependencies", {}).get("ready", False):
        error = SocCampaignError("real SoC dependencies are not ready")
        report["errors"] = [_error_record(error, "preflight")]
        report.update(status="failed", final_status="dependency-unavailable")
        _write_report(report_path, report)
        return report
    if not reset["all_state_domains_declared"]:
        error = SocCampaignProtocolError(
            "reset contract must clear driver, memory, CPU/IP, IRQ and coverage state"
        )
        report["errors"] = [_error_record(error, "reset")]
        report.update(status="failed", final_status="reset-contract-unverified")
        _write_report(report_path, report)
        return report
    if preflight["client"]["requested"] and not preflight["client"]["ready"]:
        error = SocCampaignError("official RFuzz client is missing or not executable")
        report["errors"] = [_error_record(error, "client")]
        report.update(status="failed", final_status="client-unavailable")
        _write_report(report_path, report)
        return report
    client = _resolve_path(root, normal["client_binary"])
    if client is None:
        error = SocCampaignError("official RFuzz client path is required")
        report["errors"] = [_error_record(error, "client")]
        report.update(status="failed", final_status="client-unavailable")
        _write_report(report_path, report)
        return report

    build_dir = output / "build"
    live_dir = output / "live"
    phase = "build"
    artifact = None
    client_termination: dict[str, object] | None = None
    try:
        build_hook = builder or config.get("build") or config.get("build_artifact")
        if build_hook is None and config.get("artifact") is None:
            # Production default: a real campaign renders its cell and compiles
            # the source-backed artifact.  Tests may still inject a hook, name
            # one in the config, or pass a prebuilt artifact explicitly.
            from .soc_builder import build_soc_campaign_artifact
            build_hook = build_soc_campaign_artifact
        if build_hook is None:
            artifact = config.get("artifact")
        elif callable(build_hook):
            artifact = _call_forms(build_hook, ((config, build_dir), (build_dir,), (config,), ()))
        else:
            raise ValueError("build hook must be callable")
        if artifact is None:
            raise SocCampaignError("source-backed simulator artifact was not built")
        transport = _transport_document(artifact)
        if transport is None:
            raise SocCampaignError("input transport identity is missing")
        report["input_transport"] = {
            "status": "observed", "document": transport, "transport_hash": _hash(transport),
        }
        phase = "client"
        try:
            if runner is None:
                run_result = run_live(
                    artifact, client, live_dir,
                    duration_seconds=normal["duration_seconds"],
                    seed_cycles=max(1, normal["seed_cycles"]),
                )
            else:
                run_result = _call_forms(
                    runner,
                    ((config, artifact, client, live_dir),
                     (artifact, client, live_dir), (artifact, live_dir), (artifact,)),
                )
        except BaseException as client_error:
            # Interrupted-run policy: our bounded drain may end a client that
            # already produced real receipts and a corpus.  Recover that
            # evidence and fall through to the replay/classification step;
            # anything else keeps failing exactly as before.
            recovered = _recover_terminated_client_run(
                client_error, artifact, live_dir, report)
            if recovered is None:
                raise
            run_result, client_termination = recovered
        if not isinstance(run_result, Mapping):
            raise SocCampaignError("RFuzz runner did not return a mapping")
        receipts, receipt_errors = _receipt_document(run_result.get("fifo_reply_receipts"))
        report["fifo_reply_receipts"] = receipts
        report["errors"].extend(receipt_errors)
        report["rtl_execution"] = _execution_document(run_result)
        report["source_target_transactions"] = _transactions_document(normal, run_result)
        report["corpus"] = _corpus_document(live_dir, run_result)
        if run_result.get("corpus_manifest_error"):
            report["corpus"]["manifest_error"] = run_result["corpus_manifest_error"]
        remaining = run_result.get("remaining_segments")
        cleanup_is_explicitly_clean = (
            isinstance(remaining, Sequence)
            and not isinstance(remaining, (str, bytes))
            and len(remaining) == 0
        )
        report["cleanup"] = {
            "status": "clean" if cleanup_is_explicitly_clean else "leaked-or-unreported-shmem",
            "remaining_segments": _plain(remaining),
            "removed_segments": _plain(run_result.get("removed_owned_segments", [])),
            "process_group_owned_by_runner": True,
            "fifo_owned_by_runner": True,
        }
        report["client_result"] = _plain(dict(run_result))
        replay_builder = rebuilder or config.get("rebuild") or build_hook
        if callable(replay_builder):
            replay_dir = output / "rebuild"
            rebuilt = _call_forms(replay_builder, ((config, replay_dir), (replay_dir,), (config,), ()))
            replay = replay_corpus(rebuilt, live_dir / "corpus")
            if not isinstance(replay, Mapping):
                raise SocCampaignError("corpus replay did not return a mapping")
            report["replay"] = {
                "status": replay.get("status", "failed"),
                "entries": replay.get("entries", 0),
                "document": _plain(replay),
            }
        else:
            report["replay"] = {"status": "not-requested"}
        actual = report["rtl_execution"]
        report["effective_fuzz_seconds"] = _measured_fuzz_seconds(run_result)
        evidence_missing = _campaign_evidence_gaps(
            normal, report, run_result, receipt_errors)
        report["evidence_missing"] = evidence_missing
        if client_termination is not None:
            policy = client_termination.setdefault("policy", {})
            policy["missing"] = sorted(set(policy.get("missing", []))
                                       | set(evidence_missing))
            policy["applied"] = not policy["missing"] and not report["errors"]
            if policy["applied"]:
                report.update(status=CLIENT_TERMINATED_STATUS,
                              final_status=CLIENT_TERMINATED_FINAL_STATUS)
            else:
                report.update(status="failed", final_status="failed")
                report["errors"].append({
                    "category": "client",
                    "phase": "client",
                    "type": "SocCampaignError",
                    "message": ("interrupted-run policy not applied; missing evidence: "
                                + ", ".join(policy["missing"])
                                if policy["missing"] else
                                ("interrupted-run policy not applied; evidence errors "
                                 "or a non-clean cleanup were recorded")),
                })
        else:
            complete = (
                type(run_result.get("returncode")) is int
                and run_result["returncode"] == 0
                and int(actual.get("tests", 0)) > 0
                and not evidence_missing
                and not report["errors"]
            )
            report.update(status="completed" if complete else "incomplete-evidence",
                          final_status="passed" if complete else "failed-acceptance")
    except BaseException as error:
        report["errors"].append(_error_record(error, phase))
        report["cleanup"] = {
            "status": ("runner-owned-cleanup-attempted" if phase == "client" else "not-started"),
            "process_group_owned_by_runner": phase == "client",
            "fifo_owned_by_runner": phase == "client",
        }
        report.update(status="failed", final_status="failed")
    _write_report(report_path, report)
    return report


__all__ = [
    "SOC_RESULT_SCHEMA", "CLIENT_TERMINATED_STATUS", "CLIENT_TERMINATED_FINAL_STATUS",
    "INTERRUPTED_RUN_POLICY", "SocCampaignError", "SocCampaignProtocolError",
    "SocCampaignSoftwareTrap", "preflight_soc_campaign", "run_soc_campaign",
]
