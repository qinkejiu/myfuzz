"""Replay RFuzz saved raw corpus through fresh independent scenario RTL."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from itertools import zip_longest
from pathlib import Path
from typing import Callable

from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.rfuzz_decoder import GenomeRecordDecoder, RECORD_BYTES
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.replay import ReplayComparison, ScenarioTrace, _difference_context

from .rfuzz_wire import InputBatch
from .scenario_rfuzz import ScenarioRfuzzExecutor


@dataclass(frozen=True)
class CorpusReplayResult:
    total_entries: int
    matched_entries: int
    mismatches: tuple[str, ...]


@dataclass(frozen=True)
class ContinuousReplayResult:
    """Scope includes case checker replay and trace, plus decoder checker identity.

    RFuzz selection policies, per-candidate coverage and cumulative decoder
    checker verdicts are retained as evidence, not recomputed by this API.
    """
    comparison: ReplayComparison
    verification_scope: tuple[str, ...] = (
        "complete_admitted_session_prefix", "session_case_checker",
        "decoder_checker_identity")

    @property
    def matches(self) -> bool:
        return self.comparison.matches


@dataclass(frozen=True)
class CandidateExplorationReplayResult:
    comparison: ReplayComparison
    verification_scope: tuple[str, ...] = (
        'complete_admitted_session_prefix', 'session_case_checker',
        'decoder_checker', 'online_source_selection', 'candidate_case_scoring',
        'candidate_terminal_state')

    @property
    def matches(self):
        return self.comparison.matches


def _candidate_reference(output):
    from myfuzz.scenario.event_journal import JsonlEventView, ZlibChunkEventView
    path = output / 'online_final_trace.json'
    if not path.is_file():
        path = output / 'online_final_trace.meta.json'
    document = json.loads(path.read_bytes())
    schema = document.get('schema_version')
    if schema in ('online_trace_jsonl.v1', 'online_trace_zlib_chunks.v1'):
        compressed = schema == 'online_trace_zlib_chunks.v1'
        filename = 'online_events.zlib' if compressed else 'online_events.jsonl'
        if document.get('events_file') != filename:
            raise ValueError('candidate replay trace metadata mismatch')
        cls = ZlibChunkEventView if compressed else JsonlEventView
        view = cls(output / document.pop('events_file'), document.pop('event_count'))
        if compressed:
            view.verify_trace_semantic(status=document['status'],
                local_ticks=document['local_ticks'], expected_sha256=document['semantic_sha256'])
        document.pop('schema_version')
        document['events'] = view
    return path, ScenarioTrace(**document)


def _candidate_receipt_record(executor, receipt):
    """Deterministic live receipt fields; host timing is never a replay oracle."""
    decision = executor._online_decisions_by_slot[(receipt.buffer_id, receipt.slot)]
    record = {key: getattr(receipt, key) for key in (
        'run_id', 'buffer_id', 'slot', 'raw_sha256', 'path_id', 'applied_sources',
        'applied_source_ids', 'effective_genome_sha256', 'manifest_sha256',
        'semantic_sha256', 'status', 'local_ticks', 'coverage_hex', 'violations',
        'error', 'online_weights', 'source_action', 'rejection')}
    record['genome_sha256'] = receipt.genome_sha256
    for key in ('case_id', 'direction', 'flow_id', 'target_id', 'source_id',
                'operator_id', 'candidate_id', 'source_selection_reason',
                'candidate_disposition', 'candidate_disposition_reason', 'candidate_exploration'):
        record[key] = decision.get(key)
    record['interaction_source_gains'] = decision.get('interaction_source_gains', {})
    record['interaction_feedback'] = receipt.interaction_feedback or {}
    record['online_source'] = (receipt.online_case.get('source')
                               if receipt.online_case is not None else None)
    return record


def replay_candidate_exploration_files(output_dir: Path, *,
        executor_factory: Callable[[], ScenarioRfuzzExecutor], decoder_checker=None,
        checker_config=None, checker_identity_target=None) -> CandidateExplorationReplayResult:
    """Recompute saved exploration from raw inputs with a fresh trusted factory.

    The caller supplies the actual assembly, including checker, bootstrap and
    search switches. Saved decoder documents/weights/state are comparisons,
    never search configuration or runtime authority. No RFuzz client is started.
    Artifact and raw-input validation precede factory construction; configuration
    comparison precedes case commands (a factory may already run its bootstrap).
    """
    from .scenario_rfuzz_live import _verify_online_run_identity, _fresh_checker_identity
    from myfuzz.scenario.session_runtime import _online_manifest
    output = Path(output_dir)
    trace_path, reference = _candidate_reference(output)
    plan_path = output / 'online_plan.json'
    identity = _verify_online_run_identity(output, plan_path=plan_path,
        trace_path=trace_path, trace=reference, decoder_checker=decoder_checker,
        checker_config=checker_config, checker_identity_target=checker_identity_target)
    if (identity is None or identity.get('execution_mode') != 'online_cases'
            or not any(k in identity.get('run_config', {}) for k in ('candidate_exploration', 'classified_feedback'))):
        raise ValueError('candidate replay requires a verified enabled online bundle')
    config = identity['run_config']
    if (type(config.get('run_id')) is not str or not config['run_id']
            or type(config.get('feedback_interval')) is not int
            or config['feedback_interval'] < 1
            or any(type(config.get(key)) is not bool
                   for key in ('closed_loop_energy', 'path_switch'))):
        raise ValueError('candidate replay configuration types are invalid')
    def artifact(name):
        raw = (output / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != identity['artifacts'].get(name):
            raise ValueError('candidate replay artifact changed after verification: ' + name)
        return raw
    plan_raw = artifact('online_plan.json')
    plan = json.loads(plan_raw)
    decoder_document = json.loads(artifact('decoder_manifest.json'))
    target_document = json.loads(artifact('targets.json'))
    session_manifest = json.loads(artifact('online_session_manifest.json'))
    report = json.loads((output / 'report.json').read_bytes())
    channels = tuple(k for k in ('candidate_exploration', 'classified_feedback') if k in config)
    scopes = ('complete_admitted_session_prefix', 'session_case_checker', 'decoder_checker', 'online_source_selection')
    if 'candidate_exploration' in channels:
        scopes += ('candidate_case_scoring', 'candidate_terminal_state')
    if 'classified_feedback' in channels:
        scopes += ('classified_case_feedback', 'classified_terminal_state')
    def replay_result(comparison):
        return CandidateExplorationReplayResult(comparison, scopes)
    saved_states = {k: report.get(k) for k in channels}
    for key, state in saved_states.items():
        if type(state) is not dict or _canonical(state.get('configuration')) != _canonical(config[key]):
            raise ValueError('candidate replay configuration changed after verification')
    def states(executor):
        return {'candidate_exploration': executor.candidate_exploration_state(),
                'classified_feedback': executor.classified_feedback_state()}
    max_tests = config.get('max_tests')
    if type(max_tests) is not int or max_tests < 1:
        raise ValueError('candidate replay receipt bound is invalid')
    rows = [json.loads(line) for line in artifact('receipts.jsonl').splitlines()]
    if len(rows) > max_tests:
        raise ValueError('candidate replay receipt capacity exceeded')
    groups, identities = [], set()
    for row in rows:
        if (type(row) is not dict or type(row.get('buffer_id')) is not int
                or not 0 <= row['buffer_id'] <= 0xffffffff
                or type(row.get('slot')) is not int or not 0 <= row['slot'] < 65535):
            raise ValueError('candidate replay receipt identity is invalid')
        key = row['buffer_id'], row['slot']
        if key in identities:
            raise ValueError('candidate replay receipt identity is duplicated')
        identities.add(key)
        records = row.get('online_raw_records_hex')
        if (type(records) is not list or not 1 <= len(records) <= 65535
                or any(type(raw) is not str or re.fullmatch('[0-9a-f]{16}', raw) is None
                       for raw in records)):
            raise ValueError('candidate replay raw input is invalid')
        records = tuple(bytes.fromhex(raw) for raw in records)
        if hashlib.sha256(b''.join(records)).hexdigest() != row.get('raw_sha256'):
            raise ValueError('candidate replay raw input digest mismatch')
        if not groups or groups[-1][0] != row['buffer_id']:
            if any(group[0] == row['buffer_id'] for group in groups):
                raise ValueError('candidate replay receipt buffer order is invalid')
            groups.append((row['buffer_id'], []))
        if row['slot'] != len(groups[-1][1]):
            raise ValueError('candidate replay receipt slot order is invalid')
        groups[-1][1].append(records)
    resets = plan.get('reset_operations', [])
    if (type(resets) is not list
            or any(type(op) is not dict or set(op) != {'after_cases', 'policy'}
                   or type(op['after_cases']) is not int
                   or not 1 <= op['after_cases'] <= len(plan['cases'])
                   or op['policy'] not in ('warm_all', 'cold_all') for op in resets)
            or any(a['after_cases'] > b['after_cases'] for a, b in zip(resets, resets[1:]))):
        raise ValueError('candidate replay reset timeline is invalid')
    executor = executor_factory()
    if not isinstance(executor, ScenarioRfuzzExecutor):
        raise ValueError('candidate replay factory must return a fresh executor')
    error = None
    try:
        if (executor.online_decoder is None
                or any(states(executor)[k] is None for k in channels)
                or executor.receipts or executor.online_decisions or executor.session.cases
                or executor.session._finished or executor._completed
                or executor._selection_uses or executor._selection_gains or executor._target_hits
                or any(states(executor)[k]['cases'] != 0 for k in channels)):
            raise ValueError('candidate replay requires fresh initial executor state')
        if ('online_assembly' in config
                and _canonical(executor.online_assembly_configuration())
                != _canonical(config['online_assembly'])):
            raise ValueError('candidate replay assembly configuration mismatch')
        if (any(_canonical(states(executor)[k]['configuration']) != _canonical(config[k]) for k in channels)
                or any((states(executor)[k] is not None) != (k in channels) for k in states(executor))
                or executor.run_id != config.get('run_id')
                or executor.feedback_interval != config.get('feedback_interval')
                or executor.closed_loop_energy != config.get('closed_loop_energy')
                or executor.path_switch != config.get('path_switch')
                or _canonical(executor.online_decoder.document()) != _canonical(decoder_document)
                or _canonical([vars(t) for t in executor.targets]) != _canonical(target_document)
                or _canonical(_online_manifest(executor.session.runner, executor.session.checker,
                    runtime_paths=executor.session.runtime_path_document,
                    checker_configuration_only=executor.session._checker_configuration_only)) != _canonical(session_manifest)
                or _fresh_checker_identity(executor.checker, config=executor.checker_config,
                    identity_target=executor.checker_identity_target) != identity.get('decoder_checker')):
            raise ValueError('candidate replay factory configuration mismatch')
        index, reset_index = 0, 0
        def observed(receipt):
            nonlocal index, reset_index
            actual = _candidate_receipt_record(executor, receipt)
            if index >= len(rows) or any(key not in rows[index]
                    or _canonical(value) != _canonical(rows[index][key]) for key, value in actual.items()):
                raise ValueError(f'candidate replay receipt selection/scoring mismatch at {index}')
            index += 1
            while reset_index < len(resets) and resets[reset_index]['after_cases'] == len(executor.session.cases):
                executor.session.reset(resets[reset_index]['policy'])
                reset_index += 1
        for buffer_id, records in groups:
            executor.execute_batch(InputBatch(buffer_id, RECORD_BYTES, tuple(records)), on_receipt=observed)
        if index != len(rows) or reset_index != len(resets):
            raise ValueError('candidate replay receipt/reset prefix is incomplete')
        actual, encoded = executor._finish_online_session()
        if encoded is None or bytes.fromhex(encoded) != plan_raw:
            raise ValueError('candidate replay admitted plan mismatch')
        if any(_canonical(states(executor)[k]) != _canonical(saved_states[k]) for k in channels):
            raise ValueError('candidate replay terminal state mismatch')
        for offset, (expected_event, actual_event) in enumerate(zip_longest(reference.events, actual.events)):
            if _canonical(expected_event) != _canonical(actual_event):
                return replay_result(ReplayComparison(False, offset,
                    expected_event, actual_event, actual,
                    _difference_context(expected_event, actual_event, offset)))
        matches = all(_canonical(getattr(reference, field)) == _canonical(getattr(actual, field))
                      for field in ('genome_sha256', 'status', 'local_ticks',
                                    'semantic_sha256', 'manifest_sha256'))
        return replay_result(ReplayComparison(matches,
            None if matches else len(reference.events), None, None, actual))
    except BaseException as exc:
        error = exc
        raise
    finally:
        try:
            executor._finish_online_session()
        except BaseException as cleanup:
            if error is None:
                raise
            error.add_note(f'candidate replay cleanup failed: {type(cleanup).__name__}: {cleanup}')


def replay_scenario_rfuzz_continuous(
        output_dir: Path, factory: Callable[[], ScenarioRunner], *,
        session_checker=None, decoder_checker=None, checker_config=None,
        checker_identity_target=None) -> ContinuousReplayResult:
    """Replay an actual continuous admission prefix as one stateful testcase."""
    from myfuzz.scenario.event_journal import JsonlEventView, ZlibChunkEventView
    from myfuzz.scenario.replay import ScenarioTrace
    from myfuzz.scenario.session_runtime import replay_online_session, _checker_identity
    from .scenario_rfuzz_live import _verify_online_run_identity, _fresh_checker_identity

    output = Path(output_dir)
    report = json.loads((output / "report.json").read_bytes())
    if report.get("execution_mode") != "continuous_decoder":
        raise ValueError("continuous replay requires a saved continuous decoder run")
    trace_path = output / "online_final_trace.json"
    if not trace_path.is_file():
        trace_path = output / "online_final_trace.meta.json"
    document = json.loads(trace_path.read_bytes())
    if document.get("schema_version") == "online_trace_jsonl.v1":
        if document.get("events_file") != "online_events.jsonl":
            raise ValueError("invalid continuous JSONL trace metadata")
        document["events"] = JsonlEventView(output / document.pop("events_file"),
                                           document.pop("event_count"))
        document.pop("schema_version")
    elif document.get("schema_version") == "online_trace_zlib_chunks.v1":
        expected = {"schema_version", "events_file", "event_count",
                    "genome_sha256", "status", "local_ticks",
                    "semantic_sha256", "manifest_sha256"}
        if set(document) != expected or document["events_file"] != "online_events.zlib":
            raise ValueError("invalid continuous compressed trace metadata")
        view = ZlibChunkEventView(output / document.pop("events_file"),
                                  document.pop("event_count"))
        view.verify_trace_semantic(status=document["status"],
                                   local_ticks=document["local_ticks"],
                                   expected_sha256=document["semantic_sha256"])
        document["events"] = view
        document.pop("schema_version")
    reference = ScenarioTrace(**document)
    plan_path = output / "online_plan.json"
    identity = _verify_online_run_identity(output, plan_path=plan_path,
                                         trace_path=trace_path, trace=reference,
                                         decoder_checker=decoder_checker,
                                         checker_config=checker_config,
                                         checker_identity_target=checker_identity_target)
    if identity is None or identity.get("execution_mode") != "continuous_decoder":
        raise ValueError("continuous run identity is required")
    if identity.get("checker") != _checker_identity(session_checker):
        raise ValueError("continuous session checker identity mismatch")
    if identity.get("decoder_checker") != _fresh_checker_identity(
            decoder_checker, config=checker_config, identity_target=checker_identity_target):
        raise ValueError("continuous decoder checker identity mismatch")
    return ContinuousReplayResult(replay_online_session(
        plan_path.read_bytes(), factory, reference, checker=session_checker))


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _wall_cut_factory(factory: Callable[[], ScenarioRunner], marker: dict):
    """Recreate a physical cutoff at its recorded semantic boundary."""
    if (not isinstance(marker, dict)
            or marker.get("kind") != "budget_exhausted"
            or marker.get("limit") != "max_wall_time_ms"
            or not isinstance(marker.get("semantic_prefix_sha256"), str)
            or type(marker.get("prefix_event_count")) is not int
            or not isinstance(marker.get("prefix_local_ticks"), dict)):
        raise ValueError("invalid saved wall cutoff")
    if marker.get("phase") == "inflight_finalize":
        timeout_us = marker.get("finalize_timeout_us")
        if type(timeout_us) is not int or timeout_us < 0:
            raise ValueError("invalid finalize timeout in saved wall cutoff")

    def make_runner():
        runner = factory()
        kwargs = {"prefix_event_count": marker["prefix_event_count"]}
        if marker.get("phase") == "inflight_finalize":
            timeout_us = marker["finalize_timeout_us"]
            budget = getattr(runner, "_resource_budget", None)
            maximum_ms = getattr(budget, "max_wall_time_ms", None)
            if (type(maximum_ms) is int
                    and timeout_us > maximum_ms * 1000):
                raise ValueError(
                    "finalize timeout exceeds replay wall budget")
            kwargs["finalize_timeout_us"] = timeout_us
        if marker.get("phase") in ("before_begin", "inflight_begin"):
            kwargs.update({"failed_component": marker["failed_component"],
                           "started_components": tuple(marker["started_components"])})
        runner.set_replay_wall_cut(
            sum(marker["prefix_local_ticks"].values()),
            marker["phase"], **kwargs)
        return runner

    return make_runner


def _wall_cut_mismatch(marker: dict, trace) -> str | None:
    prefix = marker["prefix_event_count"]
    if (type(prefix) is not int or prefix < 0
            or len(trace.events) != prefix + 1):
        return "wall cutoff budget marker missing or event count differs"
    if hashlib.sha256(_canonical(trace.events[:prefix])).hexdigest() != \
            marker["semantic_prefix_sha256"]:
        return "wall cutoff semantic prefix differs"
    actual = trace.events[prefix]
    for key in ("event_id", "kind", "limit", "phase",
                "effect_may_have_occurred", "local_ticks", "cleanup_errors",
                "prefix_event_count", "prefix_local_ticks",
                "step_timeout_us", "finalize_timeout_us",
                "failed_component", "started_components",
                "status_before_finalize"):
        if _canonical(actual.get(key)) != _canonical(marker.get(key)):
            return f"wall cutoff {key} differs"
    if trace.status != "budget_exhausted" and not (
            marker["phase"] == "inflight_finalize"
            and trace.status == marker.get("status_before_finalize")):
        return "wall cutoff budget status differs"
    return None


def replay_scenario_rfuzz_corpus(
        output_dir: Path, factory: Callable[[], ScenarioRunner], *,
        checker: Callable | None = None,
        checker_config: dict | None = None,
        checker_identity_target: Callable | None = None) -> CorpusReplayResult:
    output = Path(output_dir)
    admission_report = json.loads((output / "report.json").read_bytes())
    if admission_report.get("execution_mode") == "continuous_decoder":
        raise ValueError("continuous history requires replay_scenario_rfuzz_continuous")
    from .scenario_rfuzz_live import _verify_fresh_run_identity
    run_identity = _verify_fresh_run_identity(
        output, checker=checker, checker_config=checker_config,
        checker_identity_target=checker_identity_target)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "decoder_manifest.json").read_text(
        encoding="utf-8"))
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != report["decoder_manifest_sha256"]:
        raise ValueError("decoder manifest identity mismatch")
    decoder = GenomeRecordDecoder.from_document(manifest)
    targets = tuple(CoverageTarget(**item) for item in json.loads(
        (output / "targets.json").read_text(encoding="utf-8")))
    executor = ScenarioRfuzzExecutor(run_id="corpus-replay", decoder=decoder,
                                     factory=factory, targets=targets,
                                     checker=checker, replay_only=True)
    if run_identity is not None:
        executor._observe_fresh_identity(json.loads(
            (output / "runner_manifest.json").read_bytes()))
        executor._install_runtime_replay_identity(run_identity.get("runtime_paths"))
    original: dict[str, dict] = {}
    with (output / "receipts.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            old = original.setdefault(row["raw_sha256"], row)
            comparable = ("genome_sha256", "path_id", "manifest_sha256",
                          "semantic_sha256", "status",
                          "total_local_ticks", "coverage_hex", "wall_cut")
            if any(old.get(key) != row.get(key) for key in comparable):
                raise ValueError("original receipts disagree for identical raw input")
    entries = sorted((output / "corpus").glob("entry_*.json"))
    if not entries:
        raise ValueError("RFuzz saved corpus is empty")
    mismatches: list[str] = []
    for index, path in enumerate(entries):
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("oversized RFuzz corpus entry")
        document = json.loads(path.read_text(encoding="utf-8"))
        raw_values = document.get("entry", {}).get("inputs")
        if (not isinstance(raw_values, list) or not raw_values
                or len(raw_values) % RECORD_BYTES
                or len(raw_values) // RECORD_BYTES > decoder.max_records
                or any(type(value) is not int or not 0 <= value <= 255
                       for value in raw_values)):
            raise ValueError(f"invalid RFuzz corpus bytes: {path.name}")
        raw = bytes(raw_values)
        raw_hash = hashlib.sha256(raw).hexdigest()
        prior = original.get(raw_hash)
        if prior is None:
            mismatches.append(f"{path.name}: no original execution receipt")
            continue
        records = tuple(raw[offset:offset + RECORD_BYTES]
                        for offset in range(0, len(raw), RECORD_BYTES))
        marker = prior.get("wall_cut")
        if marker is not None:
            try:
                executor.factory = _wall_cut_factory(factory, marker)
            except (KeyError, TypeError, ValueError) as exc:
                mismatches.append(f"{path.name}: invalid wall cut: {exc}")
                continue
        else:
            executor.factory = factory
        executor.execute_batch(InputBatch(index, RECORD_BYTES, (records,)))
        actual = executor.receipts[-1]
        if marker is not None:
            if actual.trace is None:
                mismatches.append(f"{path.name}: replay budget trace missing")
                continue
            mismatch = _wall_cut_mismatch(marker, actual.trace)
            if mismatch is not None:
                mismatches.append(f"{path.name}: {mismatch}")
                continue
            for key in ("genome_sha256", "path_id", "manifest_sha256"):
                if getattr(actual, key) != prior[key]:
                    mismatches.append(f"{path.name}: {key} differs")
                    break
            continue
        for key in ("genome_sha256", "path_id", "manifest_sha256",
                    "semantic_sha256", "status",
                    "total_local_ticks", "coverage_hex", "violations"):
            actual_value = getattr(actual, key)
            prior_value = prior.get(key, () if key == "violations" else None)
            if key == "violations":
                actual_value, prior_value = tuple(actual_value), tuple(prior_value)
            if actual_value != prior_value:
                mismatches.append(f"{path.name}: {key} differs")
                break
    return CorpusReplayResult(len(entries), len(entries) - len(mismatches),
                              tuple(mismatches))
