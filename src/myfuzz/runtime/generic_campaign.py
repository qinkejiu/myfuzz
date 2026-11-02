"""Data-driven generic scenario campaigns.

A scenario descriptor names the inputs (compose/supplement/capability), the
flows to prepare and the code-owned executor for each flow. F2/F4 use the
shared runtime plan and campaign. F6 delegates to its existing standalone
directed executor, which retains its own binding, evidence and fresh replay.

The point is that adding a new CPU/IP pair is data, not a new scenario class:
the descriptor is JSON, and this module is the only execution path. It still
requires real source contracts and the existing refusal/evidence rules; a
descriptor cannot weaken them.
"""
from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
import shutil
import time
from typing import Callable

from .admission import verify_component
from .binding import bind_execution_plan
from .campaign import CampaignBudget, run_directed_campaign
from .compiler import (
    compile_execution_plan,
    plan_bindings,
    requirement_for_binding,
)
from .flows.storage import StorageFlowBackend, StorageFlowKernel
from .flows.mixed import MixedStorageFlowBackend
from .preparation import create_preparation
from .registry import select_adapter
from .recorded_commands import recorded_command_documents

SCHEMA_VERSION = 'generic_scenario_descriptor.v1'
FLOWS = ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')
_STANDALONE_EXECUTORS = {'F5': 'compiled_f5_obi_gpio', 'F6': 'compiled_f6_cpu_dma'}
_MMIO_EXECUTORS = frozenset({'compiled_mmio', 'compiled_mmio_obi_apb'})
_HEX_RECORD = re.compile(r'(?:[0-9a-fA-F]{2})+')
_KEYS = {'schema_version', 'scenario_id', 'root', 'compose', 'supplement',
         'capability', 'flow_ids', 'executors', 'f4_records', 'f2_records',
         'rounds'}


class GenericScenarioRefused(ValueError):
    """Descriptor is malformed or inconsistent with the shared runtime."""

    def __init__(self, code: str, pointer: str, detail=None):
        super().__init__(f'{code} at {pointer}')
        self.code = code
        self.pointer = pointer
        self.detail = detail


def _refuse(code: str, pointer: str, detail=None) -> None:
    raise GenericScenarioRefused(code, pointer, detail)


def _relative_member(root: Path, value, pointer: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        _refuse('generic-scenario-path-invalid', pointer)
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        _refuse('generic-scenario-path-missing', pointer, {'path': value})
    return path


def _records(value, pointer: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        _refuse('generic-scenario-records-invalid', pointer)
    rows = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not _HEX_RECORD.fullmatch(item):
            _refuse('generic-scenario-record-invalid', f'{pointer}[{index}]')
        rows.append(item.lower())
    if not rows:
        _refuse('generic-scenario-records-empty', pointer)
    return tuple(rows)


@dataclass(frozen=True)
class ScenarioDescriptor:
    scenario_id: str
    root: Path
    compose: Path
    supplement: Path
    capability: Path
    flow_ids: tuple[str, ...]
    executors: dict[str, str]
    f4_records: tuple[str, ...]
    f2_records: tuple[str, ...]
    rounds: int
    f6_records: tuple[str, ...] = ()
    f5_records: tuple[str, ...] = ()
    f1_records: tuple[str, ...] = ()
    f3_records: tuple[str, ...] = ()
    irq_firmware: bool = False
    shared_slots: bool = False

    def records(self, flow: str) -> list[str]:
        if flow in ('F1','F3'):
            return list(self.f1_records if flow=='F1' else self.f3_records)
        if flow == 'F4':
            return list(self.f4_records)
        if flow == 'F6':
            return list(self.f6_records)
        if flow == 'F5':
            return list(self.f5_records)
        path = self.root / 'f2_read_records.json'
        if path.is_file():
            rows = json.loads(path.read_text())
            if not isinstance(rows, list):
                _refuse('generic-scenario-records-invalid', '/f2_read_records.json')
            return list(rows)
        return list(self.f2_records)

    def executor(self, flow: str) -> str:
        try:
            return self.executors[flow]
        except KeyError:
            _refuse('generic-scenario-flow-unsupported', '/executors', {'flow': flow})


def load_descriptor(path, *, base_dir) -> ScenarioDescriptor:
    """Load one descriptor with exact keys and base-dir-scoped paths."""
    path = Path(path).resolve()
    base = Path(base_dir).resolve()
    if not path.is_file() or not path.is_relative_to(base):
        _refuse('generic-scenario-path-invalid', '/descriptor')
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        _refuse('generic-scenario-json-invalid', '/descriptor', {'reason': str(error)[:160]})
    if (type(document) is not dict or not _KEYS <= set(document)
            or set(document) - _KEYS - {'f1_records','f3_records','f5_records', 'f6_records','irq_firmware','shared_slots'}):
        _refuse('generic-scenario-schema-invalid', '/descriptor',
                {'missing': sorted(_KEYS - set(document)) if type(document) is dict else None})
    if document['schema_version'] != SCHEMA_VERSION:
        _refuse('generic-scenario-schema-invalid', '/schema_version')
    scenario_id = document['scenario_id']
    if not isinstance(scenario_id, str) or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,63}', scenario_id):
        _refuse('generic-scenario-id-invalid', '/scenario_id')
    if not isinstance(document['root'], str) or Path(document['root']).is_absolute():
        _refuse('generic-scenario-root-invalid', '/root')
    root = (base / document['root']).resolve()
    if not root.is_relative_to(base) or not root.is_dir():
        _refuse('generic-scenario-root-missing', '/root')
    compose = _relative_member(root, document['compose'], '/compose')
    supplement = _relative_member(root, document['supplement'], '/supplement')
    shared_slots = document.get('shared_slots', False)
    if type(shared_slots) is not bool:
        _refuse('generic-scenario-shared-slots-invalid', '/shared_slots')
    capability = (tuple(_relative_member(root, value, '/capability') for value in document['capability'])
        if shared_slots and isinstance(document['capability'], list)
        else _relative_member(root, document['capability'], '/capability'))
    flow_ids = document['flow_ids']
    if (not isinstance(flow_ids, list) or not flow_ids
            or len(set(flow_ids)) != len(flow_ids)
            or any(flow not in FLOWS for flow in flow_ids)):
        _refuse('generic-scenario-flow-unsupported', '/flow_ids', {'supported': list(FLOWS)})
    executors = document['executors']
    if (type(executors) is not dict or set(executors) != set(flow_ids)
            or any(not isinstance(value, str) or not value for value in executors.values())):
        _refuse('generic-scenario-executors-invalid', '/executors')
    shared_executor = (shared_slots and {'F4', 'F6'} <= set(flow_ids)
        and set(executors.values()) == {'compiled_f6_cpu_dma'})
    for standalone, executor in _STANDALONE_EXECUTORS.items():
        if standalone not in flow_ids:
            continue
        shared_f5 = standalone=='F5' and 'F4' in flow_ids and executors[standalone]=='compiled_f4_obi_apb'
        if not shared_f5 and not shared_executor and (executors[standalone] != executor or flow_ids != [standalone]):
            _refuse('generic-scenario-flow-unsupported', '/executors/' + standalone)
    if shared_slots and (not shared_executor or not capability):
        _refuse('generic-scenario-shared-slots-invalid', '/shared_slots')
    irq_firmware=document.get('irq_firmware',False)
    if type(irq_firmware) is not bool or irq_firmware and not {'F4','F5'}<=set(flow_ids):
        _refuse('generic-scenario-IRQ-firmware-invalid','/irq_firmware')
    rounds = document['rounds']
    if type(rounds) is not int or rounds < 1 or rounds > 65536:
        _refuse('generic-scenario-rounds-invalid', '/rounds')
    f4_records = _records(document['f4_records'], '/f4_records')
    f2_records = _records(document['f2_records'], '/f2_records')
    f6_records = _records(document.get('f6_records'), '/f6_records')
    f5_records = _records(document.get('f5_records'), '/f5_records')
    f1_records = _records(document.get('f1_records'), '/f1_records')
    f3_records = _records(document.get('f3_records'), '/f3_records')
    if 'F4' in flow_ids and not f4_records:
        _refuse('generic-scenario-records-required', '/f4_records')
    if 'F2' in flow_ids and not (f2_records or (root / 'f2_read_records.json').is_file()):
        _refuse('generic-scenario-records-required', '/f2_records')
    if 'F6' in flow_ids and not f6_records:
        _refuse('generic-scenario-records-required', '/f6_records')
    if f6_records and ('F6' not in flow_ids or any(len(row) != 16 for row in f6_records)):
        _refuse('generic-scenario-records-invalid', '/f6_records')
    if 'F5' in flow_ids and not f5_records:
        _refuse('generic-scenario-records-required', '/f5_records')
    if f5_records and ('F5' not in flow_ids or any(len(row) != 16 for row in f5_records)):
        _refuse('generic-scenario-records-invalid', '/f5_records')
    return ScenarioDescriptor(scenario_id=scenario_id, root=root, compose=compose,
                              supplement=supplement, capability=capability,
                              flow_ids=tuple(flow_ids), executors=dict(executors),
                              f4_records=f4_records, f2_records=f2_records,
                              f1_records=f1_records, f3_records=f3_records,
                              rounds=rounds, f6_records=f6_records, f5_records=f5_records,irq_firmware=irq_firmware,shared_slots=shared_slots)


def _json(value, path: Path, *, rendered: str | None = None) -> str:
    """Write one exported document and return its exact rendered bytes.

    ``rendered`` republishes text this function produced for the same,
    unmodified value.  Only byte-identical duplicate exports may use it
    (``prefix.json`` / ``compiled_f6_prefix.json``); every other caller renders.
    """
    if rendered is not None and path.name == 'summary.json':
        raise ValueError('summary documents are rendered, never republished')
    if rendered is None:
        if path.name == 'summary.json':
            from myfuzz.search.workflow import candidate_summary
            value = candidate_summary(value)
        rendered = json.dumps(value, indent=2, sort_keys=True, default=str) + '\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered)
    return rendered


def select_case_records(descriptor: ScenarioDescriptor, *, flow: str,
                        records=None, record_limit: int = 0) -> tuple[tuple[str, str], ...]:
    """Select a bounded, explicit sequence before preparing any harness."""
    if type(record_limit) is not int or record_limit < 0:
        _refuse('generic-scenario-record-limit-invalid', '/record_limit')
    if flow == 'mixed':
        if 'F4' not in descriptor.flow_ids or ('F6' in descriptor.flow_ids and not descriptor.shared_slots):
            _refuse('generic-scenario-flow-unsupported', '/flow', {'flow': flow})
        protocol_mmio = (set(descriptor.flow_ids) <= {'F1', 'F2', 'F3', 'F4'}
            and set(descriptor.executors.values()) <= _MMIO_EXECUTORS)
        for case_flow, required in ((f, 'compiled_f2_obi_apb' if f=='F2' else 'compiled_f4_obi_apb')
                                    for f in descriptor.flow_ids):
            if descriptor.shared_slots:
                required = 'compiled_f6_cpu_dma'
            elif protocol_mmio:
                required = descriptor.executor(case_flow)
            if descriptor.executor(case_flow) != required:
                _refuse('generic-scenario-flow-unsupported', '/executors/' + case_flow,
                        {'reason': 'mixed-runtime-not-available'})
        if not isinstance(records, (list, tuple)) or not records:
            _refuse('generic-scenario-records-required', '/records')
        cases = []
        for index, entry in enumerate(records):
            if not isinstance(entry, str) or ':' not in entry:
                _refuse('generic-scenario-record-invalid', f'/records/{index}')
            case_flow, raw = entry.split(':', 1)
            allowed=set(descriptor.flow_ids) | ({'F1','F3'} if not protocol_mmio and set(descriptor.flow_ids)=={'F2','F4'} else set())
            if case_flow not in allowed or not _HEX_RECORD.fullmatch(raw):
                _refuse('generic-scenario-record-invalid', f'/records/{index}')
            if case_flow in ('F5','F6') and len(raw)!=16:
                _refuse('generic-scenario-record-invalid', f'/records/{index}')
            if case_flow in ('F1', 'F3'):
                from .flows.memory import MemoryFlowContext, MemoryFlowKernel
                from myfuzz.isa.constraints import IsaContract
                try:
                    # At selection time only check the implemented I/M/C encoding envelope.
                    # The bound CPU profile is enforced by the live kernel and memory.
                    MemoryFlowKernel().lower(MemoryFlowContext('0' * 64, 'validation', case_flow, 'source', IsaContract(32, ('I', 'M', 'C'), instruction_alignment=2)),
                        {'testcase_id': 'validation', 'path_id': 'validation', 'source_id': 'source',
                         'raw_records_hex': [raw]})
                except ValueError:
                    _refuse('generic-scenario-record-invalid', f'/records/{index}')
            cases.append((case_flow, raw.lower()))
    elif descriptor.shared_slots and flow in descriptor.flow_ids:
        rows = records if records is not None else [flow+':'+raw for raw in descriptor.records(flow)]
        cases = list(select_case_records(descriptor, flow='mixed', records=rows))
        if any(f != flow for f, _ in cases):
            _refuse('generic-scenario-record-invalid', '/records')
    elif flow in ('F1','F3','F5') and shared_f5_descriptor(descriptor):
        rows=records if records is not None else [flow+':'+raw for raw in descriptor.records(flow)]
        cases=list(select_case_records(descriptor,flow='mixed',records=rows))
        if any(f!=flow for f,_ in cases):
            _refuse('generic-scenario-record-invalid','/records')
    elif flow in _STANDALONE_EXECUTORS and descriptor.executor(flow)==_STANDALONE_EXECUTORS[flow]:
        if descriptor.flow_ids != (flow,) or descriptor.executor(flow) != _STANDALONE_EXECUTORS[flow]:
            _refuse('generic-scenario-flow-unsupported', '/flow', {'flow': flow})
        if records is None:
            cases = [(flow, raw) for raw in descriptor.records(flow)]
        else:
            if type(records) not in (list, tuple) or not records:
                _refuse('generic-scenario-records-invalid', '/records')
            cases = []
            for index, entry in enumerate(records):
                if (type(entry) is not str or not entry.startswith(flow + ':')
                        or len(entry) != 19 or not _HEX_RECORD.fullmatch(entry[3:])):
                    _refuse('generic-scenario-record-invalid', f'/records/{index}')
                cases.append((flow, entry[3:].lower()))
    else:
        if flow not in descriptor.flow_ids:
            _refuse('generic-scenario-flow-unsupported', '/flow', {'flow': flow})
        if records is not None:
            _refuse('generic-scenario-records-invalid', '/records',
                    {'reason': 'explicit-records-require-mixed-flow'})
        cases = [(flow, raw) for raw in descriptor.records(flow)]
    if record_limit:
        cases = cases[:record_limit]
    if not cases:
        _refuse('generic-scenario-records-empty', '/records')
    if flow in _STANDALONE_EXECUTORS and not shared_f5_descriptor(descriptor) and len(cases) > 16:
        _refuse('generic-scenario-records-invalid', '/records',
                {'reason': flow + '-slot-limit', 'maximum': 16})
    return tuple(cases)


def shared_f5_descriptor(descriptor):
    return descriptor.executors.get('F5')=='compiled_f4_obi_apb' and 'F4' in descriptor.flow_ids


def case_sequence_for_plan(*, scenario_id: str, plan_document: dict,
                           plan_sha256: str, cases: tuple[tuple[str, str], ...]) -> dict:
    """Bind each input to the corresponding declared path and fuzzable source."""
    paths = plan_document.get('paths', ())
    bindings = {}
    for flow in {case_flow for case_flow, _ in cases}:
        matches = [row for row in paths if row.get('flow_id') == flow]
        if len(matches) != 1:
            _refuse('generic-scenario-flow-unsupported', '/plan/paths', {'flow': flow})
        path = matches[0]
        kinds = {'F1': 'instruction_image', 'F2': 'cpu_load_stream',
                 'F3': 'cpu_store_stream', 'F4': 'cpu_mmio_stream','F5':'external_pin'}
        kind = kinds.get(flow)
        if kind is None:
            _refuse('generic-scenario-flow-unsupported', '/plan/paths', {'flow': flow})
        sources = [source for source in path['sources']
                   if source['kind'] == kind and source.get('origin') == 'fuzzable']
        if len(sources) != 1:
            _refuse('generic-scenario-source-invalid', '/plan/paths', {'flow': flow})
        bindings[flow] = (path['path_id'], sources[0]['source_id'])
    return {
        'schema_version': 'generic_case_sequence.v1',
        'plan_sha256': plan_sha256,
        'cases': [
            {'testcase_id': f'{scenario_id}:{case_flow}:{index}',
             'path_id': bindings[case_flow][0], 'source_id': bindings[case_flow][1],
             'raw_records_hex': [raw]}
            for index, (case_flow, raw) in enumerate(cases)
        ],
    }


def summarize_execution_identities(audit: dict) -> dict:
    """Read actual launched and reaped process facts from the saved audit."""
    if not isinstance(audit, dict):
        return {}
    identities, exits = audit.get('identities'), audit.get('exits')
    identities = identities if isinstance(identities, dict) else {}
    exits = exits if isinstance(exits, dict) else {}
    result = {}
    for name in sorted(set(identities) | set(exits)):
        identity = identities.get(name)
        exit_row = exits.get(name)
        identity = identity if isinstance(identity, dict) else {}
        exit_row = exit_row if isinstance(exit_row, dict) else {}
        pid, code, reaped = identity.get('pid'), exit_row.get('returncode'), exit_row.get('reaped')
        result[name] = {'pid': pid if type(pid) is int and pid > 0 else None,
                        'returncode': code if type(code) is int else None,
                        'reaped': reaped if type(reaped) is bool else None}
    return result


def resolve_rounds(descriptor: ScenarioDescriptor, override: int | None) -> int:
    """Select a complete per-case advance budget before any preparation."""
    value = descriptor.rounds if override is None else override
    if type(value) is not int or not 1 <= value <= 65536:
        _refuse('generic-scenario-rounds-invalid', '/rounds',
                {'minimum': 1, 'maximum': 65536})
    return value


def _trace_document(trace):
    return {name: getattr(trace, name) for name in (
        'genome_sha256', 'status', 'local_ticks', 'semantic_sha256', 'manifest_sha256')} | {
            'events': list(trace.events)}


def _f5_recorded_trace(rows, *, expected, scope):
    return recorded_command_documents(rows, scope='F5', executions={scope: {
        component: {'execution_nonce': nonce} for component, nonce in expected.items()}})[scope]


def _close_runtime_resources(runtime, resources, primary_error, label):
    """Settle existing sessions and release owners while preserving the failure."""
    cleanup_errors = []
    # Finish only the real active session; runtime.finish() also repeats
    # source checks that may themselves have caused the primary failure.
    session = getattr(runtime, 'session', None)
    runner = getattr(runtime, 'runner', None)
    if runner is None:
        runner = getattr(session, 'runner', None)
    sessions = tuple(getattr(runner, 'sessions', {}).values())
    if (session is not None and getattr(session, '_begun', False)
            and not getattr(session, '_finished', False)
            and not getattr(runtime, 'finished', False)):
        try:
            session.finish()
        except BaseException as error:
            cleanup_errors.append(error)
    # A partial begin or an early finalize guard failure can leave children
    # alive even when the scenario session cannot be finished normally.
    for local in sessions:
        try:
            process = getattr(local, 'process', None)
            if process is not None and process.poll() is None:
                local.end_case()
        except BaseException as error:
            cleanup_errors.append(error)
    for resource in resources:
        close = getattr(resource, 'close', None)
        if close is not None:
            try:
                close()
            except BaseException as error:
                cleanup_errors.append(error)
    if cleanup_errors:
        if primary_error is None:
            primary_error = cleanup_errors.pop(0)
            for error in cleanup_errors:
                primary_error.add_note(label + ' cleanup: ' + repr(error))
            raise primary_error
        for error in cleanup_errors:
            primary_error.add_note(label + ' cleanup: ' + repr(error))


def _write_runtime_failure(out, error, runtime):
    """Persist existing evidence before cleanup without claiming a case passed."""
    failure = dict(error_type=type(error).__name__, error=str(error))
    if hasattr(error, 'timeout_diagnostic'):
        failure['timeout_diagnostic'] = error.timeout_diagnostic
    if runtime is not None and getattr(runtime, 'runner', None) is not None:
        runner = runtime.runner
        failure.update(failure_status=runner.failure_status, runner_status=runner._status,
                       local_ticks=dict(runner.local_ticks),
                       events=list(runner.events_since(max(0, runner.event_count-40))))
        session = getattr(runtime, 'session', None)
        failure['terminal_failure'] = getattr(session, '_terminal_failure', None)
    _json(failure, out / 'failure.json')


def _run_f5_descriptor(descriptor, *, cases, mode, case_root, base, cache,
                       rounds, command_trace, max_wall_seconds=None, execution_mode=None,
                       record_selector=None, selected_count=None, expected_records=None):
    """Reuse the checked GPIO online session and its complete fresh replay."""
    if rounds != 32:
        _refuse('generic-scenario-rounds-invalid', '/rounds', {'required': 32})
    from dataclasses import asdict
    from ..integration.ibex_pulp_online import make_ibex_pulp_online_runtime

    out = case_root / mode
    if out.exists():
        _refuse('generic-scenario-output-exists', '/case', {'path': str(out)})
    out.mkdir(parents=True)
    started = time.monotonic()
    context = runtime = None
    try:
        context = create_preparation(base_dir=base, compose_path=descriptor.compose,
            capability_paths=(descriptor.capability,), supplement_path=descriptor.supplement,
            generated_dir=out / 'generated', flow_ids=('F5',))
        runtime = make_ibex_pulp_online_runtime(cache_dir=cache,
            run_id=descriptor.scenario_id + '-F5', f5_only=True,
            preparation_context=context, ip_cross_case=False, initial_ram_data=False)
        _json(runtime.compiled_f5_crosswalk, out / 'topology.json')
        _json([flow + ':' + raw for flow, raw in cases], out / (
            'records.catalog.json' if record_selector is not None else 'records.requested.json'))
        receipts = []
        execution_started = time.monotonic()
        executed = []
        total = len(cases) if record_selector is None else selected_count
        for index in range(total):
            if receipts and max_wall_seconds is not None and time.monotonic() - execution_started >= max_wall_seconds:
                break
            row = None if record_selector is None else record_selector.choose()
            if row is not None and expected_records is not None and row != expected_records[index]:
                raise ValueError('F5 replay decision differs from original')
            raw = cases[index][1] if row is None else row.split(':', 1)[1]
            receipt = runtime.submit_f5(bytes.fromhex(raw))
            document = asdict(receipt)
            with (out / 'receipts.jsonl').open('a', encoding='utf-8') as stream:
                json.dump(document, stream, separators=(',', ':'), sort_keys=True)
                stream.write('\n')
            receipts.append({key: value for key, value in document.items() if key != 'events'})
            if receipt.status != 'running' or receipt.violations:
                raise ValueError('F5-case-not-running:' + receipt.status + ':' + repr(receipt.violations))
            if record_selector is not None:
                record_selector.settle(row)
            executed.append('F5:' + raw)
        execution_seconds = time.monotonic() - execution_started
        _json(executed, out / 'records.json')
        _json(receipts, out / 'receipts.json')
        trace = runtime.session.finish()
        (out / 'online_plan.json').write_bytes(runtime.session.encode_plan())
        _json(_trace_document(trace), out / 'prefix.json')
        _json(list(trace.events), out / 'events.json')
        if trace.status != 'complete':
            raise ValueError('F5-original-not-complete:' + trace.status)
        original_nonces = None
        if command_trace is not None:
            original_nonces = {name: local._execution
                               for name, local in runtime.session.runner.sessions.items()}
            _json(_f5_recorded_trace(command_trace.export_sessions(),
                expected=original_nonces, scope='original'), out / 'local_commands.json')
        replay_matches = None
        if _requires_replay(execution_mode, mode):
            replay = runtime.replay(trace)
            _json(_trace_document(replay.actual_trace), out / 'fresh_prefix.json')
            replay_result = {name: getattr(replay, name) for name in (
                'matches', 'verification_scope', 'first_difference', 'expected_event',
                'actual_event', 'difference_context')}
            _json(replay_result, out / 'replay.json')
            if command_trace is not None:
                rows = command_trace.export_sessions()
                fresh_nonces = {}
                for component in original_nonces:
                    candidates = [row['identity']['execution_nonce'] for row in rows
                                  if row['component'] == component
                                  and row['identity']['execution_nonce'] not in original_nonces.values()]
                    if len(candidates) != 1:
                        raise ValueError('F5 fresh recorded session missing or ambiguous:' + component)
                    fresh_nonces[component] = candidates[0]
                _json(_f5_recorded_trace(rows, expected=fresh_nonces, scope='fresh'),
                      out / 'fresh_local_commands.json')
            replay_matches = (replay.matches is True and replay.verification_scope == 'full'
                and replay.first_difference is None and replay.actual_trace.status == 'complete')
        context.assert_current()
        summary = {'scenario': descriptor.scenario_id, 'flow': 'F5', 'mode': mode,
            'backend': 'compiled_f5_gpio_standalone', 'plan_identity_sha256': None,
            'case_count': len(receipts), 'requested_case_count': total,
            'budget_ended': len(receipts) < total, 'first_case_always_admitted': True,
            'max_wall_seconds': max_wall_seconds, 'execution_seconds': execution_seconds,
            'wall_budget_overrun_seconds': max(0, execution_seconds - max_wall_seconds) if max_wall_seconds is not None else 0,
            'rounds_per_case': rounds,
            'execution_mode': execution_mode, 'verification': _verification(replay_matches, mode),
            'replay_matches': replay_matches,
            'replay_scope': 'within_invocation', 'evidence_dir': str(out),
            'wall_seconds': round(time.monotonic() - started, 2),
            'instruction_retirement': 'unknown', 'isr_causality': 'unknown'}
        _json(summary, out / 'summary.json')
        return summary
    except (ValueError, RuntimeError) as error:
        _refuse('generic-scenario-f5-execution-refused', '/execution',
                {'reason': str(error), 'error_type': type(error).__name__,
                 'evidence_dir': str(out)})
    finally:
        import sys
        _close_runtime_resources(runtime, (context,), sys.exc_info()[1], 'F5')


def _execution_capacity(cases, flow, capacity):
    if capacity is None:
        return len(cases)
    maximum = 16 if flow in ('F5', 'F6') else 65535
    if type(capacity) is not int or not max(1, len(cases)) <= capacity <= maximum:
        _refuse('generic-scenario-case-capacity-invalid', '/execution_case_capacity',
                {'minimum': max(1, len(cases)), 'maximum': maximum})
    return capacity


def _run_f6_descriptor(descriptor, *, cases, mode, case_root, base, cache,
                       rounds, command_trace, max_wall_seconds=None, execution_case_capacity=None, execution_mode=None,
                       record_selector=None, selected_count=None, expected_records=None):
    """Use the existing directed F6 runtime and its own plan and replay."""
    capacity = _execution_capacity(() if record_selector is not None else cases, 'F6', execution_case_capacity)
    if rounds > 4096:
        _refuse('generic-scenario-rounds-invalid', '/rounds', {'maximum': 4096})
    from ..integration.compiled_execution_files import run_compiled_execution_files

    case_root.mkdir(parents=True, exist_ok=True)
    records_path = case_root / (mode + '-f6-records.json')
    try:
        with records_path.open('x', encoding='utf-8') as stream:
            json.dump([raw for _, raw in cases], stream)
            stream.write('\n')
    except FileExistsError:
        _refuse('generic-scenario-output-exists', '/case', {'path': str(records_path)})
    started = time.monotonic()
    evidence_dir = case_root / mode
    try:
        report = run_compiled_execution_files(
            base_dir=base, compose_path=descriptor.compose,
            capability_paths=(descriptor.capability,), supplement_path=descriptor.supplement,
            records_path=records_path, output_dir=evidence_dir, cache_dir=cache,
            executor=descriptor.executor('F6'), run_id=descriptor.scenario_id + '-F6',
            rounds_per_case=rounds, max_cases=capacity, replay_count=int(_requires_replay(execution_mode, mode)),
            max_wall_seconds=max_wall_seconds,
            **({'record_selector':record_selector, 'selected_count':selected_count,
                'expected_records':expected_records} if record_selector is not None else {}))
    except (ValueError, RuntimeError) as error:
        raise GenericScenarioRefused('generic-scenario-f6-execution-refused',
            '/executor/F6', {'error_type': type(error).__name__, 'error': str(error),
                'evidence_dir': str(evidence_dir),
                'evidence_dir_exists': evidence_dir.is_dir()}) from error
    if command_trace is not None:
        try:
            original = json.loads((evidence_dir / 'compiled_f6_prefix.json').read_text())['original_execution_audit']['identities']
            fresh = (json.loads((evidence_dir / 'compiled_f6_fresh_execution_audit.json').read_text())['identities']
                if _requires_replay(execution_mode, mode) else None)
            rows = command_trace.export_sessions()
            documents = recorded_command_documents(rows, scope='F6', audited=True,
                executions={'original': original, **({'fresh': fresh} if fresh is not None else {})})
            _json(documents['original'], evidence_dir/'local_commands.json')
            if fresh is not None:
                _json(documents['fresh'], evidence_dir/'fresh_local_commands.json')
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
            raise GenericScenarioRefused('generic-scenario-f6-trace-refused',
                '/record_local_commands', {'error_type':type(error).__name__, 'error':str(error),
                                           'evidence_dir':str(evidence_dir)}) from error
    verification = report.get('fresh_verification')
    replay_matches = (report.get('status') == 'complete'
        and report.get('runtime_admitted') is True
        and type(report.get('case_count')) is int
        and 0 <= report['case_count'] <= (selected_count if record_selector is not None else len(cases))
        and type(verification) is dict and verification.get('matches') is True
        and verification.get('completed') is True
        and verification.get('verification_scope') == 'full')
    if not _requires_replay(execution_mode, mode):
        replay_matches = None
    summary = {'execution_mode': execution_mode, 'verification': _verification(replay_matches, mode),
        'scenario': descriptor.scenario_id, 'flow': 'F6', 'mode': mode,
        'backend': 'compiled_f6_standalone', 'plan_identity_sha256': None,
        'execution_case_capacity': capacity,
        'replay_scope': 'within_invocation', 'evidence_dir': str(evidence_dir),
        'case_count': report.get('case_count'),
        'requested_case_count': selected_count if record_selector is not None else len(cases),
        'budget_ended': report.get('budget_ended', False),
        'first_case_always_admitted': report.get('first_case_always_admitted', True),
        'max_wall_seconds': max_wall_seconds,
        'execution_seconds': report.get('execution_seconds'),
        'wall_budget_overrun_seconds': report.get('wall_budget_overrun_seconds'),
        'rounds_per_case': rounds,
        'replay_matches': replay_matches, 'wall_seconds': time.monotonic() - started}
    _json(summary, evidence_dir / 'summary.json')
    return summary


def run_descriptor(descriptor: ScenarioDescriptor, *, flow: str, mode: str,
                   case_root, base_dir, cache_dir=None, record_limit: int = 0,
                   sequence=None, rounds: int | None = None, command_trace=None,
                   max_wall_seconds: float | None = None, allow_empty_sequence=False,
                   preparation_memory_flows: bool | None = None,
                   execution_case_capacity: int | None = None, execution_mode=None,
                   record_selector=None, selected_count=None, expected_records=None,
                   log: Callable[[str], None] = print) -> dict:
    """Execute one descriptor using its admitted flow backend."""
    from ..local_harness.generated_execution_admission import create_compiled_execution
    from myfuzz.search.workflow import requires_replay
    requires_replay(execution_mode, mode)

    if max_wall_seconds is not None and (type(max_wall_seconds) not in (int, float)
            or not math.isfinite(max_wall_seconds) or max_wall_seconds <= 0):
        _refuse('generic-scenario-wall-budget-invalid', '/max_wall_seconds')
    if preparation_memory_flows is not None and type(preparation_memory_flows) is not bool:
        _refuse('generic-scenario-preparation-invalid', '/preparation_memory_flows')
    if allow_empty_sequence and (mode != 'fresh' or sequence != []):
        _refuse('generic-scenario-empty-sequence-invalid', '/sequence')
    if mode not in ('original', 'fresh'):
        _refuse('generic-scenario-mode-invalid', '/mode')
    effective_rounds = resolve_rounds(descriptor, rounds)
    shared_f5=shared_f5_descriptor(descriptor)
    shared_campaign=flow=='mixed' or shared_f5
    single_selector = (record_selector is not None and flow == 'F4'
                       and descriptor.flow_ids == ('F4',)
                       and descriptor.executor('F4') == 'compiled_f4_wishbone')
    if single_selector:
        cases = select_case_records(descriptor, flow=flow)
    elif record_selector is not None and flow in ('F5', 'F6', 'mixed'):
        # The catalog is a domain, not an execution sequence: its size need
        # not fit the standalone executor's per-campaign case limit.
        cases = tuple(case for row in sequence for case in
                      select_case_records(descriptor, flow=flow, records=[row]))
    else:
        cases = () if allow_empty_sequence else select_case_records(descriptor, flow=flow, records=sequence,
                                    record_limit=record_limit)
    if record_selector is not None:
        if ((not single_selector and flow not in ('F5', 'F6', 'mixed')) or type(selected_count) is not int
                or not (0 if (flow == 'mixed' or single_selector) and mode == 'fresh' else 1) <= selected_count <= (16 if flow in ('F5', 'F6') else 65535)):
            _refuse('generic-scenario-selector-invalid', '/record_selector')
        if expected_records is not None and len(expected_records) != selected_count:
            _refuse('generic-scenario-selector-invalid', '/expected_records')
        capacity = _execution_capacity((), flow, execution_case_capacity)
        if selected_count > capacity:
            _refuse('generic-scenario-case-capacity-invalid', '/execution_case_capacity')
    else:
        capacity = _execution_capacity(cases, flow, execution_case_capacity)
    selected_memory_flows = any(case_flow in ('F1', 'F3') for case_flow, _ in cases)
    if preparation_memory_flows is False and selected_memory_flows:
        _refuse('generic-scenario-preparation-invalid', '/preparation_memory_flows',
                {'reason': 'selected-memory-flow-requires-memory-preparation'})
    base = Path(base_dir).resolve()
    case_root = Path(case_root)
    if not case_root.is_absolute():
        case_root = (base / case_root).resolve()
    cache = Path(cache_dir) if cache_dir is not None else Path(
        os.environ.get('GENERIC_SCENARIO_CACHE', str(case_root / 'cache')))
    if not cache.is_absolute():
        cache = (base / cache).resolve()
    if allow_empty_sequence and flow in ('F5', 'F6'):
        _refuse('generic-scenario-empty-sequence-invalid', '/sequence',
                {'reason': 'standalone-first-case-always-admitted-no-zero-prefix-executor'})
    if descriptor.shared_slots:
        from .flows.shared_slots import run_shared_slot_descriptor
        return run_shared_slot_descriptor(descriptor, cases=cases, mode=mode, case_root=case_root,
            base=base, cache=cache, rounds=effective_rounds, capacity=capacity,
            execution_mode=execution_mode, max_wall_seconds=max_wall_seconds,
            record_selector=record_selector, selected_count=selected_count, expected_records=expected_records,
            command_trace=command_trace)
    if flow == 'F6':
        return _run_f6_descriptor(descriptor, cases=cases, mode=mode,
            case_root=case_root, base=base, cache=cache, rounds=effective_rounds,
            command_trace=command_trace, max_wall_seconds=max_wall_seconds,
            execution_case_capacity=capacity, execution_mode=execution_mode,
            **({'record_selector':record_selector, 'selected_count':selected_count,
                'expected_records':expected_records} if record_selector is not None else {}))
    if flow == 'F5' and not shared_f5:
        return _run_f5_descriptor(descriptor, cases=cases, mode=mode,
            case_root=case_root, base=base, cache=cache, rounds=effective_rounds,
            command_trace=command_trace, max_wall_seconds=max_wall_seconds, execution_mode=execution_mode,
            record_selector=record_selector, selected_count=selected_count, expected_records=expected_records)
    work = case_root / 'work'
    generated = work / 'generated'
    work.mkdir(parents=True, exist_ok=True)
    out = case_root / mode
    out.mkdir(parents=True, exist_ok=True)
    if mode == 'fresh':
        sidecars = out / 'work-sidecars'
        sidecars.mkdir(parents=True, exist_ok=True)
        for name in ('path_compile_request.json', 'compiled_paths.json',
                     'capability_selection.json'):
            source = work / name
            if source.exists():
                shutil.move(str(source), str(sidecars / name))
        if generated.exists():
            shutil.move(str(generated), str(out / 'generated-partial'))
    started = time.time()
    memory_flows = ((selected_memory_flows if preparation_memory_flows is None
                    else preparation_memory_flows) or (shared_f5 and bool(set(descriptor.flow_ids)&{'F1','F3'})))
    context = create_preparation(
        base_dir=base, compose_path=descriptor.compose,
        capability_paths=(descriptor.capability,),
        supplement_path=descriptor.supplement,
        generated_dir=generated, flow_ids=(descriptor.flow_ids if shared_f5 else
            ('F1', 'F2', 'F3', 'F4') if memory_flows else descriptor.flow_ids))
    runtime = bound = None
    try:
        bindings = plan_bindings(context)
        components = []
        selections = []
        requirements = []
        by_instance = {}
        for binding in bindings:
            component = by_instance.get(binding.instance_id)
            if component is None:
                component = verify_component(context.artifact(binding.instance_id),
                                             preparation=context, base_dir=base)
                by_instance[binding.instance_id] = component
                components.append(component)
            requirement = requirement_for_binding(component, binding)
            selection = select_adapter(component, requirement, preparation=context)
            selections.append(selection)
            requirements.append(requirement)
        plan = compile_execution_plan(context, components=tuple(components),
                                      selections=tuple(selections),
                                      requirements=tuple(requirements))
        sequence = case_sequence_for_plan(scenario_id=descriptor.scenario_id,
            plan_document=plan.document(), plan_sha256=plan.identity_sha256, cases=cases)
        _json({'components': [c.document() for c in components],
               'selections': [s.document() for s in selections],
               'input_digests': context.input_digests}, out / 'declarations.json')
        (out / 'execution_plan.json').write_bytes(plan.document_bytes)
        runtime_options = ({'mixed_flows': True, 'memory_flows': True} if memory_flows
                           else {'mixed_flows': True} if shared_campaign else {})
        if descriptor.executor('F4' if shared_campaign else flow) in _MMIO_EXECUTORS:
            runtime_options['default_flow'] = None if shared_campaign else flow
        if shared_f5:
            runtime_options['f5_preparation']=context
            runtime_options['irq_firmware']=descriptor.irq_firmware
        runtime = create_compiled_execution(
            artifacts=context.artifacts, compiled_inputs=context.compiled_inputs(),
            executor=descriptor.executor('F4' if shared_campaign else flow),
            base_dir=base, cache_dir=cache,
            run_id=f'{descriptor.scenario_id}-{flow}', rounds_per_case=effective_rounds,
            max_cases=capacity + 1, defer_begin=True, **runtime_options)
        sessions = dict(runtime.runner.sessions)
        context.attach_runtime(runner=runtime.runner, sessions=sessions)
        admitted = (runtime.session._runtime_prepared if shared_campaign
                    else runtime.runtime_path_admission.prepared)
        context.register_prepared_paths(prepared=admitted,
                                        runtime_paths=admitted.runtime_paths,
                                        graph=admitted.graph)
        bound = bind_execution_plan(plan, preparation=context, sessions=sessions,
                                    prepared_paths=admitted, runner=runtime.runner)
        _json(bound.documentary(), out / 'binding.json')
        _json(sequence, out / 'case_sequence.requested.json')
        backend = (MixedStorageFlowBackend(runtime=runtime) if shared_campaign
                   else StorageFlowBackend(runtime=runtime, flow_id=flow))
        if record_selector is not None and callable(getattr(record_selector, 'attach_runtime', None)):
            record_selector.attach_runtime(runtime)
        case_feedback_factory = None
        if shared_campaign:
            from myfuzz.search.record_feedback import RecordConsumptionFeedback
            case_feedback_factory = lambda: RecordConsumptionFeedback(runtime.runner)
        from .flows.mixed import MixedStorageKernel
        report = run_directed_campaign(
            bound_plan=bound, backend=backend, sequence=sequence,
            kernel=MixedStorageKernel(flow_ids=context.flow_ids) if shared_campaign else StorageFlowKernel(),
            budget=CampaignBudget(max_cases=capacity + 1, max_wall_seconds=max_wall_seconds),
            run_id=f'{descriptor.scenario_id}-{flow}',
            **({'case_feedback_factory': case_feedback_factory} if case_feedback_factory is not None else {}),
            **({'record_selector': record_selector, 'selected_count': selected_count,
                'expected_records': expected_records, 'case_id_prefix': descriptor.scenario_id}
               if record_selector is not None else {}),
            **({'allow_empty_sequence': True} if allow_empty_sequence else {}))
        _json(report, out / 'campaign.json')
        prefix = runtime.finish()
        _json(prefix, out / 'prefix.json')
        events = list(runtime.trace.events)
        _json(events, out / 'events.json')
        execution_audit = runtime.execution_audit()
        _json(execution_audit, out / 'execution_audit.json')
        if command_trace is not None:
            _json({'schema_version': 'local_command_trace.v1',
                   'scope': 'successful driver wire commands from the completed campaign',
                   'sessions': {name: {'complete': command_trace.complete_for(session),
                                       'identity': execution_audit.get('identities', {}).get(name),
                                       'records': command_trace.for_session(session)}
                                for name, session in runtime.runner.sessions.items()}},
                  out / 'local_commands.json')
        identities = summarize_execution_identities(execution_audit)
        replay = {'matches': None}
        if requires_replay(execution_mode, mode):
            replay = runtime.replay(prefix)
        _json({key: value for key, value in replay.items()
               if key not in ('actual_prefix', 'actual_events')}, out / 'replay.json')
        summary = {'mode': mode, 'flow': flow, 'scenario': descriptor.scenario_id,
                   'plan_identity_sha256': plan.identity_sha256,
                   'input_digests': context.input_digests,
                   'case_count': report.get('case_count', report.get('sequence_case_count')),
                   'requested_case_count': selected_count if record_selector is not None else len(cases),
                   'execution_case_capacity': capacity,
                   'budget_ended': report.get('budget_ended', False),
                   'max_wall_seconds': max_wall_seconds,
                   'execution_seconds': report.get('execution_seconds'),
                   'wall_budget_overrun_seconds': report.get('wall_budget_overrun_seconds'),
                   'rounds_per_case': effective_rounds,
                   'identities': identities,
                   'execution_mode': execution_mode,
                   'verification': _verification(replay.get('matches'), mode),
                   'replay_matches': replay.get('matches'),
                   'wall_seconds': round(time.time() - started, 2),
                   'generated_path': str(generated),
                   'status': 'observed'}
        _json(summary, out / 'summary.json')
        shutil.copytree(generated, out / 'generated', dirs_exist_ok=False)
    except BaseException as error:
        try:
            _write_runtime_failure(out, error, runtime)
        except Exception as diagnostic_error:
            error.add_note('failure diagnostic could not be saved: ' + repr(diagnostic_error))
        raise
    finally:
        import sys
        _close_runtime_resources(runtime, (bound, context, runtime),
                                 sys.exc_info()[1], 'shared campaign')
    shutil.move(str(generated), str(case_root / f'generated-{mode}-archived'))
    log(json.dumps({'mode': mode, 'scenario': descriptor.scenario_id, 'flow': flow,
                    'plan': plan.identity_sha256,
                    'cases': report.get('case_count', report.get('sequence_case_count')),
                    'execution_mode': execution_mode,
                   'verification': _verification(replay.get('matches'), mode),
                   'replay_matches': replay.get('matches'),
                    'wall_seconds': round(time.time() - started, 2)},
                   sort_keys=True))
    return summary


def _requires_replay(execution_mode, mode):
    from myfuzz.search.workflow import requires_replay
    return requires_replay(execution_mode, mode)


def _verification(matches, mode):
    return {"within_invocation": {"status": "not-requested" if matches is None else "verified" if matches is True else "failed", "matches": matches},
            "cross_invocation": {"status": "pending" if mode == "fresh" else "not-requested", "matches": None}}
