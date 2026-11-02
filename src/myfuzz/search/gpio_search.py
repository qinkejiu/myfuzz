"""Finite live GPIO search. Saved documents never confer execution authority.

Run fresh as a separate CLI invocation. Build/init are separate from the search
clock; deadlines stop at the original runtime's complete advance boundary.
"""
import argparse
from contextlib import nullcontext
from dataclasses import asdict, is_dataclass
from hashlib import sha256
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
import time
import traceback
from uuid import uuid4

from .workflow import requires_replay, run_boundary
from .case_adapter import CaseAdapter, CaseContext
from .gpio_case_adapter import GpioCaseAdapter
from .frontier import frontier
from .journal import Journal, verify_journal
from .model import Condition, Goal, Observation, Snapshot, canonical
from .native import ROOT, save, source_files as _base_source_files
from .policy import Policy
from .r1_session import create_r1_session

_CONTROLLER_EXECUTION_NONCE = uuid4().hex


def source_files():
    """Freeze R1 Python assembly/gates in addition to the shared research code.

    Native build/source receipts independently authenticate actual executable
    closure. This manifest also detects host admission/observer policy drift.
    """
    rows = _base_source_files()
    existing = {(row['base'], row['path']) for row in rows}
    for directory in ('src/myfuzz/scenario', 'src/myfuzz/local_harness', 'src/myfuzz/integration'):
        for path in sorted((ROOT / directory).glob('*.py')):
            relative = str(path.relative_to(ROOT))
            if ('project', relative) not in existing:
                rows.append({'base': 'project', 'path': relative,
                             'sha256': sha256(path.read_bytes()).hexdigest()})
    for relative in ('src/myfuzz/runtime/recorded_commands.py',):
        path = ROOT / relative
        rows.append({'base': 'project', 'path': relative,
                     'sha256': sha256(path.read_bytes()).hexdigest()})
    return sorted(rows, key=lambda row: (row['base'], row['path']))


def runtime_identity(configuration):
    """DUT/profile identity uses actual configured RTL pins, never host code."""
    sources, profiles = {}, {}
    for component, artifact in configuration.get('artifacts', {}).items():
        verification, plan = artifact['source_verification'], artifact['plan']
        sources[component] = {key: verification.get(key) for key in
            ('selected_content_hash', 'closure_sha256')}
        sources[component]['plan_source_content_hash'] = plan['source_content_hash']
        sources[component]['source_files'] = plan['source_files']
        profiles[component] = {'profile_sha256': plan['profile_sha256'],
            'current_profile_fingerprint': artifact['current_profile_fingerprint'],
            'binding_hash': artifact['current_binding']['binding_hash']}
    if not sources:
        return {'source': None, 'profile': None}  # Failed init/documentary fixtures.
    return {'source': 'sha256:' + sha256(canonical(sources)).hexdigest(),
            'profile': 'sha256:' + sha256(canonical(profiles)).hexdigest()}


def semantic_relation(row):
    """Declared endpoint/value class only: no event, epoch, nonce or version."""
    return 'gpio-consumption:' + sha256(canonical([
        row.get('proof_scope', 'register_version'), row['component'], row['register'], row['bit_lo'], row['width'],
        [r['value'] for r in row['bit_resources']]])).hexdigest()


def field_identity(field):
    if field.get('status') != 'observed' or not field.get('bit_resources'):
        return None
    return canonical([field.get('reset_epoch'), field['bit_resources']])


def semantic_field(field):
    # Resource identities remain in state-transitions; only classes enter policy.
    return {key: field.get(key) for key in ('status', 'value', 'bit_lo', 'width', 'writer_attributed')}


def search_view(field, report, *, ablation='none'):
    goal = Goal('gpio:configuration-consumption', 'gpioen:consumed', (
        Condition('gpioen:configured'),
        Condition('gpioen:observed', ('gpioen:configured',)),
        Condition('pin8:proposed', ('gpioen:configured',)),
        Condition('gpioen:consumed', ('gpioen:observed', 'pin8:proposed'), 'any')))
    epoch = field.get('reset_epoch', 0)
    known = field_identity(field) is not None
    written = (known and field.get('writer_attributed') is True
               and all(r.get('version', 0) > 0 for r in field['bit_resources']))
    matching = [r for r in report.get('relations', ()) if r.get('reward_eligible') is True
        and canonical([r.get('reset_epoch'), r.get('bit_resources')]) == field_identity(field)]
    consumed = written and any(r.get('proof_scope') != 'native_gpio_irq_configuration_consumption'
        for r in matching)
    irq_consumed = written and any(r.get('proof_scope') == 'native_gpio_irq_configuration_consumption'
        for r in matching)
    observations = {
        'pin8:proposed': Observation('satisfied' if irq_consumed else 'unknown',
            'consumed' if irq_consumed else 'unobserved',
            ('live:irq-configuration-consumption',) if irq_consumed else (), epoch),
        'gpioen:configured': Observation('satisfied' if written else 'unknown',
            str(field.get('value')) if written else 'unknown',
            ('live:gpioen-resources',) if written else (), epoch),
        'gpioen:observed': Observation('satisfied' if consumed else 'unknown',
            'consumed' if consumed else 'unobserved',
            ('live:exact-read',) if consumed else (), epoch)}
    if ablation == 'state':
        observations = {}
    if ablation == 'frontier':
        # Flat unreachable-by-proposal marker removes only frontier focusing.
        goal = Goal('gpio:write-read:unfocused', 'unfocused', (Condition('unfocused'),))
    return goal, Snapshot(epoch, observations)


class GpioCredit:
    """Exact live-report joins; unresolved/overwritten producers are censored.

    The runner passes only its installed observer's report. This helper itself
    has no authority and cannot authenticate a caller-supplied dictionary.
    """
    def __init__(self, policy, *, ablation='none'):
        self.policy, self.ablation = policy, ablation
        self.pending = {}
        self.writers = {}
        self.costs = {}
        self.case_decisions = {}

    def observe(self, decision, case_id, field, report, cost_ns):
        self.costs[decision.id] = cost_ns
        self.case_decisions[case_id] = decision.id
        answers, accepted = [], []
        current = field_identity(field)
        self.writers = {key: row for key, row in self.writers.items()
                        if current is not None and row['resource'] == current}
        for key, row in list(self.pending.items()):
            if current is None or current != row['resource']:
                answers.append(self.policy.settle(key, {}, self.costs[key], censored=True))
                del self.pending[key]
        if decision.action_id == 'gpioen:write' and current is not None:
            self.pending[decision.id] = {'case_id': case_id, 'resource': current}
            self.writers[decision.id] = {'case_id': case_id, 'resource': current}
        joined = False
        if self.ablation != 'credit':
            for relation in report.get('relations', ()):
                if (relation.get('reward_eligible') is not True
                        or relation.get('status') != 'verified'
                        or relation.get('read_case_id', relation.get('consumer_case_id')) != case_id):
                    continue
                writers = relation.get('writer_case_ids', ())
                participants = tuple(sorted(set(self.case_decisions.get(v, '') for v in writers)))
                resource = canonical([relation.get('reset_epoch'), relation.get('bit_resources')])
                if (not participants or '' in participants
                        or not all(v in self.writers and self.writers[v]['resource'] == resource
                                   for v in participants)):
                    continue  # Missing reliable ownership never consumes novelty.
                participants = tuple(sorted(set(participants + (decision.id,))))
                feature = semantic_relation(relation)
                incremental = self.policy.settle_relation_group(participants,
                    {'relation': (feature,)}, {v: self.costs[v] for v in participants})
                if incremental is None:
                    continue
                answers.extend(incremental)
                for key in participants:
                    self.pending.pop(key, None)
                accepted.append(feature)
                joined = True
                break  # One slice; no duplicate terminal settlement of consumer.
        if self.ablation == 'credit':
            self.pending.pop(decision.id, None)
            eligible = [r for r in report.get('relations', ())
                if r.get('reward_eligible') is True and r.get('status') == 'verified'
                and r.get('read_case_id', r.get('consumer_case_id')) == case_id
                and r.get('writer_case_ids')
                and all(v in self.case_decisions for v in r['writer_case_ids'])]
            if eligible:
                features = tuple(sorted(set(semantic_relation(r) for r in eligible)))
                answers.append(self.policy.settle(decision.id, {'relation': features}, cost_ns))
                accepted.extend(features)
                joined = True
        if decision.id not in self.pending and not joined:
            answers.append(self.policy.settle(decision.id, {}, cost_ns))
        return {'settlements': answers, 'pending': sorted(self.pending),
                'credited_relations': accepted, 'native_authority': False}

    def finalize_cost(self, decision_id, cost_ns):
        self.policy.finalize_cost(decision_id, cost_ns)
        self.costs[decision_id] = cost_ns

    def finish(self):
        answers = [self.policy.settle(key, {}, self.costs[key], censored=True)
                   for key in sorted(self.pending)]
        self.pending.clear()
        return {'settlements': answers, 'relation_observation': 'budget-ended',
                'native_authority': False}


def live_report(assembly):
    report = assembly.observer.report()
    irq = (assembly.observer.irq_report() if hasattr(assembly.observer, 'irq_report')
           else {'status': 'unknown', 'relations': (), 'irq_status': 'unknown',
                 'isr_status': 'unknown'})
    return dict(report, relations=list(report.get('relations', ())) + list(irq.get('relations', ())),
                irq_status=irq.get('irq_status', 'unknown'),
                isr_status=irq.get('isr_status', 'unknown'))


def _plain(value):
    if is_dataclass(value):
        return _plain(asdict(value))
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


def _load(path):
    return json.loads(Path(path).read_text())


def _prefix(assembly):
    return assembly.session.encode_plan()


def _advance_count(plan, case_id):
    matches = [row for row in json.loads(plan)['cases'] if row['case_id'] == case_id]
    if len(matches) != 1 or not matches[0]['advances']:
        raise ValueError('actual case advance prefix missing')
    return len(matches[0]['advances'])


def execute(*, mode, policy, cases, seconds, seed, output, cache,
            ablation='none', original=None, record_local_commands=False, command_trace=None,
            execution_mode=None, elaboration_mode=None):
    from myfuzz.composition.component_profile import elaboration_mode_scope, supervisor_available
    preexisting_output = Path(output).exists() or Path(output).is_symlink()
    if elaboration_mode not in (None, 'direct', 'supervised'):
        raise ValueError('invalid elaboration mode')
    selected_mode = elaboration_mode
    if mode == 'fresh':
        if original is None:
            raise ValueError('fresh requires --original')
        reference = _load(Path(original) / 'summary.json')
        recorded_mode = reference.get('elaboration_mode')
        if recorded_mode not in (None, 'direct', 'supervised'):
            raise ValueError('invalid original elaboration mode')
        if recorded_mode is None and execution_mode is not None:
            raise ValueError('original elaboration mode missing')
        if recorded_mode is not None:
            configuration_mode = _load(Path(original) / 'configuration.json').get('elaboration_mode')
            if configuration_mode != recorded_mode:
                raise ValueError('original elaboration mode configuration mismatch')
        if selected_mode is not None and selected_mode != recorded_mode:
            raise ValueError('fresh elaboration mode differs from original')
        selected_mode = recorded_mode
    elif selected_mode is None and execution_mode is not None:
        selected_mode = 'supervised' if supervisor_available()[0] else 'direct'
    parameters = dict(mode=mode, policy=policy, cases=cases, seconds=seconds, seed=seed,
                      output=output, cache=cache, ablation=ablation, original=original,
                      record_local_commands=record_local_commands, command_trace=command_trace,
                      execution_mode=execution_mode, elaboration_mode=selected_mode)
    run = lambda: _execute(**parameters)
    try:
        with elaboration_mode_scope(selected_mode):
            return run() if execution_mode is None else run_boundary(output, run, execution_mode=execution_mode, mode=mode)
    except Exception as error:
        if execution_mode is not None and not preexisting_output and Path(output).is_dir():
            specimen = export_gpio_failure_specimen(output, error, cache_dir=cache)
            if specimen['status'] == 'ready':
                from .failure_replay import launch_failure_replay
                try:
                    diagnosis = launch_failure_replay(Path(output) / 'failure-specimen.json',
                        Path(output) / 'failure-reproduction')
                except Exception as replay_error:
                    diagnosis = {'status': 'replay-error', 'accepted': False, 'dut_bug': False,
                                 'error': repr(replay_error)}
            else:
                diagnosis = {'status': 'refused', 'accepted': False, 'dut_bug': False,
                             'reason': specimen.get('reason', 'GPIO specimen unavailable')}
            save(Path(output) / 'failure-replay.json', diagnosis)
        raise


def _execute(*, mode, policy, cases, seconds, seed, output, cache,
            ablation='none', original=None, record_local_commands=False, command_trace=None,
            execution_mode=None, elaboration_mode=None):
    requires_replay(execution_mode, mode, legacy_default=False)
    if (mode not in ('original', 'fresh') or policy not in ('state', 'uniform', 'legacy')
            or ablation not in ('none', 'frontier', 'state', 'credit', 'cost')
            or type(cases) is not int or not 1 <= cases <= 128
            or type(seconds) not in (int, float) or not 0 < seconds <= 86400
            or type(seed) is not int):
        raise ValueError('bounded GPIO search configuration required')
    if type(record_local_commands) is not bool or (record_local_commands and command_trace is None):
        raise ValueError('recording requires an active command trace context')
    output, cache = Path(output), Path(cache)
    output.mkdir(parents=True, exist_ok=False)
    e2e = time.monotonic_ns()
    frozen = source_files()
    reference = expected = None
    if mode == 'fresh':
        if original is None:
            raise ValueError('fresh requires --original')
        original = Path(original)
        reference = _load(original / 'summary.json')
        sidecar_path = original / 'search-summary.json'
        boundary = reference.get('verification', {}).get('session_boundary')
        if sidecar_path.exists():
            sidecar = _load(sidecar_path)
            boundary = sidecar.get('verification', {}).get('session_boundary')
            if boundary is None or boundary.get('status') != 'verified' or boundary.get('matches') is not True:
                raise ValueError('fresh requires verified original session boundary')
        elif boundary is not None and boundary.get('status') != 'verified':
            raise ValueError('fresh requires verified original session boundary')
        verify_journal(original / 'decisions.jsonl', expected_head=reference['journal_head'])
        if (reference['status'] not in ('completed', 'budget-ended')
                or reference.get('controller_execution_nonce') == _CONTROLLER_EXECUTION_NONCE
                or not reference.get('controller_execution_nonce')
                or reference['source_files'] != frozen
                or reference.get('record_local_commands', False) != record_local_commands
                or (policy, cases, seconds, seed, ablation) != tuple(reference[k]
                    for k in ('policy', 'requested_cases', 'fixed_seconds', 'seed', 'ablation'))):
            raise ValueError('fresh requires separate process and identical original configuration/source')
        expected = _load(original / 'selected_cases.json')
    journal = Journal(output / 'decisions.jsonl')
    assembly = None
    steps, selected, events, seen = [], [], [], set()
    processes = {}
    useful_case_ids = set()
    useful_case_events = []
    unadmitted = None
    configuration = {}
    command_export_ready = False
    command_export_seconds = 0
    error = None
    search_started = None
    build_ns = init_ns = tail_ns = 0
    status, replay_matches = 'failed', None
    terminal = None
    failure_phase = 'prepare'
    try:
        build_start = time.monotonic_ns()
        assembly = create_r1_session(cache_dir=cache, advance_rounds=96,
                                     audit_all_components=record_local_commands)
        build_ns = time.monotonic_ns() - build_start
        save(output / 'catalog.json', assembly.space.document())
        configuration = _plain(assembly.registers.configuration())
        if elaboration_mode is not None:
            configuration['elaboration_mode'] = elaboration_mode
        save(output / 'configuration.json', configuration)
        if original is not None and mode == 'fresh' and configuration != _load(original / 'configuration.json'):
            raise ValueError('fresh runtime configuration differs')
        init_start = time.monotonic_ns()
        assembly.begin()
        init_ns = time.monotonic_ns() - init_start
        processes = {name: session.process for name, session in assembly.runner.sessions.items()}
        scheduler = Policy(seed=seed, mode=policy)
        credit = GpioCredit(scheduler, ablation=ablation)
        case_adapter: CaseAdapter = GpioCaseAdapter(assembly, credit)
        search_started = time.monotonic_ns()
        deadline = search_started + int(seconds * 1e9)
        limit = len(expected) if expected is not None else cases
        status = 'completed'
        for index in range(limit):
            failure_phase = 'decision'
            t0 = time.monotonic_ns()
            if mode == 'original' and t0 >= deadline:
                status = 'budget-ended'
                break
            before = case_adapter.current_state()
            report_before = live_report(assembly)
            goal, view = search_view(before, report_before, ablation=ablation)
            if mode == 'original' and time.monotonic_ns() >= deadline:
                status = 'budget-ended'
                break
            choose_started = time.monotonic_ns()
            decision = scheduler.choose(goal, view, assembly.space.catalog)
            decision_ns = time.monotonic_ns() - choose_started
            case_id = f'gpio-search-{index}'
            entry = {'case_id': case_id, 'decision': decision.document()}
            if expected is not None and entry != {k: expected[index][k] for k in entry}:
                raise ValueError('fresh live-state policy decision differs')
            journal.append({'kind': 'decision', **entry, 'field': before,
                            'frontier': frontier(goal, view)})
            case_context = CaseContext(case_id,
                replay_advance_count=expected[index]['advance_count'] if mode == 'fresh' else None,
                deadline_ns=deadline if mode == 'original' else None)
            try:
                failure_phase = 'submit'
                receipt = case_adapter.execute(decision, case_context)
            except TimeoutError as timeout:
                if mode != 'original' or str(timeout) != 'R1 search budget expired before admission':
                    raise
                cost = max(1, time.monotonic_ns() - t0)
                unadmitted = {'decision': decision.document(), 'cost_ns': cost,
                    'settlement': scheduler.settle(decision.id, {}, cost, censored=True)}
                journal.append({'kind': 'unadmitted-budget-censor', **unadmitted})
                status = 'budget-ended'
                break
            failure_phase = 'feedback'
            after = case_adapter.current_state()
            report = live_report(assembly)
            plan = _prefix(assembly)
            entry['advance_count'] = _advance_count(plan, case_id)
            selected.append(entry)
            elapsed = max(1, time.monotonic_ns() - t0)
            policy_execution_cost = (expected[index]['execution_cost_ns']
                                     if expected is not None else elapsed)
            if ablation == 'cost':
                policy_execution_cost = 1
            settlement = case_adapter.settle(decision, case_context, receipt, after, report, policy_execution_cost)
            semantic = {'field': semantic_field(after), 'relations': sorted(set(
                semantic_relation(r) for r in report.get('relations', ())
                if r.get('reward_eligible') is True)), 'settlement': settlement}
            if expected is not None and semantic != expected[index]['semantic']:
                raise ValueError('fresh relation/state/participant settlement differs')
            now_seconds = (time.monotonic_ns() - search_started) / 1e9
            # Metrics use certified observed relations, independently of ablation reward.
            for key in semantic['relations']:
                if key not in seen:
                    seen.add(key)
                    events.append({'seconds': now_seconds, 'semantic_key': key})
                    actual_cases = {entry['case_id'] for entry in selected}
                    for relation in report.get('relations', ()):
                        if relation.get('reward_eligible') is True and semantic_relation(relation) == key:
                            consumer = relation.get('read_case_id', relation.get('consumer_case_id'))
                            if consumer in actual_cases and consumer not in useful_case_ids:
                                useful_case_ids.add(consumer)
                                useful_case_events.append({'seconds': now_seconds, 'case_id': consumer})
            row = {'case_index': index, 'before': before, 'after': after,
                   'report': report, 'settlement': settlement,
                   'execution_cost_ns': elapsed, 'decision_seconds': decision_ns / 1e9}
            steps.append(_plain(row))
            entry.update(execution_cost_ns=policy_execution_cost, semantic=semantic)
            journal.append({'kind': 'settlement', **_plain(row)})
            save(output / 'selected_cases.json', selected)
            save(output / 'state-transitions.json', steps)
            (output / 'prefix.json').write_bytes(plan)
            measured_cost = max(elapsed, time.monotonic_ns() - t0)
            policy_cost = (expected[index]['action_cost_ns'] if expected is not None else measured_cost)
            if ablation == 'cost':
                policy_cost = 1
            cost_tail = time.monotonic_ns()
            credit.finalize_cost(decision.id, policy_cost)
            entry.update(action_cost_ns=policy_cost, measured_action_cost_ns=measured_cost)
            journal.append({'kind': 'cost_finalization', 'decision_id': decision.id,
                            'measured_action_cost_ns': measured_cost, 'policy_action_cost_ns': policy_cost})
            tail_ns += time.monotonic_ns() - cost_tail
            if mode == 'original' and time.monotonic_ns() >= deadline:
                status = 'budget-ended'
                break
        failure_phase = 'finalize'
        if mode == 'fresh':
            original_unadmitted = _load(original / 'unadmitted-decision.json')
            if original_unadmitted is not None:
                before = case_adapter.current_state()
                goal, view = search_view(before, live_report(assembly), ablation=ablation)
                decision = scheduler.choose(goal, view, assembly.space.catalog)
                settlement = scheduler.settle(decision.id, {}, original_unadmitted['cost_ns'], censored=True)
                unadmitted = {'decision': decision.document(),
                    'cost_ns': original_unadmitted['cost_ns'], 'settlement': settlement}
                if unadmitted != original_unadmitted:
                    raise ValueError('fresh terminal unadmitted decision or censoring differs')
                journal.append({'kind': 'unadmitted-budget-censor', **unadmitted})
        save(output / 'unadmitted-decision.json', unadmitted)
        search_end = time.monotonic_ns()
        terminal = credit.finish()
        journal.append({'kind': 'terminal', 'credit': terminal})
        plan = _prefix(assembly)
        (output / 'plan.json').write_bytes(plan)
        (output / 'prefix.json').write_bytes(plan)
        save(output / 'selected_cases.json', selected)
        save(output / 'state-transitions.json', steps)
        save(output / 'relations.json', events)
        save(output / 'terminal-credit.json', terminal)
        launches = assembly.runner.sessions['gpio_b'].built_executable_launch_observations()
        save(output / 'live-launches.json', launches)
        if mode == 'fresh':
            previous_launches = _load(original / 'live-launches.json')
            replay_matches = ((original / 'plan.json').read_bytes() == plan
                and terminal == _load(original / 'terminal-credit.json')
                and len(launches) == len(previous_launches) == 1
                and launches[0]['execution_nonce'] != previous_launches[0]['execution_nonce'])
            if not replay_matches:
                raise ValueError('fresh actual prefix, terminal credit or native process identity differs')
            status = reference['status']
        if (mode == 'fresh' or execution_mode not in ('search', 'develop')) and source_files() != frozen:
            raise ValueError('sources changed during search')
    except BaseException as exc:
        error = exc
        status = 'failed'
        search_end = time.monotonic_ns()
        from .failure_replay import exception_signature
        save(output / 'failure.json', {'error': repr(exc), 'signature': exception_signature(exc), 'traceback': traceback.format_exc(),
            'failure_phase': failure_phase, 'journal_head': journal.head})
        if (assembly is not None and failure_phase in ('submit', 'feedback')
                and getattr(getattr(assembly, 'session', None), '_begun', False)
                and not getattr(assembly.session, '_finished', False)):
            try:
                failed_plan, failed_trace = assembly.session.finish_export()
                (output / 'failure-plan.json').write_bytes(failed_plan)
                save(output / 'failure-trace.json', _trace_document(failed_trace))
                save(output / 'failure-launches.json', {name: list(local.built_executable_launch_observations())
                    for name, local in assembly.runner.sessions.items()})
            except BaseException as export_error:
                save(output / 'failure-export-unavailable.json', {'reason': repr(export_error)})
        if assembly is not None:
            try:
                (output / 'prefix.json').write_bytes(_prefix(assembly))
            except BaseException as prefix_error:
                save(output / 'prefix-unavailable.json', {'error': repr(prefix_error)})
    finally:
        if assembly is not None:
            try:
                try:
                    save(output / 'events.json', _plain(assembly.runner.events_since(0)))
                except BaseException as exc:
                    error = error or exc
                    status = 'failed'
                    save(output / 'capture-error.json', {'error': repr(exc)})
            finally:
                try:
                    assembly.close(error)
                except BaseException as exc:
                    error = error or exc
                    status = 'failed'
                    save(output / 'cleanup-error.json', {'error': repr(exc)})
    if command_trace is not None:
        export_start = time.monotonic_ns()
        raw_commands = command_trace.export_sessions()
        save(output / 'local-commands-raw.json', raw_commands)
        if assembly is not None:
            try:
                from myfuzz.runtime.recorded_commands import recorded_command_documents
                actual = {}
                for component, local_session in assembly.runner.sessions.items():
                    launches = local_session.built_executable_launch_observations()
                    if len(launches) != 1:
                        raise ValueError('actual single native launch missing: ' + component)
                    actual[component] = dict(launches[0], component=component)
                exported = recorded_command_documents(raw_commands, audited=True,
                    executions={mode: actual}, scope='R1 GPIO search')
                save(output / 'local-commands.json', exported[mode])
                command_export_ready = all(row['complete'] for row in exported[mode]['sessions'].values())
            except BaseException as command_error:
                save(output / 'local-commands-unavailable.json', {'error': repr(command_error)})
        command_export_seconds = (time.monotonic_ns() - export_start) / 1e9
    process_errors = {name: p.poll() for name, p in processes.items()
                      if p is not None and p.poll() != 0}
    if process_errors:
        error = error or RuntimeError('native process exit/reaping failed: ' + repr(process_errors))
        status = 'failed'
    end = time.monotonic_ns()
    search_ns = 0 if search_started is None else search_end - search_started
    coverage = {'status': 'unavailable', 'metric': 'rtl-line-block',
                'covered': None, 'total': None, 'denominator_sha256': None,
                'reason': 'No online line/block provider; captured commands require explicit offline measurement',
                'offline_measure_ready': command_export_ready}
    summary = dict(schema_version='dependency_search_gpio_search.v1', status=status,
        mode=mode, policy=policy, seed=seed, ablation=ablation, process_pid=os.getpid(),
        controller_execution_nonce=_CONTROLLER_EXECUTION_NONCE,
        record_local_commands=record_local_commands, command_export_seconds=command_export_seconds,
        requested_cases=cases, submitted_cases=len(selected), fixed_seconds=seconds,
        identity={'target': 'gpio_b.GPIOEN[8]',
                  **runtime_identity(configuration),
                  'catalog_sha256': None if assembly is None else assembly.space.catalog.identity,
                  'coverage_metric': 'certified-interaction.v1'},
        budget={'cases': cases, 'seconds': seconds},
        metrics={'certified_events': events, 'useful_cases': sum(row['seconds'] <= seconds for row in useful_case_events),
                 'useful_case_events': useful_case_events,
                 'decision_seconds': [s['decision_seconds'] for s in steps],
                 'search_seconds': search_ns / 1e9, 'build_seconds': build_ns / 1e9,
                 'init_seconds': init_ns / 1e9, 'coverage': coverage,
                 'fresh': {'status': ('verified' if replay_matches else 'mismatch')
                           if mode == 'fresh' else 'not-run'}},
        search_wall_seconds=search_ns / 1e9, build_init_seconds=(build_ns + init_ns) / 1e9,
        e2e_seconds=(end-e2e) / 1e9,
        e2e_tail_seconds=max(0, end - (search_end if search_started else e2e)) / 1e9,
        accounting_tail_ns=tail_ns, budget_overrun_seconds=max(0, search_ns / 1e9-seconds),
        completed_targets=len(events), first_relation_seconds=events[0]['seconds'] if events else None,
        coverage=coverage, journal_head=journal.head, replay_matches=replay_matches,
        source_files=frozen, native_authority=False,
        irq_status=steps[-1]['report'].get('irq_status', 'unknown') if steps else 'unknown',
        isr_status=steps[-1]['report'].get('isr_status', 'unknown') if steps else 'unknown',
        missing_baselines=['B2 closed-loop feedback', 'B3 candidate exploration', 'B4 CDDGuzz adaptation'],
        timing_cutoff='after cleanup; excludes final summary serialization',
        processes={name: {'reaped': p.poll() is not None, 'exit_code': p.poll()}
                   for name, p in processes.items() if p is not None})
    if elaboration_mode is not None:
        summary['elaboration_mode'] = elaboration_mode
    if execution_mode is not None:
        summary['execution_mode'] = execution_mode
        summary['verification'] = {
            'within_invocation': {'status': 'not-requested', 'matches': None},
            'cross_invocation': {
                'status': ('verified' if replay_matches else 'failed') if mode == 'fresh'
                          else ('pending' if execution_mode == 'acceptance' else 'not-requested'),
                'matches': replay_matches if mode == 'fresh' else None}}
    verify_journal(output / 'decisions.jsonl', expected_head=journal.head)
    save(output / 'coverage-availability.json', coverage)
    save(output / 'summary.json', summary)
    if error is not None:
        raise error
    return summary


def _trace_document(trace):
    # EventJournalSnapshot is a Sequence, not a JSON list. Avoid deepcopying
    # the live journal owner through dataclasses.asdict.
    return {name: (list(trace.events) if name == 'events' else getattr(trace, name))
            for name in ('genome_sha256', 'status', 'events', 'local_ticks',
                         'semantic_sha256', 'manifest_sha256')}


def _gpio_failure_material(output):
    """Validate complete committed material without installing replay authority."""
    from .failure_replay import _original_gate, _check_sources
    from myfuzz.scenario.session_runtime import validate_register_program_plan
    from myfuzz.scenario.replay import ScenarioTrace
    output = Path(output)
    _original_gate(output)
    if any((output / name).exists() for name in ('cleanup-error.json', 'capture-error.json',
                                                'failure-export-unavailable.json')):
        raise ValueError('GPIO cleanup or terminal export unavailable')
    summary = _load(output / 'summary.json')
    failure = _load(output / 'failure.json')
    if failure.get('failure_phase') not in ('submit', 'feedback'):
        raise ValueError('GPIO failure is not an attempted runtime operation')
    if failure['journal_head'] != summary['journal_head']:
        raise ValueError('GPIO failure journal head differs')
    verify_journal(output / 'decisions.jsonl', expected_head=failure['journal_head'])
    sources = []
    for row in summary['source_files']:
        if row.get('base') != 'project':
            raise ValueError('unsupported GPIO source root')
        sources.append({'path': str((ROOT / row['path']).resolve()), 'sha256': row['sha256']})
    _check_sources(sources)
    configuration = _load(output / 'configuration.json')
    mode = summary.get('elaboration_mode')
    if mode not in ('direct', 'supervised') or configuration.get('elaboration_mode') != mode:
        raise ValueError('GPIO original elaboration mode unavailable')
    plan = (output / 'failure-plan.json').read_bytes()
    document = json.loads(plan)
    validate_register_program_plan(document)
    original_configuration = dict(configuration)
    original_configuration.pop('elaboration_mode')
    if document['register_programs']['configuration'] != original_configuration:
        raise ValueError('GPIO failure configuration differs from original')
    terminal = document.get('terminal_failure')
    if not terminal or terminal.get('phase') not in ('step', 'checker'):
        raise ValueError('GPIO failure has no replayable runtime terminal failure')
    signature = failure.get('signature', {})
    if (terminal.get('error_type') != signature.get('type')
            or terminal.get('error_message') != signature.get('message')):
        raise ValueError('GPIO terminal exception differs from original failure')
    decisions = [json.loads(line)['document'] for line in (output / 'decisions.jsonl').read_text().splitlines()]
    decisions = [row for row in decisions if row.get('kind') == 'decision']
    if not decisions or decisions[-1]['case_id'] != terminal['case_id']:
        raise ValueError('GPIO terminal attempt is not the journaled decision')
    trace_document = _load(output / 'failure-trace.json')
    expected_fields = {'genome_sha256', 'status', 'events', 'local_ticks', 'semantic_sha256', 'manifest_sha256'}
    if set(trace_document) != expected_fields:
        raise ValueError('GPIO complete terminal trace required')
    trace = ScenarioTrace(**trace_document)
    if (trace.genome_sha256 != sha256(plan).hexdigest()
            or len(trace.manifest_sha256) != 64
            or any(c not in '0123456789abcdef' for c in trace.manifest_sha256)
            or trace.status not in ('failed', 'finding', 'runner_failed', 'uncertain_effect', 'protocol_violation')
            or trace.semantic_sha256 != sha256(canonical({'status': trace.status,
                'events': trace.events, 'local_ticks': trace.local_ticks})).hexdigest()):
        raise ValueError('GPIO terminal trace digest or status mismatch')
    launches = _load(output / 'failure-launches.json')
    if len(launches.get('gpio_b', [])) != 1:
        raise ValueError('GPIO original native launch identity unavailable')
    for rows in launches.values():
        for launch in rows:
            if not launch.get('execution_nonce') or launch.get('reaped') is not True:
                raise ValueError('GPIO original native launch was not reaped')
    files = ('failure-plan.json', 'failure-trace.json', 'failure-launches.json',
             'configuration.json', 'failure.json', 'summary.json', 'search-summary.json', 'decisions.jsonl')
    hashes = {name: sha256((output / name).read_bytes()).hexdigest() for name in files}
    return summary, configuration, plan, trace, launches, sources, hashes


def export_gpio_failure_specimen(output, error, *, cache_dir=None):
    from .failure_replay import SCHEMA, exception_signature, _business_signature
    output = Path(output)
    result = {'schema_version': SCHEMA, 'backend': 'gpio', 'status': 'refused',
              'accepted': False, 'dut_bug': False}
    try:
        signature = exception_signature(error)
        if not _business_signature(signature):
            raise ValueError('GPIO infrastructure or admission failure')
        summary, configuration, plan, trace, launches, sources, hashes = _gpio_failure_material(output)
        if _load(output / 'failure.json').get('signature') != signature:
            raise ValueError('GPIO original exception signature differs')
        result.update(status='ready', original_output=str(output.resolve()), signature=signature,
            sources=sources, files_sha256=hashes, elaboration_mode=summary['elaboration_mode'],
            controller_execution_nonce=summary['controller_execution_nonce'],
            record_local_commands=summary.get('record_local_commands', False),
            cache_dir=str(Path(cache_dir).resolve()) if cache_dir is not None else None)
    except (OSError, ValueError, KeyError, TypeError) as failure:
        result['reason'] = str(failure)
    save(output / 'failure-specimen.json', result)
    return result


def replay_gpio_failure_specimen(specimen, output, cache_dir):
    """Called only by the dedicated worker; successful agreement remains a failure."""
    from .failure_replay import SCHEMA, _check_sources, _business_signature
    from myfuzz.local_harness.execution_validation import execution_validation_scope, static_validation
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.scenario.session_runtime import replay_online_session
    from .r1_session import r1_replay_factories
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    result = {'status': 'refused', 'accepted': False, 'dut_bug': False, 'trace_equal': False}
    try:
        if (specimen.get('schema_version') != SCHEMA or specimen.get('backend') != 'gpio'
                or specimen.get('status') != 'ready'):
            raise ValueError('GPIO specimen is not ready')
        if specimen['controller_execution_nonce'] == _CONTROLLER_EXECUTION_NONCE:
            raise ValueError('GPIO failure replay requires an independent controller process')
        original = Path(specimen['original_output'])
        summary, configuration, plan, trace, old_launches, sources, hashes = _gpio_failure_material(original)
        if (summary['controller_execution_nonce'] != specimen['controller_execution_nonce']
                or _load(original / 'failure.json').get('signature') != specimen['signature']
                or not _business_signature(specimen['signature'])):
            raise ValueError('GPIO failure identity or exception signature changed')
        if hashes != specimen['files_sha256'] or sources != specimen['sources']:
            raise ValueError('GPIO specimen material changed')
        if summary['elaboration_mode'] != specimen['elaboration_mode']:
            raise ValueError('GPIO specimen elaboration mode changed')
        registers = json.loads(plan)['register_programs']['configuration']
        runners = []
        def capture_factory():
            runner = factory()
            runners.append(runner)
            return runner
        with elaboration_mode_scope(specimen['elaboration_mode']), execution_validation_scope() as boundary:
            def validate_inputs():
                _check_sources(sources)
                actual = {name: sha256((original / name).read_bytes()).hexdigest() for name in hashes}
                if actual != hashes:
                    raise ValueError('GPIO replay input hashes changed')
                return actual
            static_validation(('GPIO-failure-replay', str(original)), validate_inputs)
            factory, install = r1_replay_factories(cache_dir,
                advance_rounds=registers['advance_rounds'], enable_external=bool(registers.get('external_sources')),
                audit_all_components=specimen['record_local_commands'])
            comparison = replay_online_session(plan, capture_factory, trace, checker=None,
                                               register_runtime_factory=install)
            actual_launches = {name: list(local.built_executable_launch_observations())
                for name, local in runners[0].sessions.items()} if len(runners) == 1 else {}
            save(output / 'actual-trace.json', _trace_document(comparison.actual_trace))
            save(output / 'actual-launches.json', actual_launches)
        if boundary.get('status') != 'verified':
            raise ValueError('GPIO replay static boundary unverified')
        identities_match = set(old_launches) == set(actual_launches)
        stable_fields = ('argv', 'artifact_digest', 'binary_sha256', 'build_digest', 'built_receipt_sha256',
                         'observed_executable_sha256', 'ready_artifact_digest', 'aborted', 'failure_stage', 'returncode')
        for name, old_rows in old_launches.items():
            rows = actual_launches.get(name, [])
            identities_match &= len(rows) == len(old_rows)
            for old, fresh in zip(old_rows, rows):
                identities_match &= (bool(fresh.get('execution_nonce'))
                    and old.get('execution_nonce') != fresh.get('execution_nonce')
                    and fresh.get('reaped') is True
                    and all(old.get(key) == fresh.get(key) for key in stable_fields))
        result.update(status='reproduced' if comparison.matches and identities_match else 'not-reproduced',
            trace_equal=comparison.matches, native_identity_verified=identities_match,
            native_identity_scope=sorted(name for name, rows in old_launches.items() if rows),
            first_difference=comparison.first_difference, difference_context=comparison.difference_context,
            verification_scope=comparison.verification_scope)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result.update(status='refused', reason=str(error))
    except Exception as error:
        result.update(status='replay-error', error=repr(error))
    save(output / 'failure-replay.json', result)
    return result


def _acceptance_fresh(args, summary):
    fresh = args.output / 'acceptance-fresh'
    argv = [sys.executable, str(ROOT / 'scripts/run_dependency_search.py'),
            '--mode', 'fresh', '--execution-mode', 'acceptance',
            '--original', str(args.output.resolve()), '--output', str(fresh.resolve()),
            '--policy', args.policy, '--ablation', args.ablation,
            '--cases', str(args.cases), '--seconds', str(args.seconds),
            '--seed', str(args.seed), '--cache', str(args.cache.resolve())]
    if summary.get('elaboration_mode') is not None:
        argv.extend(['--elaboration-mode', summary['elaboration_mode']])
    if args.record_local_commands:
        argv.append('--record-local-commands')
    verified = False
    replay_started = time.monotonic()
    try:
        child = subprocess.run(argv, cwd=ROOT, check=False, capture_output=True, text=True)
        (args.output / 'acceptance-fresh-stdout.txt').write_text(
            getattr(child, 'stdout', '') or '', encoding='utf8')
        (args.output / 'acceptance-fresh-stderr.txt').write_text(
            getattr(child, 'stderr', '') or '', encoding='utf8')
        path = fresh / 'search-summary.json'
        result = _load(path if path.exists() else fresh / 'summary.json')
        cross = result.get('verification', {}).get('cross_invocation', {})
        boundary = result.get('verification', {}).get('session_boundary', {'status': 'verified'})
        verified = (child.returncode == 0 and result.get('mode') == 'fresh'
                    and result.get('status') in ('completed', 'budget-ended')
                    and result.get('replay_matches') is True
                    and cross.get('status') == 'verified' and cross.get('matches') is True
                    and boundary.get('status') == 'verified')
    finally:
        elapsed = time.monotonic() - replay_started
        summary['automatic_replay_seconds'] = elapsed
        for timing in ('workflow_wall_seconds', 'e2e_seconds'):
            if timing in summary:
                summary[timing] += elapsed
        summary['verification']['cross_invocation'] = {
            'status': 'verified' if verified else 'failed', 'matches': verified}
        summary['replay_matches'] = verified
        if not verified:
            summary['status'] = 'failed'
        save(args.output / 'summary.json', summary)
        save(args.output / 'search-summary.json', summary)
    if not verified:
        raise RuntimeError('GPIO acceptance cross-invocation replay did not verify')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('original', 'fresh'), required=True)
    parser.add_argument('--execution-mode', choices=('develop', 'search', 'acceptance'), default='search')
    parser.add_argument('--elaboration-mode', choices=('direct', 'supervised'))
    parser.add_argument('--policy', choices=('state', 'uniform', 'legacy'), default='state')
    parser.add_argument('--cases', type=int, required=True)
    parser.add_argument('--seconds', type=float, required=True)
    parser.add_argument('--seed', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--original', type=Path)
    parser.add_argument('--record-local-commands', action='store_true')
    parser.add_argument('--ablation', choices=('none', 'frontier', 'state', 'credit', 'cost'), default='none')
    args = parser.parse_args(argv)
    from myfuzz.local_harness.build import host_source_discovery_scope
    previous_handler = signal.getsignal(signal.SIGTERM)
    def terminated(signum, frame):
        raise TimeoutError('GPIO search terminated by SIGTERM')
    signal.signal(signal.SIGTERM, terminated)
    try:
        from myfuzz.local_harness.session import record_local_commands
        recording = record_local_commands() if args.record_local_commands else nullcontext(None)
        with recording as command_trace, host_source_discovery_scope(reuse_nested=True):
            summary = execute(**vars(args), command_trace=command_trace)
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
    if args.mode == 'original' and (args.execution_mode == 'acceptance'
            or (args.execution_mode == 'search' and summary.get('completed_targets', 0) > 0)):
        summary['replay_reason'] = ('new-certified-relation' if args.execution_mode == 'search'
                                    else 'acceptance')
        _acceptance_fresh(args, summary)
    print(json.dumps({'status': summary['status'], 'completed_targets': summary['completed_targets'],
                      'submitted_cases': summary['submitted_cases']}))
    return 0


if __name__ == '__main__':
    main()
