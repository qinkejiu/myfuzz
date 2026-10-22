#!/usr/bin/env python3
"""Explicit bounded native/PULP 3-case gate; never executes on import."""
from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import asdict
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
GATE_RUN_ID_PATTERN = re.compile(r'[0-9a-f]{64}\Z')
GATE_BRANCHES = frozenset(('positive', 'controlled-response', 'native-source-refusal'))


def validate_gate_run_id(value):
    """Argparse validator for the controller-generated, canonical run identity."""
    if not isinstance(value, str) or GATE_RUN_ID_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError('--gate-run-id must be exactly 64 lowercase hexadecimal characters')
    return value


def gate_result_identity(gate_run_id, gate_branch):
    """Identity fields shared by each persisted branch result."""
    if not isinstance(gate_run_id, str) or GATE_RUN_ID_PATTERN.fullmatch(gate_run_id) is None:
        raise ValueError('invalid-gate-run-id')
    if gate_branch not in GATE_BRANCHES:
        raise ValueError('invalid-gate-branch')
    return dict(gate_run_id=gate_run_id, gate_branch=gate_branch, gate_pid=os.getpid())


def gate_summary_identity(gate_run_id):
    if not isinstance(gate_run_id, str) or GATE_RUN_ID_PATTERN.fullmatch(gate_run_id) is None:
        raise ValueError('invalid-gate-run-id')
    return dict(gate_run_id=gate_run_id, gate_pid=os.getpid())


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache-dir', type=Path, required=True)
    parser.add_argument('--heavy-lock', type=Path, required=True)
    parser.add_argument('--gate-run-id', type=validate_gate_run_id, required=True,
                        help='controller-generated 64-character lowercase hex identity for this planned gate')
    parser.add_argument('--native-completion-observation', action='store_true',
                        help='select passive native CPU PRE/POST observation')
    parser.add_argument('--native-source-binding', action='store_true',
                        help='bind selected CPU host input to actual acceptance; no CPU consumption grant')
    parser.add_argument('--native-source-completion', action='store_true',
                        help='audit selected four-byte native instruction bus completions and contradiction refusal')
    return parser


def validate_gate_args(args, parser, *, source_root=ROOT):
    """Validate option dependencies and keep run outputs outside frozen source."""
    if args.native_source_completion and not args.native_source_binding:
        parser.error('native-source-completion requires native-source-binding')
    if args.native_source_completion and not args.native_completion_observation:
        parser.error('native-source-completion requires native-completion-observation')
    if args.native_source_binding and not args.native_completion_observation:
        parser.error('native-source-binding requires native-completion-observation')
    frozen_root = Path(source_root).resolve()
    for name in ('output', 'cache_dir', 'heavy_lock'):
        if getattr(args, name).resolve().is_relative_to(frozen_root):
            parser.error(name + ' must be outside frozen source')


def save(path, document):
    encoded = json.dumps(document, sort_keys=True, allow_nan=False).encode()
    Path(path).write_bytes(gzip.compress(encoded, mtime=0))
    return {'path': Path(path).name, 'json_sha256': hashlib.sha256(encoded).hexdigest(),
            'gzip_sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}


def save_gate_result(path, result, gate_run_id, gate_branch):
    """Persist a branch result with its validated shared run identity."""
    document = dict(result)
    document.update(gate_result_identity(gate_run_id, gate_branch))
    return save(path, document)


def trace_document(trace):
    document = asdict(trace)
    # Online traces retain an immutable EventJournalSnapshot; asdict correctly
    # preserves that view, so explicitly export every event to JSON's list ABI.
    document['events'] = list(trace.events)
    return document


def select_raw(decoder, wanted, *, forbidden_values=()):
    """Bounded pure proposals; these are directed gate inputs, not search hits."""
    for attempt in range(4096):
        raw = hashlib.sha256(f'native-three-case:{wanted}:{attempt}'.encode()).digest()[:8]
        case = decoder.decode(raw)
        if case.source.action_id.endswith(':' + wanted):
            value = (int.from_bytes(case.source.data, 'little') >> 20
                     if wanted == 'cpu.instructions' else case.source.value)
            if value not in forbidden_values:
                return raw
    raise ValueError('directed-source-selection-bound:' + wanted)


class ProcessCapture:
    """Read-only callback on real command completion; stores actual Popen handles."""
    def __init__(self):
        self.runners = []
        self.processes = {}
        self.errors = []

    def register(self, runner):
        self.runners.append(runner)
        return runner

    def snapshot(self, runner):
        result = {}
        for component, session in runner.sessions.items():
            process = session.process
            if process is None or process.poll() is not None:
                raise ValueError('actual-process-not-running:' + component)
            row = dict(pid=process.pid, execution_nonce=session._execution,
                       reset_epoch=session.reset_epoch,
                       artifact_digest=session._artifact_document['artifact_digest'],
                       runner_namespace=f'runner-{self.runners.index(runner)}')
            if type(row['pid']) is not int or row['pid'] <= 0 or not row['execution_nonce']:
                raise ValueError('actual-process-identity-missing')
            self.processes[id(process)] = (process, component, row)
            result[component] = row
        return result

    def __call__(self, operation, elapsed):
        try:
            for runner in self.runners:
                if all(session.process is not None for session in runner.sessions.values()):
                    self.snapshot(runner)
        except Exception as error:
            self.errors.append(repr(error))

    def document(self):
        return [dict(component=component, **row, terminal_returncode=process.poll())
                for process, component, row in self.processes.values()]


def cleanup_registered(capture, output):
    """Finalize every actual runner, including a failed fresh begin/submit.

    All namespaces are preserved independently. Failure collecting one receipt
    must not prevent cleanup or collection of the remaining actual processes.
    """
    errors, partials = [], []
    seen = set()
    for index, runner in enumerate(capture.runners):
        if id(runner) in seen:
            continue
        seen.add(id(runner))
        namespace = f'runner-{index}'
        partial = dict(namespace=namespace)
        try:
            partial['failure_event_count_before_cleanup'] = runner.event_count
            partial['failure_ticks_before_cleanup'] = dict(runner.local_ticks)
        except BaseException as error:
            errors.append(dict(namespace=namespace, phase='failure_boundary', error=repr(error)))
        for component, session in runner.sessions.items():
            try:
                process = session.process
                if process is not None:
                    row = dict(pid=process.pid, execution_nonce=session._execution,
                        reset_epoch=session.reset_epoch,
                        artifact_digest=session._artifact_document['artifact_digest'],
                        runner_namespace=namespace)
                    capture.processes[id(process)] = (process, component, row)
            except BaseException as error:
                errors.append(dict(namespace=namespace, phase='capture_before_close', error=repr(error)))
        try:
            # Already finalized runners must not be finalized a second time.
            if runner._status in ('running', 'quiescing', 'failed'):
                runner.finalize()
        except BaseException as error:
            errors.append(dict(namespace=namespace, phase='finalize', error=repr(error)))
        # A partial begin or a guard failure before finalize's close loop can
        # retain a live session. Use its real close path once, never an external
        # kill/restart. end_case clears the owned handle before actual reaping.
        for component, session in runner.sessions.items():
            try:
                if session.process is not None:
                    session.end_case()
            except BaseException as error:
                errors.append(dict(namespace=namespace, component=component,
                                   phase='remaining_session_close', error=repr(error)))
        for key, read in (('events', lambda: list(runner.events)),
                          ('local_ticks', lambda: dict(runner.local_ticks)),
                          ('runner_status', lambda: runner._status)):
            try:
                partial[key] = read()
            except BaseException as error:
                errors.append(dict(namespace=namespace, phase='collect_' + key, error=repr(error)))
        try:
            partial['processes'] = [row for row in capture.document()
                                    if row['runner_namespace'] == namespace]
        except BaseException as error:
            errors.append(dict(namespace=namespace, phase='collect_lifecycles', error=repr(error)))
        try:
            partials.append(save(output / (namespace + '-partial.json.gz'), partial))
        except BaseException as error:
            errors.append(dict(namespace=namespace, phase='save_partial', error=repr(error)))
    return partials, errors


def install_corruption(runner, records):
    """One intentional delivered-response fault after a real queued IP read.

    Original enqueue, target access, ledger and all raw samples run unchanged;
    only the callback's first PADOUT read response is perturbed. Never re-execute.
    """
    router = runner.sessions['cpu'].router
    original = router.enqueue
    injected = False

    def enqueue(ledger, key, *, address, write, wdata, be, beat_bytes, callback):
        def completed(response):
            nonlocal injected
            if not injected and not write and address == 0x4000000c:
                altered = (response[0] ^ 1, response[1])
                records.append(dict(transaction=asdict(key), address=address,
                    actual_target_response=list(response), delivered_response=list(altered)))
                injected = True
                return callback(altered)
            return callback(response)
        return original(ledger, key, address=address, write=write, wdata=wdata,
                        be=be, beat_bytes=beat_bytes, callback=completed)
    router.enqueue = enqueue


def install_native_source_poison(runner, records):
    """One real post-binding RAM write before the first candidate CPU tick."""
    from dataclasses import asdict
    from myfuzz.scenario.ledger import TransactionKey

    original = runner.step_batch
    state = {'injected': False}

    def step_batch(schedule, *, on_step=None):
        if not state['injected'] and 'cpu' in schedule:
            bindings = [event for event in runner.events
                if event.get('schema_version') == 'native_instruction_source_binding.v1'
                and event.get('kind') == 'native_instruction_source_bound'
                and event.get('component') == 'cpu']
            if bindings:
                if len(bindings) != 1:
                    raise ValueError('native-source-poison-selected-binding-count')
                binding = bindings[0]
                cpu = runner.sessions['cpu']
                key = TransactionKey('local-execution', cpu._case_id,
                    cpu.artifact.plan.request.instance_id, cpu.reset_epoch,
                    'native-source-poison', 1)
                event_start = len(cpu.service.events)
                receipt = cpu.service.write(key, binding['source']['address'],
                    0x00000013, width_bytes=4, byte_enable=15)
                service_events = cpu.service.events[event_start:]
                if len(service_events) != 1:
                    raise ValueError('native-source-poison-actual-service-event-count')
                records.append(dict(
                    transaction=asdict(key),
                    write_receipt_object=asdict(receipt),
                    write_receipt=receipt.commit_document(),
                    write_service_event=deepcopy(service_events[0]),
                    binding_event_id=binding['event_id']))
                state['injected'] = True
        return original(schedule, on_step=on_step)

    runner.step_batch = step_batch
    return state


def native_source_refusal_record(events, plan_document, injection):
    """Join the actual poison write to the selected candidate terminal prefix."""
    case = plan_document['cases'][-1]
    source = case['source']
    failure = plan_document.get('terminal_failure')
    if (type(failure) is not dict or failure.get('error_message') != 'native_source_candidate_refused'
            or failure.get('error_type') != 'ValueError'):
        raise ValueError('native-source-poison-terminal-failure-missing')
    failures = [event for event in events
        if event.get('kind') == 'harness_failure' and event.get('component') == 'cpu'
        and event.get('error_type') == 'ValueError']
    if len(failures) != 1:
        raise ValueError('native-source-poison-runner-failure-count')
    failure_event_id = failures[0]['event_id']
    refused = [event for event in events
        if event.get('kind') == 'local_tick_sample'
        and event.get('component') == 'cpu' and event.get('phase') == 'pre'
        and event.get('producer_event_id') == failure_event_id]
    if len(refused) != 1:
        raise ValueError('native-source-poison-terminal-raw-pre-count')
    raw_pre = refused[0]

    accepted = [event for event in events
        if event.get('kind') == 'native_backend_request_accepted'
        and event.get('component') == 'cpu'
        and event.get('native', {}).get('instruction') == 1
        and event.get('native', {}).get('addr') == source['address']]
    if len(accepted) != 1:
        raise ValueError('native-source-poison-selected-native-acceptance-count')
    native_key = accepted[0]['transaction']
    journal_writes = [event for event in events
        if event.get('kind') == 'memory_write' and event.get('component') == 'cpu'
        and event.get('transaction') == injection['transaction']]
    if len(journal_writes) != 1:
        raise ValueError('native-source-poison-runner-write-event-count')
    binding_rows = [event for event in events
        if event.get('schema_version') == 'native_instruction_source_binding.v1'
        and event.get('kind') == 'native_instruction_source_bound'
        and event.get('source', {}).get('action_id') == source['action_id']]
    if len(binding_rows) != 1:
        raise ValueError('native-source-poison-binding-row-count')
    return dict(schema_version='native_source_candidate_refusal.v1',
        selected_action_id=source['action_id'], native_transaction=native_key,
        refused_raw_event_id=raw_pre['event_id'],
        write_transaction=injection['transaction'],
        write_receipt_object=injection['write_receipt_object'],
        write_receipt=injection['write_receipt'],
        write_service_event=injection['write_service_event'],
        write_journal_event_id=journal_writes[0]['event_id'],
        write_journal_event=journal_writes[0],
        original_acceptance=binding_rows[0]['acceptance'])


def run_native_source_refusal_gate(output, cache_dir, *, gate_run_id, gate_branch):
    """Real selected-byte contradiction plus exact original/fresh terminal replay."""
    if gate_branch != 'native-source-refusal':
        raise ValueError('native-source-refusal-gate-branch-mismatch')
    identity = gate_result_identity(gate_run_id, gate_branch)
    from myfuzz.local_harness.session import observe_local_command_timings
    from myfuzz.integration.picorv32_native_online import make_picorv32_native_online_runtime
    from myfuzz.scenario.session_runtime import replay_online_session
    from verifier.native_completion_gate_checks import check_native_source_completion_refusal

    output.mkdir()
    runtime = make_picorv32_native_online_runtime(cache_dir=cache_dir, max_cases=3,
        native_completion_observation=True, native_source_binding=True,
        native_source_completion=True)
    capture = ProcessCapture()
    original_runner = capture.register(runtime.session.runner)
    injected_original = []
    install_native_source_poison(original_runner, injected_original)
    injected_fresh = []
    result = {**identity, 'status': 'failed', 'native_source_completion': True,
        'source_authority': False, 'retirement_authority': False,
        'controlled_response_negative_preserved': True}
    primary = None
    try:
        with observe_local_command_timings(capture):
            runtime.begin()
            result['initial_process_identities'] = capture.snapshot(original_runner)
            raw = select_raw(runtime.decoder, 'cpu.instructions')
            selected = runtime.decoder.decode(raw)
            try:
                runtime.submit(raw)
            except ValueError as error:
                if str(error) != 'native_source_candidate_refused':
                    raise
            else:
                raise ValueError('native-source-poison-contradiction-was-not-refused')
            if not runtime._terminal or len(injected_original) != 1:
                raise ValueError('native-source-poison-original-execution-incomplete')
            plan = runtime.session.encode_plan()
            plan_document = json.loads(plan)
            trace = runtime.session.trace(genome_sha256=hashlib.sha256(plan).hexdigest())
            original_record = native_source_refusal_record(
                trace.events, plan_document, injected_original[0])
            runtime_document = original_runner.sessions['cpu'].artifact.runtime_document
            original_checks = check_native_source_completion_refusal(
                trace.events, plan_document, runtime_document,
                execution=original_runner.sessions['cpu']._execution,
                refusal_record=original_record)
            if original_checks['status'] != 'native_source_refusal_checks_passed':
                raise ValueError('native-source-poison-original-audit-failed:'
                    + repr(original_checks['errors']))
            (output / 'plan.json').write_bytes(plan)
            result['original_bundle'] = save(output / 'original-terminal.json.gz',
                dict(plan=plan_document, trace=trace_document(trace),
                     injection=injected_original[0], refusal_record=original_record,
                     checks=original_checks, selected_case=asdict(selected)))

            actual_factory = runtime.factory

            def fresh_factory():
                runner = capture.register(actual_factory())
                install_native_source_poison(runner, injected_fresh)
                return runner

            comparison = replay_online_session(plan, fresh_factory, trace,
                native_max_cases=3,
                native_reference_execution=original_runner.sessions['cpu']._execution,
                native_source_binding=True, native_source_completion=True,
                native_reference_session=runtime.session)
            if (comparison.matches is not True or comparison.first_difference is not None
                    or comparison.verification_scope != 'full'
                    or comparison.actual_trace is None or len(injected_fresh) != 1):
                raise ValueError('native-source-poison-terminal-full-replay-mismatch')
            fresh_runner = capture.runners[-1]
            fresh_record = native_source_refusal_record(
                comparison.actual_trace.events, plan_document, injected_fresh[0])
            fresh_checks = check_native_source_completion_refusal(
                comparison.actual_trace.events, plan_document,
                fresh_runner.sessions['cpu'].artifact.runtime_document,
                execution=fresh_runner.sessions['cpu']._execution,
                refusal_record=fresh_record)
            if fresh_checks['status'] != 'native_source_refusal_checks_passed':
                raise ValueError('native-source-poison-fresh-audit-failed:'
                    + repr(fresh_checks['errors']))
            comparison_document = asdict(comparison)
            comparison_document['actual_trace'] = trace_document(comparison.actual_trace)
            result['fresh_replay'] = save(output / 'fresh-terminal-replay.json.gz',
                dict(comparison=comparison_document, injection=injected_fresh[0],
                     refusal_record=fresh_record, checks=fresh_checks))
            result['native_source_completion_checks'] = save(
                output / 'native-source-refusal-checks.json.gz',
                dict(original=original_checks, fresh=fresh_checks))
            if len(capture.runners) != 2 or capture.errors:
                raise ValueError('native-source-poison-two-run-capture-incomplete')
            processes = capture.document()
            if len(processes) != 4 or any(row['terminal_returncode'] != 0 for row in processes):
                raise ValueError('native-source-poison-process-capture-incomplete')
            process_pairs = {}
            for component in ('cpu', 'gpio0'):
                pair = [row for row in processes if row['component'] == component]
                if (len(pair) != 2 or pair[0]['pid'] == pair[1]['pid']
                        or pair[0]['execution_nonce'] == pair[1]['execution_nonce']
                        or pair[0]['reset_epoch'] != pair[1]['reset_epoch']
                        or pair[0]['artifact_digest'] != pair[1]['artifact_digest']):
                    raise ValueError('native-source-poison-fresh-process-identity-mismatch:'
                        + component)
                process_pairs[component] = pair
            result['original_fresh_process_pairs'] = process_pairs
            result['processes'] = processes
            result['status'] = 'native_source_completion_refusal_gate_passed'
    except BaseException as error:
        primary = error
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if primary is not None:
            result['partial_bundles'], result['cleanup_collection_errors'] = cleanup_registered(capture, output)
        try:
            result['processes'] = capture.document()
            result['capture_errors'] = capture.errors
            save_gate_result(output / 'result.json.gz', result, gate_run_id, gate_branch)
        except BaseException as error:
            if primary is not None:
                primary.add_note('secondary refusal-gate evidence write failure: ' + repr(error))
                raise primary
            cleanup_registered(capture, output)
            raise
    if primary is not None and not isinstance(primary, Exception):
        raise primary
    return result


def check_case(events, case):
    """Independent relation checker over real delivery/consumption/RAM events."""
    deliveries = [row for row in events if row.get('kind') == 'mmio_delivery']
    shape = [(bool(row['write']), row['offset']) for row in deliveries]
    if shape != [(True, 12), (False, 12), (False, 8), (True, 12)]:
        raise ValueError('actual-mmio-shape:' + repr(shape))
    if any(row.get('device_id') != 'gpio0' or row.get('byte_enable') != 15
           or row.get('beat_bytes') != 4 for row in deliveries):
        raise ValueError('actual-mmio-fields')
    first, a_read, b_read, final = deliveries
    a, b = a_read['read_value'], b_read['read_value']
    if any(type(value) is not int or not 0 <= value < 1 << 32 for value in (a, b)):
        raise ValueError('actual-read-value-shape')
    if a != first['write_value']:
        raise ValueError('actual-padout-readback-mismatch')
    if case.source.action_id.endswith(':cpu.instructions'):
        word = int.from_bytes(bytes.fromhex(case.source.data_hex), 'little')
        if a != ((word >> 20) & 0xfff):
            raise ValueError('actual-cpu-candidate-not-consumed')
    elif b != case.source.value:
        raise ValueError('actual-ip-candidate-not-consumed')
    joint = a ^ b
    writes = [row for row in events if row.get('kind') == 'memory_write'
              and row.get('address') == 0x100]
    if len(writes) != 1 or writes[0].get('byte_enable') != 15:
        raise ValueError('actual-joint-ram-write-count')
    if not b_read['event_id'] < writes[0]['event_id'] < final['event_id']:
        raise ValueError('actual-joint-order')
    consumed = []
    for row in (a_read, b_read):
        key = row['source_transaction']
        matches = [event for event in events
            if event.get('component') == 'cpu' and event.get('kind') is None
            and event.get('outputs', {}).get('data_rsp_consumed') == 1
            and event['outputs'].get('data_rsp_source_sequence') == key['source_sequence']
            and event['outputs'].get('data_rsp_source_epoch') == key['source_epoch']]
        if len(matches) != 1 or matches[0]['event_id'] <= row['event_id']:
            raise ValueError('actual-cpu-response-consumer-missing')
        consumed.append(dict(target_event_id=row['event_id'], cpu_event_id=matches[0]['event_id'],
            target_value=row['read_value'], cpu_value=matches[0]['outputs']['data_rsp_rdata']))
    failures = []
    if any(row['target_value'] != row['cpu_value'] for row in consumed):
        failures.append('routed_read_response_mismatch')
    if writes[0]['value'] != joint:
        failures.append('joint_ram_mismatch')
    if final['write_value'] != joint:
        failures.append('joint_gpio_mismatch')
    return dict(case_id=case.case_id, actual_a=a, actual_b=b, expected_joint=joint,
        actual_ram=writes[0]['value'], actual_final_gpio=final['write_value'],
        delivery_event_ids=[row['event_id'] for row in deliveries],
        ram_event_id=writes[0]['event_id'], response_consumers=consumed, findings=failures)


def run_gate(output, cache_dir, *, gate_run_id, gate_branch, corrupt,
             native_completion_observation=False, native_source_binding=False,
             native_source_completion=False):
    if gate_branch not in ('positive', 'controlled-response'):
        raise ValueError('directed-gate-branch-mismatch')
    if corrupt != (gate_branch == 'controlled-response'):
        raise ValueError('directed-gate-corruption-branch-mismatch')
    identity = gate_result_identity(gate_run_id, gate_branch)
    from myfuzz.local_harness.session import observe_local_command_timings
    from myfuzz.integration.picorv32_native_online import make_picorv32_native_online_runtime
    output.mkdir()
    runtime = make_picorv32_native_online_runtime(cache_dir=cache_dir, max_cases=3,
        native_completion_observation=native_completion_observation,
        native_source_binding=native_source_binding,
        native_source_completion=native_source_completion)
    capture = ProcessCapture()
    capture.register(runtime.session.runner)
    fault_records = []
    if corrupt:
        install_corruption(runtime.session.runner, fault_records)
    actual_factory = runtime.factory

    def fresh_factory():
        runner = capture.register(actual_factory())
        if corrupt:
            install_corruption(runner, fault_records)
        return runner
    runtime.factory = fresh_factory
    records = []
    result = {**identity, 'status': 'failed', 'controlled_fault': corrupt, 'cases': records,
              'native_completion_observation': native_completion_observation,
              'native_source_binding': native_source_binding,
              'native_source_completion': native_source_completion}
    primary = None
    try:
        with observe_local_command_timings(capture):
            runtime.begin()
            identity = capture.snapshot(runtime.session.runner)
            result['initial_process_identities'] = identity
            result['actual_runner_identity'] = runtime.session.runner.identity_document()
            for wanted in ('cpu.instructions', 'gpio0.pin_byte', 'cpu.instructions'):
                forbidden = (0,) if not records else (0, records[-1]['relation']['expected_joint'])
                raw = select_raw(runtime.decoder, wanted, forbidden_values=forbidden)
                selected = runtime.decoder.decode(raw)
                receipt = runtime.submit(raw)
                if capture.snapshot(runtime.session.runner) != identity:
                    raise ValueError('cross-case-process-or-epoch-changed')
                runtime._require_packet_boundary(runtime.decoder.instruction_cursor, phase='gate_after_case')
                relation = check_case(receipt.events, selected)
                records.append(dict(raw_hex=raw.hex(), selected_source=wanted,
                    case=asdict(selected), receipt=asdict(receipt), relation=relation,
                    process_identities=identity, actual_next_slot=runtime.decoder.instruction_cursor))
                save(output / f'case-{len(records)}.json.gz', records[-1])
                if not corrupt and relation['findings']:
                    raise ValueError('positive-relation-check-failed')
                if corrupt:
                    if set(relation['findings']) != {'routed_read_response_mismatch', 'joint_ram_mismatch', 'joint_gpio_mismatch'}:
                        raise ValueError('controlled-fault-not-detected-by-independent-checker')
                    break
            plan, trace = runtime.finish()
            (output / 'plan.json').write_bytes(plan)
            result['first_bundle'] = save(output / 'first.json.gz', trace_document(trace))
            result['source_selection'] = [row['selected_source'] for row in records]
            expected = ['cpu.instructions'] if corrupt else ['cpu.instructions', 'gpio0.pin_byte', 'cpu.instructions']
            if result['source_selection'] != expected:
                raise ValueError('directed-source-selection-incomplete')
            comparison = runtime.replay(plan, trace)
            comparison_document = asdict(comparison)
            comparison_document['actual_trace'] = trace_document(comparison.actual_trace)
            result['fresh_bundle'] = save(output / 'fresh-comparison.json.gz', comparison_document)
            if native_source_binding:
                from verifier.native_completion_gate_checks import check_host_source_bindings
                binding_checks = {}
                saved_plan = json.loads(plan)
                for label, actual_trace, runner in (
                        ('original', trace, capture.runners[0]),
                        ('fresh', comparison.actual_trace, capture.runners[1])):
                    binding_checks[label] = check_host_source_bindings(actual_trace.events,
                        saved_plan, execution=runner.sessions['cpu']._execution)
                result['native_source_binding_checks'] = save(
                    output / 'native-source-binding-checks.json.gz', binding_checks)
                if any(check['status'] != 'host_input_binding_checks_passed' for check in binding_checks.values()):
                    raise ValueError('native-host-input-binding-check-failed')
            if native_source_completion and not corrupt:
                from verifier.native_completion_gate_checks import check_native_source_completion
                completion_checks = {}
                for label, actual_trace, runner in (
                        ('original', trace, capture.runners[0]),
                        ('fresh', comparison.actual_trace, capture.runners[1])):
                    completion_checks[label] = check_native_source_completion(
                        actual_trace.events, saved_plan,
                        runner.sessions['cpu'].artifact.runtime_document,
                        execution=runner.sessions['cpu']._execution)
                result['native_source_completion_checks'] = save(
                    output / 'native-source-completion-checks.json.gz', completion_checks)
                if any(check['status'] != 'native_source_completion_checks_passed'
                       for check in completion_checks.values()):
                    raise ValueError('independent-native-source-completion-check-failed')
            if native_completion_observation:
                from verifier.native_completion_gate_checks import check_native_completion
                native_checks = {}
                for label, actual_trace, runner, faults in (
                        ('original', trace, capture.runners[0], fault_records[:1] if corrupt else ()),
                        ('fresh', comparison.actual_trace, capture.runners[1],
                         fault_records[1:] if corrupt else ())):
                    artifact_document = runner.sessions['cpu'].artifact.runtime_document
                    native_checks[label] = check_native_completion(actual_trace.events,
                        artifact_document, controlled_response_records=faults)
                    native_checks[label]['artifact_document'] = artifact_document
                result['native_observation_checks'] = save(
                    output / 'native-observation-checks.json.gz', native_checks)
                if any(check['status'] != 'raw_checks_passed' for check in native_checks.values()):
                    raise ValueError('independent-native-raw-check-failed')
            if (comparison.matches is not True or comparison.first_difference is not None
                    or comparison.verification_scope != 'full'):
                raise ValueError('complete-full-prefix-fresh-mismatch')
            if len(capture.runners) != 2 or len(capture.processes) != 4 or capture.errors:
                raise ValueError('actual-first-fresh-process-capture-incomplete')
            processes = capture.document()
            if any(row['terminal_returncode'] != 0 for row in processes):
                raise ValueError('actual-model-not-reaped-zero')
            for component in ('cpu', 'gpio0'):
                pair = [row for row in processes if row['component'] == component]
                if (len(pair) != 2 or pair[0]['pid'] == pair[1]['pid']
                        or pair[0]['execution_nonce'] == pair[1]['execution_nonce']
                        or pair[0]['artifact_digest'] != pair[1]['artifact_digest']):
                    raise ValueError('fresh-process-not-distinct-with-same-artifact')
            if corrupt and len(fault_records) != 2:
                raise ValueError('controlled-fault-not-once-per-first-fresh')
            result['status'] = 'bounded_directed_gate_passed'
    except BaseException as error:
        primary = error
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if primary is not None:
            result['status'] = 'failed'
            result['partial_bundles'], result['cleanup_collection_errors'] = cleanup_registered(capture, output)
            result['boundary_failure'] = runtime.boundary_failure
            try:
                result['attempted_plan'] = json.loads(runtime.session.encode_plan())
            except BaseException as error:
                result['plan_collection_error'] = repr(error)
        try:
            result['processes'] = capture.document()
            result['capture_errors'] = capture.errors
            result['controlled_response_records'] = fault_records
            save_gate_result(output / 'result.json.gz', result, gate_run_id, gate_branch)
        except BaseException as error:
            if primary is not None:
                primary.add_note('secondary gate evidence write failure: ' + repr(error))
                raise primary
            # Even a final receipt-write failure may not strand a fresh model.
            cleanup_registered(capture, output)
            raise
    if primary is not None and not isinstance(primary, Exception):
        raise primary
    return result


def main():
    parser = build_parser()
    args = parser.parse_args()
    validate_gate_args(args, parser, source_root=ROOT)
    args.output.mkdir(parents=True, exist_ok=False)
    with args.heavy_lock.open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sys.path.insert(0, str(ROOT / 'src'))
        positive = run_gate(args.output / 'positive', args.cache_dir,
            gate_run_id=args.gate_run_id, gate_branch='positive', corrupt=False,
            native_completion_observation=args.native_completion_observation,
            native_source_binding=args.native_source_binding,
            native_source_completion=args.native_source_completion)
        if positive['status'] != 'bounded_directed_gate_passed':
            return 1
        negative = run_gate(args.output / 'controlled-response', args.cache_dir,
            gate_run_id=args.gate_run_id, gate_branch='controlled-response', corrupt=True,
            native_completion_observation=args.native_completion_observation,
            native_source_binding=args.native_source_binding,
            native_source_completion=args.native_source_completion)
        refusal = None
        if args.native_source_completion:
            refusal = run_native_source_refusal_gate(
                args.output / 'native-source-refusal', args.cache_dir,
                gate_run_id=args.gate_run_id, gate_branch='native-source-refusal')
        summary = dict(schema_version='native_online_directed_gate.v1',
            **gate_summary_identity(args.gate_run_id),
            positive_status=positive['status'], controlled_status=negative['status'],
            native_completion_observation=args.native_completion_observation,
            native_source_binding=args.native_source_binding,
            native_source_completion=args.native_source_completion,
            native_source_refusal_status=(refusal['status'] if refusal is not None else None),
            script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            formal_p6_complete=False, source_authority=False, retirement_authority=False,
            coverage_guided_search=False)
        save(args.output / 'summary.json.gz', summary)
        return 0 if (negative['status'] == 'bounded_directed_gate_passed'
            and (refusal is None
                or refusal['status'] == 'native_source_completion_refusal_gate_passed')) else 1


if __name__ == '__main__':
    raise SystemExit(main())
