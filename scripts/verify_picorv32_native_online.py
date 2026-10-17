#!/usr/bin/env python3
"""Explicit bounded native/PULP 3-case gate; never executes on import."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import fcntl
import gzip
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def save(path, document):
    encoded = json.dumps(document, sort_keys=True, allow_nan=False).encode()
    Path(path).write_bytes(gzip.compress(encoded, mtime=0))
    return {'path': Path(path).name, 'json_sha256': hashlib.sha256(encoded).hexdigest(),
            'gzip_sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}


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
                       artifact_digest=session._artifact_document['artifact_digest'])
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


def run_gate(output, cache_dir, *, corrupt):
    from myfuzz.local_harness.session import observe_local_command_timings
    from myfuzz.integration.picorv32_native_online import make_picorv32_native_online_runtime
    output.mkdir()
    runtime = make_picorv32_native_online_runtime(cache_dir=cache_dir, max_cases=3)
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
    result = {'status': 'failed', 'controlled_fault': corrupt, 'cases': records}
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
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
        try:
            runtime.session.runner.finalize()
        except Exception as cleanup:
            result['cleanup_error'] = repr(cleanup)
        partial = dict(events=list(runtime.session.runner.events),
            local_ticks=dict(runtime.session.runner.local_ticks),
            boundary_failure=runtime.boundary_failure)
        try:
            partial['attempted_plan'] = json.loads(runtime.session.encode_plan())
        except Exception as collection:
            partial['plan_collection_error'] = repr(collection)
        result['partial_bundle'] = save(output / 'partial.json.gz', partial)
    finally:
        result['processes'] = capture.document()
        result['capture_errors'] = capture.errors
        result['controlled_response_records'] = fault_records
        save(output / 'result.json.gz', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache-dir', type=Path, required=True)
    parser.add_argument('--heavy-lock', type=Path, required=True)
    args = parser.parse_args()
    for name in ('output', 'cache_dir', 'heavy_lock'):
        if getattr(args, name).resolve().is_relative_to(ROOT):
            parser.error(name + ' must be outside frozen source')
    args.output.mkdir(parents=True, exist_ok=False)
    with args.heavy_lock.open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sys.path.insert(0, str(ROOT / 'src'))
        positive = run_gate(args.output / 'positive', args.cache_dir, corrupt=False)
        if positive['status'] != 'bounded_directed_gate_passed':
            return 1
        negative = run_gate(args.output / 'controlled-response', args.cache_dir, corrupt=True)
        summary = dict(schema_version='native_online_directed_gate.v1',
            positive_status=positive['status'], controlled_status=negative['status'],
            script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            formal_p6_complete=False, source_authority=False, retirement_authority=False,
            coverage_guided_search=False)
        save(args.output / 'summary.json.gz', summary)
        return 0 if negative['status'] == 'bounded_directed_gate_passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
