"""Native verification gate for the standard BOOM/PULP GPIO scenario.

Controls substitute or suppress a response only after actual GPIO RTL returns;
they retain the real target receipt separately from the offered CPU response.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import asdict, is_dataclass
import hashlib
import json
import sys
import time
from pathlib import Path

from myfuzz.local_harness.build import host_source_discovery_scope

from .boom_gpio_example import PADOUT, RESULT
from .boom_gpio_runner import make_boom_gpio_runner


def _jsonable(value):
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _canonical(value):
    return json.dumps(_jsonable(value), sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def scoped_prefix(events, identities):
    """Normalize declared process/stream scope fields only; retain all data.

    Raw files retain nonces. Unknown strings and payload values are never
    redacted. Embedded projected IDs may replace only a declared stream prefix.
    """
    replacements = {value: 'declared-scope:' + name for name, value in identities.items()}
    fields = {'execution', 'execution_id', 'previous_execution_id',
              'raw_event_scope', 'stream_id'}

    def visit(value, path=()):
        if isinstance(value, dict):
            return {key: visit(item, (*path, key)) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [visit(item, (*path, index)) for index, item in enumerate(value)]
        if isinstance(value, str):
            field = path[-1] if path else None
            record_scope = len(path) == 2 and type(path[0]) is int
            transaction_scope = len(path) >= 2 and path[-2] == 'source_transaction'
            reset_scope = len(path) >= 2 and path[-2] == 'native_acknowledgement'
            if field in fields and (record_scope or transaction_scope or reset_scope) and value in replacements:
                return replacements[value]
            stream = identities.get('coherent_stream')
            if (stream and record_scope and field == 'local_event_id'
                    and value.startswith(stream + '|')):
                return replacements[stream] + value[len(stream):]
        return value

    return visit(events)


def functional_check(run):
    """Require physical target effects, real CPU A/D, branch result and drain."""
    if run['error'] is not None:
        return False
    rows = [row['native_event'] for row in run['runtime_events']
            if row.get('kind') == 'coherent_accepted_raw']
    requests = [row for row in rows if row['channel'] == 'A' and row.get('address') == PADOUT]
    responses = [row for row in rows if row['channel'] == 'D' and row.get('external') is True]
    result_stores = [row for row in rows if row['channel'] == 'A'
                     and row.get('opcode') in (0, 1) and row.get('address') in (RESULT, RESULT + 4)]
    accesses = [row for row in run['gpio_events'] if row.get('kind') == 'gpio_apb_access']
    report = run['coherent_report']
    queued = [row for row in run['source_events'] if row.get('kind') == 'boom_external_a_queued']
    consumed = [row for row in run['source_events'] if row.get('kind') == 'boom_external_d_accepted']
    bindings = len(queued) == len(consumed) == len(run['router_deliveries']) == len(accesses) == 2
    if bindings:
        for request, response, acceptance, completion, access, delivery in zip(
                requests, responses, queued, consumed, accesses, run['router_deliveries']):
            key = acceptance['source_transaction']
            bindings = bindings and bool(
                completion['source_transaction'] == access['source_transaction'] == delivery['source_transaction'] == key
                and key['execution_id'] == run['identities']['cpu_execution']
                and all(acceptance['native_request'][field] == value for field, value in request.items())
                and completion['native_response'] == response
                and delivery['target_access_id'] == access['access_id']
                and delivery['target_apb_access'] == access
                and delivery['target_request']['status'] == delivery['target_response']['status'] == 'observed')
    return bool(bindings
        and set(run['native_processes']) == {'cpu', 'gpio'}
        and all(row['exit'] == 0 for row in run['native_processes'].values())
        and
        run['last_cpu_outputs'].get('ram_3000') == (1 << 32) | 53
        and run['last_cpu_outputs'].get('drained') == 1
        and report['structural_error'] is False and report['stream_closed'] is True
        and len(requests) == len(responses) == len(accesses) == len(result_stores) == 2
        and requests[0]['opcode'] in (0, 1) and requests[0]['size'] == 2
        and requests[0]['mask'] == 0xf0 and requests[0]['data'] >> 32 & 0xffffffff == 53
        and requests[1]['opcode'] == 4 and requests[1]['size'] == 2 and requests[1]['mask'] == 0xf0
        and responses[0]['opcode'] == 0 and responses[1]['opcode'] == 1
        and all(response['source'] == request['source'] and response['size'] == request['size']
                for request, response in zip(requests, responses))
        and responses[1]['data'] >> 32 & 0xffffffff == 53
        and accesses[0]['status'] == accesses[1]['status'] == 'observed'
        and accesses[0]['write'] is True and accesses[0]['wdata'] == 53
        and accesses[0]['post'].get('gpio_out') == 53
        and accesses[1]['pre'].get('gpio_out') == 53
        and accesses[1]['write'] is False and accesses[1]['read_rdata'] == 53
        and result_stores[0]['address'] == RESULT and result_stores[0]['data'] & 0xffffffff == 53
        and result_stores[1]['address'] == RESULT + 4 and result_stores[1]['data'] >> 32 & 0xffffffff == 1
        and len(run['router_deliveries']) == 2 and not run['uncertain_keys'])


def run_prefix(*, repo, cpu_output, cache_dir, edges=1200, control=None):
    """Use ScenarioRunner.step for every CPU and GPIO step in a fixed prefix."""
    runner = make_boom_gpio_runner(repo=repo, cpu_output=cpu_output, cache_dir=cache_dir)
    cpu, gpio = runner.sessions['cpu'], runner.sessions['gpio']
    substitutions = []
    if control is not None:
        if control not in ('changed_read', 'missing_read'):
            raise ValueError('unknown BOOM verification control')
        enqueue = cpu.router.enqueue

        def controlled_enqueue(ledger, key, **kwargs):
            if not kwargs['write']:
                callback = kwargs['callback']

                def controlled_callback(response):
                    actual, error = response
                    offered = None if control == 'missing_read' else actual ^ (1 << 32)
                    substitutions.append({'source_transaction': asdict(key),
                        'actual_target_response': [actual, error],
                        'offered_cpu_response': None if offered is None else [offered, error]})
                    if offered is not None:
                        callback((offered, error))

                kwargs['callback'] = controlled_callback
            return enqueue(ledger, key, **kwargs)

        cpu.router.enqueue = controlled_enqueue
    error = None
    identities = {}
    processes = {}
    last = {}
    try:
        runner.begin_test('boom-pulp-gpio-prefix')
        processes = {'cpu': cpu.process, 'gpio': gpio.process}
        identities = {'cpu_execution': cpu._native.execution_id,
                      'coherent_stream': cpu._stream.stream_id,
                      'gpio_execution': gpio._execution,
                      'runner_execution': runner.execution_id}
        for _ in range(edges):
            last = runner.step('cpu')
            runner.step('gpio')
    except Exception as exc:
        error = {'type': type(exc).__name__, 'message': str(exc)}
    finally:
        try:
            runner.finalize()
        except Exception as exc:
            error = error or {'type': type(exc).__name__, 'message': str(exc)}
    return _jsonable({'error': error, 'identities': identities,
        'events': list(runner.events), 'last_cpu_outputs': last,
        'native_processes': {name: {'pid': process.pid, 'exit': process.poll()}
                             for name, process in processes.items()},
        'local_ticks': runner.local_ticks, 'coherent_report': cpu.coherent_report(),
        'coherent_coverage': cpu.coherent_coverage(),
        'runtime_events': cpu.runtime_events, 'source_events': cpu.source_events,
        'gpio_events': gpio.gpio_events,
        'router_deliveries': cpu.router.deliveries,
        'uncertain_keys': tuple(str(key) for key in cpu.mmio_ledger.uncertain_keys),
        'substitutions': substitutions})


@host_source_discovery_scope()
def verify(*, repo: Path, cpu_output: Path, cache_dir: Path, output: Path, edges=1200):
    output.mkdir(parents=True, exist_ok=True)
    runs = {}
    for name, control in [('fresh1', None), ('fresh2', None),
                          ('changed_read', 'changed_read'), ('missing_read', 'missing_read')]:
        run = run_prefix(repo=repo, cpu_output=cpu_output, cache_dir=cache_dir,
                         edges=edges, control=control)
        (output / (name + '.json')).write_bytes(_canonical(run) + b'\n')
        (output / (name + '.events.jsonl')).write_bytes(b''.join(_canonical(row) + b'\n' for row in run['events']))
        run['functional_pass'] = functional_check(run)
        runs[name] = run
        print(json.dumps({'run': name, 'functional_pass': run['functional_pass'],
                          'error': run['error'], 'events': len(run['events'])}), flush=True)
    normalized = [scoped_prefix(runs[name]['events'], runs[name]['identities']) for name in ('fresh1', 'fresh2')]
    fresh_ids = bool(len(runs['fresh1']['identities']) == len(runs['fresh2']['identities']) == 4
        and all(runs['fresh1']['identities'][field] != runs['fresh2']['identities'].get(field)
                for field in runs['fresh1']['identities']))
    match = normalized[0] == normalized[1]
    changed, missing = runs['changed_read'], runs['missing_read']
    def actual_target_read(run):
        reads = [row for row in run['gpio_events']
                 if row.get('kind') == 'gpio_apb_access' and row.get('write') is False]
        return (len(reads) == 1 and reads[0].get('status') == 'observed'
                and reads[0].get('read_rdata') == 53)
    changed_causal = bool(changed['error'] is None and actual_target_read(changed)
        and changed['last_cpu_outputs'].get('ram_3000') == (0xffffffff << 32) | 52
        and len(changed['substitutions']) == 1
        and changed['substitutions'][0]['actual_target_response'] == [53 << 32, 0]
        and changed['substitutions'][0]['offered_cpu_response'] == [52 << 32, 0]
        and not changed['coherent_report']['structural_error'])
    missing_causal = bool(missing['error'] is None and actual_target_read(missing)
        and missing['last_cpu_outputs'].get('ram_3000') == 0
        and len(missing['substitutions']) == 1
        and missing['substitutions'][0]['actual_target_response'] == [53 << 32, 0]
        and missing['substitutions'][0]['offered_cpu_response'] is None
        and missing['coherent_report']['pending_sources'] == 1
        and not missing['coherent_report']['structural_error'])
    controls = (not changed['functional_pass'] and not missing['functional_pass']
                and changed_causal and missing_causal)
    report = {'schema_version': 'boom_gpio_native_verification.v1',
        'fresh_native_scopes_distinct': fresh_ids, 'full_scoped_prefix_equal': match,
        'fresh_functional_pass': all(runs[name]['functional_pass'] for name in ('fresh1', 'fresh2')),
        'counterfactuals_rejected': controls,
        'changed_response_cpu_branch_causality': changed_causal,
        'missing_response_cpu_stall_causality': missing_causal,
        'normalized_prefix_sha256': [hashlib.sha256(_canonical(prefix)).hexdigest() for prefix in normalized],
        'runs': {name: {'functional_pass': run['functional_pass'], 'error': run['error'],
                       'identities': run['identities'], 'events': len(run['events']),
                       'last_cpu_outputs': run['last_cpu_outputs'], 'coherent_report': run['coherent_report'],
                       'substitutions': run['substitutions']} for name, run in runs.items()},
        'scope_policy': 'declared native execution and stream identity fields only; raw nonces retained',
        'generic_admission': False, 'full_P6': False}
    report['pass'] = bool(fresh_ids and match and report['fresh_functional_pass'] and controls)
    if not match:
        for index, (left, right) in enumerate(zip(*normalized)):
            if left != right:
                report['first_prefix_difference'] = {'index': index, 'left': left, 'right': right}
                break
    (output / 'gate.json').write_bytes(_canonical(report) + b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'cpu-output', 'cache-dir', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--edges', type=int, default=1200)
    args = parser.parse_args()
    # Profiling observes the code-owned discovery calls without replacing any
    # pinned source/hash validation function or excluding its per-use rereads.
    from myfuzz.local_harness import build
    discovery_code = build._discover_host_sources.__code__
    profile = {'discover_host_sources_calls': 0, 'scope': 'complete four-run native gate'}
    def count_calls(frame, event, arg):
        if event == 'call' and frame.f_code is discovery_code:
            profile['discover_host_sources_calls'] += 1
    started = time.monotonic()
    previous_profile = sys.getprofile()
    sys.setprofile(count_calls)
    try:
        report = verify(repo=args.repo, cpu_output=args.cpu_output,
                        cache_dir=args.cache_dir, output=args.output, edges=args.edges)
    finally:
        sys.setprofile(previous_profile)
        profile['elapsed_seconds'] = time.monotonic() - started
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'host-discovery-profile.json').write_bytes(_canonical(profile) + b'\n')
    print(json.dumps({'pass': report['pass'], 'full_P6': False}))
    raise SystemExit(0 if report['pass'] else 1)


if __name__ == '__main__':
    main()
