#!/usr/bin/env python3
"""Opt-in BOOM uncached shared-memory DMA gate with complete action replay.

This file is deliberately inert unless MYFUZZ_BOOM_DMA_RAM_REAL=1 is set.
It never builds the prebuilt BOOM CPU artifact.
"""
from __future__ import annotations

import copy
import ast
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import uuid


def save(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(json.dumps(value, sort_keys=True, indent=2,
        default=lambda value: asdict(value) if is_dataclass(value) else repr(value)).encode(), mtime=0))


def plain(value):
    if is_dataclass(value):
        return plain(asdict(value))
    if type(value) is bytes:
        return dict(encoding='hex', bytes=value.hex())
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value


def _memory_effects(events):
    return [row for row in events if row.get('kind') in ('memory_read', 'memory_write')]


def _marker(cpu, result):
    return [row for row in _memory_effects(cpu.service.events)
            if row.get('kind') == 'memory_write' and row.get('address') == result + 20]


_KEY_FIELDS = ('execution_id', 'testcase_id', 'source_component', 'source_epoch',
               'channel_id', 'source_sequence')


def _transaction_id(value):
    from myfuzz.scenario.ledger import TransactionKey
    assert type(value) is dict and set(value) == set(_KEY_FIELDS), 'complete TransactionKey required'
    assert all(type(value[n]) is str and value[n] for n in
               ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
    assert all(type(value[n]) is int and 0 <= value[n] < 1 << 64
               for n in ('source_epoch', 'source_sequence'))
    assert value['source_sequence'] > 0
    return tuple(asdict(TransactionKey(**value))[name] for name in _KEY_FIELDS)


def _index_transactions(rows, field='transaction'):
    result = {}
    for row in rows:
        key = _transaction_id(row[field])
        assert key not in result, 'duplicate full transaction key'
        result[key] = row
    return result


def _advance_partial_a(partial, row):
    """Only Put carries multiple A data beats; Get/Acquire carry one A."""
    header = {name: row[name] for name in ('opcode', 'param', 'source', 'size', 'address')}
    assert all(type(value) is int for value in header.values())
    assert header['opcode'] in (0, 1, 4, 6, 7) and 0 <= header['param'] < 8
    assert 0 <= header['size'] <= 12 and 0 <= header['source'] < 8
    assert 0 <= header['address'] < 1 << 32
    assert header['address'] % (1 << header['size']) == 0
    if partial is not None:
        assert header == partial['header'], 'changed/interleaved partial Put A header'
        assert header['opcode'] in (0, 1) and partial['remaining'] > 0
        remaining = partial['remaining'] - 1
        return None if remaining == 0 else dict(header=header, remaining=remaining)
    beats = max(1, (1 << header['size']) // 8) if header['opcode'] in (0, 1) else 1
    return None if beats == 1 else dict(header=header, remaining=beats - 1)


@contextmanager
def _capture_native_launches(component, binary, launches):
    """Observe returned Popen handles without changing native launch arguments."""
    original = subprocess.Popen
    def observe(*args, **kwargs):
        process = original(*args, **kwargs)
        argv = args[0] if args else kwargs['args']
        if isinstance(argv, (list, tuple)) and argv and Path(argv[0]).resolve() == binary.resolve():
            launches.append((component, process, list(map(str, argv))))
        return process
    subprocess.Popen = observe
    try:
        yield
    finally:
        subprocess.Popen = original


def _install_begin_capture(runner, cpu_output, launches):
    for component, session in runner.sessions.items():
        original = session.begin_case
        def begin(case, *, owner=component, target=session, method=original):
            binary = cpu_output/'obj/VBoomTile' if owner == 'cpu' else target._binary
            assert binary is not None
            with _capture_native_launches(owner, binary, launches):
                return method(case)
        session.begin_case = begin


def _require_prebuilt_dma(dma):
    """Use the existing admission/cache validator; never invoke the builder."""
    from myfuzz.local_harness.build import local_build_identity, _validate_cache
    def prepare():
        identity = local_build_identity(dma.artifact, base_dir=dma.base_dir)
        dma._binary = _validate_cache(dma.cache_dir/identity['build_digest'], identity)
    dma.prepare_local = prepare


def _input_check(repo, cpu_output, cache, frozen, phase):
    measured = {name: hashlib.sha256(data).hexdigest()
                for name, data in source_inputs(repo, cpu_output, cache).items()}
    return dict(phase=phase, files=measured, matches_frozen=measured == frozen)


def _write_commits(service):
    from myfuzz.scenario.memory_service import WriteReceipt
    commits = []
    for key, entry in service.ledger._entries.items():
        if type(entry.receipt) is WriteReceipt:
            assert entry.status == 'complete' and entry.receipt.transaction_id == key
            commits.append(entry.receipt.commit_document())
    return commits


def run(repo: Path, cache: Path, cpu_output: Path, key: int, output: Path, actions=None,
        *, frozen_inputs):
    from myfuzz.scenario.boom_dma_runner import make_boom_dma_runner
    from myfuzz.scenario.boom_dma_example import SOURCE, DESTINATION, RESULT

    evidence = dict(schema_version='boom_dma_run.v1', start_key=key, actions=[],
                    cpu_samples=[], cpu_outputs=[], cpu_acceptances=[], quiesce_boundary=None,
                    input_checks={}, schedule_steps=[])
    runner = cpu = dma = None
    processes = {}
    launches = []
    primary = None
    try:
        evidence['input_checks']['before'] = _input_check(
            repo, cpu_output, cache, frozen_inputs, 'before_session_construction')
        assert evidence['input_checks']['before']['matches_frozen'], 'run input drift before startup'
        runner = make_boom_dma_runner(repo=repo, cpu_output=cpu_output, cache_dir=cache, start_key=key)
        cpu, dma = runner.sessions['cpu'], runner.sessions['dma']
        _require_prebuilt_dma(dma)
        fixture_identity = plain(runner.identity_document())
        evidence['identities'] = fixture_identity
        _install_begin_capture(runner, cpu_output, launches)
        runner.begin_test('boom-dma-ram')
        processes = {name: session.process for name, session in runner.sessions.items()}
        assert all(any(owner == name and handle is process for owner, handle, _ in launches)
                   for name, process in processes.items())
        evidence.update(
            pids={name: process.pid for name, process in processes.items()},
            executions={name: getattr(session, '_native', None).execution_id if name == 'cpu'
                        else session._execution for name, session in runner.sessions.items()},
            scenario_execution=runner.execution_id,
            identities=fixture_identity,
            runtime_identities={name: plain(session.identity_document()) for name, session in runner.sessions.items()},
            cpu_coherent_identity=plain(cpu.coherent_report()),
            native_identity=plain(cpu._native.identity_document()),
            dma_identity=plain(dma.identity_document()))

        quiesced = False
        marker_seen = False
        partial_a = None
        def terminal():
            return (marker_seen and quiesced
                    and all(session.pending_responses == 0 for session in runner.sessions.values())
                    and not cpu.router.pending_targets
                    and not getattr(dma, 'pending_responses', 0))

        def apply(action):
            nonlocal quiesced, marker_seen, partial_a
            action = copy.deepcopy(action)
            evidence['actions'].append(action)
            if action['operation'] == 'begin_quiesce':
                assert not quiesced and marker_seen
                assert partial_a is None, 'cannot quiesce with an incomplete TileLink A transfer'
                ticks = dict(runner.local_ticks)
                cpu.begin_quiesce()
                assert dict(runner.local_ticks) == ticks, 'quiesce action unexpectedly clocked a target'
                quiesced = True
                evidence['quiesce_boundary'] = dict(
                    marker=plain(copy.deepcopy(_marker(cpu, RESULT)[-1])),
                    local_ticks=ticks, partial_a=partial_a,
                    simultaneous_a_count=0, operation='begin_quiesce_no_edge')
                return
            assert action == {'operation': 'step', 'component': action.get('component')}
            component = action['component']
            assert component in ('dma', 'cpu')
            step = dict(action_index=len(evidence['actions'])-1, component=component,
                        local_ticks_before=dict(runner.local_ticks))
            evidence['schedule_steps'].append(step)
            dma_event_start = len(dma.events)
            try:
                observed = runner.step(component)
            finally:
                step.update(local_ticks_after=dict(runner.local_ticks),
                            dma_event_ticks=[row['tick'] for row in dma.events[dma_event_start:]])
            if component == 'dma':
                dma.drain_tick_samples()
            else:
                samples = plain(cpu.last_samples)
                evidence['cpu_samples'].extend(samples)
                evidence['cpu_outputs'].append(plain(observed))
                for sample in samples:
                    events = sample.get('events', ())
                    accepted = [row for row in events if row.get('channel') == 'A']
                    evidence['cpu_acceptances'].extend(copy.deepcopy(accepted))
                    if marker_seen and accepted:
                        raise AssertionError('new external A accepted at/after marker boundary')
                    accepted_this_step = len(accepted)
                    for row in accepted:
                        partial_a = _advance_partial_a(partial_a, row)
                current = _marker(cpu, RESULT)
                if current and not marker_seen:
                    # Marker is considered complete only after its matched D is accepted.
                    marker_key = current[-1].get('transaction')
                    complete = any(event.get('kind') == 'boom_external_d_accepted'
                                   and plain(event.get('source_transaction')) == plain(marker_key)
                                   for event in cpu.source_events)
                    if complete:
                        assert partial_a is None, 'partial A outstanding at actual marker D boundary'
                        assert accepted_this_step == 0, 'simultaneous A acceptance on marker D sample'
                        marker_seen = True
                        evidence['marker_boundary'] = dict(
                            transaction=plain(marker_key), local_tick=cpu.local_ticks,
                            partial_a=partial_a, simultaneous_a_count=0)

        if actions is None:
            for _ in range(4000):
                for component in ('dma', 'cpu'):
                    apply(dict(operation='step', component=component))
                    if marker_seen and not quiesced:
                        apply(dict(operation='begin_quiesce'))
                if terminal():
                    break
        else:
            assert sum(a.get('operation') == 'step' for a in actions) <= 8000
            for action in actions:
                apply(action)
        assert terminal(), 'marker and all native/Router/DMA responses did not drain within 4000 rounds'
        assert partial_a is None
    except BaseException as error:
        primary = error
        evidence['failure'] = repr(error)
        raise
    finally:
        capture_errors, cleanup_errors = [], []
        try:
            captures = {} if cpu is None else dict(
                runner_events=lambda: plain(list(runner.events)),
                dma_events=lambda: plain(copy.deepcopy(dma.events)),
                dma_memory=lambda: plain(copy.deepcopy(dma.memory_service.events)),
                dma_write_commits=lambda: plain(_write_commits(dma.memory_service)),
                cpu_memory=lambda: plain(copy.deepcopy(cpu.service.events)),
                shared_records=lambda: plain(copy.deepcopy(cpu.shared_memory_service.records)),
                shared_receipts=lambda: plain(copy.deepcopy(cpu.shared_memory_service.receipts)),
                source_events=lambda: plain(copy.deepcopy(cpu.source_events)),
                runtime_events=lambda: plain(copy.deepcopy(cpu.runtime_events)),
                cpu_native_samples=lambda: plain(copy.deepcopy(cpu.last_samples)),
                router_acceptances=lambda: plain(copy.deepcopy(cpu.router.acceptances)),
                router_deliveries=lambda: plain(copy.deepcopy(cpu.router.deliveries)),
                local_ticks=lambda: dict(runner.local_ticks),
                pending=lambda: {name: session.pending_responses for name, session in runner.sessions.items()},
                router_pending=lambda: plain(cpu.router.pending_targets),
                source=lambda: [cpu.memory.read(SOURCE + 4*i, 4, transaction_id='gate-source').value for i in range(4)],
                destination=lambda: [cpu.memory.read(DESTINATION + 4*i, 4, transaction_id='gate-destination').value for i in range(4)],
                result=lambda: [cpu.memory.read(RESULT + 4*i, 4, transaction_id='gate-result').value for i in range(6)],
                coherent_report=lambda: plain(cpu.coherent_report()),
                cpu_identity=lambda: plain(cpu.identity_document()),
                dma_identity=lambda: plain(dma.identity_document()))
            for name, capture in captures.items():
                try:
                    evidence[name] = capture()
                except BaseException as error:
                    capture_errors.append(dict(field=name, error=repr(error)))
        finally:
            for name, session in (() if runner is None else runner.sessions.items()):
                try:
                    session.end_case()
                except BaseException as error:
                    cleanup_errors.append(dict(component=name, error=repr(error)))
            # Includes handles from constructors that failed before a session
            # could publish .process, and handles hidden by Runner cleanup.
            from myfuzz.scenario.protocol_io import end_local_process
            for name, process, _ in launches:
                try:
                    if process.poll() is None:
                        end_local_process(process)
                except BaseException as error:
                    cleanup_errors.append(dict(component=name, pid=process.pid,
                                               phase='retained_handle_cleanup', error=repr(error)))
            instances = []
            for name, process, argv in launches:
                instances.append(dict(component=name,
                    launch_sequence=1+sum(row['component'] == name for row in instances),
                    pid=process.pid, returncode=process.poll(), argv=argv))
            try:
                evidence['input_checks']['after_teardown'] = _input_check(
                    repo, cpu_output, cache, frozen_inputs, 'after_session_teardown')
                assert evidence['input_checks']['after_teardown']['matches_frozen'], 'run input drift after teardown'
            except BaseException as error:
                capture_errors.append(dict(field='input_checks.after_teardown', error=repr(error)))
            evidence.update(process_instances=instances,
                process_returncodes={row['component']+':'+str(row['launch_sequence']):row['returncode']
                                     for row in instances},
                cleanup_errors=cleanup_errors, capture_errors=capture_errors,
                status='failed' if primary or capture_errors or cleanup_errors else 'captured')
            if primary is None and not capture_errors and not cleanup_errors:
                try:
                    assert_chain(evidence, key)
                except BaseException as error:
                    primary = error
                    evidence.update(status='failed', failure=repr(error))
            try:
                save(output, evidence)
            except BaseException as error:
                evidence['save_failure'] = repr(error)
                if primary is None:
                    raise
            if (capture_errors or cleanup_errors) and primary is None:
                raise RuntimeError(repr(capture_errors + cleanup_errors))
    if primary is not None:
        raise primary
    return evidence


def _parse_key_string(value):
    """Accept only the exact dataclass repr grammar, never arbitrary UUID text."""
    if type(value) is not str or not value.startswith('TransactionKey('):
        return None
    try:
        node = ast.parse(value, mode='eval').body
        assert isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        assert node.func.id == 'TransactionKey' and not node.args
        assert [item.arg for item in node.keywords] == list(_KEY_FIELDS)
        fields = {item.arg:ast.literal_eval(item.value) for item in node.keywords}
        _transaction_id(fields)
        assert _key_string(fields) == value
        return fields
    except (AssertionError, SyntaxError, ValueError, TypeError):
        return None


def _uuid_owner(value):
    assert type(value) is str
    parsed = uuid.UUID(value)
    assert value in (parsed.hex,str(parsed)), 'noncanonical declared UUID owner'
    return value


def _stream_owners(document):
    stream = document.get('cpu_coherent_identity',{}).get('stream_id')
    if stream is None:
        return None
    _uuid_owner(stream)
    assert document['coherent_report']['stream_id'] == stream
    runtime = document['runtime_events']
    raw = {row['raw_event_id']:row for row in runtime if 'raw_event_id' in row}
    assert list(raw) == list(range(1,len(raw)+1))
    assert len(raw) == sum('raw_event_id' in row for row in runtime)
    identifiers = set()
    for row in runtime:
        assert row['raw_event_scope'] == stream
        for ref in tuple(row.get('raw_event_refs',()))+tuple(row.get('related_request_event_refs',())):
            assert type(ref) is int and ref in raw
        if 'local_event_id' in row:
            value = row['local_event_id']
            assert type(value) is str and value.startswith(stream+'|')
            suffix = value[len(stream)+1:]
            assert re.fullmatch(r'cpu\|coherent\|[1-9][0-9]*\|[A-Za-z0-9_-]+',suffix)
            assert value not in identifiers
            identifiers.add(value)
    for row in document.get('runner_events',()):
        if 'raw_event_scope' in row:
            assert row['raw_event_scope'] == stream
            if 'raw_event_id' in row:
                assert row['raw_event_id'] in raw
                assert row.get('native_event') == raw[row['raw_event_id']].get('native_event')
            for ref in tuple(row.get('raw_event_refs',()))+tuple(row.get('related_request_event_refs',())):
                assert type(ref) is int and ref in raw
            if 'local_event_id' in row:
                assert row['local_event_id'] in identifiers
    return stream


def _normalized(document):
    """Normalize only validated owner references and their checked derived hashes."""
    value = copy.deepcopy(document)
    owners = value.get('executions',{})
    mapping = {_uuid_owner(ident):'native-execution:'+role for role,ident in owners.items()}
    scenario = value.get('scenario_execution')
    if scenario is not None:
        mapping[_uuid_owner(scenario)] = 'scenario-execution'
    assert len(mapping) == len(owners)+(scenario is not None)
    stream = _stream_owners(value)
    if stream is not None:
        assert stream not in mapping
    pids = value.get('pids',{})
    assert all(type(pid) is int and pid>0 for pid in pids.values())
    instances = value.get('process_instances',())
    assert len({row['pid'] for row in instances}) == len(instances)
    if instances:
        assert set(pids.values()) <= {row['pid'] for row in instances}
        assert all(type(row['pid']) is int and row['pid']>0 for row in instances)
    # Owner documents are checked before removing them, before serialization.
    for field in ('pids','executions','scenario_execution'):
        value.pop(field,None)

    def owner_role(path,row):
        if len(path)==2 and path[0] in ('source_events','runtime_events'):
            return 'cpu'
        if len(path)==2 and path[0]=='runner_events':
            return row.get('component')
        if path in (('native_identity',),('cpu_identity','native_identity'),
                    ('runtime_identities','cpu','native_identity')):
            return 'cpu'
        return None

    def key_material(fields):
        _transaction_id(fields)
        assert fields['source_component'] in owners
        assert fields['execution_id'] == owners[fields['source_component']]
        result = dict(fields)
        result['execution_id'] = mapping[fields['execution_id']]
        return result

    def walk(item,path=()):
        if type(item) is dict:
            if set(item)==set(_KEY_FIELDS):
                return key_material(item)
            commit = item.get('schema_version')=='memory_write_commit_receipt.v1'
            if commit:
                material={name:data for name,data in item.items() if name!='commit_id'}
                assert item['commit_id']==hashlib.sha256(json.dumps(material,sort_keys=True,
                    separators=(',',':'),allow_nan=False).encode()).hexdigest(), 'raw commit digest mismatch'
            result={}
            role=owner_role(path,item)
            for name,data in item.items():
                if name=='execution_id' and role in owners:
                    assert data==owners[role], 'execution owner reference mismatch'
                    continue
                if name=='pid' and len(path)==2 and path[0]=='process_instances':
                    assert data in {row['pid'] for row in instances}
                    continue
                if name=='stream_id' and path in (('cpu_coherent_identity',),('coherent_report',)):
                    assert data==stream
                    result[name]='coherent-stream:cpu'
                    continue
                if (name in ('raw_event_scope','local_event_id') and len(path)==2
                        and path[0] in ('runtime_events','runner_events')
                        and 'raw_event_scope' in item):
                    if name=='raw_event_scope':
                        assert data==stream
                        result[name]='coherent-stream:cpu'
                    else:
                        assert stream is not None and data.startswith(stream+'|')
                        result[name]='coherent-stream:cpu|'+data[len(stream)+1:]
                    continue
                parsed=_parse_key_string(name)
                normalized_name=_key_string(key_material(parsed)) if parsed is not None else name
                assert normalized_name not in result
                result[normalized_name]=walk(data,path+(name,))
            if commit:
                material={name:data for name,data in result.items() if name!='commit_id'}
                result['commit_id']=hashlib.sha256(json.dumps(material,sort_keys=True,
                    separators=(',',':'),allow_nan=False).encode()).hexdigest()
            return result
        if type(item) is list:
            return [walk(child,path+(index,)) for index,child in enumerate(item)]
        parsed=_parse_key_string(item)
        return _key_string(key_material(parsed)) if parsed is not None else item
    return json.dumps(walk(value),sort_keys=True,separators=(',',':'),allow_nan=False)



def _assert_commit(document, event):
    assert document['schema_version'] == 'memory_write_commit_receipt.v1'
    material = {name:value for name,value in document.items() if name != 'commit_id'}
    assert document['commit_id'] == hashlib.sha256(json.dumps(
        material, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    assert document['fullkey'] == event['transaction']
    assert document['commit_status'] == 'complete' and document['performed_effect'] is True
    for name in ('memory_id', 'generation', 'byte_offset', 'width_bytes', 'byte_enable', 'version'):
        assert document[name] == event[name]
    assert document['width_bytes'] == 4 and document['byte_enable'] == 15
    cells = document['enabled_byte_cells']
    assert len(cells) == 4
    writer = _key_string(event['transaction'])
    for index, cell in enumerate(cells):
        assert cell == dict(byte_offset=event['byte_offset']+index,
            value=(event['value'] >> (8*index)) & 255, version=event['version'],
            writer_kind='STORE', writer_event_id=writer)


def _key_string(key):
    from myfuzz.scenario.ledger import TransactionKey
    _transaction_id(key)
    return str(TransactionKey(**key))


def _assert_cpu_chain(document):
    from myfuzz.local_harness.boom_shared_memory import validate_boom_external_request
    events = document['source_events']
    accepted = [row for row in events if row['kind'] in
                ('boom_external_a_queued', 'boom_external_a_memory_accepted')]
    offered = _index_transactions(
        [row for row in events if row['kind'] == 'boom_external_d_offered'], 'source_transaction')
    consumed = _index_transactions(
        [row for row in events if row['kind'] == 'boom_external_d_accepted'], 'source_transaction')
    by_a = _index_transactions(accepted, 'source_transaction')
    assert set(by_a) == set(offered) == set(consumed) and by_a
    cpu_execution = document['executions']['cpu']
    epoch = document['native_identity']['reset_epoch']
    samples = {row['cycle']:row for row in document['cpu_samples']}
    assert len(samples) == len(document['cpu_samples'])
    previous_d_tick = 0
    for sequence, row in enumerate(accepted, 1):
        key, request = row['source_transaction'], row['native_request']
        assert _transaction_id(key) == (cpu_execution, 'boom-dma-ram', 'cpu',
                                        epoch, 'coherent-A-uncached', sequence)
        assert key['source_sequence'] == request['request_sequence']
        validate_boom_external_request(request, reset_epoch=epoch)
        identifier = _transaction_id(key)
        offer, complete = offered[identifier], consumed[identifier]
        native_d = complete['native_response']
        assert previous_d_tick < row['local_tick'] <= offer['local_tick'] < complete['local_tick']
        previous_d_tick = complete['local_tick']
        assert native_d['source'] == request['source'] and native_d['size'] == request['size']
        assert native_d['opcode'] == (1 if request['opcode'] == 4 else 0)
        assert native_d['param'] == native_d['sink'] == native_d['beat'] == 0
        assert native_d['external'] is True
        assert native_d['data'] == offer['response_data']
        raw_a = {name:value for name,value in request.items()
                 if name not in ('request_sequence', 'reset_epoch')}
        assert samples[row['local_tick']]['events'].count(raw_a) == 1
        assert samples[complete['local_tick']]['events'].count(native_d) == 1
    cpu_memory = _memory_effects(document['cpu_memory'])
    assert len(cpu_memory) == len(document['cpu_memory']), 'unexpected CPU memory initialization/event'
    effects = _index_transactions(cpu_memory)
    records = _index_transactions(document['shared_records'], 'source_transaction')
    memory_a = {key:row for key,row in by_a.items() if row['kind'] == 'boom_external_a_memory_accepted'}
    service_events = _index_transactions([row for row in events
        if row['kind'] == 'boom_external_memory_service_complete'], 'source_transaction')
    assert set(effects) == set(records) == set(memory_a) == set(service_events)
    assert len(document['shared_receipts']) == len(effects)
    for identifier, effect in effects.items():
        row, record = memory_a[identifier], records[identifier]
        request, receipt = row['native_request'], record['service_receipt']
        assert effect['width_bytes'] == 4 and effect['address'] == request['address']
        assert record['native_request'] == request and record['status'] == 'd_accepted'
        assert record['response_data'] == consumed[identifier]['native_response']['data']
        issued = copy.deepcopy(service_events[identifier]['service_record'])
        assert issued['status'] == 'service_complete_d_pending'
        issued['status'] = 'd_accepted'
        assert issued == record
        actual_receipt = document['shared_receipts'][_key_string(effect['transaction'])]
        assert actual_receipt['transaction_id'] == (
            effect['transaction'] if effect['kind'] == 'memory_write'
            else _key_string(effect['transaction']))
        if effect['kind'] == 'memory_write':
            assert request['opcode'] in (0, 1) and effect['byte_enable'] == 15
            assert effect['value'] == (request['data'] >> (8*(request['address'] & 7))) & 0xffffffff
            assert record['operation'] == 'write' and record['response_data'] == 0
            assert actual_receipt['version'] == effect['version'] and actual_receipt['byte_enable'] == 15
            _assert_commit(receipt, effect)
        else:
            assert request['opcode'] == 4 and record['operation'] == 'read'
            assert record['response_data'] == effect['value'] << (8*(request['address'] & 7))
            for name in ('memory_id', 'generation', 'byte_offset', 'value',
                         'data_hex', 'versions', 'writer_event_ids', 'writer_kinds'):
                assert receipt[name] == effect[name]
            for name in ('memory_id', 'generation', 'byte_offset', 'versions',
                         'writer_event_ids', 'writer_kinds'):
                assert actual_receipt[name] == effect[name]
            assert actual_receipt['data'] == dict(encoding='hex', bytes=effect['data_hex'])
            assert len(effect['versions']) == len(effect['writer_event_ids']) == 4
            assert len(bytes.fromhex(effect['data_hex'])) == 4
            assert int.from_bytes(bytes.fromhex(effect['data_hex']), 'little') == effect['value']
    return cpu_memory, by_a, consumed


def _assert_control_chain(document, by_a, consumed):
    from myfuzz.scenario.boom_dma_example import DMA_BASE
    queued = {key:row for key,row in by_a.items() if row['kind'] == 'boom_external_a_queued'}
    acceptances = _index_transactions(document['router_acceptances'], 'source_transaction')
    deliveries = _index_transactions(document['router_deliveries'], 'source_transaction')
    assert set(queued) == set(acceptances) == set(deliveries)
    edge_by_tick = {row['tick']:row for row in document['dma_events']}
    assert len(edge_by_tick) == len(document['dma_events'])
    scheduled = {}
    step_by_action = {}
    for step in document['schedule_steps']:
        index = step['action_index']
        assert index not in step_by_action
        step_by_action[index] = step
        assert document['actions'][index] == dict(operation='step', component=step['component'])
        for tick in step['dma_event_ticks']:
            assert step['component'] == 'dma' and tick not in scheduled
            assert step['local_ticks_before']['dma'] < tick <= step['local_ticks_after']['dma']
            scheduled[tick] = index
    assert set(step_by_action) == {index for index,action in enumerate(document['actions'])
                                  if action['operation'] == 'step'}
    assert list(scheduled) == list(edge_by_tick), 'DMA edges must belong to recorded scheduled steps'
    previous_tick = 0
    for order, delivery in enumerate(document['router_deliveries'], 1):
        identifier = _transaction_id(delivery['source_transaction'])
        acceptance, queue = acceptances[identifier], queued[identifier]
        request = queue['native_request']
        address, write = request['address'], request['opcode'] != 4
        value = (request['data'] >> (8*(address & 7))) & 0xffffffff
        assert delivery['source_sequence'] == acceptance['source_sequence'] == identifier[-1]
        assert acceptance['acceptance_order'] == delivery['delivery_order'] == delivery['target_delivery_order'] == order
        for row in (acceptance, delivery):
            assert row['device_id'] == 'dma' and row['address'] == address
            assert row['offset'] == address-DMA_BASE and row['write'] is write
            assert row['beat_bytes'] == 8 and row['byte_enable'] == 15
            assert row['write_value'] == (value if write else None)
        control = delivery['dma_control_receipt']
        assert control['source_transaction'] == delivery['source_transaction']
        assert control['address'] == address and control['offset'] == address-DMA_BASE
        assert control['write'] is write and control['value'] == value and control['byte_enable'] == 15
        assert control['delivery_context'] == dict(source_transaction=delivery['source_transaction'],
            device_id='dma', window_base=DMA_BASE, window_size=16, address=address,
            offset=address-DMA_BASE, write=write, value=value, be=15)
        ticks = control['edge_ticks']
        assert ticks and ticks == sorted(set(ticks)) and ticks[0] > previous_tick
        assert ticks == list(range(ticks[0], ticks[-1]+1))
        previous_tick = ticks[-1]
        assert len({scheduled[tick] for tick in ticks}) == 1
        scheduled_step = step_by_action[scheduled[ticks[0]]]
        assert (queue['local_tick'] <= scheduled_step['local_ticks_before']['cpu']
                == scheduled_step['local_ticks_after']['cpu']
                < consumed[identifier]['local_tick'])
        edges = [edge_by_tick[tick] for tick in ticks]
        strobes = [row['payload']['pre_backend'] for row in edges if row['payload']['pre_backend']['swb_stb']]
        acks = [row['payload']['pre_backend'] for row in edges if row['payload']['pre_backend']['swb_ack']]
        assert len(strobes) == len(acks) == 1
        assert strobes[0]['swb_cyc'] == acks[0]['swb_cyc'] == 1
        assert strobes[0]['swb_adr'] == (address-DMA_BASE)//4
        assert strobes[0]['swb_we'] == int(write) and strobes[0]['swb_dat_w'] == value
        response = 0 if write else acks[0]['swb_dat_r'] << (8*(address & 7))
        assert consumed[identifier]['native_response']['data'] == response
        assert delivery['read_value'] == (None if write else response)
    return document['router_deliveries']


def _assert_dma_chain(document, cpu_memory, sources):
    from myfuzz.scenario.boom_dma_example import SOURCE, DESTINATION, WORDS
    accepted_rows = [row for row in document['dma_events'] if row.get('accepted')]
    response_rows = [row for row in document['dma_events'] if row.get('response')]
    accepted = _index_transactions([row['accepted'] for row in accepted_rows])
    responses = _index_transactions([row['response'] for row in response_rows])
    effects = _index_transactions(_memory_effects(document['dma_memory']))
    assert len(effects) == len(document['dma_memory']), 'unexpected DMA memory initialization/event'
    commits = _index_transactions(document['dma_write_commits'], 'fullkey')
    assert len(accepted) == len(responses) == len(effects) == 8
    assert set(accepted) == set(responses) == set(effects)
    assert [(row['address'],row['write']) for row in accepted.values()] == (
        [(SOURCE+4*i,False) for i in range(4)]+[(DESTINATION+4*i,True) for i in range(4)])
    assert set(commits) == {key for key,row in accepted.items() if row['write']}
    response_events = {_transaction_id(row['response']['transaction']):row for row in response_rows}
    previous_response_tick = 0
    for sequence, accepted_event in enumerate(accepted_rows, 1):
        beat = accepted_event['accepted']
        identifier = _transaction_id(beat['transaction'])
        assert identifier == (document['executions']['dma'], 'boom-dma-ram', 'dma',
            accepted_event['reset_epoch'], 'dma-memory', sequence)
        response_event, effect = response_events[identifier], effects[identifier]
        response = responses[identifier]
        pre, rp = accepted_event['payload']['pre_backend'], response_event['payload']['pre_backend']
        assert previous_response_tick < accepted_event['tick'] < response_event['tick']
        previous_response_tick = response_event['tick']
        assert pre['mwb_cyc'] == pre['mwb_stb'] == 1 and pre['mwb_stall'] == 0
        assert beat['address'] == pre['mwb_adr'] << 2 and beat['word_address'] == pre['mwb_adr']
        assert beat['byte_enable'] == 15 and beat['write'] is bool(pre['mwb_we'])
        assert beat['value'] == pre['mwb_dat_w']
        assert effect['address'] == beat['address'] and effect['width_bytes'] == 4
        assert rp['mwb_cyc'] == rp['mwb_ack'] == 1
        assert rp['mwb_err'] == response['error'] == 0 and rp['mwb_dat_r'] == response['rdata']
        index = (beat['address']-(DESTINATION if beat['write'] else SOURCE))//4
        if beat['write']:
            assert effect['kind'] == 'memory_write' and effect['byte_enable'] == 15
            assert effect['value'] == beat['value'] == WORDS[index] and response['rdata'] == 0
            _assert_commit(commits[identifier], effect)
            observed, = [row for row in cpu_memory if row['kind'] == 'memory_read'
                          and row['address'] == beat['address']]
            assert observed['value'] == effect['value']
            assert observed['memory_id'] == effect['memory_id'] and observed['generation'] == effect['generation']
            assert observed['byte_offset'] == effect['byte_offset']
            assert observed['versions'] == [effect['version']]*4
            assert observed['writer_event_ids'] == [_key_string(effect['transaction'])]*4
            assert observed['writer_kinds'] == ['STORE']*4
        else:
            source = sources[index]
            assert effect['kind'] == 'memory_read' and effect['value'] == response['rdata'] == WORDS[index]
            assert effect['memory_id'] == source['memory_id'] and effect['generation'] == source['generation']
            assert effect['byte_offset'] == source['byte_offset']
            assert effect['versions'] == [source['version']]*4
            assert effect['writer_event_ids'] == [_key_string(source['transaction'])]*4


def assert_chain(document, key):
    from myfuzz.scenario.boom_dma_example import SOURCE, DESTINATION, RESULT, WORDS
    assert key in (0xfed, 0x3db) and document['status'] == 'captured'
    assert document['process_instances'] and all(code == 0 for code in document['process_returncodes'].values())
    assert {row['component'] for row in document['process_instances']} == {'cpu','dma'}
    assert len({row['pid'] for row in document['process_instances']}) == len(document['process_instances'])
    terminal_codes = {row['component']+':'+str(row['launch_sequence']):row['returncode']
                      for row in document['process_instances']}
    assert len(terminal_codes) == len(document['process_instances'])
    assert document['process_returncodes'] == terminal_codes
    assert set(document['pids']) == set(document['executions']) == {'cpu','dma'}
    for component in ('cpu','dma'):
        instances = [row for row in document['process_instances'] if row['component'] == component]
        assert [row['launch_sequence'] for row in instances] == list(range(1,len(instances)+1))
        assert document['pids'][component] == instances[-1]['pid']
    assert all(check['matches_frozen'] for check in document['input_checks'].values())
    assert set(document['input_checks']) == {'before','after_teardown'}
    assert document['input_checks']['before']['files'] == document['input_checks']['after_teardown']['files']
    assert all(value == 0 for value in document['pending'].values()) and not document['router_pending']
    assert document['coherent_report']['stream_closed'] is True
    assert not document['coherent_report']['structural_error']
    assert not document['coherent_report']['normalization_poisoned']
    assert document['quiesce_boundary']['partial_a'] is document['marker_boundary']['partial_a'] is None
    partial = None
    observed_a = []
    for sample in document['cpu_samples']:
        accepted_a = [row for row in sample['events'] if row['channel']=='A']
        observed_a.extend(accepted_a)
        for row in accepted_a:
            partial = _advance_partial_a(partial,row)
        if sample['cycle'] >= document['marker_boundary']['local_tick']:
            assert partial is None and not accepted_a, 'A prefix not quiescent at/after marker D'
    assert observed_a == document['cpu_acceptances']
    assert partial is None
    cpu_memory, by_a, consumed = _assert_cpu_chain(document)
    deliveries = _assert_control_chain(document, by_a, consumed)
    control_writes = [row for row in deliveries if row['write']]
    assert [row['offset'] for row in control_writes] == [8,12,4,0]
    assert [row['write_value'] for row in control_writes] == [SOURCE,DESTINATION,4,(key<<16)|4]
    polls = [row for row in deliveries if not row['write']]
    assert polls and all(row['offset'] == 0 for row in polls)
    assert polls[-1]['read_value'] & 0xc0000000 == 0
    assert all(row['read_value'] & 0x80000000 for row in polls[:-1])
    sources = [row for row in cpu_memory if row['kind'] == 'memory_write' and SOURCE <= row['address'] < SOURCE+16]
    assert [(row['address'],row['value']) for row in sources] == [(SOURCE+4*i,v) for i,v in enumerate(WORDS)]
    assert not any(row['kind']=='memory_write' and DESTINATION <= row['address'] < DESTINATION+16 for row in cpu_memory)
    result_writes = [row for row in cpu_memory if row['kind']=='memory_write' and RESULT <= row['address'] < RESULT+24]
    expected_offsets = [0,4,8,12,16,20] if key == 0xfed else [0,4,20]
    assert [row['address']-RESULT for row in result_writes] == expected_offsets
    status, marker = result_writes[0], result_writes[-1]
    assert status['value'] == polls[-1]['read_value'] == document['result'][0]
    assert status['value'] & 0xc0000000 == 0
    assert marker['value'] == (1 if key==0xfed else 0xffffffff) == document['result'][5]
    marker_id = _transaction_id(marker['transaction'])
    assert document['marker_boundary']['transaction'] == marker['transaction']
    assert document['quiesce_boundary']['marker'] == marker
    assert document['marker_boundary']['local_tick'] == consumed[marker_id]['local_tick']
    assert document['marker_boundary']['simultaneous_a_count'] == 0
    assert document['quiesce_boundary']['simultaneous_a_count'] == 0
    assert not any(row['channel']=='A' for row in document['cpu_samples'][
        document['marker_boundary']['local_tick']-1]['events'])
    assert max(row['transaction']['source_sequence'] for row in sources) < control_writes[0]['source_sequence']
    assert polls[-1]['source_sequence'] < status['transaction']['source_sequence']
    destination_reads = [row for row in cpu_memory if row['kind']=='memory_read' and DESTINATION <= row['address'] < DESTINATION+16]
    source_reads = [row for row in cpu_memory if row['kind']=='memory_read' and SOURCE <= row['address'] < SOURCE+16]
    count = 4 if key == 0xfed else 1
    assert len(destination_reads) == len(source_reads) == count
    for index,(destination,source,result) in enumerate(zip(destination_reads,source_reads,result_writes[1:-1])):
        assert destination['address'] == DESTINATION+4*index and source['address'] == SOURCE+4*index
        assert result['address'] == RESULT+4*(index+1) and result['value'] == destination['value']
        assert source['value'] == WORDS[index]
        assert source['versions'] == [sources[index]['version']]*4
        assert source['writer_event_ids'] == [_key_string(sources[index]['transaction'])]*4
        ordered = [status,destination,result,source,marker]
        assert [row['transaction']['source_sequence'] for row in ordered] == sorted(
            {row['transaction']['source_sequence'] for row in ordered})
        if index:
            assert source_reads[index-1]['transaction']['source_sequence'] < destination['transaction']['source_sequence']
        if key == 0xfed:
            assert destination['value'] == source['value']
        else:
            assert destination['value'] == result['value'] == 0 and source['value'] != destination['value']
            assert destination['versions'] == [[destination['generation'],0]]*4
            assert destination['writer_event_ids'] == ['initial-image']*4
    assert len(cpu_memory) == 4+len(result_writes)+2*count
    assert document['source'] == list(WORDS)
    if key == 0x3db:
        assert not any(row.get('accepted') or row.get('response') for row in document['dma_events'])
        assert not document['dma_memory'] and not document['dma_write_commits']
        assert document['destination'] == [0]*4 and document['result'][1:5] == [0]*4
    else:
        _assert_dma_chain(document,cpu_memory,sources)
        assert document['destination'] == document['result'][1:5] == list(WORDS)


def _hole_state(shared):
    ledger = shared.service.ledger
    return dict(records=copy.deepcopy(shared.records), receipts=copy.deepcopy(shared.receipts),
        service=copy.deepcopy(shared.service.events), ledger=copy.deepcopy(ledger._entries),
        next_channel=copy.deepcopy(ledger._next_channel_sequence),
        next_target=copy.deepcopy(ledger._next_target_sequence),
        memory=shared.memory.identity_document(), memory_state=shared.memory.state_summary(),
        generation=shared.memory.generation)


def _hole_refusal(repo, cache, cpu_output, output):
    """Exercise undeclared span refusal before effects, without native startup."""
    from myfuzz.scenario.boom_dma_runner import make_boom_dma_runner
    from myfuzz.scenario.ledger import TransactionKey
    runner = make_boom_dma_runner(repo=repo, cpu_output=cpu_output, cache_dir=cache)
    cpu = runner.sessions['cpu']
    shared = cpu.shared_memory_service
    shared.bind(execution_id='hole-check', testcase_id='hole-check',
                source_component='cpu', reset_epoch=0)
    key = TransactionKey('hole-check', 'hole-check', 'cpu', 0,
                         'coherent-A-uncached', 1)
    request = dict(channel='A', opcode=0, param=0, size=2, source=0,
                   address=0x4110, mask=15, data=0x12345678,
                   request_sequence=1, reset_epoch=0)
    before = _hole_state(shared)
    try:
        try:
            shared.execute(key, request)
            raise AssertionError('undeclared source hole unexpectedly accepted')
        except ValueError as error:
            refusal = repr(error)
        after = _hole_state(shared)
        assert after == before
        report = dict(status='pre_effect_layout_refusal', refusal=refusal,
                      native_started=any(session.process is not None for session in runner.sessions.values()),
                      fabricated_native_error=False, request=request, before=before, after=after)
        assert not report['native_started']
        save(output, report)
        return report
    finally:
        for session in runner.sessions.values():
            session.end_case()


def _selected_lock_inputs(repo, component):
    """Resolve the selected central lock evidence and its actual closure bytes."""
    lock_path = repo/'configs/soc/sources.lock.json'
    record, = [row for row in json.loads(lock_path.read_text())['components'] if row['id'] == component]
    paths = {lock_path}
    def require(name, digest=None):
        path = repo/name
        assert path.resolve().is_relative_to(repo.resolve()) and not path.is_symlink() and path.is_file()
        if digest is not None:
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'source-lock dependency drift: '+name
        paths.add(path)
        return path
    for row in record.get('artifacts', ()):
        require(str(Path(record['source']['root'])/row['path']), row['sha256'])
    for name in record['source'].get('files', ()):
        require(str(Path(record['source']['root'])/name))
    elaboration = record['elaboration']
    evidence = require(elaboration['evidence'], elaboration['evidence_sha256'])
    closure = json.loads(evidence.read_text())
    assert closure['component'] == component and closure['top_module'] == record['source']['top_module']
    assert elaboration['closure_files'] == len(closure['closure_files'])
    for row in closure['closure_files']:
        require(str(Path(row.get('root',closure['root']))/row['path']), row['sha256'])
    for row in closure.get('authenticated_inputs', ()):
        require(str(Path(row.get('root','.'))/row['path']), row.get('sha256'))
    physical = closure.get('physical_elaboration', {})
    if physical.get('evidence'):
        require(physical['evidence'], physical.get('sha256'))
    for block in (closure.get('lint',{}), physical):
        if block.get('log'):
            require(block['log'])
        for argument in block.get('command', ()):
            if type(argument) is str and (repo/argument).is_file():
                require(argument)
    return paths


def source_inputs(repo: Path, cpu_output: Path, cache: Path):
    paths = {Path(__file__).resolve(), repo/'configs/soc/sources.lock.json',
             repo/'scripts/verify_soc_sources.py', repo/'scripts/build_boom_session.py',
             repo/'scripts/build_wishbone_dma.py'}
    from myfuzz.local_harness.boom_shared_memory import BoomSharedMemoryContract
    for name, expected in BoomSharedMemoryContract().identity_document()['source_hashes'].items():
        path = repo/name
        assert not path.is_symlink() and path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'direct BOOM input drift: '+name
        paths.add(path)
    paths.update(_selected_lock_inputs(repo,'zipcpu_wbdmac'))
    paths.update(p for p in (repo/'src/myfuzz').rglob('*') if p.is_file()
                 and p.suffix in {'.py', '.cpp', '.h', '.sv', '.v', '.json'})
    paths.update(p for root in (repo/'configs/cpus/boom', repo/'configs/peripherals/zipcpu_wbdmac')
                 for p in root.rglob('*') if p.is_file() and 'evidence' not in p.parts)
    for profile_path in (repo/'configs/cpus/boom/component_profile.json',
                         repo/'configs/peripherals/zipcpu_wbdmac/component_profile.json'):
        profile = json.loads(profile_path.read_text())
        source = profile['source']
        source_root = repo/source['root']
        paths.update(source_root/name for name in source.get('files', ()))
        if source.get('filelist'):
            from myfuzz.composition.component_profile import _source_locator
            from myfuzz.composition.source_crawler import _declared_files
            def record_read(path):
                paths.add(path)
                return path.read_bytes()
            _declared_files(source_root, _source_locator(source), record_read)
    for root in (repo/'configs/cpus/boom', repo/'configs/peripherals/zipcpu_wbdmac'):
        closure_path = root/'closure.json'
        if closure_path.is_file():
            closure = json.loads(closure_path.read_text())
            paths.update(repo/row.get('root', '.')/row['path'] for row in closure.get('closure_files', ()))
            paths.update(repo/row['path'] for row in closure.get('authenticated_inputs', ()))
    paths.update(p for p in cpu_output.rglob('*') if p.is_file())
    paths.update(p for p in cache.rglob('*') if p.is_file())
    paths.update(p for p in (repo/'docs/superpowers/specs').glob('*boom*') if p.is_file())
    paths.update(p for p in (repo/'docs/superpowers/plans').glob('*boom*') if p.is_file())
    paths.update((repo/'.superpowers/sdd'/name for name in
                  ('task-1-brief.md', 'task-2-brief.md', 'task-3-brief.md')
                  if (repo/'.superpowers/sdd'/name).is_file()))
    def archive_name(path):
        if path.is_relative_to(repo):
            return str(path.relative_to(repo))
        if path.is_relative_to(cpu_output):
            return 'prebuilt_cpu/' + str(path.relative_to(cpu_output))
        if path.is_relative_to(cache):
            return 'dma_cache/' + str(path.relative_to(cache))
        return 'declared_source/' + hashlib.sha256(str(path.parent).encode()).hexdigest()[:12] + '/' + path.name
    files = {archive_name(path): path.read_bytes()
             for path in sorted(paths) if path.is_file() and not path.is_symlink()}
    from myfuzz.scenario.boom_dma_example import MAIN, boom_dma_images
    files['executed-program/0x80000000.bin'] = boom_dma_images(start_key=0xfed)[MAIN]
    files['executed-program/0x80000000-stale.bin'] = boom_dma_images(start_key=0x3db)[MAIN]
    return files


def execute():
    repo = Path(__file__).resolve().parents[1]
    cache = Path(os.environ['MYFUZZ_BOOM_DMA_RAM_CACHE']).resolve()
    cpu_output = Path(os.environ['MYFUZZ_BOOM_DMA_RAM_CPU_OUTPUT']).resolve()
    evidence_root = Path(os.environ['MYFUZZ_BOOM_DMA_RAM_EVIDENCE']).resolve()
    if not cache.is_dir() or not cpu_output.is_dir():
        raise SystemExit('Existing DMA cache and prebuilt BOOM CPU output directories are required')
    output = evidence_root / ('attempt-' + uuid.uuid4().hex)
    output.mkdir(parents=True, exist_ok=False)
    verdict = dict(schema_version='boom_dma_verification.v1', status='running', matches=False,
        started_utc=datetime.now(timezone.utc).isoformat(), rounds_max=4000,
        normalization=('validated execution/stream owners and exact TransactionKey references only; '
            'raw commit digests validated, normalized commit digests recomputed; PIDs checked separately'), stages=[])
    inputs = {}
    try:
        inputs = source_inputs(repo, cpu_output, cache)
        frozen = {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()}
        with tarfile.open(output/'executed-inputs.tar.gz', 'w:gz') as archive:
            for name, data in inputs.items():
                member = tarfile.TarInfo(name); member.size = len(data); member.mode = 0o644
                archive.addfile(member, io.BytesIO(data))
        archive_sha256 = hashlib.sha256((output/'executed-inputs.tar.gz').read_bytes()).hexdigest()
        verdict['executed_input_archive_sha256'] = archive_sha256
        save(output/'input-freeze.json.gz', dict(files=frozen, archive_sha256=archive_sha256,
             boundary=('captured project, exact BOOM source-contract inputs including physical_ports, '
                 'selected central ZipCPU lock/closure dependencies, CPU output and existing DMA cache; '
                 'external runtime tool executable bytes are not archived'), toolbytes_not_pinned=True))
        save(output/'worker.json.gz', dict(pid=os.getpid(), started_utc=verdict['started_utc'],
             canonical_heavy_lock=True, toolbytes_not_pinned=True,
             executed_input_archive_sha256=archive_sha256, cpu_output=str(cpu_output), cache=str(cache)))
        _hole_refusal(repo, cache, cpu_output, output/'hole-refusal.json.gz')
        for label, key in (('positive', 0xfed), ('stale-key', 0x3db)):
            first = run(repo, cache, cpu_output, key, output/(label+'-first.json.gz'), frozen_inputs=frozen)
            assert_chain(first, key)
            fresh = run(repo, cache, cpu_output, key, output/(label+'-fresh.json.gz'),
                        first['actions'], frozen_inputs=frozen)
            assert_chain(fresh, key)
            assert first['actions'] == fresh['actions']
            assert first['identities'] == fresh['identities']
            assert len(set(first['pids'].values()) | set(fresh['pids'].values())) == 4
            assert len(set(first['executions'].values()) | set(fresh['executions'].values())
                       | {first['scenario_execution'], fresh['scenario_execution']}) == 6
            first_pids = {row['pid'] for row in first['process_instances']}
            fresh_pids = {row['pid'] for row in fresh['process_instances']}
            assert first_pids and fresh_pids and first_pids.isdisjoint(fresh_pids)
            first_stream, fresh_stream = _stream_owners(first), _stream_owners(fresh)
            assert first_stream is not None and fresh_stream is not None and first_stream != fresh_stream
            assert {first_stream,fresh_stream}.isdisjoint(
                set(first['executions'].values()) | set(fresh['executions'].values())
                | {first['scenario_execution'],fresh['scenario_execution']})
            assert _normalized(first) == _normalized(fresh)
            now = source_inputs(repo, cpu_output, cache)
            assert {name: hashlib.sha256(data).hexdigest() for name, data in now.items()} == frozen
            verdict['stages'].append(dict(label=label, status='passed',
                normalized_prefix_sha256=hashlib.sha256(_normalized(first).encode()).hexdigest()))
        verdict.update(status='passed', matches=True)
    except BaseException as error:
        verdict.update(status='failed', failure=repr(error))
        raise
    finally:
        save(output/'verification.json.gz', verdict)
    print(output)


def main():
    if not __debug__:
        raise SystemExit('Optimized Python disables evidence assertions; run without -O')
    if os.environ.get('MYFUZZ_BOOM_DMA_RAM_REAL') != '1':
        raise SystemExit('Set MYFUZZ_BOOM_DMA_RAM_REAL=1 to authorize native execution')
    required = ('MYFUZZ_BOOM_DMA_RAM_CACHE', 'MYFUZZ_BOOM_DMA_RAM_CPU_OUTPUT',
                'MYFUZZ_BOOM_DMA_RAM_EVIDENCE')
    if any(not os.environ.get(name) for name in required):
        raise SystemExit('Set explicit cache, prebuilt CPU output, and evidence paths')
    from myfuzz.local_harness.auto_harness_test import _heavy_worker_lock
    with _heavy_worker_lock(Path(__file__).resolve().parents[1]):
        execute()


if __name__ == '__main__':
    main()
