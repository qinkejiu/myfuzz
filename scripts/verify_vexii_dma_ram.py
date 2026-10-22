#!/usr/bin/env python3
"""Opt-in Vexii CPU-programmed DMA RAM gate, with complete action replay."""
import copy
from dataclasses import asdict
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import uuid


def save(path, value):
    path.write_bytes(gzip.compress(json.dumps(value, sort_keys=True, indent=2,
        default=asdict).encode(), mtime=0))


def transaction_id(key):
    return tuple(key[name] for name in ('execution_id', 'testcase_id',
        'source_component', 'source_epoch', 'channel_id', 'source_sequence'))


def run(cache, key, output, actions=None):
    from myfuzz.scenario.vexii_dma_runner import make_vexii_dma_runner
    from myfuzz.scenario.vexii_dma_example import SOURCE, DESTINATION, RESULT
    runner = make_vexii_dma_runner(cache_dir=cache, start_key=key)
    cpu, dma = runner.sessions['cpu'], runner.sessions['dma']
    evidence = dict(start_key=key, actions=[], cpu_samples=[], cpu_outputs=[])
    processes = {}
    try:
        runner.begin_test('vexii-dma-ram')
        processes = {name: session.process for name, session in runner.sessions.items()}
        evidence.update(pids={name: process.pid for name, process in processes.items()},
            executions={name: session._execution for name, session in runner.sessions.items()},
            scenario_execution=runner.execution_id,
            identities={name: session.identity_document() for name, session in runner.sessions.items()})
        quiesced = False
        def terminal():
            marker = any(row['kind'] == 'memory_write' and row['address'] == RESULT+20
                         for row in cpu.service.events)
            return marker and all(session.pending_responses == 0
                for session in runner.sessions.values()) and not cpu.router.pending_targets
        def apply(action):
            nonlocal quiesced
            evidence['actions'].append(copy.deepcopy(action))
            if action == {'operation': 'begin_quiesce', 'component': 'cpu'}:
                assert not quiesced
                assert any(row['kind'] == 'memory_write' and row['address'] == RESULT+20
                           for row in cpu.service.events)
                cpu.begin_quiesce()
                quiesced = True
            else:
                assert action['operation'] == 'step' and action['component'] in ('dma', 'cpu')
                observed = runner.step(action['component'])
                if action['component'] == 'cpu':
                    evidence['cpu_samples'].extend(copy.deepcopy(cpu.last_samples))
                    evidence['cpu_outputs'].append(copy.deepcopy(observed))
        if actions is None:
            for _ in range(4000):
                for component in ('dma', 'cpu'):
                    apply(dict(operation='step', component=component))
                    marker = any(row['kind'] == 'memory_write' and row['address'] == RESULT+20
                                 for row in cpu.service.events)
                    if marker and not quiesced and not terminal():
                        apply(dict(operation='begin_quiesce', component='cpu'))
                if terminal():
                    break
        else:
            assert sum(row['operation'] == 'step' for row in actions) <= 8000
            for action in actions:
                apply(action)
        assert terminal(), 'marker and drained native/Router responses absent within 4000 rounds'
    except BaseException as error:
        evidence['failure'] = repr(error)
        raise
    finally:
        capture_errors, cleanup_errors = [], []
        try:
            captures = dict(events=lambda: list(runner.events),
                dma_events=lambda: copy.deepcopy(dma.events),
                cpu_memory=lambda: copy.deepcopy(cpu.service.events),
                dma_memory=lambda: copy.deepcopy(dma.memory_service.events),
                deliveries=lambda: [{**row, 'source_transaction': asdict(row['source_transaction'])}
                                    for row in cpu.router.deliveries],
                local_ticks=lambda: dict(runner.local_ticks),
                pending=lambda: {name: session.pending_responses for name, session in runner.sessions.items()},
                router_pending=lambda: cpu.router.pending_targets,
                result=lambda: [cpu.memory.read(RESULT+4*i, 4, transaction_id='gate-result').value for i in range(6)],
                source=lambda: [cpu.memory.read(SOURCE+4*i, 4, transaction_id='gate-source').value for i in range(4)],
                destination=lambda: [cpu.memory.read(DESTINATION+4*i, 4, transaction_id='gate-destination').value for i in range(4)])
            for name, capture in captures.items():
                try:
                    evidence[name] = capture()
                except BaseException as error:
                    capture_errors.append(dict(field=name, error=repr(error)))
        finally:
            for name, session in runner.sessions.items():
                try:
                    session.end_case()
                except BaseException as error:
                    cleanup_errors.append(dict(component=name, error=repr(error)))
            evidence.update(process_returncodes={name: process.returncode for name, process in processes.items()},
                cleanup_errors=cleanup_errors, capture_errors=capture_errors,
                status='failed' if ('failure' in evidence or capture_errors or cleanup_errors) else 'captured')
            try:
                save(output, evidence)
            except BaseException:
                if 'failure' not in evidence:
                    raise
            if (capture_errors or cleanup_errors) and 'failure' not in evidence:
                raise RuntimeError(str(capture_errors + cleanup_errors))
    return evidence


def axi_operations(document):
    """Reconstruct split AW/W and AR/R from measured PRE edges, never names."""
    effects = {}
    for row in document['cpu_memory']:
        if row['kind'] in ('memory_read', 'memory_write'):
            ident = transaction_id(row['transaction'])
            assert ident not in effects
            effects[ident] = dict(address=row['address'], write=row['kind'] == 'memory_write',
                value=row['value'], byte_enable=row.get('byte_enable', 15))
    for row in document['deliveries']:
        ident = transaction_id(row['source_transaction'])
        assert ident not in effects
        effects[ident] = dict(address=row['address'], write=row['write'],
            value=row['write_value'] if row['write'] else row['read_value'], byte_enable=row['byte_enable'])
    states = {p: dict(read=None, aw=None, w=None, b=None, sequence=0) for p in ('i', 'd')}
    operations, completed = {}, set()
    def enroll(prefix, state, address, write, value=None, be=15):
        state['sequence'] += 1
        ident = (document['executions']['cpu'], 'vexii-dma-ram', 'cpu', 0,
                 'instr' if prefix == 'i' else 'data', state['sequence'])
        assert ident not in operations and ident in effects
        effect = effects[ident]
        assert effect['address'] == address and effect['write'] == write
        if write:
            assert effect['value'] == value and effect['byte_enable'] == be
        operations[ident] = {**effect, 'accepted_tick': tick}
        return ident
    for sample in document['cpu_samples']:
        tick = sample['local_tick']
        assert type(tick) is int and tick > 0
        pre = sample['pre']['backend']
        for prefix, state in states.items():
            def field(role): return pre[prefix+'_'+role]
            def handshake(channel): return field(channel+'valid') == field(channel+'ready') == 1
            if handshake('r'):
                pending = state['read']
                assert pending is not None
                ident, bus_id = pending
                assert field('rid') == bus_id and field('rresp') == 0 and field('rlast') == 1
                assert field('rdata') == operations[ident]['value'] and ident not in completed
                assert tick > operations[ident]['accepted_tick']
                operations[ident]['completed_tick'] = tick
                completed.add(ident)
                state['read'] = None
            if prefix == 'd' and handshake('b'):
                pending = state['b']
                assert pending is not None
                ident, bus_id = pending
                assert field('bid') == bus_id and field('bresp') == 0 and ident not in completed
                assert tick > operations[ident]['accepted_tick']
                operations[ident]['completed_tick'] = tick
                completed.add(ident)
                state['b'] = None
            # Session sequence assignment order is AR then joined AW/W.
            if handshake('ar'):
                assert state['read'] is None and field('arsize') == 2 and field('araddr') % 4 == 0
                ident = enroll(prefix, state, field('araddr'), False)
                state['read'] = (ident, field('arid'))
            if prefix == 'd':
                if handshake('aw'):
                    assert state['aw'] is None and state['b'] is None
                    assert field('awsize') == 2 and field('awaddr') % 4 == 0
                    state['aw'] = (field('awaddr'), field('awid'))
                if handshake('w'):
                    assert state['w'] is None and state['b'] is None and field('wlast') == 1
                    assert field('wstrb') == 15
                    state['w'] = field('wdata')
                if state['aw'] is not None and state['w'] is not None:
                    address, bus_id = state['aw']
                    ident = enroll(prefix, state, address, True, state['w'])
                    state['b'] = (ident, bus_id)
                    state['aw'] = state['w'] = None
    assert set(effects) == set(operations) == completed
    assert all(state[name] is None for state in states.values() for name in ('read', 'aw', 'w', 'b'))
    return operations


def assert_cpu_result_chain(document, operations, key):
    """Bind firmware result stores to completed native CPU read responses."""
    from myfuzz.scenario.vexii_dma_example import SOURCE, DESTINATION, RESULT, WORDS
    from myfuzz.scenario.ledger import TransactionKey
    def records(address, write):
        kind = 'memory_write' if write else 'memory_read'
        return [row for row in document['cpu_memory'] if row['kind'] == kind and row['address'] == address]
    def actual(address, write):
        rows = records(address, write)
        assert len(rows) == 1
        row = rows[0]
        operation = operations[transaction_id(row['transaction'])]
        assert operation['address'] == address and operation['write'] == write
        assert operation['value'] == row['value']
        return row, operation
    polls = [row for row in document['deliveries'] if not row['write']]
    assert polls
    poll_operation = operations[transaction_id(polls[-1]['source_transaction'])]
    status, status_operation = actual(RESULT, True)
    assert status['value'] == polls[-1]['read_value'] == document['result'][0]
    assert status_operation['accepted_tick'] > poll_operation['completed_tick']
    marker, marker_operation = actual(RESULT+20, True)
    assert marker['value'] == document['result'][5] == (1 if key == 0xfed else 0xffffffff)
    prerequisites = [status_operation['completed_tick']]
    count = 4 if key == 0xfed else 1
    for index in range(count):
        destination, destination_operation = actual(DESTINATION+4*index, False)
        source, source_operation = actual(SOURCE+4*index, False)
        source_write, _ = actual(SOURCE+4*index, True)
        assert source['value'] == WORDS[index]
        assert len(source['versions']) == len(source['writer_event_ids']) == 4
        assert tuple(source['writer_event_ids']) == (str(TransactionKey(**source_write['transaction'])),)*4
        assert all(tuple(version) == tuple(source_write['version']) for version in source['versions'])
        data, data_operation = actual(RESULT+4+4*index, True)
        assert data['value'] == destination['value'] == document['result'][index+1]
        assert data_operation['accepted_tick'] > destination_operation['completed_tick']
        prerequisites.extend((destination_operation['completed_tick'],
                              source_operation['completed_tick'], data_operation['completed_tick']))
    assert marker_operation['accepted_tick'] > max(prerequisites)
    if key != 0xfed:
        assert destination['value'] != source['value']
        assert not any(records(RESULT+4+4*index, True) for index in range(1, 4))


def assert_queued_deliveries(document):
    """Require each accepted CPU MMIO beat to run on its scheduled DMA step."""
    events = document['events']
    ids = [row['event_id'] for row in events]
    assert ids == sorted(set(ids))
    steps = [row for row in events if 'kind' not in row and
             {'component', 'local_tick', 'inputs', 'outputs'} <= set(row)]
    actions = [row for row in document['actions'] if row['operation'] == 'step']
    assert [row['component'] for row in steps] == [row['component'] for row in actions]
    acceptances = [row for row in events if row.get('kind') == 'mmio_acceptance']
    deliveries = [row for row in events if row.get('kind') == 'mmio_delivery']
    assert len(acceptances) == len(deliveries) == len(document['deliveries'])
    assert len({transaction_id(row['source_transaction']) for row in acceptances}) == len(acceptances)
    assert len({transaction_id(row['source_transaction']) for row in deliveries}) == len(deliveries)
    envelope = {'kind', 'event_id', 'producer_event_id', 'component'}
    assert [{k:v for k,v in row.items() if k not in envelope} for row in deliveries] == document['deliveries']
    queue, seen_acceptances, seen_deliveries = [], [], []
    for index, step in enumerate(steps):
        end = steps[index+1]['event_id'] if index+1 < len(steps) else ids[-1]+1
        emitted = [row for row in events if step['event_id'] < row['event_id'] < end]
        accepted = [row for row in emitted if row.get('kind') == 'mmio_acceptance']
        delivered = [row for row in emitted if row.get('kind') == 'mmio_delivery']
        assert all(row['producer_event_id'] == step['event_id'] and row['component'] == 'cpu'
                   for row in accepted+delivered)
        if step['component'] == 'cpu':
            assert not delivered
            queue.extend(accepted)
        else:
            assert step['component'] == 'dma' and not accepted
            assert len(delivered) == int(bool(queue))
            if delivered:
                acceptance, delivery = queue.pop(0), delivered[0]
                assert acceptance['event_id'] < step['event_id'] < delivery['event_id']
                assert delivery['source_transaction'] == acceptance['source_transaction']
                for name in ('device_id', 'source_sequence', 'address', 'offset',
                             'beat_bytes', 'write', 'byte_enable', 'write_value'):
                    assert delivery[name] == acceptance[name]
                assert delivery['device_id'] == 'dma'
                ticks = delivery['dma_control_receipt']['edge_ticks']
                assert ticks == list(range(step['local_tick']+1, step['local_tick']+1+len(ticks)))
                samples = [row for row in emitted if row.get('kind') == 'local_tick_sample'
                           and row['component'] == 'dma' and row['local_tick'] in ticks]
                assert {(row['local_tick'], row['phase']) for row in samples} == {
                    (tick, phase) for tick in ticks for phase in ('pre', 'post')}
                assert len(samples) == 2*len(ticks)
                assert all(row['producer_event_id'] == step['event_id'] for row in samples)
        seen_acceptances.extend(accepted)
        seen_deliveries.extend(delivered)
    assert not queue and seen_acceptances == acceptances and seen_deliveries == deliveries


def assert_chain(document, key):
    from myfuzz.scenario.vexii_dma_example import SOURCE, DESTINATION, RESULT, DMA_BASE, WORDS
    from myfuzz.scenario.ledger import TransactionKey
    assert document['pending'] == {'cpu': 0, 'dma': 0} and not document['router_pending']
    assert document['process_returncodes'] == {'cpu': 0, 'dma': 0}
    assert not document['cleanup_errors'] and not document['capture_errors']
    operations = axi_operations(document)
    assert_cpu_result_chain(document, operations, key)
    assert_queued_deliveries(document)
    assert document['source'] == list(WORDS)
    steps = [row['component'] for row in document['actions'] if row['operation'] == 'step']
    assert steps == ['dma', 'cpu'] * (len(steps)//2) and len(steps) <= 8000
    assert len([row for row in document['actions'] if row['operation'] == 'begin_quiesce']) <= 1
    writes = [row for row in document['deliveries'] if row['write']]
    assert [(row['offset'], row['write_value']) for row in writes] == [
        (8, SOURCE), (12, DESTINATION), (4, 4), (0, key << 16 | 4)]
    previous = 0
    for delivery in document['deliveries']:
        control = delivery['dma_control_receipt']
        assert transaction_id(delivery['source_transaction']) in operations
        assert control['source_transaction'] == delivery['source_transaction']
        assert delivery['byte_enable'] == 15 and delivery['beat_bytes'] == 4
        assert control['edge_ticks'] == sorted(set(control['edge_ticks'])) and control['edge_ticks'][0] > previous
        previous = control['edge_ticks'][-1]
        edges = [row for row in document['dma_events'] if row['tick'] in control['edge_ticks']]
        strobes = [row['payload']['pre_backend'] for row in edges if row['payload']['pre_backend']['swb_stb']]
        acks = [row['payload']['pre_backend'] for row in edges if row['payload']['pre_backend']['swb_ack']]
        assert len(strobes) == len(acks) == 1 and strobes[0]['swb_cyc'] == acks[0]['swb_cyc'] == 1
        assert strobes[0]['swb_adr'] == delivery['offset']//4 and strobes[0]['swb_we'] == int(delivery['write'])
        assert strobes[0]['swb_dat_w'] == control['value']
        if delivery['write']:
            assert control['value'] == delivery['write_value']
        else:
            assert acks[0]['swb_dat_r'] == delivery['read_value']
    polls = [row for row in document['deliveries'] if not row['write']]
    assert polls and all(row['offset'] == 0 for row in polls)
    assert polls[-1]['read_value'] & 0xc0000000 == 0 and document['result'][0] == polls[-1]['read_value']
    source = [row for row in document['cpu_memory'] if row['kind'] == 'memory_write' and SOURCE <= row['address'] < SOURCE+16]
    assert [(row['address'],row['value']) for row in source] == [(SOURCE+4*i,v) for i,v in enumerate(WORDS)]
    assert not any(row['kind'] == 'memory_write' and DESTINATION <= row['address'] < DESTINATION+16 for row in document['cpu_memory'])
    accepted = [row for row in document['dma_events'] if 'accepted' in row]
    responses = [row for row in document['dma_events'] if 'response' in row]
    measured_accepts = [row for row in document['dma_events'] if
        row['payload']['pre_backend']['mwb_cyc'] and row['payload']['pre_backend']['mwb_stb']
        and not row['payload']['pre_backend']['mwb_stall']]
    assert measured_accepts == accepted
    assert len(accepted) == len(responses)
    for request, response in zip(accepted, responses):
        request_pre, beat = request['payload']['pre_backend'], request['accepted']
        assert beat['address'] == request_pre['mwb_adr'] << 2
        assert beat['write'] == bool(request_pre['mwb_we']) and beat['byte_enable'] == 15
        assert beat['value'] == request_pre['mwb_dat_w']
        pre, result = response['payload']['pre_backend'], response['response']
        assert request['tick'] < response['tick'] and result['transaction'] == request['accepted']['transaction']
        assert pre['mwb_cyc'] == pre['mwb_ack'] == 1 and pre['mwb_err'] == result['error'] == 0
        assert pre['mwb_dat_r'] == result['rdata']
    marker = [row for row in document['cpu_memory'] if row['kind'] == 'memory_write' and row['address'] == RESULT+20]
    assert len(marker) == 1
    ticks = {row['local_tick'] for row in document['events'] if row.get('kind') == 'local_tick_sample' and row['component'] == 'dma'}
    assert ticks == set(range(1,document['local_ticks']['dma']+1))
    if key != 0xfed:
        assert not accepted and not responses and not document['dma_memory']
        assert document['destination'] == [0]*4 and document['result'][1:] == [0,0,0,0,0xffffffff]
        reads = [row for row in document['cpu_memory'] if row['kind'] == 'memory_read' and DESTINATION <= row['address'] < DESTINATION+16]
        assert len(reads) == 1 and reads[0]['address'] == DESTINATION and reads[0]['value'] == 0
        return
    assert [(row['accepted']['address'],row['accepted']['write']) for row in accepted] == [
        (SOURCE+4*i,False) for i in range(4)]+[(DESTINATION+4*i,True) for i in range(4)]
    assert document['destination'] == document['result'][1:5] == list(WORDS)
    assert document['result'][5] == marker[0]['value'] == 1
    dma_reads = [row for row in document['dma_memory'] if row['kind'] == 'memory_read']
    dma_writes = [row for row in document['dma_memory'] if row['kind'] == 'memory_write']
    assert len(dma_reads) == len(dma_writes) == 4
    def provenance(read, write):
        assert read['value'] == write['value'] and len(read['versions']) == len(read['writer_event_ids']) == 4
        assert all(tuple(v) == tuple(write['version']) for v in read['versions'])
        assert tuple(read['writer_event_ids']) == (str(TransactionKey(**write['transaction'])),)*4
    for index, (read, write) in enumerate(zip(dma_reads, source)):
        assert read['address'] == SOURCE+4*index and read['transaction'] == accepted[index]['accepted']['transaction']
        assert responses[index]['response']['rdata'] == read['value'] == WORDS[index]
        provenance(read,write)
    for index, write in enumerate(dma_writes):
        assert write['address'] == DESTINATION+4*index and write['transaction'] == accepted[index+4]['accepted']['transaction']
        assert write['value'] == accepted[index+4]['accepted']['value'] == WORDS[index]
        reads = [row for row in document['cpu_memory'] if row['kind'] == 'memory_read' and row['address'] == write['address']]
        assert len(reads) == 1
        provenance(reads[0],write)
    source_reads = [row for row in document['cpu_memory'] if row['kind'] == 'memory_read' and SOURCE <= row['address'] < SOURCE+16]
    assert [(row['address'],row['value']) for row in source_reads] == [(SOURCE+4*i,v) for i,v in enumerate(WORDS)]
    for read,write in zip(source_reads,source): provenance(read,write)


def source_inputs():
    repo = Path(__file__).resolve().parents[1]
    lock_path = repo/'configs/soc/sources.lock.json'
    files = {Path(__file__).resolve(), lock_path, repo/'scripts/verify_soc_sources.py'}
    lock = json.loads(lock_path.read_text())
    def include_closure(path):
        files.add(path)
        closure = json.loads(path.read_text())
        for row in closure.get('closure_files', ()):
            files.add(repo/row.get('root', '.')/row['path'])
        for row in closure.get('authenticated_inputs', ()):
            files.add(repo/row['path'])
    for profile in ('configs/cpus/vexiiriscv/component_profile.json', 'configs/peripherals/zipcpu_wbdmac/component_profile.json'):
        path = repo/profile
        document = json.loads(path.read_text())
        files.update(repo/document['source']['root']/name for name in document['source']['files'])
        files.update(item for item in path.parent.rglob('*') if item.is_file() and 'evidence' not in item.parts)
        for record in lock['components']:
            if record['id'] == document['component_id'] and record.get('elaboration', {}).get('evidence'):
                include_closure(repo/record['elaboration']['evidence'])
        # Generated-profile source contracts authenticate this profile-local
        # closure independently of the central source-lock component list.
        if (path.parent/'closure.json').is_file():
            include_closure(path.parent/'closure.json')
    files.update(item for item in (repo/'src/myfuzz').rglob('*') if item.is_file() and item.suffix in {'.py','.sv','.v','.h','.cpp','.json'})
    return {str(path.relative_to(repo)): path.read_bytes() for path in sorted(files)}


def normalize(document):
    values = {key:value for key,value in document.items() if key not in {'identities','pids','executions','scenario_execution'}}
    encoded = json.dumps(values,sort_keys=True)
    for role,ident in document['executions'].items(): encoded = encoded.replace(ident,'native-execution:'+role)
    return encoded.replace(document['scenario_execution'],'scenario-execution')


def execute():
    output = Path(os.environ.get('MYFUZZ_VEXII_DMA_RAM_EVIDENCE','runs/vexii-dma-ram'))/('attempt-'+uuid.uuid4().hex)
    output.mkdir(parents=True,exist_ok=False)
    cache = Path(os.environ.get('MYFUZZ_VEXII_DMA_RAM_CACHE','/tmp/myfuzz-vexii-dma-ram-cache'))
    verdict = dict(status='running',matches=False,stages=[],scope='complete_recorded_actions_and_prefix',
        normalization='declared native/Runner execution UUIDs only; PIDs separate; identities compare exactly',
        composition='independent RTL sharing host memory service')
    try:
        inputs = source_inputs()
        frozen = {name:hashlib.sha256(data).hexdigest() for name,data in inputs.items()}
        save(output/'input-freeze.json.gz',dict(files=frozen,boundary='declared inputs, not whole elaborated closure',toolbytes_not_pinned=True))
        with tarfile.open(output/'executed-inputs.tar.gz','w:gz') as archive:
            for name,data in inputs.items():
                member = tarfile.TarInfo(name); member.size = len(data); member.mode = 0o644
                archive.addfile(member,io.BytesIO(data))
        save(output/'worker.json.gz',dict(pid=os.getpid(),started_utc=datetime.now(timezone.utc).isoformat(),
            script_sha256=frozen[str(Path(__file__).resolve().relative_to(Path(__file__).resolve().parents[1]))],
            canonical_heavy_lock=True,toolbytes_not_pinned=True))
        for label,key in (('positive',0xfed),('wrong-key',0x3db)):
            first = run(cache,key,output/(label+'-first.json.gz'))
            fresh = run(cache,key,output/(label+'-fresh.json.gz'),first['actions'])
            assert_chain(first,key); assert_chain(fresh,key)
            assert first['identities'] == fresh['identities']
            assert len(set([*first['pids'].values(),*fresh['pids'].values()])) == 4
            assert len(set([*first['executions'].values(),*fresh['executions'].values(),first['scenario_execution'],fresh['scenario_execution']])) == 6
            assert normalize(first) == normalize(fresh)
            assert {name:hashlib.sha256(data).hexdigest() for name,data in source_inputs().items()} == frozen
            verdict['stages'].append(dict(label=label,status='passed',fullprefix_sha256=hashlib.sha256(normalize(first).encode()).hexdigest()))
        verdict.update(status='passed',matches=True)
    except BaseException as error:
        verdict.update(status='failed',failure=repr(error))
        raise
    finally:
        save(output/'verification.json.gz',verdict)
    print(output)


def main():
    if not __debug__: raise SystemExit('Optimized Python disables assertions; run without -O')
    if os.environ.get('MYFUZZ_VEXII_DMA_RAM_REAL') != '1':
        raise SystemExit('Set MYFUZZ_VEXII_DMA_RAM_REAL=1 to authorize native execution')
    from myfuzz.local_harness.auto_harness_test import _heavy_worker_lock
    with _heavy_worker_lock(Path(__file__).resolve().parents[1]): execute()


if __name__ == '__main__': main()
