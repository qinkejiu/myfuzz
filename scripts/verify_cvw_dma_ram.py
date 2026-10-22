#!/usr/bin/env python3
"""Opt-in native CVW/DMA RAM evidence gate; independent full schedule replay.

Run with PYTHONPATH=src MYFUZZ_CVW_DMA_RAM_REAL=1. This advances independent
RTL processes sharing a host memory service, not a physical AHB/Wishbone SoC.
Only declared native/Runner execution UUIDs are normalized in comparisons.
"""
import copy
from dataclasses import asdict
import gzip
import hashlib
import json
import os
from pathlib import Path
import uuid


def save(path, document):
    path.write_bytes(gzip.compress(json.dumps(document, sort_keys=True,
        indent=2, default=lambda value: asdict(value)).encode(), mtime=0))


def normalized(value, executions, scenario):
    encoded = json.dumps(value, sort_keys=True)
    for name, nonce in executions.items():
        encoded = encoded.replace(nonce, 'native-execution:' + name)
    return json.loads(encoded.replace(scenario, 'scenario-execution'))


def run(cache, key, output, schedule=None):
    from myfuzz.scenario.cvw_dma_runner import make_cvw_dma_runner
    from myfuzz.scenario.cvw_dma_example import RESULT, SOURCE, DESTINATION
    runner = make_cvw_dma_runner(cache_dir=cache, start_key=key)
    cpu, dma = runner.sessions['cpu'], runner.sessions['dma']
    recorded, cpu_samples, cpu_outputs = [], [], []
    evidence = dict(start_key=key, schedule=recorded)
    processes = {}
    try:
        runner.begin_test('cvw-dma-ram')
        processes = {name: session.process for name, session in runner.sessions.items()}
        evidence['pids'] = {name: process.pid for name, process in processes.items()}
        evidence['executions'] = {name: session._execution for name, session in runner.sessions.items()}
        evidence['scenario_execution'] = runner.execution_id
        evidence['identities'] = {name: session.identity_document() for name, session in runner.sessions.items()}
        steps = schedule if schedule is not None else ['dma', 'cpu'] * 4000
        terminal = False
        for component in steps:
            observed = runner.step(component)
            recorded.append(component)
            if component == 'cpu':
                cpu_samples.extend(copy.deepcopy(cpu.last_samples))
                cpu_outputs.append(copy.deepcopy(observed))
            marker = any(event['kind'] == 'memory_write' and event['address'] == RESULT + 20
                         for event in cpu.service.events)
            terminal = marker and all(session.pending_responses == 0
                for session in runner.sessions.values()) and not cpu.router.pending_targets
            if schedule is None and terminal:
                break
        assert terminal, 'CPU result write and drained native responses absent within 4000 rounds'
    except BaseException as error:
        evidence['failure'] = repr(error)
        raise
    finally:
        capture_errors, cleanup_errors = [], []
        try:
            captures = dict(events=lambda: list(runner.events),
                cpu_samples=lambda: cpu_samples, cpu_outputs=lambda: cpu_outputs,
                dma_events=lambda: copy.deepcopy(dma.events),
                cpu_memory=lambda: copy.deepcopy(cpu.service.events),
                dma_memory=lambda: copy.deepcopy(dma.memory_service.events),
                deliveries=lambda: [{**row, 'source_transaction': asdict(row['source_transaction'])}
                                    for row in cpu.router.deliveries],
                local_ticks=lambda: dict(runner.local_ticks),
                pending=lambda: {name: session.pending_responses for name, session in runner.sessions.items()},
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
            evidence['process_returncodes'] = {name: process.returncode for name, process in processes.items()}
            evidence['cleanup_errors'] = cleanup_errors
            evidence['capture_errors'] = capture_errors
            evidence['status'] = 'failed' if ('failure' in evidence or capture_errors or cleanup_errors) else 'captured'
            try:
                save(output, evidence)
            except BaseException:
                if 'failure' not in evidence:
                    raise
            if (capture_errors or cleanup_errors) and 'failure' not in evidence:
                raise RuntimeError(str(capture_errors + cleanup_errors))
    return evidence


def assert_chain(run, key):
    from myfuzz.scenario.cvw_dma_example import SOURCE, DESTINATION, RESULT, DMA_BASE, WORDS
    from myfuzz.scenario.ledger import TransactionKey
    def cpu_key(key):
        expected = TransactionKey('local-execution', 'cvw-dma-ram', 'cpu', 0,
                                  'memory', key['source_sequence'])
        assert key == asdict(expected)
    assert run['pending'] == {'cpu': 0, 'dma': 0}
    assert not run['cleanup_errors'] and not run['capture_errors']
    assert set(run['process_returncodes']) == {'cpu', 'dma'}
    assert all(code == 0 for code in run['process_returncodes'].values())
    assert run['source'] == list(WORDS)
    writes = [row for row in run['deliveries'] if row['write']]
    assert [(row['offset'], row['write_value']) for row in writes] == [
        (8, SOURCE), (12, DESTINATION), (4, 4), (0, key << 16 | 4)]
    assert all(row['byte_enable'] == 15 and row['beat_bytes'] == 4 for row in run['deliveries'])
    requests = [sample['pre']['backend'] for sample in run['cpu_samples']
        if sample['pre']['backend']['m_req_valid'] and sample['pre']['backend']['m_req_ready']]
    mmio = [row for row in requests if DMA_BASE <= row['m_req_addr'] < DMA_BASE + 16]
    assert [(row['m_req_addr'] - DMA_BASE, bool(row['m_req_write']),
             row['m_req_wdata'] if row['m_req_write'] else None) for row in mmio] == [
        (row['offset'], row['write'], row['write_value']) for row in run['deliveries']]
    previous_control_tick = 0
    for delivery in run['deliveries']:
        cpu_key(delivery['source_transaction'])
        sequence = delivery['source_transaction']['source_sequence']
        assert delivery['source_transaction']['source_component'] == 'cpu'
        request = requests[sequence - 1]
        assert request['m_req_addr'] == DMA_BASE + delivery['offset']
        assert bool(request['m_req_write']) == delivery['write']
        control = delivery['dma_control_receipt']
        assert control['source_transaction'] == delivery['source_transaction']
        assert control['edge_ticks'] and control['edge_ticks'][0] > previous_control_tick
        assert control['edge_ticks'] == sorted(set(control['edge_ticks']))
        previous_control_tick = control['edge_ticks'][-1]
        edges = [edge for edge in run['dma_events'] if edge['tick'] in control['edge_ticks']]
        strobes = [edge['payload']['pre_backend'] for edge in edges
                   if edge['payload']['pre_backend']['swb_stb']]
        assert len(strobes) == 1
        strobe = strobes[0]
        assert strobe['swb_cyc'] == 1 and strobe['swb_adr'] == delivery['offset'] // 4
        assert strobe['swb_we'] == int(delivery['write'])
        assert strobe['swb_dat_w'] == control['value']
        if delivery['write']:
            assert control['value'] == delivery['write_value']
        acks = [edge['payload']['pre_backend'] for edge in edges
                if edge['payload']['pre_backend']['swb_ack']]
        assert len(acks) == 1 and acks[0]['swb_cyc'] == 1
        if not delivery['write']:
            assert acks[0]['swb_dat_r'] == delivery['read_value']
        if not delivery['write']:
            responses = [row for row in run['cpu_outputs'] if row['data_rsp_consumed']
                         and row['data_rsp_source_sequence'] == delivery['source_sequence']]
            assert len(responses) == 1 and responses[0]['data_rsp_rdata'] == delivery['read_value']
            assert responses[0]['data_rsp_source_epoch'] == delivery['source_transaction']['source_epoch']
    polls = [row for row in run['deliveries'] if not row['write']]
    assert polls and all(row['offset'] == 0 for row in polls)
    assert polls[-1]['read_value'] & 0xC0000000 == 0
    assert run['result'][0] == polls[-1]['read_value']
    source = [row for row in run['cpu_memory'] if row['kind'] == 'memory_write'
              and SOURCE <= row['address'] < SOURCE + 16]
    assert [(row['address'], row['value']) for row in source] == [(SOURCE + 4*i, value) for i, value in enumerate(WORDS)]
    for commit in source:
        cpu_key(commit['transaction'])
        request = requests[commit['transaction']['source_sequence'] - 1]
        assert request['m_req_addr'] == commit['address'] and request['m_req_write'] == 1
        matching = [row for row in requests if row['m_req_write']
                    and row['m_req_addr'] == commit['address']]
        assert len(matching) == 1
        assert matching[0]['m_req_wdata'] == commit['value'] and matching[0]['m_req_be'] == 15
    assert not any(row['kind'] == 'memory_write' and DESTINATION <= row['address'] < DESTINATION + 16
                   for row in run['cpu_memory'])
    accepted = [row['accepted'] for row in run['dma_events'] if 'accepted' in row]
    responses = [row for row in run['dma_events'] if 'response' in row]
    assert len(responses) == len(accepted)
    for accepted_beat, response_edge in zip(accepted, responses):
        response = response_edge['response']
        pre = response_edge['payload']['pre_backend']
        assert response['transaction'] == accepted_beat['transaction']
        assert response['error'] == 0 and pre['mwb_cyc'] == 1
        assert pre['mwb_ack'] == 1 and pre['mwb_err'] == 0
        assert pre['mwb_dat_r'] == response['rdata']
    dma_writes = [row for row in run['dma_memory'] if row['kind'] == 'memory_write']
    marker = [row for row in run['cpu_memory'] if row['kind'] == 'memory_write' and row['address'] == RESULT + 20]
    assert len(marker) == 1
    if key != 0xfed:
        assert accepted == [] and dma_writes == []
        assert run['destination'] == [0] * 4
        assert run['result'][1:5] == [0] * 4 and marker[0]['value'] == 0xffffffff
        assert run['result'][5] == 0xffffffff
        reads = [row for row in run['cpu_memory'] if row['kind'] == 'memory_read'
                 and DESTINATION <= row['address'] < DESTINATION + 16]
        assert len(reads) == 1 and reads[0]['address'] == DESTINATION and reads[0]['value'] == 0
        return
    assert [(row['address'], row['write']) for row in accepted] == [
        (SOURCE + i*4, False) for i in range(4)] + [(DESTINATION + i*4, True) for i in range(4)]
    assert [row['value'] for row in accepted if row['write']] == list(WORDS)
    assert run['destination'] == run['result'][1:5] == list(WORDS)
    assert marker[0]['value'] == run['result'][5] == 1
    reads = [row for row in run['dma_memory'] if row['kind'] == 'memory_read']
    assert len(reads) == len(dma_writes) == 4
    for index, (read, commit) in enumerate(zip(reads, source)):
        assert read['transaction'] == accepted[index]['transaction']
        assert read['value'] == WORDS[index]
        assert responses[index]['response']['rdata'] == read['value']
        assert len(read['versions']) == len(read['writer_event_ids']) == 4
        assert all(tuple(version) == tuple(commit['version']) for version in read['versions'])
        assert all(writer == str(TransactionKey(**commit['transaction'])) for writer in read['writer_event_ids'])
    for index, commit in enumerate(dma_writes):
        assert commit['transaction'] == accepted[index + 4]['transaction']
        observed = [row for row in run['cpu_memory'] if row['kind'] == 'memory_read'
                    and row['address'] == DESTINATION + index*4]
        assert len(observed) == 1 and observed[0]['value'] == WORDS[index]
        cpu_key(observed[0]['transaction'])
        assert len(observed[0]['versions']) == len(observed[0]['writer_event_ids']) == 4
        assert all(tuple(version) == tuple(commit['version']) for version in observed[0]['versions'])
        assert all(writer == str(TransactionKey(**commit['transaction'])) for writer in observed[0]['writer_event_ids'])
        responses = [row for row in run['cpu_outputs'] if row['data_rsp_consumed']
                     and row['data_rsp_source_sequence'] == observed[0]['transaction']['source_sequence']]
        assert len(responses) == 1 and responses[0]['data_rsp_rdata'] == WORDS[index]
        assert responses[0]['data_rsp_source_epoch'] == observed[0]['transaction']['source_epoch']
    source_reads = [row for row in run['cpu_memory'] if row['kind'] == 'memory_read'
                    and SOURCE <= row['address'] < SOURCE + 16]
    assert [(row['address'], row['value']) for row in source_reads] == [
        (SOURCE + 4*i, value) for i, value in enumerate(WORDS)]
    for read, commit in zip(source_reads, source):
        cpu_key(read['transaction'])
        assert len(read['versions']) == len(read['writer_event_ids']) == 4
        assert all(tuple(version) == tuple(commit['version']) for version in read['versions'])
        assert all(writer == str(TransactionKey(**commit['transaction'])) for writer in read['writer_event_ids'])
        request = requests[read['transaction']['source_sequence'] - 1]
        assert request['m_req_addr'] == read['address'] and request['m_req_write'] == 0
        responses = [row for row in run['cpu_outputs'] if row['data_rsp_consumed']
                     and row['data_rsp_source_sequence'] == read['transaction']['source_sequence']]
        assert len(responses) == 1 and responses[0]['data_rsp_rdata'] == read['value']
        assert responses[0]['data_rsp_source_epoch'] == read['transaction']['source_epoch']
    ticks = {row['local_tick'] for row in run['events']
             if row.get('kind') == 'local_tick_sample' and row['component'] == 'dma'}
    assert ticks == set(range(1, run['local_ticks']['dma'] + 1))


def source_hashes():
    repo = Path(__file__).resolve().parents[1]
    files = {Path(__file__).resolve()}
    for profile in ('configs/cpus/cvw/component_profile.json',
                    'configs/peripherals/zipcpu_wbdmac/component_profile.json'):
        path = repo / profile
        document = json.loads(path.read_text())
        source_root = repo / document['source']['root']
        files.update(source_root / name for name in document['source']['files'])
        files.update(item for item in path.parent.rglob('*') if item.is_file() and 'evidence' not in item.parts)
    files.update(item for item in (repo / 'src/myfuzz').rglob('*')
                 if item.is_file() and item.suffix in {'.py', '.sv', '.v', '.h', '.cpp', '.json'})
    return dict(files={str(path.relative_to(repo)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(files)}, boundary='declared file hashes, not whole elaborated source closure',
            toolbytes_not_pinned=True)


def main():
    if not __debug__:
        raise SystemExit('Optimized Python disables gate assertions; run without -O')
    if os.environ.get('MYFUZZ_CVW_DMA_RAM_REAL') != '1':
        raise SystemExit('Set MYFUZZ_CVW_DMA_RAM_REAL=1 to authorize native execution')
    from myfuzz.local_harness.auto_harness_test import _heavy_worker_lock
    with _heavy_worker_lock(Path(__file__).resolve().parents[1]):
        execute()


def execute():
    root = Path(os.environ.get('MYFUZZ_CVW_DMA_RAM_EVIDENCE', 'runs/cvw-dma-ram'))
    output = root / ('attempt-' + uuid.uuid4().hex)
    output.mkdir(parents=True, exist_ok=False)
    cache = Path(os.environ.get('MYFUZZ_CVW_DMA_RAM_CACHE', '/tmp/myfuzz-cvw-dma-ram-cache'))
    verdict = dict(status='running', matches=False, stages=[],
        scope='full_recorded_schedule',
        normalization='only declared native and Runner UUIDs; PIDs retained separately',
        composition='independent RTL with shared host memory service')
    try:
        frozen = source_hashes()
        save(output / 'input-freeze.json.gz', frozen)
        for label, key in (('positive', 0xfed), ('wrong-key', 0x3db)):
            first = run(cache, key, output / (label + '-first.json.gz'))
            fresh = run(cache, key, output / (label + '-fresh.json.gz'), first['schedule'])
            assert_chain(first, key)
            assert_chain(fresh, key)
            assert first['identities'] == fresh['identities']
            assert all(first['executions'][name] != fresh['executions'][name] for name in first['executions'])
            assert all(first['pids'][name] != fresh['pids'][name] for name in first['pids'])
            def comparable(document):
                return {key: value for key, value in document.items()
                    if key not in {'pids', 'executions', 'scenario_execution', 'identities'}}
            assert normalized(comparable(first), first['executions'], first['scenario_execution']) == normalized(
                comparable(fresh), fresh['executions'], fresh['scenario_execution'])
            assert source_hashes() == frozen, 'source inputs changed during execution'
            verdict['stages'].append(dict(label=label, status='passed'))
        verdict.update(status='passed', matches=True)
    except BaseException as error:
        verdict.update(status='failed', failure=repr(error))
        raise
    finally:
        save(output / 'verification.json.gz', verdict)
    print(output)


if __name__ == '__main__':
    main()
