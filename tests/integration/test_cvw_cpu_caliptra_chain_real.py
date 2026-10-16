"""Explicit real CPU→SHA256→RAM acceptance; static boot, fresh native processes."""
import copy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path

import pytest

from myfuzz.scenario.cvw_caliptra_example import BASE, RESULT, make_cvw_caliptra_chain
from myfuzz.scenario.contracts import ProtocolEnvironmentError

pytestmark = pytest.mark.skipif(os.environ.get('MYFUZZ_SCENARIO_REAL') != '1',
                               reason='explicit real CVW/Caliptra RTL gate')


def _run(cache, *, base=BASE, limit=20000):
    cpu, sha, router, memory = make_cvw_caliptra_chain(cache_dir=cache, sha_base=base)
    cpu.prepare_local()
    sha.prepare_local()
    records, target_samples, outputs = [], [], []
    try:
        sha.begin_case('cvw-sha-directed')
        cpu.begin_case('cvw-sha-directed')
        executions = [cpu._execution, sha._execution]
        for _ in range(limit):
            output = cpu.step_local({})
            records.extend(copy.deepcopy(cpu.last_samples))
            if output['data_req_accepted'] or output['data_rsp_consumed']:
                outputs.append(copy.deepcopy(output))
            target_samples.extend(sha.drain_tick_samples())
            if any(e.get('kind') == 'memory_write' and e['address'] == RESULT+64
                   for e in cpu.service.events) and cpu.pending_responses == 0:
                break
        words = [memory.read(RESULT+i*4, 4, transaction_id=f'check-{i}').value for i in range(17)]
        ticks = sha.local_ticks
        for offset, be in ((0x80, 1), (0x81, 15)):
            with pytest.raises(ValueError):
                sha._access(True, offset, 1, be)
        assert sha.local_ticks == ticks
        return dict(result=words, cpu_samples=records, sha_samples=target_samples,
            outputs=outputs, executions=executions, pending_responses=cpu.pending_responses,
            deliveries=[{**row, 'source_transaction': asdict(row['source_transaction'])}
                        for row in router.deliveries], ram_events=copy.deepcopy(cpu.service.events),
            cpu_identity=cpu.identity_document(), sha_identity=sha.identity_document(),
            artifact_hashes=[cpu.artifact.runtime_document['artifact_digest'],
                             sha.artifact.runtime_document['artifact_digest']],
            trace=sha.artifact.runtime_document['base_protocol_trace'])
    finally:
        cpu.end_case()
        sha.end_case()


def _assert_chain(run):
    assert run['result'][16] == 1
    assert run['pending_responses'] == 0
    for i, payload in enumerate((b'abc', b'abd')):
        digest = b''.join(w.to_bytes(4, 'big') for w in run['result'][i*8:i*8+8])
        assert digest == hashlib.sha256(payload).digest()
    assert run['result'][:8] != run['result'][8:16]
    deliveries = run['deliveries']
    assert sum(d['write'] for d in deliveries) == 34
    assert all(d['beat_bytes'] == 4 and d['byte_enable'] == 15 for d in deliveries)
    assert len({d['source_sequence'] for d in deliveries}) == len(deliveries)
    assert [d['offset'] for d in deliveries if not d['write'] and d['offset'] >= 0x100] == list(range(0x100,0x120,4))*2
    starts = [i for i,d in enumerate(deliveries) if d['write'] and d['offset'] == 0x10]
    assert len(starts) == 2
    for number, payload in enumerate((b'abc', b'abd')):
        start = starts[number]
        block = [int.from_bytes(payload+b'\x80','big')]+[0]*14+[24]
        assert [(d['offset'],d['write_value']) for d in deliveries[start-16:start]] == [
            (0x80+4*i,value) for i,value in enumerate(block)]
        assert deliveries[start]['write_value'] == 5
        polls = deliveries[start+1:next(i for i in range(start+1,len(deliveries))
                                      if deliveries[i]['offset'] == 0x100)]
        assert polls and all(not d['write'] and d['offset'] == 0x18 for d in polls)
        assert polls[-1]['read_value'] & 2
    pins = run['trace']['signals']
    samples = run['sha_samples']
    physical = []
    for index, sample in enumerate(samples):
        pre = {role: sample['pre']['backend'][name] for role,name in pins.items()}
        if pre['hsel'] and pre['hreadyin'] and pre['htrans'] & 2:
            assert pre['hsize'] == 2
            following = {role: samples[index+1]['pre']['backend'][name] for role,name in pins.items()}
            assert following['hreadyout'] == 1 and following['hresp'] == 0
            assert following['htrans'] == 0
            physical.append((pre['haddr'], bool(pre['hwrite']),
                             following['hwdata'] if pre['hwrite'] else following['hrdata']))
    assert physical == [(d['offset'], d['write'], d['write_value'] if d['write'] else d['read_value']) for d in deliveries]
    requests = [s['pre']['backend'] for s in run['cpu_samples']
                if s['pre']['backend']['m_req_valid'] and s['pre']['backend']['m_req_ready']]
    mmio = [r for r in requests if BASE <= r['m_req_addr'] < BASE+4096]
    assert [(r['m_req_addr']-BASE, bool(r['m_req_write']), r['m_req_wdata'] if r['m_req_write'] else None)
            for r in mmio] == [(d['offset'],d['write'],d['write_value']) for d in deliveries]
    for d in deliveries:
        if not d['write']:
            response = [r for r in run['outputs'] if r['data_rsp_consumed'] and
                        r['data_rsp_source_sequence'] == d['source_sequence']]
            assert len(response) == 1 and response[0]['data_rsp_rdata'] == d['read_value']


def test_real_cpu_two_hashes_and_fresh_process(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_CVW_SHA_CACHE', str(tmp_path/'cache')))
    first, fresh = _run(cache), _run(cache)
    evidence = Path(os.environ.get('MYFUZZ_CVW_SHA_EVIDENCE', str(tmp_path/'evidence')))
    evidence.mkdir(parents=True, exist_ok=True)
    for name, run in (('first',first),('fresh',fresh)):
        (evidence/f'{name}.json').write_text(json.dumps(run,sort_keys=True,indent=2)+'\n')
    _assert_chain(first)
    _assert_chain(fresh)
    assert first['executions'] != fresh['executions']
    for key in first:
        if key != 'executions':
            assert first[key] == fresh[key], key


def test_wrong_internal_window_cannot_reach_sha(tmp_path):
    run = _run(Path(os.environ.get('MYFUZZ_CVW_SHA_CACHE', str(tmp_path/'cache'))), base=0, limit=2000)
    assert run['deliveries'] == []
    assert run['sha_samples'] == []
    assert run['result'] == [0]*17


def test_cpu_partial_store_rejected_before_target_ticks(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_CVW_SHA_CACHE', str(tmp_path/'cache')))
    cpu, sha, router, memory = make_cvw_caliptra_chain(cache_dir=cache, partial_store=True)
    cpu.prepare_local()
    sha.prepare_local()
    try:
        sha.begin_case('cvw-sha-partial-control')
        cpu.begin_case('cvw-sha-partial-control')
        before = sha.local_ticks
        with pytest.raises(ProtocolEnvironmentError, match='native backend error without completion') as error:
            for _ in range(2000):
                cpu.step_local({})
        assert isinstance(error.value.__cause__, ValueError)
        assert str(error.value.__cause__) == 'invalid generic AHB-Lite access'
        pre = cpu.last_samples[0]['pre']['backend']
        assert pre['m_req_valid'] and pre['m_req_ready']
        assert pre['m_req_addr'] == BASE+0x80 and pre['m_req_write'] == 1
        assert pre['m_req_be'] == 1
        assert sha.local_ticks == before
        assert router.deliveries == []
        assert sha.drain_tick_samples() == []
        assert memory.read(RESULT+64, 4, transaction_id='partial-check').value == 0
    finally:
        cpu.end_case()
        sha.end_case()
