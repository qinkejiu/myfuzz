"""Failure replay refuses missing authority before any executor can start."""
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from myfuzz.search import failure_replay as replay
from myfuzz.search.journal import Journal


def fixture(tmp_path):
    descriptor=tmp_path/'descriptor.json';descriptor.write_text('{}')
    source=tmp_path/'source.py';source.write_text('pinned')
    import hashlib
    out=tmp_path/'original';out.mkdir()
    (out/'search-summary.json').write_text(json.dumps({'status':'failed','verification':{'session_boundary':{'status':'verified','matches':True}}}))
    journal=Journal(out/'decisions.jsonl')
    journal.append({'kind':'decision','decision':{'action_id':'write:00000001'},'case':{
        'testcase_id':'original:1','source_id':'writer','path_id':'path', 'raw_records_hex':['01000000']}})
    (out/'failure.json').write_text(json.dumps({'journal_head':journal.head,'failure_phase':'submit','attempted_case_count':1}))
    args=dict(output=out,descriptor_path=descriptor,sources=[{'path':str(source),'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}],
        flow='mixed',rounds=32,capacity=6,error=ValueError('effect mismatch'),preparation_memory_flows=True,base_dir=tmp_path,cache_dir='original-cache')
    return out,args


def test_native_specimen_binds_exact_attempt_prefix(tmp_path):
    out,args=fixture(tmp_path)
    result=replay.export_failure_specimen(**args)
    assert result['status']=='ready'
    assert result['sequence']==['F4:01000000']
    assert result['case_mapping'][0]['original_case_id']=='original:1'
    assert result['capacity']==6 and result['preparation_memory_flows'] is True


@pytest.mark.parametrize('damage', ['boundary','source','journal','planned-only','cleanup'])
def test_unsafe_specimens_refuse_before_worker(tmp_path,damage):
    out,args=fixture(tmp_path)
    if damage=='boundary': (out/'search-summary.json').write_text('{"status":"failed"}')
    if damage=='source': Path(args['sources'][0]['path']).write_text('changed')
    if damage=='journal': (out/'failure.json').write_text('{"journal_head":"wrong","failure_phase":"submit","attempted_case_count":1}')
    if damage=='planned-only': (out/'failure.json').unlink();args['sequence']=['F4:01000000']
    if damage=='cleanup': (out/'cleanup-errors.json').write_text('["cleanup"]')
    assert replay.export_failure_specimen(**args)['status']=='refused'


def test_worker_requires_static_success_before_signature_comparison(tmp_path,monkeypatch):
    out,args=fixture(tmp_path); manifest=replay.export_failure_specimen(**args)
    from myfuzz.runtime import generic_campaign
    seen=[]
    monkeypatch.setattr(generic_campaign,'load_descriptor',lambda *a,**kw:SimpleNamespace(scenario_id='case'))
    def run(*a,**kw): seen.append(kw);raise ValueError('effect mismatch')
    monkeypatch.setattr(generic_campaign,'run_descriptor',run)
    result=replay.run_worker(out/'failure-specimen.json',tmp_path/'replay')
    assert result['status']=='reproduced'
    assert seen[0]['sequence']==manifest['sequence']
    assert seen[0]['execution_case_capacity']==6
    assert seen[0]['execution_mode']=='search'
    assert manifest['cache_dir']==str(tmp_path/'original-cache')
    assert seen[0]['cache_dir']==str(tmp_path/'original-cache')
    assert result['trace_equal'] is False


def test_worker_rechecks_source_bytes_before_executor(tmp_path,monkeypatch):
    out,args=fixture(tmp_path);replay.export_failure_specimen(**args)
    Path(args['sources'][0]['path']).write_text('drift')
    from myfuzz.runtime import generic_campaign
    monkeypatch.setattr(generic_campaign,'run_descriptor',lambda *a,**kw:pytest.fail('native forbidden'))
    assert replay.run_worker(out/'failure-specimen.json',tmp_path/'replay')['status']=='refused'


@pytest.mark.parametrize('behavior,status', [('different','not-reproduced'),('success','not-reproduced'),('admission','refused'),('drift','refused')])
def test_worker_does_not_promote_different_or_infrastructure_failures(tmp_path,monkeypatch,behavior,status):
    out,args=fixture(tmp_path);replay.export_failure_specimen(**args)
    from myfuzz.runtime import generic_campaign
    monkeypatch.setattr(generic_campaign,'load_descriptor',lambda *a,**kw:SimpleNamespace(scenario_id='case'))
    def run(*a,**kw):
        if behavior=='success': return {}
        if behavior=='drift': Path(args['sources'][0]['path']).write_text('drift')
        raise ValueError('admission refused' if behavior=='admission' else 'effect mismatch' if behavior=='drift' else 'different error')
    monkeypatch.setattr(generic_campaign,'run_descriptor',run)
    assert replay.run_worker(out/'failure-specimen.json',tmp_path/'replay')['status']==status


def test_f6_partial_prefix_preserves_original_case_mapping(tmp_path):
    out,args=fixture(tmp_path)
    (out/'decisions.jsonl').unlink(); (out/'failure.json').unlink()
    (out/'compiled_f6_partial_prefix.json').write_text(json.dumps({'path_id':'dma:path','records':[
        {'raw8_hex':'0000000000000000','case_id':'original:attempt:0'}], 'attempts':[
        {'raw8_hex':'0000000000000000','case_id':'original:attempt:0','sources':[]}]}))
    args['flow']='F6'
    result=replay.export_failure_specimen(**args)
    assert result['status']=='ready'
    assert result['sequence']==['F6:0000000000000000']
    assert result['case_mapping'][0]['path_id']=='dma:path'


def test_descriptor_mismatch_blocks_worker_before_native(tmp_path,monkeypatch):
    out,args=fixture(tmp_path);replay.export_failure_specimen(**args)
    Path(args['descriptor_path']).write_text('{"different":true}')
    from myfuzz.runtime import generic_campaign
    monkeypatch.setattr(generic_campaign,'run_descriptor',lambda *a,**kw:pytest.fail('native forbidden'))
    assert replay.run_worker(out/'failure-specimen.json',tmp_path/'replay')['status']=='refused'


def test_launcher_preserves_terminal_not_reproduced_result(tmp_path,monkeypatch):
    from scripts import reproduce_search_failure as cli, run_search_comparison
    def execute(argv,directory,timeout,env):
        assert '--worker' in argv
        worker=directory/'worker';worker.mkdir()
        (worker/'failure-replay.json').write_text('{"status":"not-reproduced","accepted":false}')
        return {'returncode':0,'timed_out':False}
    monkeypatch.setattr(run_search_comparison,'execute',execute)
    assert cli.main(['--specimen',str(tmp_path/'specimen.json'),'--output',str(tmp_path/'run')])==1
    assert json.loads((tmp_path/'run/failure-replay.json').read_text())['status']=='not-reproduced'


def test_gpio_worker_dispatches_before_descriptor_checks(tmp_path, monkeypatch):
    from myfuzz.search import gpio_search
    specimen = {'schema_version': replay.SCHEMA, 'status': 'ready',
                'backend': 'gpio', 'cache_dir': 'existing-cache'}
    path = tmp_path / 'specimen.json'
    path.write_text(json.dumps(specimen))
    calls = []
    def handler(actual, output, cache):
        calls.append((actual, output, cache))
        return {'status': 'not-reproduced', 'accepted': False, 'dut_bug': False}
    monkeypatch.setattr(gpio_search, 'replay_gpio_failure_specimen', handler)
    result = replay.run_worker(path, tmp_path / 'worker')
    assert result['status'] == 'not-reproduced'
    assert calls == [(specimen, tmp_path / 'worker' / 'execution', 'existing-cache')]
    assert json.loads((tmp_path / 'worker' / 'failure-replay.json').read_text()) == result
