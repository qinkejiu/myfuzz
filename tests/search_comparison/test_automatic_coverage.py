"""Automatic measurement invokes current replay tooling; unit tests launch no RTL."""
import json
from hashlib import sha256
from pathlib import Path

import pytest

from myfuzz.search import coverage as pipeline


def setup(tmp_path):
    search=tmp_path/'search'; search.mkdir()
    digest='a'*64; nonce='b'*32
    cache_root=tmp_path/'cache'; cache=cache_root/digest; cache.mkdir(parents=True)
    (cache/'harness').write_bytes(b'actual original binary')
    binary=sha256((cache/'harness').read_bytes()).hexdigest()
    summary={'status':'completed','metrics':{'certified_events':None},'coverage':{'status':'unavailable'}}
    (search/'search-summary.json').write_text(json.dumps(summary))
    trace={'schema_version':'local_command_trace.v1','sessions':{'device':{'complete':True,
        'identity':{'component':'device','build_digest':digest,'binary_sha256':binary,'execution_nonce':nonce},
        'records':[{'sequence':1,'reset_epoch':0,'command':f'CMD {nonce} 1 STEP_WB_REG',
                    'reply':f'RESULT {nonce} 1 0 1 payload'}]}}}
    (search/'local_commands.json').write_text(json.dumps(trace))
    return search,cache_root,cache,trace


def test_pipeline_measures_exact_current_prefix_and_exports_without_changing_search(tmp_path,monkeypatch):
    search,cache_root,cache,trace=setup(tmp_path)
    original=(search/'search-summary.json').read_bytes()
    calls=[]
    def measure(cache_arg,output,commands,*,expected_replies):
        calls.append((cache_arg,commands,expected_replies))
        output.mkdir(); (output/'coverage.dat').write_bytes(b'actual instrumented measurement')
        return {'coverage_kind':'verilator-line-block','source_selection':['dut.sv'], 'replay':{'identical_stdout':True}}
    def attach(search_arg,component,measurement,cache_arg):
        assert calls and (measurement/'coverage.dat').exists()
        assert component=='device' and cache_arg==cache
        return {'metrics':{'certified_events':None},'coverage':{'status':'available','metric':'verilator-line-block:device:dut',
            'total':2,'covered':1,'denominator_sha256':'c'*64,'attestation':'recorded-prefix-replay.v1'}}
    monkeypatch.setattr(pipeline,'measure_cached_harness',measure)
    monkeypatch.setattr(pipeline,'attach',attach)
    result=pipeline.measure_search_prefix(search,component='device',cache_root=cache_root,output=tmp_path/'measured')
    assert len(calls)==1
    assert calls[0][1]==[trace['sessions']['device']['records'][0]['command']]
    assert calls[0][2]==[trace['sessions']['device']['records'][0]['reply']]
    assert result['summary']['metrics']['certified_events'] is None
    assert result['cost']['outside_search_budget'] is True
    assert result['cost']['instrumentation_and_replay_seconds']>=0
    assert (search/'search-summary.json').read_bytes()==original
    assert Path(result['summary_path']).exists()


@pytest.mark.parametrize('bad',['missing_trace','incomplete','wrong_binary','too_many'])
def test_pipeline_refuses_before_instrumentation_without_complete_matching_prefix(tmp_path,monkeypatch,bad):
    search,cache_root,cache,trace=setup(tmp_path)
    trace_path=search/'local_commands.json'
    if bad=='missing_trace': trace_path.unlink()
    elif bad=='incomplete': trace['sessions']['device']['complete']=False
    elif bad=='wrong_binary': (cache/'harness').write_bytes(b'wrong binary')
    elif bad=='too_many': trace['sessions']['device']['records']*=513
    if bad!='missing_trace': trace_path.write_text(json.dumps(trace))
    monkeypatch.setattr(pipeline,'measure_cached_harness',lambda *a,**kw:pytest.fail('invalid prefix reached native tool'))
    with pytest.raises((OSError,ValueError)):
        pipeline.measure_search_prefix(search,component='device',cache_root=cache_root,output=tmp_path/'measured')
    assert not (tmp_path/'measured').exists()


def test_comparison_plan_requests_real_measurement_and_records_native_commands(tmp_path):
    import subprocess,sys
    root=Path(__file__).resolve().parents[2]
    result=subprocess.run([sys.executable,str(root/'scripts/run_search_comparison.py'),
        '--output',str(tmp_path/'plan'),'--plan-only','--variants','state','--seeds','7',
        '--cases','1','--measure-coverage','device'],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    plan=json.loads(result.stdout)
    assert plan['coverage_measurement']['component']=='device'
    assert plan['coverage_measurement']['outside_search_budget'] is True
    assert '--record-local-commands' in plan['runs'][0]['argv']
    assert not (tmp_path/'plan').exists()


@pytest.mark.parametrize('failure',[False,True])
def test_comparison_executes_measurement_for_successful_current_run(tmp_path,monkeypatch,failure):
    from tests.search_comparison.test_runner import runner_module
    runner=runner_module()
    calls=[]
    def execute(argv,directory,timeout,env):
        output=Path(argv[argv.index('--output')+1]); output.mkdir()
        assert '--record-local-commands' in argv
        row=dict(status='completed',seed=7,policy='state',ablation='none',mode='original',
            budget={'cases':1,'seconds':1},identity=dict(target='device',source='s',profile='p',
                catalog_sha256='a'*64,coverage_metric=None),
            metrics={'certified_events':None,'useful_case_events':None},coverage={'status':'unavailable'})
        (output/'summary.json').write_text(json.dumps(row))
        return {'returncode':0,'timed_out':False}
    def measure(search,**kwargs):
        calls.append((search,kwargs))
        if failure: raise ValueError('instrumented-replay-mismatch')
        row=json.loads((search/'summary.json').read_text())
        row['coverage']=dict(status='available',attestation='recorded-prefix-replay.v1',
            metric='verilator-line-block:device:dut',denominator_sha256='c'*64,total=4,covered=2)
        return {'summary':row,'component':'device','cost':{'outside_search_budget':True}}
    monkeypatch.setattr(runner,'execute',execute)
    monkeypatch.setattr(pipeline,'measure_search_prefix',measure)
    output=tmp_path/'matrix'
    result=runner.main(['--output',str(output),'--seeds','7','--variants','state',
        '--cases','1','--seconds','1','--measure-coverage','device'])
    assert len(calls)==1
    report=json.loads((output/'comparison.json').read_text())['results'][0]
    assert report['execution']['returncode']==0
    if failure:
        assert result==1 and report['status']=='coverage-failed'
        assert report['coverage_error']=='instrumented-replay-mismatch'
    else:
        assert result==0 and report['metrics']['coverage']['covered']==2
        assert report['metrics']['unique_certified_interactions'] is None


def test_explicit_long_budget_reaches_real_measurement_and_attachment_calls(tmp_path,monkeypatch):
    from tests.integration.test_measure_local_coverage import long_recorded_trace
    search,cache_root,cache,trace=setup(tmp_path)
    long=long_recorded_trace(513)['sessions']['device']['records']
    nonce=trace['sessions']['device']['identity']['execution_nonce']
    for row in long:
        row['command']=row['command'].replace('a'*32,nonce)
        row['reply']=row['reply'].replace('a'*32,nonce)
    trace['sessions']['device']['records']=long
    (search/'local_commands.json').write_text(json.dumps(trace))
    calls=[]
    def measure(cache_arg,output,commands,*,expected_replies,**budget):
        calls.append(budget)
        assert len(commands)==len(expected_replies)==513
        output.mkdir()
        return {'coverage_kind':'verilator-line-block','source_selection':[],'replay':{}}
    def attach(*args,**budget):
        calls.append(budget)
        return {'metrics':{},'coverage':{'denominator_sha256':'c'*64}}
    monkeypatch.setattr(pipeline,'measure_cached_harness',measure)
    monkeypatch.setattr(pipeline,'attach',attach)
    result=pipeline.measure_search_prefix(search,component='device',cache_root=cache_root,
        output=tmp_path/'measured',max_commands=600,max_wall_seconds=120)
    assert calls==[{'max_commands':600,'max_wall_seconds':120}]*2
    assert result['replay_budget']['max_commands']==600
