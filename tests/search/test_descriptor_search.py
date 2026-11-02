from pathlib import Path
from types import SimpleNamespace
import pytest


def test_unknown_catalog_keeps_full_records_and_never_rewards():
    from myfuzz.search.descriptor_search import select_records
    d = SimpleNamespace(flow_ids=('F6',), records=lambda flow: ['0102030405060708', '1112131415161718'])
    a = select_records(d, flow='F6', records=None, policy='state', seed=7, cases=5)
    b = select_records(d, flow='F6', records=None, policy='state', seed=7, cases=5)
    assert a == b
    assert len(a['sequence']) == 5
    assert set(a['sequence']) <= {'F6:0102030405060708', 'F6:1112131415161718'}
    assert a['state_observation'] == 'unknown'
    assert a['statistics']['features'] == 0
    assert a['statistics']['settled_trials'] == 0


def test_existing_output_refused_before_runtime(tmp_path):
    from myfuzz.search.descriptor_search import execute
    (tmp_path / 'original').mkdir()
    with pytest.raises(ValueError, match='existing output'):
        execute(descriptor_path='absent', base_dir=tmp_path, output=tmp_path)


def test_invalid_seconds_refused_before_runtime(tmp_path):
    from myfuzz.search.descriptor_search import execute
    with pytest.raises(ValueError, match='seconds'):
        execute(descriptor_path='absent', base_dir=tmp_path, output=tmp_path, seconds=float('nan'))


def test_native_production_parameters_refuse_other_root_before_tool(tmp_path):
    from myfuzz.search.native import execute
    with pytest.raises(ValueError, match='base_dir'):
        execute(descriptor_path='absent', case_root=tmp_path, mode='original',
                base_dir=tmp_path, restrict_output=False)


@pytest.mark.parametrize('seconds,actual', [(None,2),(0.1,1)])
def test_fallback_uses_selected_records_and_reexecutes_fresh(tmp_path, monkeypatch, seconds, actual):
    import json
    from myfuzz.runtime import generic_campaign
    from myfuzz.search.descriptor_search import execute
    root = Path(__file__).resolve().parents[2]
    path = root / 'configs/scenarios/compiled-f6-ibex-dma/generic_scenario.json'
    matches = list((root / 'configs/scenarios').glob('*/*scenario.json'))
    path = next(p for p in matches if json.loads(p.read_text()).get('flow_ids') == ['F6'])
    calls = []
    def run(descriptor, **kwargs):
        calls.append(kwargs)
        out = Path(kwargs['case_root']) / kwargs['mode']
        out.mkdir(parents=True)
        selector = kwargs['record_selector']
        executed = []
        for i in range(actual):
            row = selector.choose()
            if kwargs['expected_records'] is not None:
                assert row == kwargs['expected_records'][i]
            selector.settle(row)
            executed.append(row)
        result = {'replay_matches': True, 'case_count': actual, 'budget_ended': actual < kwargs['selected_count']}
        (out / 'summary.json').write_text(json.dumps(result))
        from myfuzz.integration.compiled_f6 import _canonical
        from myfuzz.scenario.session_runtime import _trace_semantic_sha256
        from hashlib import sha256
        plan = {'cases': executed}
        nonce = f'{len(calls)*10+1:032x}'
        events = [{'event_id': 1, 'execution': nonce, 'kind': 'sample', 'data': actual}]
        prefix = {'trace_manifest_sha256': 'a'*64, 'compiled_document_sha256': 'b'*64,
            'online_plan': plan, 'trace_genome_sha256': sha256(_canonical(plan).encode()).hexdigest(),
            'trace_status': 'complete', 'trace_local_ticks': {'cpu': 1}, 'actual_events': events,
            'original_execution_audit': {'identities': {'cpu': {
                'component': 'cpu', 'role': 'cpu', 'execution_nonce': nonce}}}}
        prefix['semantic_hash'] = _trace_semantic_sha256('complete', events, {'cpu': 1})
        (out / 'compiled_f6_prefix.json').write_text(json.dumps(prefix))
        # This software-only adapter fixture supplies observed execution rows;
        # it does not launch or certify a native process.
        rows = [dict(component='cpu',execution_nonce=f'{len(calls)*10+i:032x}',
                     pid=1,reaped=True,exit_code=0,build_digest='a'*64,
                     binary_sha256='b'*64,artifact_digest='c'*64,manifest_sha256='d'*64)
                for i in (1,2)]
        monkeypatch.setattr(kwargs['command_trace'], 'export_executions', lambda: rows)
        return result
    monkeypatch.setattr(generic_campaign, 'run_descriptor', run)
    original = execute(descriptor_path=path, base_dir=root, output=tmp_path, cases=2, seconds=seconds, record_local_commands=True)
    fresh = execute(descriptor_path=path, base_dir=root, output=tmp_path, cases=2, seconds=seconds, mode='fresh', record_local_commands=True)
    assert len(calls) == 2
    assert all(c['command_trace'] is not None for c in calls)
    assert all(c['preparation_memory_flows'] is False for c in calls)
    assert all(c['execution_case_capacity'] == 2 for c in calls)
    assert calls[0]['record_selector'].document()['sequence'] == calls[1]['expected_records']
    assert calls[0].get('max_wall_seconds') == seconds
    assert calls[1].get('max_wall_seconds') is None
    assert original['state_observation'] == fresh['state_observation'] == 'unknown'
    assert fresh['fresh_verification_scope'] == 'strict-cross-invocation'
    assert fresh['policy'] == 'state'
    assert fresh['seed'] == 7
    assert fresh['status'] == ('completed' if actual == 2 else 'budget-ended')
    assert fresh['budget']['cases'] == 2
    assert fresh['identity']['target']
    assert fresh['identity']['source'].startswith('sha256:')
    assert fresh['identity']['profile'].startswith('sha256:')
    assert len(fresh['identity']['catalog_sha256']) == 64
    assert fresh['identity']['coverage_metric'] is None
    assert fresh['metrics']['certified_events'] is None
    assert fresh['metrics']['useful_case_events'] is None


@pytest.mark.parametrize('field,value', [('seed',8), ('strategy','uniform'), ('rounds',64), ('seconds',2), ('requested_cases',9)])
def test_native_fresh_request_mismatch_refused(field, value):
    from myfuzz.search.native import fresh_case_count
    request = dict(seed=7, strategy='state', rounds=32, seconds=1, requested_cases=6)
    reference = dict(request=request, cases=0)
    changed = dict(request, **{field:value})
    with pytest.raises(ValueError, match='request'):
        fresh_case_count(reference, changed)


def test_native_zero_case_replay_retains_positive_request_capacity():
    from myfuzz.search.native import fresh_case_count
    request = dict(seed=7, strategy='state', rounds=32, seconds=1, requested_cases=6)
    assert fresh_case_count(dict(request=request, cases=0), request) == 0
    with pytest.raises(ValueError, match='case count'):
        fresh_case_count(dict(request=request, cases=7), request)


def test_driver_records_commands_in_owned_context(tmp_path, monkeypatch):
    from myfuzz.search import descriptor_search
    from myfuzz.local_harness.session import _local_command_trace
    observed = []
    def execute(**kwargs):
        assert kwargs['command_trace'] is _local_command_trace.get()
        assert kwargs['command_trace'] is not None
        observed.append(kwargs)
        return {'recorded': True}
    monkeypatch.setattr(descriptor_search, '_execute', execute)
    assert descriptor_search.execute(descriptor_path='x',base_dir=tmp_path,output=tmp_path,record_local_commands=True)['recorded']
    assert len(observed) == 1
    assert _local_command_trace.get() is None


@pytest.mark.parametrize('record', [False, True])
@pytest.mark.parametrize('execution_mode', [None, 'search', 'develop', 'acceptance'])
def test_native_zero_case_original_and_fresh_execute_complete_prefix(tmp_path, monkeypatch, record, execution_mode):
    """Exercise the native driver lifecycle without launching a process."""
    from myfuzz.search import native
    from myfuzz.runtime import generic_campaign, binding, engine, campaign
    from myfuzz.local_harness import generated_execution_admission
    descriptor = SimpleNamespace(f4_records=('01000000',), executor=lambda f: 'compiled_f4_obi_apb')
    monkeypatch.setattr(generic_campaign, 'load_descriptor', lambda *a, **kw: descriptor)
    monkeypatch.setattr(native, 'preflight', lambda p: {'status': 'ready-for-attempt'})
    monkeypatch.setattr(native, 'source_files', lambda: [])
    bound = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(binding, 'bind_execution_plan', lambda *a, **kw: bound)
    def prepare(descriptor, generated):
        generated.mkdir(parents=True)
        context = SimpleNamespace(artifacts=(), compiled_inputs=lambda: (),
            attach_runtime=lambda **kw: None, register_prepared_paths=lambda **kw: None,
            close=lambda: None)
        return context, SimpleNamespace(document_bytes=b'plan', identity_sha256='p'*64)
    monkeypatch.setattr(native, '_prepare', prepare)
    runtimes, replays, capacities, audits = [], [], [], []
    class Runtime:
        _mixed_flows = True
        finished = False
        def __init__(self):
            self.runner = SimpleNamespace(sessions={})
            self.runtime_path_admission = SimpleNamespace(prepared=SimpleNamespace(runtime_paths=(), graph=None))
            self.trace = SimpleNamespace(events=())
            self.closure = {}
            self.serial = len(runtimes) + 1
            runtimes.append(self)
        def finish(self):
            self.finished = True
            return {'semantic_hash': 'zero-prefix', 'records': []}
        def execution_audit(self):
            row = dict(component='cpu', role='cpu',pid=self.serial,
                       execution_nonce=f'{self.serial:032x}')
            row.update({k:'a'*64 for k in ('build_digest','binary_sha256','artifact_digest',
                       'observed_executable_sha256','ready_artifact_digest')})
            return dict(schema_version='compiled_F4_execution_audit.v1',closed=True,
                identities={'cpu':row},exits={'cpu':{'reaped':True,'returncode':0}})
        def replay(self, prefix, audit_sink=None):
            from copy import deepcopy
            replays.append(prefix)
            original = self.execution_audit()
            fresh = deepcopy(original)
            fresh['identities']['cpu']['execution_nonce'] = f'{self.serial + 10:032x}'
            audits.extend([original, fresh])
            if audit_sink is not None:
                audit_sink({'execution_audit':fresh})
            return {'matches':True}
    monkeypatch.setattr(generated_execution_admission, 'create_compiled_execution', lambda **kw: Runtime())
    class Engine:
        def __init__(self, bound, **kw):
            capacities.append(kw['max_cases'])
            self.context = SimpleNamespace(flows={f:SimpleNamespace(current_source_id=f,
                path_id=f, domains=(SimpleNamespace(source_id=f,minimum=0),)) for f in ('F2','F4')})
            self.state = 'PREPARED'
        def prepare(self): pass
        def validate(self, row): pass
        def start(self): self.state='RUNNING'
        def submit(self, row): pytest.fail('expired budget submitted a case')
        def finish(self):
            self.state='CLOSED'
            return {'process_identities':{},'initialization_counts':{}}
        def close(self): pass
    monkeypatch.setattr(engine, 'PersistentCampaignRuntime', Engine)
    from myfuzz.runtime.flows import mixed
    monkeypatch.setattr(mixed, 'MixedStorageFlowBackend', lambda **kw:SimpleNamespace(open=lambda:None))
    monkeypatch.setattr(campaign, 'RfuzzDirectedAdapter', lambda **kw:SimpleNamespace(encode=lambda value:b'\0'*4))
    kwargs=dict(descriptor_path=tmp_path/'descriptor',case_root=tmp_path,seed=7,cases=6,
                seconds=1e-30,restrict_output=False,execution_mode=execution_mode)
    if record:
        trace = SimpleNamespace(export_sessions=lambda: tuple({'component':'cpu',
            'identity':audit['identities']['cpu'], 'complete':True, 'records':[]}
            for audit in {audit['identities']['cpu']['execution_nonce']:audit
                for audit in [*(runtime.execution_audit() for runtime in runtimes), *audits]}.values()))
        kwargs['command_trace'] = trace
    original = native.execute(mode='original', **kwargs)
    fresh = native.execute(mode='fresh', **kwargs)
    assert original['cases'] == fresh['cases'] == 0
    assert original['status'] == fresh['status'] == 'budget-ended'
    assert capacities == [6,6]
    assert original['metrics']['certified_events'] == []
    assert fresh['metrics']['certified_events'] == []
    assert replays == [{'semantic_hash':'zero-prefix','records':[]}] * (1 if execution_mode in ('search','develop') else 2)
    assert original['replay_matches'] is (None if execution_mode in ('search','develop') else True)
    if record:
        assert (tmp_path/'original'/'local_commands.json').exists()
        assert (tmp_path/'original'/'fresh_local_commands.json').exists() == (execution_mode not in ('search','develop'))
    assert (tmp_path/'fresh'/'summary.json').is_file()
    assert (tmp_path/'fresh'/'events.json').exists()
    assert json.loads((tmp_path/'fresh'/'prefix.json').read_text())['records'] == []
    if execution_mode == 'search' and not record:
        assert not (tmp_path/'original'/'events.json').exists()
        assert json.loads((tmp_path/'original'/'prefix.json').read_text())['full_prefix_saved'] is False
        assert fresh['verification']['cross_invocation']['matches'] is True
    if record:
        assert (tmp_path/'fresh'/'local_commands.json').is_file()
        assert (tmp_path/'fresh'/'fresh_local_commands.json').is_file()


def test_live_fresh_manifest_rejects_summary_tamper(tmp_path, monkeypatch):
    import json
    from myfuzz.search import native, descriptor_search
    root = Path(__file__).resolve().parents[2]
    path = root / 'configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json'
    calls = []
    def run(**kwargs):
        calls.append(kwargs)
        out = tmp_path/kwargs['mode']
        out.mkdir(parents=True)
        (out/'public-catalog.json').write_text(json.dumps({'sha256':'a'*64}))
        result = {'status':'observed-uncompleted','cases':1}
        (out/'summary.json').write_text(json.dumps(result))
        return result
    monkeypatch.setattr(native, 'execute', run)
    descriptor_search.execute(descriptor_path=path,base_dir=root,output=tmp_path,cases=1)
    (tmp_path/'original'/'summary.json').write_text('{}')
    with pytest.raises(ValueError, match='summary binding'):
        descriptor_search.execute(descriptor_path=path,base_dir=root,output=tmp_path,cases=1,mode='fresh')
    assert len(calls) == 1


def test_strict_fresh_identity_join_rejects_nonce_reuse_and_build_drift():
    from myfuzz.search.descriptor_search import validate_execution_prefixes
    def row(nonce):
        return dict(component='cpu',execution_nonce=nonce*32,pid=1,reaped=True,exit_code=0,
                    build_digest='a'*64,binary_sha256='b'*64,artifact_digest='c'*64,manifest_sha256='d'*64)
    original, fresh = [row('1'),row('2')], [row('3'),row('4')]
    validate_execution_prefixes(original, fresh)
    with pytest.raises(ValueError,match='nonce'):
        validate_execution_prefixes(original, [row('1'),row('4')])
    fresh[0]['binary_sha256']='e'*64
    with pytest.raises(ValueError,match='build'):
        validate_execution_prefixes(original, fresh)
    with pytest.raises(ValueError,match='exit'):
        validate_execution_prefixes(original, [dict(row('3'),exit_code=1),row('4')])


@pytest.mark.parametrize('actual', [0,1])
def test_mixed_fresh_keeps_planned_memory_preparation_after_budget(tmp_path, monkeypatch, actual):
    import json
    from myfuzz.runtime import generic_campaign
    from myfuzz.search import descriptor_search
    root=Path(__file__).resolve().parents[2]
    path=root/'configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json'
    calls=[]
    def run(descriptor, **kwargs):
        calls.append(kwargs)
        selector=kwargs['record_selector']
        for _ in range(actual):
            row=selector.choose(); selector.settle(row)
        assert kwargs['preparation_memory_flows'] is True
        assert kwargs['execution_case_capacity'] == 2
        out=tmp_path/kwargs['mode']; out.mkdir(parents=True)
        summary={'case_count':actual,'replay_matches':True,'plan_identity_sha256':'b'*64,
                 'budget_ended':actual<len(kwargs['sequence'])}
        (out/'summary.json').write_text(json.dumps(summary))
        (out/'prefix.json').write_text(json.dumps({'semantic_hash':'a'*64}))
        rows=[dict(component='cpu',execution_nonce=f'{10*len(calls)+i:032x}',pid=1,
                   reaped=True,exit_code=0,build_digest='a'*64,binary_sha256='b'*64,
                   artifact_digest='c'*64,manifest_sha256='d'*64) for i in (1,2)]
        monkeypatch.setattr(kwargs['command_trace'],'export_executions',lambda:rows)
        return summary
    monkeypatch.setattr(generic_campaign,'run_descriptor',run)
    kwargs=dict(descriptor_path=path,base_dir=root,output=tmp_path,flow='mixed',cases=2,
                seconds=1e-9,records=['F4:55000000','F3:55000000'])
    descriptor_search.execute(mode='original',**kwargs)
    result=descriptor_search.execute(mode='fresh',**kwargs)
    assert calls[0]['sequence']==['F4:55000000','F3:55000000']
    assert calls[1]['sequence']==calls[0]['sequence']
    assert calls[1]['selected_count']==actual
    assert result['executed_case_count']==actual
    assert result['fresh_verification_scope']=='strict-cross-invocation'


def test_record_catalog_identity_binds_actual_packed_record_bytes():
    from myfuzz.search.descriptor_search import select_records
    descriptor=SimpleNamespace(flow_ids=('F6',),records=lambda f:['0102030405060708'])
    other=SimpleNamespace(flow_ids=('F6',),records=lambda f:['1112131415161718'])
    kwargs=dict(flow='F6',records=None,policy='state',seed=7,cases=1)
    assert select_records(descriptor,**kwargs)['catalog_sha256'] != select_records(other,**kwargs)['catalog_sha256']


def test_cross_invocation_prefix_ignores_process_and_output_metadata(tmp_path):
    import json
    from myfuzz.search.descriptor_search import _prefix_identity
    expected=[]
    for mode,nonce in [('original','1'*32),('fresh','2'*32)]:
        out=tmp_path/mode;out.mkdir()
        prefix={k:'a'*64 for k in ('semantic_sha256','genome_sha256','manifest_sha256')}
        prefix.update(mode=mode,execution_nonce=nonce,work_path=str(out/'work'))
        (out/'prefix.json').write_text(json.dumps(prefix))
        (out/'online_plan.json').write_text('{"schema_version":24,"cases":[]}')
        expected.append(_prefix_identity(out,'F5',{}))
    assert expected[0]==expected[1]
    (tmp_path/'fresh'/'online_plan.json').write_text('{"schema_version":24,"cases":[1]}')
    assert _prefix_identity(tmp_path/'fresh','F5',{}) != expected[0]
# Software-only F6 cross-invocation regressions. These documentary fixtures
# are test data, not native execution credentials.
from hashlib import sha256
import json
import pytest
from myfuzz.search.descriptor_search import _prefix_identity
from myfuzz.integration.compiled_f6 import _canonical
from myfuzz.scenario.session_runtime import _trace_semantic_sha256


def prefix(nonce):
    plan={'schema_version':24,'cases':[]}
    result={'schema_version':'compiled_F6_prefix.v1','completed':True,
            'trace_status':'complete','trace_local_ticks':{'cpu':1},
            'trace_manifest_sha256':'a'*64,'compiled_document_sha256':'b'*64,
            'online_plan':plan,'trace_genome_sha256':sha256(_canonical(plan).encode()).hexdigest(),
            'actual_events':[{'event_id':1,'kind':'sample','execution':nonce,'data':7}],
            'original_execution_audit':{'identities':{'cpu':{'component':'cpu','role':'cpu','execution_nonce':nonce}}}}
    result['semantic_hash']=_trace_semantic_sha256(result['trace_status'],result['actual_events'],result['trace_local_ticks'])
    return result


def identity(tmp_path,name,document):
    out=tmp_path/name;out.mkdir()
    (out/'compiled_f6_prefix.json').write_text(json.dumps(document))
    return _prefix_identity(out,'F6',{})


def test_new_owned_nonce_changes_raw_hash_but_not_full_replay_projection(tmp_path):
    a,b=prefix('1'*32),prefix('2'*32)
    assert a['semantic_hash']!=b['semantic_hash']
    assert identity(tmp_path,'original',a)==identity(tmp_path,'fresh',b)


def test_actual_data_change_is_not_hidden_by_nonce_projection(tmp_path):
    a,b=prefix('1'*32),prefix('2'*32)
    b['actual_events'][0]['data']=8
    b['semantic_hash']=_trace_semantic_sha256(b['trace_status'],b['actual_events'],b['trace_local_ticks'])
    assert identity(tmp_path,'original',a)!=identity(tmp_path,'fresh',b)


def test_raw_semantic_hash_tamper_is_refused(tmp_path):
    b=prefix('2'*32);b['semantic_hash']='0'*64
    with pytest.raises(ValueError,match='semantic hash'):
        identity(tmp_path,'fresh',b)


def test_online_plan_genome_tamper_is_refused(tmp_path):
    b=prefix('2'*32);b['online_plan']['cases']=[{'data':8}]
    with pytest.raises(ValueError,match='genome hash'):
        identity(tmp_path,'fresh',b)


def test_shared_slot_prefix_binds_the_full_flow_ledger(tmp_path):
    document=prefix('1'*32)
    document['flow_records']=[{'flow':'F4','raw_hex':'55000000'},
                              {'flow':'F6','raw_hex':'0000000000000000'}]
    output=tmp_path/'mixed';output.mkdir()
    path=output/'compiled_f6_prefix.json'
    path.write_text(json.dumps(document))
    summary={'shared_slots':True,'case_count':2}
    original=_prefix_identity(output,'mixed',summary)
    assert original==_prefix_identity(output,'F6',{})
    document['flow_records'][0]['raw_hex']='aa000000'
    path.write_text(json.dumps(document))
    assert _prefix_identity(output,'mixed',summary)!=original
    with pytest.raises(ValueError,match='flow count'):
        _prefix_identity(output,'mixed',dict(summary,case_count=1))


def test_shared_manifest_pins_each_capability_file(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from myfuzz.search import descriptor_search
    paths=[tmp_path/name for name in ('descriptor.json','compose.json','supplement.json','dma.json','storage.json')]
    for path in paths:path.write_text(path.name)
    descriptor=SimpleNamespace(root=tmp_path,compose=paths[1],supplement=paths[2],capability=tuple(paths[3:]))
    monkeypatch.setattr(descriptor_search,'_configured_files',lambda *_:(set(),set()))
    before=descriptor_search._manifest(descriptor,paths[0],tmp_path)
    assert {row['path'] for row in before}=={str(path) for path in paths}
    paths[-1].write_text('changed storage capability')
    after=descriptor_search._manifest(descriptor,paths[0],tmp_path)
    assert [row['path'] for row in before if row not in after]==[str(paths[-1])]


def test_shared_slot_preflight_reports_bounded_slot_capacity():
    from myfuzz.search.descriptor_search import preflight_scenario
    root=Path(__file__).resolve().parents[2]
    result=preflight_scenario({'descriptor':'configs/scenarios/compiled-f6-ibex-wbdmac-storage/generic_shared_slots.json',
        'flow':'mixed'},root)
    assert result['capabilities']['max_cases']==16


def test_closed_commit_digest_is_still_authenticated(tmp_path):
    b=prefix('2'*32)
    b['actual_events'][0]['commit_document']={'schema_version':'memory_write_commit_receipt.v1','commit_id':'0'*64,'fullkey':{}}
    b['semantic_hash']=_trace_semantic_sha256(b['trace_status'],b['actual_events'],b['trace_local_ticks'])
    with pytest.raises(ValueError,match='commit-digest-invalid'):
        identity(tmp_path,'fresh',b)

@pytest.mark.parametrize('flow,record',[('F1','13000000'),('F3','55000000')])
def test_single_memory_flow_uses_mixed_executor_and_replays(tmp_path,monkeypatch,flow,record):
    import json
    from myfuzz.runtime import generic_campaign
    from myfuzz.search import descriptor_search
    root=Path(__file__).resolve().parents[2]
    path=root/'configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json'
    calls=[]
    def run(descriptor,**kwargs):
        calls.append(kwargs)
        selector=kwargs['record_selector']; row=selector.choose(); selector.settle(row)
        assert kwargs['flow']=='mixed'
        assert kwargs['sequence']==[f'{flow}:{record}']
        assert kwargs['preparation_memory_flows'] is True
        out=tmp_path/kwargs['mode'];out.mkdir(parents=True)
        summary={'flow':'mixed','case_count':1,'replay_matches':True,'plan_identity_sha256':'b'*64}
        (out/'summary.json').write_text(json.dumps(summary))
        (out/'prefix.json').write_text(json.dumps({'semantic_hash':'a'*64}))
        rows=[dict(component='cpu',execution_nonce=f'{10*len(calls)+i:032x}',pid=1,reaped=True,exit_code=0,
                   build_digest='a'*64,binary_sha256='b'*64,artifact_digest='c'*64,manifest_sha256='d'*64) for i in (1,2)]
        monkeypatch.setattr(kwargs['command_trace'],'export_executions',lambda:rows)
        return summary
    monkeypatch.setattr(generic_campaign,'run_descriptor',run)
    kwargs=dict(descriptor_path=path,base_dir=root,output=tmp_path,flow=flow,cases=1,records=[record])
    original=descriptor_search.execute(mode='original',**kwargs)
    fresh=descriptor_search.execute(mode='fresh',**kwargs)
    assert original['flow']==fresh['flow']==flow
    assert fresh['verification']['cross_invocation']['matches'] is True
    assert json.loads((tmp_path/'original/search-manifest.json').read_text())['request']['flow']==flow


def test_online_record_selector_selects_only_after_previous_result():
    from myfuzz.search.descriptor_search import RecordSelector
    descriptor=SimpleNamespace(flow_ids=('F5',), records=lambda flow:['0000000100000000','0000000200000000'])
    selector=RecordSelector(descriptor,flow='F5',records=None,policy='state',seed=7,cases=3)
    first=selector.choose()
    with pytest.raises(ValueError,match='pending'):
        selector.choose()
    assert selector.document()['sequence']==[]
    selector.settle(first)
    second=selector.choose()
    selector.settle(second)
    result=selector.document()
    assert result['sequence']==[first,second]
    assert result['statistics']['settled_trials']==0
    assert result['state_observation']=='unknown'


@pytest.mark.parametrize('requested,actual',[(1,1),(3,1),(3,3)])
def test_f5_incremental_selection_replays_only_executed_prefix(tmp_path,monkeypatch,requested,actual):
    import json
    from myfuzz.runtime import generic_campaign
    from myfuzz.search import descriptor_search
    root=Path(__file__).resolve().parents[2]
    path=root/'configs/scenarios/compiled-f5-ibex-pulp-gpio/generic_scenario.json'
    calls=[]
    def run(descriptor,**kwargs):
        calls.append(kwargs)
        selector=kwargs['record_selector']
        assert selector.document()['sequence']==[]
        assert kwargs['execution_case_capacity']==requested
        assert kwargs['selected_count']==(requested if kwargs['mode']=='original' else actual)
        for i in range(actual):
            row=selector.choose()
            if kwargs['expected_records'] is not None:
                assert row == kwargs['expected_records'][i]
            selector.settle(row)
        out=tmp_path/kwargs['mode'];out.mkdir(parents=True)
        summary={'flow':'F5','case_count':actual,'replay_matches':True,
                 'budget_ended': kwargs['mode']=='original' and actual<requested}
        (out/'summary.json').write_text(json.dumps(summary))
        (out/'online_plan.json').write_text('{}')
        (out/'prefix.json').write_text(json.dumps({'semantic_sha256':'a'*64,'genome_sha256':'b'*64,'manifest_sha256':'c'*64}))
        rows=[dict(component='cpu',execution_nonce=f'{10*len(calls)+i:032x}',pid=1,reaped=True,exit_code=0,
                   build_digest='a'*64,binary_sha256='b'*64,artifact_digest='c'*64,manifest_sha256='d'*64) for i in (1,2)]
        monkeypatch.setattr(kwargs['command_trace'],'export_executions',lambda:rows)
        return summary
    monkeypatch.setattr(generic_campaign,'run_descriptor',run)
    records=['F5:0000000100000000','F5:0000000200000000','F5:0000000100000000']
    kwargs=dict(descriptor_path=path,base_dir=root,output=tmp_path,flow='F5',cases=requested,records=records)
    original=descriptor_search.execute(mode='original',**kwargs)
    fresh=descriptor_search.execute(mode='fresh',**kwargs)
    manifest=json.loads((tmp_path/'original/search-manifest.json').read_text())
    assert len(manifest['selection']['catalog'])==2
    assert len(manifest['selection']['sequence'])==actual
    assert manifest['request']['cases']==requested
    assert fresh['executed_case_count']==actual
    assert fresh['verification']['cross_invocation']['matches'] is True
    assert original['state_observation']=='unknown'


def test_f6_incremental_selection_replays_actual_prefix(tmp_path,monkeypatch):
    import json
    from myfuzz.runtime import generic_campaign
    from myfuzz.search import descriptor_search
    root=Path(__file__).resolve().parents[2]
    path=root/'configs/scenarios/compiled-f6-ibex-wbdmac/generic_scenario.json'
    calls=[]
    def run(descriptor,**kwargs):
        calls.append(kwargs); selector=kwargs['record_selector']
        assert selector.document()['sequence']==[]
        assert kwargs['selected_count']==(3 if kwargs['mode']=='original' else 1)
        row=selector.choose()
        if kwargs['expected_records'] is not None: assert row==kwargs['expected_records'][0]
        selector.settle(row)
        out=tmp_path/kwargs['mode'];out.mkdir(parents=True)
        summary={'flow':'F6','case_count':1,'replay_matches':True,'budget_ended':kwargs['mode']=='original'}
        (out/'summary.json').write_text(json.dumps(summary))
        rows=[dict(component='cpu',execution_nonce=f'{10*len(calls)+i:032x}',pid=1,reaped=True,exit_code=0,
                   build_digest='a'*64,binary_sha256='b'*64,artifact_digest='c'*64,manifest_sha256='d'*64) for i in (1,2)]
        monkeypatch.setattr(kwargs['command_trace'],'export_executions',lambda:rows)
        return summary
    monkeypatch.setattr(generic_campaign,'run_descriptor',run)
    monkeypatch.setattr(descriptor_search,'_prefix_identity',lambda *a:{'digest':'a'*64})
    records=['F6:0110c00008000000','F6:0210c00008000000']
    kwargs=dict(descriptor_path=path,base_dir=root,output=tmp_path,flow='F6',cases=3,records=records)
    original=descriptor_search.execute(mode='original',**kwargs)
    fresh=descriptor_search.execute(mode='fresh',**kwargs)
    manifest=json.loads((tmp_path/'original/search-manifest.json').read_text())
    assert manifest['request']['cases']==3
    assert len(manifest['selection']['sequence'])==1
    assert fresh['executed_case_count']==1 and fresh['verification']['cross_invocation']['matches'] is True
    assert original['state_observation']=='unknown'


def test_six_flow_catalog_preflights_installed_RAM_and_pin_feedback():
    from myfuzz.search.descriptor_search import preflight_scenario
    root=Path(__file__).resolve().parents[2]
    config=json.loads((root/'configs/search/shared-all-flows.json').read_text())
    result=preflight_scenario(config,root)
    assert result['search_backend']=='live-shared-ram-pin'
    assert result['live_state_conditioned'] is True
    assert result['native_executed'] is False
    assert result['capabilities']['max_cases']==16


def test_shared_coverage_identity_matches_installed_feedback_provider():
    from myfuzz.search.descriptor_search import _live_coverage_metric
    assert _live_coverage_metric('shared', {'search_backend':'live-shared-ram-pin'}) == 'certified-shared-ram-and-gpio-consumption.v1'
    assert _live_coverage_metric('shared', {'search_backend':'live-shared-ram-target'}) == 'certified-shared-ram-consumption.v1'
