"""Case boundary budget validation without native execution."""
from types import SimpleNamespace
import pytest
from myfuzz.runtime import generic_campaign as campaign

@pytest.mark.parametrize('value', [True, False, 0, -1, float('nan'), float('inf'), '1'])
def test_wall_budget_rejected_before_record_selection(monkeypatch, tmp_path, value):
    monkeypatch.setattr(campaign, 'select_case_records', lambda *a, **kw: pytest.fail('selected before validation'))
    with pytest.raises(campaign.GenericScenarioRefused) as error:
        campaign.run_descriptor(SimpleNamespace(), flow='F5', mode='original',
            case_root=tmp_path, base_dir=tmp_path, max_wall_seconds=value)
    assert error.value.code == 'generic-scenario-wall-budget-invalid'


@pytest.mark.parametrize('selected_count', [1,3])
def test_f6_budget_forwarded_and_actual_count_used(monkeypatch, tmp_path,selected_count):
    from myfuzz.integration import compiled_execution_files as files
    captured = {}
    def run(**kwargs):
        captured.update(kwargs)
        kwargs['output_dir'].mkdir()
        return {'status':'complete', 'runtime_admitted':True, 'case_count':1,
            'budget_ended':True, 'fresh_verification':{'matches':True,'completed':True,'verification_scope':'full'}}
    monkeypatch.setattr(files, 'run_compiled_execution_files', run)
    descriptor = SimpleNamespace(compose='c', capability='x', supplement='s', scenario_id='test', executor=lambda f:'compiled_f6_cpu_dma')
    result = campaign._run_f6_descriptor(descriptor, cases=[('F6','00'*8)]*selected_count,
        mode='original',case_root=tmp_path,base=tmp_path,cache=tmp_path/'cache',rounds=32,
        command_trace=None,max_wall_seconds=.5,execution_case_capacity=5)
    assert captured['max_wall_seconds'] == .5
    assert captured['max_cases'] == 5
    import json
    assert len(json.loads(captured['records_path'].read_text())) == selected_count
    assert result['case_count'] == 1
    assert result['requested_case_count'] == selected_count
    assert result['budget_ended'] is True
    assert result['replay_matches'] is True


def test_shared_budget_finishes_actual_prefix_and_empty_replay():
    from myfuzz.runtime.campaign import run_directed_campaign, CampaignBudget
    from myfuzz.runtime.flows.storage import StorageFlowBackend
    from tests.runtime.test_persistent_engine import _world, FakePersistentRuntime, raw_of
    from tests.runtime.test_storage_kernel import FakeScenarioSession, directed_case, directed_sequence
    bound, runner, log, path = _world()
    runtime = FakePersistentRuntime(runner, FakeScenarioSession())
    sequence = directed_sequence(directed_case('a', records=(raw_of(1),)),
        directed_case('b', records=(raw_of(2),)),plan_sha256=bound.plan_sha256)
    report = run_directed_campaign(bound_plan=bound, backend=StorageFlowBackend(runtime=runtime,flow_id='F4'),
        sequence=sequence, budget=CampaignBudget(max_cases=1))
    assert report['budget_ended'] is True
    assert report['sequence_case_count'] == report['case_count'] == 1
    assert len(report['directed_cases']) == 1
    assert report['requested_case_count'] == 2
    bound, runner, log, path = _world()
    runtime = FakePersistentRuntime(runner, FakeScenarioSession())
    sequence['plan_sha256'] = bound.plan_sha256
    sequence['cases'] = []
    report = run_directed_campaign(bound_plan=bound,backend=StorageFlowBackend(runtime=runtime,flow_id='F4'),
        sequence=sequence,allow_empty_sequence=True)
    assert report['case_count'] == 0
    assert report['state'] == 'CLOSED'


def test_f5_budget_ends_between_cases_and_replays_full_actual_prefix(monkeypatch, tmp_path):
    import json
    from myfuzz.integration import ibex_pulp_online
    from myfuzz.scenario.session_runtime import OnlineCaseReceipt
    clock = [100.]
    calls = []
    trace = SimpleNamespace(genome_sha256='a'*64, status='complete', events=[],
        local_ticks={}, semantic_sha256='b'*64, manifest_sha256='c'*64)
    context = SimpleNamespace(close=lambda: calls.append('close'), assert_current=lambda: None)
    def build(**kw):
        clock[0] += 500 # Build is outside the budget.
        return runtime
    def submit(raw):
        calls.append(raw)
        clock[0] += 2 # Atomic case overruns one-second budget.
        return OnlineCaseReceipt('a',0,0,(),{},{},'running')
    def replay(prefix):
        assert prefix is trace
        calls.append('replay')
        clock[0] += 500 # Fresh is complete and has no new deadline.
        return SimpleNamespace(matches=True,verification_scope='full',first_difference=None,
            expected_event=None,actual_event=None,difference_context=None,actual_trace=trace)
    runtime = SimpleNamespace(compiled_f5_crosswalk={}, submit_f5=submit,replay=replay,
        session=SimpleNamespace(_finished=True,_begun=True,finish=lambda:trace,encode_plan=lambda:b'{}'))
    monkeypatch.setattr(campaign.time,'monotonic',lambda:clock[0])
    monkeypatch.setattr(campaign,'create_preparation',lambda **kw:context)
    monkeypatch.setattr(ibex_pulp_online,'make_ibex_pulp_online_runtime',build)
    result = campaign._run_f5_descriptor(SimpleNamespace(scenario_id='x',compose='c',capability='p',supplement='s'),
        cases=[('F5','00'*8),('F5','01'*8)], mode='original',case_root=tmp_path,
        base=tmp_path,cache=tmp_path, rounds=32,command_trace=None,max_wall_seconds=1)
    assert result['case_count'] == 1 and result['budget_ended'] is True
    assert result['execution_seconds'] == 2 and result['wall_budget_overrun_seconds'] == 1
    assert result['replay_matches'] is True
    assert calls == [bytes(8),'replay','close']
    assert json.loads((tmp_path/'original/records.json').read_text()) == ['F5:'+'00'*8]


def test_shared_wall_budget_can_finish_zero_cases_without_masking_failure(monkeypatch):
    from myfuzz.runtime import campaign as shared
    from myfuzz.runtime.engine import PersistentCampaignRuntime
    from myfuzz.runtime.flows.storage import StorageFlowBackend
    from tests.runtime.test_persistent_engine import _world, FakePersistentRuntime, raw_of
    from tests.runtime.test_storage_kernel import FakeScenarioSession, directed_case, directed_sequence
    clock = [0.]
    def ticking():
        clock[0] += 1
        return clock[0]
    monkeypatch.setattr(shared,'PersistentCampaignRuntime',lambda *args,**kw:PersistentCampaignRuntime(*args,clock=ticking,**kw))
    bound, runner, log, path = _world()
    runtime = FakePersistentRuntime(runner,FakeScenarioSession())
    report = shared.run_directed_campaign(bound_plan=bound,backend=StorageFlowBackend(runtime=runtime,flow_id='F4'),
        sequence=directed_sequence(directed_case('a',records=(raw_of(1),)),plan_sha256=bound.plan_sha256),
        budget=shared.CampaignBudget(max_wall_seconds=.1))
    assert report['case_count'] == report['sequence_case_count'] == 0
    assert report['directed_cases'] == [] and report['budget_ended'] is True
    assert report['state'] == 'CLOSED' and report['faults'] == []
    assert runtime.records == []


@pytest.mark.parametrize('planned', [[('F2','00'),('F4','00')], [('F1','00'),('F2','00'),('F3','00'),('F4','00')]])
@pytest.mark.parametrize('prefix', [[], ['F4:00']])
def test_empty_mixed_fresh_preserves_original_preparation_and_admission(monkeypatch,tmp_path,planned,prefix):
    from myfuzz.local_harness import generated_execution_admission as admission
    calls = []
    prepared = SimpleNamespace(runtime_paths=(),graph={})
    context = SimpleNamespace(artifacts={},input_digests={},compiled_inputs=lambda:{},close=lambda:None,
        attach_runtime=lambda **kw:calls.append(('attach',)),
        register_prepared_paths=lambda **kw:calls.append(('register',)))
    def prepare(**kw):
        calls.append(('prepare',kw['flow_ids']))
        context.flow_ids = kw['flow_ids']
        return context
    def create(**kw):
        calls.append(('admit',kw.get('mixed_flows'),kw.get('memory_flows',False),kw['max_cases']))
        return SimpleNamespace(runner=SimpleNamespace(sessions={}),session=SimpleNamespace(_runtime_prepared=prepared),
            runtime_path_admission=SimpleNamespace(prepared=prepared),finish=lambda:{},trace=SimpleNamespace(events=[]),
            execution_audit=lambda:{},replay=lambda prefix:{'matches':True})
    def bind(*args,**kw):
        calls.append(('bind',))
        return SimpleNamespace(documentary=lambda:{},close=lambda:None)
    def execute(**kw):
        calls.append(('execute',kw['sequence']['cases']))
        return {'case_count':len(prefix),'sequence_case_count':len(prefix),'budget_ended':len(kw['sequence']['cases'])>len(prefix)}
    monkeypatch.setattr(campaign,'select_case_records',lambda *a,**kw:planned if kw['records'] is None else [tuple(row.split(':')) for row in kw['records']])
    monkeypatch.setattr(campaign,'create_preparation',prepare)
    monkeypatch.setattr(campaign,'plan_bindings',lambda context:())
    monkeypatch.setattr(campaign,'compile_execution_plan',lambda *a,**kw:SimpleNamespace(document=lambda:{},document_bytes=b'{}',identity_sha256='a'*64))
    monkeypatch.setattr(campaign,'case_sequence_for_plan',lambda **kw:{'cases':list(kw['cases'])})
    monkeypatch.setattr(admission,'create_compiled_execution',create)
    monkeypatch.setattr(campaign,'bind_execution_plan',bind)
    monkeypatch.setattr(campaign,'MixedStorageFlowBackend',lambda **kw:None)
    monkeypatch.setattr(campaign,'run_directed_campaign',execute)
    monkeypatch.setattr(campaign.shutil,'copytree',lambda *a,**kw:None)
    monkeypatch.setattr(campaign.shutil,'move',lambda *a,**kw:None)
    descriptor=SimpleNamespace(compose='c',capability='p',supplement='s',rounds=32,
        scenario_id='s',flow_ids=('F2','F4'),shared_slots=False,
        executors={'F2':'compiled_f4_obi_apb','F4':'compiled_f4_obi_apb'},
        executor=lambda flow:'compiled_f4_obi_apb')
    memory=any(flow in ('F1','F3') for flow,_ in planned)
    original=campaign.run_descriptor(descriptor,preparation_memory_flows=memory,execution_case_capacity=len(planned),flow='mixed',mode='original',case_root=tmp_path,
        base_dir=tmp_path,max_wall_seconds=.1,log=lambda row:None)
    original_calls=list(calls);calls.clear()
    memory=any(flow in ('F1','F3') for flow,_ in planned)
    fresh=campaign.run_descriptor(descriptor,flow='mixed',mode='fresh',case_root=tmp_path,
        base_dir=tmp_path,sequence=prefix,allow_empty_sequence=not prefix,
        preparation_memory_flows=memory,execution_case_capacity=len(planned),log=lambda row:None)
    assert original['case_count'] == fresh['case_count'] == len(prefix)
    assert calls[:5] == original_calls[:5]
    assert [row[0] for row in calls] == ['prepare','admit','attach','register','bind','execute']
    assert calls[0] == ('prepare',('F1','F2','F3','F4') if memory else ('F2','F4'))
    assert calls[1] == ('admit',True,memory,len(planned)+1)
    assert calls[-1] == ('execute',[tuple(row.split(':')) for row in prefix])


@pytest.mark.parametrize('value', [0,1,'yes'])
def test_preparation_contract_requires_boolean(monkeypatch,tmp_path,value):
    monkeypatch.setattr(campaign,'select_case_records',lambda *a,**kw:pytest.fail('selected'))
    with pytest.raises(campaign.GenericScenarioRefused) as error:
        campaign.run_descriptor(SimpleNamespace(),flow='mixed',mode='original',
            case_root=tmp_path,base_dir=tmp_path,preparation_memory_flows=value)
    assert error.value.pointer == '/preparation_memory_flows'


def test_memory_case_cannot_disable_preparation(monkeypatch,tmp_path):
    monkeypatch.setattr(campaign,'select_case_records',lambda *a,**kw:[('F3','00')])
    monkeypatch.setattr(campaign,'create_preparation',lambda **kw:pytest.fail('prepared'))
    with pytest.raises(campaign.GenericScenarioRefused) as error:
        campaign.run_descriptor(SimpleNamespace(rounds=32,executors={},flow_ids=()),flow='mixed',mode='original',
            case_root=tmp_path,base_dir=tmp_path,preparation_memory_flows=False)
    assert error.value.detail['reason'] == 'selected-memory-flow-requires-memory-preparation'


@pytest.mark.parametrize('capacity',[True,False,0,-1,1,65536,1.5,'4'])
def test_invalid_capacity_rejected_before_preparation(monkeypatch,tmp_path,capacity):
    monkeypatch.setattr(campaign,'select_case_records',lambda *a,**kw:[('F4','00')]*2)
    monkeypatch.setattr(campaign,'create_preparation',lambda **kw:pytest.fail('prepared'))
    with pytest.raises(campaign.GenericScenarioRefused) as error:
        campaign.run_descriptor(SimpleNamespace(rounds=32,executors={},flow_ids=()),flow='mixed',mode='original',
            case_root=tmp_path,base_dir=tmp_path,execution_case_capacity=capacity)
    assert error.value.pointer == '/execution_case_capacity'


def test_f6_capacity_respects_sixteen_slot_limit(tmp_path):
    with pytest.raises(campaign.GenericScenarioRefused) as error:
        campaign._run_f6_descriptor(SimpleNamespace(),cases=[('F6','00'*8)],mode='original',
            case_root=tmp_path,base=tmp_path,cache=tmp_path,rounds=32,command_trace=None,
            execution_case_capacity=17)
    assert error.value.pointer == '/execution_case_capacity'
    assert not list(tmp_path.iterdir())


def test_f5_online_selector_runs_after_previous_submission_and_honors_budget(monkeypatch, tmp_path):
    import json
    from myfuzz.integration import ibex_pulp_online
    from myfuzz.scenario.session_runtime import OnlineCaseReceipt
    clock=[10.0]; calls=[]
    trace=SimpleNamespace(genome_sha256='a'*64,status='complete',events=[],local_ticks={},semantic_sha256='b'*64,manifest_sha256='c'*64)
    context=SimpleNamespace(close=lambda:None,assert_current=lambda:None)
    class Selector:
        def choose(self):
            calls.append('choose')
            return 'F5:'+'01'*8
        def settle(self,row):
            calls.append('settle')
    def submit(raw):
        calls.append('submit');clock[0]+=2
        return OnlineCaseReceipt('a',0,0,(),{},{},'running')
    runtime=SimpleNamespace(compiled_f5_crosswalk={},submit_f5=submit,
        session=SimpleNamespace(_finished=True,_begun=True,finish=lambda:trace,encode_plan=lambda:b'{}'))
    monkeypatch.setattr(campaign.time,'monotonic',lambda:clock[0])
    monkeypatch.setattr(campaign,'create_preparation',lambda **kw:context)
    monkeypatch.setattr(ibex_pulp_online,'make_ibex_pulp_online_runtime',lambda **kw:runtime)
    result=campaign._run_f5_descriptor(SimpleNamespace(scenario_id='x',compose='c',capability='p',supplement='s'),
        cases=[('F5','01'*8)],mode='original',case_root=tmp_path,base=tmp_path,cache=tmp_path,
        rounds=32,command_trace=None,max_wall_seconds=1,execution_mode='search',
        record_selector=Selector(),selected_count=3)
    assert calls==['choose','submit','settle']
    assert result['case_count']==1 and result['budget_ended'] is True
    assert result['requested_case_count']==3
    assert json.loads((tmp_path/'original/records.json').read_text()) == ['F5:'+'01'*8]



def test_online_selector_runs_repeated_catalog_record_after_prior_settlement():
    from myfuzz.runtime.campaign import run_directed_campaign, CampaignBudget
    from myfuzz.runtime.flows.storage import StorageFlowBackend
    from myfuzz.search.descriptor_search import RecordSelector
    from tests.runtime.test_persistent_engine import _world, FakePersistentRuntime, raw_of
    from tests.runtime.test_storage_kernel import FakeScenarioSession, directed_case, directed_sequence
    bound, runner, _, _ = _world()
    selector = RecordSelector(SimpleNamespace(flow_ids=('F4',)), flow='F4',
        records=['F4:' + raw_of(1)], policy='state', seed=7, cases=2)
    seq = directed_sequence(directed_case('catalog:F4:0', records=(raw_of(1),)), plan_sha256=bound.plan_sha256)
    report = run_directed_campaign(bound_plan=bound,
        backend=StorageFlowBackend(runtime=FakePersistentRuntime(runner, FakeScenarioSession()), flow_id='F4'),
        sequence=seq, budget=CampaignBudget(max_cases=3), record_selector=selector, selected_count=2,
        case_id_prefix='catalog')
    assert selector.sequence == ['F4:' + raw_of(1)] * 2
    assert report['case_count'] == 2
    assert [r['testcase_id'] for r in report['directed_cases']] == ['catalog:F4:0', 'catalog:F4:1']


def test_online_selector_rolls_back_budget_refusal(monkeypatch):
    from myfuzz.runtime import campaign as shared
    from myfuzz.runtime.engine import PersistentCampaignRuntime
    from myfuzz.runtime.contracts import GenericRuntimeRefused
    from myfuzz.runtime.flows.storage import StorageFlowBackend
    from myfuzz.search.descriptor_search import RecordSelector
    from tests.runtime.test_persistent_engine import _world, FakePersistentRuntime, raw_of
    from tests.runtime.test_storage_kernel import FakeScenarioSession, directed_case, directed_sequence
    bound, runner, _, _ = _world()
    selector = RecordSelector(SimpleNamespace(flow_ids=('F4',)), flow='F4',
        records=['F4:' + raw_of(1)], policy='state', seed=7, cases=2)
    before = selector.document()
    def refuse(self, row): raise GenericRuntimeRefused('generic-budget-refused', '/max_wall_seconds')
    monkeypatch.setattr(PersistentCampaignRuntime, 'submit', refuse)
    seq = directed_sequence(directed_case('catalog:F4:0', records=(raw_of(1),)), plan_sha256=bound.plan_sha256)
    report = shared.run_directed_campaign(bound_plan=bound,
        backend=StorageFlowBackend(runtime=FakePersistentRuntime(runner, FakeScenarioSession()), flow_id='F4'),
        sequence=seq, budget=shared.CampaignBudget(max_cases=3), record_selector=selector, selected_count=2,
        case_id_prefix='catalog')
    assert selector.document() == before
    assert selector.pending is None
    assert report['case_count'] == 0 and report['budget_ended']


def test_online_selector_partial_prefix_replays_same_decisions(monkeypatch):
    from myfuzz.runtime import campaign as shared
    from myfuzz.runtime.engine import PersistentCampaignRuntime
    from myfuzz.runtime.contracts import GenericRuntimeRefused
    from myfuzz.runtime.flows.storage import StorageFlowBackend
    from myfuzz.search.descriptor_search import RecordSelector
    from tests.runtime.test_persistent_engine import _world, FakePersistentRuntime, raw_of
    from tests.runtime.test_storage_kernel import FakeScenarioSession, directed_case, directed_sequence
    descriptor = SimpleNamespace(flow_ids=('F4',))
    def make_selector(): return RecordSelector(descriptor,flow='F4',records=['F4:'+raw_of(1), 'F4:'+raw_of(2)],policy='state',seed=7,cases=3)
    def run(selector, expected=None, selected_count=3):
        bound, runner, _, _ = _world()
        seq = directed_sequence(directed_case('catalog:F4:0',records=(raw_of(1),)),directed_case('catalog:F4:1',records=(raw_of(2),)),plan_sha256=bound.plan_sha256)
        return shared.run_directed_campaign(bound_plan=bound,backend=StorageFlowBackend(runtime=FakePersistentRuntime(runner,FakeScenarioSession()),flow_id='F4'),sequence=seq,
            budget=shared.CampaignBudget(max_cases=4),record_selector=selector,selected_count=selected_count,expected_records=expected,case_id_prefix='catalog')
    original_submit=PersistentCampaignRuntime.submit
    def reject_second(self,row):
        if self.cases: raise GenericRuntimeRefused('generic-budget-refused','/max_wall_seconds')
        return original_submit(self,row)
    monkeypatch.setattr(PersistentCampaignRuntime,'submit',reject_second)
    original=make_selector();first=run(original)
    assert first['case_count']==1 and first['budget_ended']
    assert len(original.sequence)==1 and original.pending is None
    monkeypatch.setattr(PersistentCampaignRuntime,'submit',original_submit)
    fresh=make_selector();second=run(fresh,original.sequence,selected_count=1)
    assert second['case_count']==1
    assert fresh.document()==original.document()
    assert first['sequence_sha256']==second['sequence_sha256']
