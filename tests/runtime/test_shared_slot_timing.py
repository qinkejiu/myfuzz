"""Controlled wall clock separates campaign work from export and fresh replay."""
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
import json
import pytest


@pytest.mark.parametrize('budget,requested,expected_cases,execution_mode',
    [(None,2,2,'acceptance'),(0,2,1,'acceptance'),(None,2,2,'search')])
@pytest.mark.parametrize('recording',[False,True])
@pytest.mark.parametrize('online',[False,True])
def test_shared_campaign_clock_excludes_finish_replay_and_scope_exit(tmp_path, monkeypatch,
        budget, requested, expected_cases, execution_mode,recording,online):
    import myfuzz.runtime.preparation as preparation
    import myfuzz.runtime.generic_campaign as campaign
    import myfuzz.integration.compiled_f6 as f6
    import myfuzz.local_harness.build as build
    import myfuzz.local_harness.execution_validation as validation
    import myfuzz.composition.component_profile as profiles
    import myfuzz.runtime.flows.shared_slots as slots
    import myfuzz.runtime.recorded_commands as commands
    monkeypatch.setattr(commands,'recorded_command_documents',lambda rows,**kwargs:
        {phase:{'sessions':{}} for phase in kwargs['executions']})
    clock = SimpleNamespace(now=0)
    def advance(seconds):clock.now += seconds
    monkeypatch.setattr(slots,'time',SimpleNamespace(monotonic=lambda:clock.now))
    real_json = campaign._json
    def measured_export(document, path, **kwargs):
        real_json(document, path, **kwargs)
        if path.name in ('prefix.json','compiled_f6_prefix.json','shared_storage_raw.json'):advance(2)
        elif path.name=='replay.json':advance(3)
    monkeypatch.setattr(campaign,'_json',measured_export)
    monkeypatch.setattr(profiles,'supervisor_available',lambda:(False,'test-host'))
    monkeypatch.setattr(build,'host_source_discovery_scope',lambda **kw:nullcontext())
    monkeypatch.setattr(build,'harness_validation_scope',lambda:nullcontext())
    @contextmanager
    def scope():
        yield
        advance(19)
    monkeypatch.setattr(validation,'execution_validation_scope',scope)
    class Preparation:
        def assert_current(self):pass
        def compiled_inputs(self):return {}
        def attach_runtime(self,**kwargs):pass
        def register_prepared_paths(self,**kwargs):pass
        def close(self):advance(17)
        artifacts={}
    def prepare(**kwargs):advance(2);return Preparation()
    monkeypatch.setattr(preparation,'create_preparation',prepare)
    class Runtime:
        def __init__(self,**kwargs):
            advance(3);self.contract={'program_contract':{'shared_slots':{'enabled_flows':['F4','F6']},'slot_count':2}}
            self.session=SimpleNamespace(_runtime_prepared=SimpleNamespace(runtime_paths=(),graph=object()))
            self.runner=SimpleNamespace(sessions={},failure_status=None,event_count=0,events_since=lambda i:());self.execution_binding={};self.execution_binding_sha256='a'*64
            self.shared_storage_raw={};self.rows=[]
        def begin(self):advance(5)
        def submit(self,raw,*,flow):advance(7);self.rows.append({'flow':flow});return {'status':'passed'}
        def finish(self):advance(11);return {'records':[], 'flow_records':self.rows,'original_execution_audit':{'identities':{}}}
        def replay(self,prefix,*,audit_sink):advance(13);return {'matches':True,'execution_audit':{'identities':{}}}
    monkeypatch.setattr(f6,'CompiledF6Runtime',Runtime)
    descriptor=SimpleNamespace(capability=Path('cap'),compose=Path('compose'),supplement=Path('supplement'),
        flow_ids=('F4','F6'),scenario_id='shared')
    class Selector:
        def attach_runtime(self,runtime):self.runtime=runtime
        def start_search_clock(self,actual_clock,started):
            self.clock=actual_clock;self.started=started
        def choose(self):return 'F4:55000000'
        def settle(self,record):assert self.clock()-self.started==7*len(self.runtime.rows)
        def finish_search_clock(self):advance(3);self.finished=self.clock()
    selector=Selector() if online else None
    result=slots.run_shared_slot_descriptor(descriptor,cases=[('F4','55000000')]*requested,
        mode='original',case_root=tmp_path,base=tmp_path,cache=None,rounds=1,capacity=2,
        execution_mode=execution_mode,max_wall_seconds=budget,record_selector=selector,
        selected_count=requested if online else None,expected_records=None,
        command_trace=SimpleNamespace(export_sessions=lambda:[]) if recording else None)
    assert result['execution_seconds']==7*expected_cases+(3 if online else 0)
    assert result['finish_export_seconds']==17
    replay_seconds=16 if execution_mode=='acceptance' else 0
    assert result['replay_seconds']==replay_seconds
    assert result['wall_seconds']==2+3+5+7*expected_cases+(3 if online else 0)+17+replay_seconds+19+17
    assert result['wall_budget_overrun_seconds']==((10 if online else 7) if budget==0 else 0)
    assert result['case_count']==expected_cases
    assert result['budget_ended'] is (budget==0)
    saved=json.loads((tmp_path/'original'/'summary.json').read_text())
    assert saved['wall_seconds']==result['wall_seconds']
    if recording:
        assert (tmp_path/'original'/'local_commands.json').is_file()

