"""Actual Runner/session coordinator with software transport, never native evidence."""
import copy
import json
from pathlib import Path
import pytest
from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.local_harness.vexii_axi_session import GeneratedReducedAxiCpuSession
from myfuzz.local_harness.vexii_axi_fields import SHAPES, STEP_PORTS
from myfuzz.local_harness.wire import parse_driver_receipt
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import OwnershipMap
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.reduced_axi_journal import ReducedAxiJournalConsumer
from tests.local_harness.test_vexii_generated_cpu import artifact

ROOT = Path(__file__).resolve().parents[2]

@pytest.fixture(scope='module')
def runtime():
    return artifact()

@pytest.fixture
def session_factory(monkeypatch, runtime, tmp_path):
    def begin(self, case):
        self._execution = f'{getattr(self, "starts", 0)+1:032x}'
        self.starts = getattr(self, 'starts', 0)+1
        self._case_id = case
        self._tick_base = self.local_ticks
        self._sequence = 0
        self._process = object()
    def end(self):
        self._process = None
        self._case_id = None
        self.ends = getattr(self, 'ends', 0)+1
    def command(self, operation, fields):
        self.transports = getattr(self, 'transports', 0)+1
        before = self.local_ticks-self._tick_base
        row = {p+'_'+r:0 for p,s in SHAPES.items() for r in s}
        row.update(zip(STEP_PORTS, fields)); row.update(getattr(self, 'signals', {}))
        sample = dict(local_tick=before+1, pre={'backend':row},post={'backend':copy.deepcopy(row)})
        payload = dict(schema_version='local_driver_result.v1',kind=self.artifact_kind,
            samples=[sample],pre_backend=row,observations={'physical':{}},rdata=0,error=0)
        raw = json.dumps(payload, sort_keys=True,separators=(',',':')).encode().hex()
        wire = f'RESULT {self._execution} {self._sequence+1:x} {before:x} {before+1:x} {raw}\n'
        receipt = parse_driver_receipt(wire.strip(), execution=self._execution,
            sequence=self._sequence+1,current_tick=before,kind=self.artifact_kind,
            clock_schedule=self._artifact_document.get('clock_schedule'))
        self._last_wire_reply = wire
        self._sequence += 1; self.local_ticks += 1
        return receipt
    monkeypatch.setattr(GeneratedLocalSession,'prepare_local',lambda self: None)
    monkeypatch.setattr(GeneratedLocalSession,'begin_case',begin)
    monkeypatch.setattr(GeneratedLocalSession,'end_case',end)
    monkeypatch.setattr(GeneratedLocalSession,'command',command)
    made=[]
    def make():
        made.append(None)
        return GeneratedReducedAxiCpuSession(runtime,base_dir=ROOT,cache_dir=tmp_path,
            memory=PersistentMemory(regions=(MemoryRegion(f'ram-{len(made)}',0,4096),),
                initialization_seed=0,max_initialized_bytes=4096))
    return make


def runner(factory, file=False, count=1):
    sessions={f'alias-{n}':factory() for n in range(count)}
    r=ScenarioRunner(sessions=sessions,ownership=OwnershipMap({}),bindings=())
    if file:r.enable_event_journal(chunk_size=2)
    return r


@pytest.mark.parametrize('file',[False,True])
def test_actual_runner_lifecycle_and_read(session_factory,file):
    r=runner(session_factory,file)
    c=r.sessions['alias-0']
    assert not r.events
    identity=r.identity_document()
    assert identity['reduced_axi_observation_streams'][0]['runner_component']=='alias-0'
    assert identity==r.identity_document()
    r.begin_test('case')
    assert not c.observation_stream_source.pending()
    c.signals={'i_arvalid':1,'i_araddr':12,'i_arsize':2}
    r._step_once('alias-0')
    assert not c.runtime_events and not c.observation_stream_source.pending()
    c.signals={'i_rready':1}
    r._step_once('alias-0')
    r.finalize()
    report=r.reduced_axi_observation_reports()['alias-0']
    assert report['status']=='complete', report
    assert len(report['boundary_observations'])==1
    assert report['authority']=='observation_only'
    assert report['journal_event_id']==len(r.events)
    events=r.events
    r.finalize()
    assert r.events==events and r.reduced_axi_observation_reports()['alias-0']==report
    assert c._process is None


@pytest.mark.parametrize('file',[False,True])
def test_two_aliases_reset_empty_lifecycle_and_global_ids(session_factory,file):
    r=runner(session_factory,file,2); r.begin_test('case')
    r._events.append_unchecked(dict(event_id=len(r.events)+1,kind='unrelated'))
    for alias in r.sessions:r._step_once(alias)
    r.reset_all('warm_all'); r.finalize()
    for alias,report in r.reduced_axi_observation_reports().items():
        assert report['status']=='complete', report
        assert report['journal_event_id']==len(r.events)
        assert report['operation_count']==5
    assert [e['event_id'] for e in r.events]==list(range(1,len(r.events)+1))
    assert len([e for e in r.events if e.get('kind')=='reduced_axi_raw'])==2


def test_mutable_observation_tamper_poison_no_retry(session_factory):
    r=runner(session_factory); r.begin_test('case'); c=r.sessions['alias-0']
    c.step_local({}); c.runtime_events[0]['local_tick']=999
    with pytest.raises(Exception):r._append_external_events('alias-0',len(r.events))
    assert c.observation_stream_source.state=='poisoned'
    count=len(r.events)
    with pytest.raises(Exception):r._append_external_events('alias-0',len(r.events))
    assert len(r.events)==count
    r.finalize(); assert c._process is None
    assert r.reduced_axi_observation_reports()['alias-0']['status']=='failed'


def test_duplicate_session_alias_rejected(session_factory):
    c=session_factory()
    with pytest.raises(ValueError,match='alias'):
        ScenarioRunner(sessions={'a':c,'b':c},ownership=OwnershipMap({}),bindings=())


def test_pending_checkpoint_preserves_scope(session_factory):
    r=runner(session_factory);r.begin_test('case');c=r.sessions['alias-0']
    c.signals={'i_arvalid':1,'i_araddr':12,'i_arsize':2};r._step_once('alias-0')
    r.finalize();report=r.reduced_axi_observation_reports()['alias-0']
    assert report['status']=='complete' and report['pending']['i']['read']
    assert not any(e.get('kind')=='reduced_axi_reset' for e in r.events)
    assert c._axi_observer.scope is not None

@pytest.mark.parametrize('stage',['operation','original','sidecar','ack_before','ack_after','lookup'])
@pytest.mark.parametrize('file',[False,True])
def test_import_failure_is_terminal_and_cleanup_reaps_all(session_factory,monkeypatch,stage,file):
    r=runner(session_factory,file,2);r.begin_test('case');c=r.sessions['alias-0']
    c.step_local({})
    source=c.observation_stream_source
    append=r._events.append
    kinds={'operation':'reduced_axi_source_operation','original':'reduced_axi_raw','sidecar':'reduced_axi_journal_binding'}
    def fail_append(row,**kw):
        append(row,**kw)
        if row.get('kind')==kinds.get(stage):raise OSError('after append effect')
    monkeypatch.setattr(r._events,'append',fail_append)
    if stage.startswith('ack'):
        ack=source.ack
        def fail_ack(token):
            if stage=='ack_after':ack(token)
            raise OSError('ACK failure')
        monkeypatch.setattr(source,'ack',fail_ack)
    if stage=='lookup':
        monkeypatch.setattr(source,'lookup',lambda token: (_ for _ in ()).throw(OSError('export failure')))
    with pytest.raises(Exception):r._append_external_events('alias-0',len(r.events))
    count=len(r.events)
    assert source.state=='poisoned' and c.runtime_events
    with pytest.raises(Exception):r._append_external_events('alias-0',len(r.events))
    assert len(r.events)==count
    r.finalize();r.finalize()
    assert all(s._process is None for s in r.sessions.values())
    report=r.reduced_axi_observation_reports()['alias-0']
    assert report['status']=='failed' and report['import_failure']['evidence_missing']


def test_ownership_drift_before_transport(session_factory):
    r=runner(session_factory);r.begin_test('case');old=r.sessions['alias-0']
    r.sessions['alias-0']=session_factory()
    with pytest.raises(Exception):r._step_once('alias-0')
    assert not getattr(r.sessions['alias-0'],'transports',0)
    assert old.observation_stream_source.state=='poisoned'
    r.sessions['alias-0']=old;r.finalize()


def test_legacy_buffer_stays_observation_only():
    class Legacy:
        runtime_events=[dict(kind='reduced_axi_raw',raw_event_ref=1)]
        def begin_case(self,case):pass
        def end_case(self):pass
        def step_local(self,inputs):return {}
    r=ScenarioRunner(sessions={'legacy':Legacy()},ownership=OwnershipMap({}),bindings=())
    r.begin_test('case');r._step_once('legacy');r.finalize()
    assert r.reduced_axi_observation_reports()=={}
    assert len([e for e in r.events if e.get('kind')=='reduced_axi_raw'])==1
    assert not any(e.get('kind')=='reduced_axi_journal_binding' for e in r.events)


def test_budget_preflight_no_transport_and_bounded_failure(session_factory):
    from myfuzz.scenario.contracts import ResourceBudget
    r=runner(session_factory)
    r.set_resource_budget(ResourceBudget(max_semantic_records=4))
    with pytest.raises(Exception):r.begin_test('case')
    c=r.sessions['alias-0']
    assert not getattr(c,'starts',0) and not getattr(c,'transports',0)
    assert c.observation_stream_source.state=='poisoned'
    r.finalize()
    assert len(json.dumps(r.reduced_axi_observation_reports()))<16384


def test_imported_record_bound_and_host_closure(session_factory):
    from myfuzz.scenario.host_identity import HARNESS_HOST_SOURCE_PATHS
    from myfuzz.scenario.evidence import _evidence_record_bound,_final_state_growth_bound
    from myfuzz.scenario.contracts import ResourceBudget
    from types import SimpleNamespace
    r=runner(session_factory)
    # Real genome for the record bound codec, with no native side effects.
    from myfuzz.scenario.genome import ScenarioGenome
    assert 'src/myfuzz/scenario/reduced_axi_runner_stream.py' in HARNESS_HOST_SOURCE_PATHS
    config=r.identity_document()['reduced_axi_observation_streams'][0]
    genome=ScenarioGenome('case','CPU_TO_IP','path',('alias-0',),1,())
    assert _final_state_growth_bound(genome,r,ResourceBudget())>=config['max_report_growth_bytes']
    assert _evidence_record_bound(genome,r,ResourceBudget())>=config['max_journal_record_bytes']

@pytest.mark.parametrize('format',['jsonl','zlib'])
@pytest.mark.parametrize('file',[False,True])
def test_durable_writer_reload_and_tail_refusal(session_factory,tmp_path,format,file):
    from myfuzz.scenario.replay import ScenarioTrace
    from myfuzz.scenario.event_journal import JsonlEventView,ZlibChunkEventView
    from myfuzz.integration.scenario_rfuzz_live import _write_online_trace_jsonl,_write_online_trace_zlib
    r=runner(session_factory,file);r.begin_test('case');r._step_once('alias-0');r.finalize()
    trace=ScenarioTrace('0'*64,'complete',r.events,r.local_ticks,'','1'*64)
    if format=='jsonl':
        saved=_write_online_trace_jsonl(tmp_path,trace)
        path=tmp_path/'online_events.jsonl';view=JsonlEventView(path,len(r.events))
    else:
        saved=_write_online_trace_zlib(tmp_path,trace,chunk_events=2)
        path=tmp_path/'online_events.zlib';view=ZlibChunkEventView(path,len(r.events))
        view.verify_trace_semantic(status=trace.status,local_ticks=trace.local_ticks,expected_sha256=saved.semantic_sha256)
    s=r._reduced_axi_streams.streams['alias-0']
    def consume(events):
        c=ReducedAxiJournalConsumer(s['binding'],runner_component='alias-0',runtime_document=s['runtime'])
        for event in events:c.consume(event)
        return c.finalize()
    assert consume(view)['status']=='complete'
    assert consume(tuple(view)[:-1])['status']=='failed'
    changed=list(copy.deepcopy(tuple(view)))
    raw=next(e for e in changed if e.get('kind')=='reduced_axi_raw')
    raw['raw_sample']['pre']['backend']['i_araddr']=4
    assert consume(changed)['status']=='failed'
    path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(ValueError):
        (JsonlEventView if format=='jsonl' else ZlibChunkEventView)(path,len(r.events))


@pytest.mark.parametrize('delta',[-1,0,1])
def test_semantic_preflight_capacity_boundary(session_factory,delta):
    from myfuzz.scenario.contracts import ResourceBudget
    r=runner(session_factory)
    # Admission reserves control/binding + worst eleven-observation operation,
    # scheduler row and one budget marker before native begin.
    r.set_resource_budget(ResourceBudget(max_semantic_records=26+delta))
    c=r.sessions['alias-0']
    if delta<0:
        with pytest.raises(Exception):r.begin_test('case')
        assert not getattr(c,'starts',0)
    else:
        r.begin_test('case');assert c.starts==1
    r.finalize()


def test_explicit_limits_and_source_operation_refusal_before_transport(session_factory):
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'source':{'max_operations':1}}})
    r.begin_test('case')
    with pytest.raises(Exception):r._step_once('a')
    assert not getattr(c,'transports',0)
    assert c.observation_stream_source.state=='poisoned'
    r.finalize()


@pytest.mark.parametrize('tamper',['observer','runtime_list','tuple','extra','delete','artifact'])
def test_source_and_observation_tampering(session_factory,tamper):
    r=runner(session_factory);r.begin_test('case');c=r.sessions['alias-0'];c.step_local({})
    if tamper=='observer':c._axi_observer=copy.copy(c._axi_observer)
    if tamper=='runtime_list':c.runtime_events=copy.deepcopy(c.runtime_events)
    if tamper=='tuple':c.runtime_events[0]['raw_sample']['pre']['backend']=(1,2)
    if tamper=='extra':c.runtime_events.append(copy.deepcopy(c.runtime_events[0]))
    if tamper=='delete':c.runtime_events.clear()
    if tamper=='artifact':c._artifact_document['kind']='reduced_dual_axi_irq_cpu'
    with pytest.raises(Exception):r._append_external_events('alias-0',len(r.events))
    assert r.reduced_axi_observation_reports()['alias-0']['status']=='failed'
    r.finalize();assert c._process is None


def test_begin_failure_cleanup_lifecycle_is_captured(session_factory,monkeypatch):
    r=runner(session_factory,count=2)
    other=r.sessions['alias-1']
    def broken_begin(case):raise OSError('fixture begin')
    monkeypatch.setattr(other,'begin_case',broken_begin)
    with pytest.raises(OSError):r.begin_test('case')
    r.finalize();r.finalize()
    s=r._reduced_axi_streams.streams['alias-0']
    operations=[e['operation']['kind'] for e in r.events if e.get('kind')=='reduced_axi_source_operation' and e['component']=='alias-0']
    assert operations==['begin_scope','end_scope','seal']
    assert r.reduced_axi_observation_reports()['alias-0']['status']=='complete'
    assert all(c._process is None for c in r.sessions.values())


def test_provenance_preserves_exact_source_envelopes(session_factory):
    from types import SimpleNamespace
    r=runner(session_factory)
    r._provenance=SimpleNamespace(decorate=lambda row: dict(row,provenance={'proof_scope':'observation_only'}))
    r.begin_test('case');r._step_once('alias-0');r.finalize()
    assert r.reduced_axi_observation_reports()['alias-0']['status']=='complete'
    assert any('provenance' in e for e in r.events if 'outputs' in e)
    assert all('provenance' not in e for e in r.events if e.get('kind','').startswith('reduced_axi_'))


@pytest.mark.parametrize('delta',[-1,0,1])
def test_source_fifo_capacity_preflight_boundary(session_factory,delta):
    required=prospective_begin_bytes(session_factory)
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'source':{
            'max_pending_bytes':required+delta}}})
    if delta<0:
        with pytest.raises(Exception):r.begin_test('case')
        assert not getattr(c,'starts',0)
    else:r.begin_test('case');assert c.starts==1
    r.finalize()


def test_evidence_preflight_refusal_does_not_transport(session_factory):
    from myfuzz.scenario.contracts import ResourceBudget
    r=runner(session_factory)
    r.set_resource_budget(ResourceBudget())
    r.arm_evidence_meter(base_bytes=0,copy_counts={},max_evidence_record_bytes=1)
    with pytest.raises(Exception):r.begin_test('case')
    assert not getattr(r.sessions['alias-0'],'starts',0)
    r.finalize()


def test_report_is_metered_final_state(session_factory):
    r=runner(session_factory);r.begin_test('case');r._step_once('alias-0');r.finalize()
    assert r.final_state_document()['reduced_axi_observations']==r.reduced_axi_observation_reports()


@pytest.mark.parametrize('limit,value',[('max_events',24),('max_total_input_bytes',100000),
    ('max_retained_records',3),('max_pending',7),('max_scopes',1)])
def test_consumer_capacity_refuses_before_affected_transport(session_factory,limit,value):
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'consumer':{limit:value}}})
    if limit in ('max_events','max_total_input_bytes'):
        with pytest.raises(Exception):r.begin_test('case')
        assert not getattr(c,'starts',0)
    elif limit=='max_scopes':
        r.begin_test('case')
        with pytest.raises(Exception):r.reset_all('warm_all')
        assert c.starts==1
    else:
        r.begin_test('case')
        with pytest.raises(Exception):r._step_once('a')
        assert not getattr(c,'transports',0)
    r.finalize()

@pytest.mark.parametrize('delta',[-1,0,1])
def test_evidence_batch_capacity_boundary_before_transport(session_factory,delta):
    from myfuzz.scenario.contracts import ResourceBudget
    r=runner(session_factory)
    streams=r._reduced_axi_streams
    bound=streams.record_bound('alias-0')
    required=25*bound*2+streams.growth_bound('alias-0')
    reserve=8*1024*1024
    r.set_resource_budget(ResourceBudget(max_evidence_bytes=required+reserve+delta,
                                         evidence_termination_reserve_bytes=reserve))
    r.arm_evidence_meter(base_bytes=0,copy_counts={},max_evidence_record_bytes=bound,
        max_final_state_growth_bytes_per_operation=streams.growth_bound('alias-0'))
    c=r.sessions['alias-0']
    if delta<0:
        with pytest.raises(Exception):r.begin_test('case')
        assert not getattr(c,'starts',0)
    else:r.begin_test('case');assert c.starts==1
    r.finalize()


def test_long_scope_and_same_edge_read_write_reports_are_bounded(session_factory):
    r=runner(session_factory);c=r.sessions['alias-0']
    r.begin_test('scope-😀'*1024)
    before=len(json.dumps(r.final_state_document(),ensure_ascii=False).encode())
    c.signals=dict(i_arvalid=1,i_araddr=12,i_arsize=2,
        d_arvalid=1,d_araddr=16,d_arsize=2,d_awvalid=1,d_awaddr=20,d_awsize=2,
        d_wvalid=1,d_wdata=53,d_wstrb=15,d_wlast=1)
    r._step_once('alias-0')
    c.signals=dict(i_rready=1,d_rready=1,d_bready=1)
    r._step_once('alias-0');r.finalize()
    report=r.reduced_axi_observation_reports()['alias-0']
    assert report['status']=='complete'
    assert len(report['boundary_observations'])==3
    growth=len(json.dumps(r.final_state_document(),ensure_ascii=False).encode())-before
    assert growth<r._reduced_axi_streams.growth_bound('alias-0')
    write=next(b for b in report['boundary_observations'] if b['channel']=='b')
    assert write['aw_w_order']=='same_edge'
    assert write['request_event_ids'][0]==write['request_event_ids'][1]


def test_runtime_event_list_type_change_cannot_hide_in_json_projection(session_factory):
    r=runner(session_factory);r.begin_test('case');c=r.sessions['alias-0'];c.step_local({})
    # Numeric equality must not hide a change in the issued JSON type.
    c.runtime_events[0]['raw_sample']['pre']['backend']['i_araddr']=0.0
    with pytest.raises(Exception):r._append_external_events('alias-0',len(r.events))
    r.finalize()
    assert r.reduced_axi_observation_reports()['alias-0']['status']=='failed'


def test_global_consumer_failure_after_seal_poison_marks_run_failed(session_factory,monkeypatch):
    r=runner(session_factory);r.begin_test('case')
    c=r.sessions['alias-0'];consumer=r._reduced_axi_streams.streams['alias-0']['consumer']
    consume=consumer.consume
    def inject(event):
        consume(event)
        if event.get('kind')=='cleanup_marker':consumer._poison('injected_global_failure')
    monkeypatch.setattr(consumer,'consume',inject)
    end=c.end_case
    def cleanup():
        end();r._events.append_unchecked(dict(event_id=len(r.events)+1,kind='cleanup_marker'))
    monkeypatch.setattr(c,'end_case',cleanup)
    r.finalize()
    assert c._process is None
    assert r.failure_status=='environment_error'
    assert c.observation_stream_source.state=='poisoned'
    assert r.reduced_axi_observation_reports()['alias-0']['status']=='failed'


def test_exact_raw_capacity_still_allows_seal(session_factory):
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'consumer':{'max_raw_mappings':1}}})
    r.begin_test('case');r._step_once('a');r.finalize()
    assert r.reduced_axi_observation_reports()['a']['status']=='complete'


def test_replaced_session_cleanup_reaps_admitted_original(session_factory):
    r=runner(session_factory);r.begin_test('case');old=r.sessions['alias-0']
    r.sessions['alias-0']=session_factory()
    with pytest.raises(Exception):r._step_once('alias-0')
    r.finalize()
    assert old._process is None
    assert r.sessions['alias-0']._process is None


def test_predrain_diagnostic_failure_still_reaps_every_session(session_factory,monkeypatch):
    from types import SimpleNamespace
    r=runner(session_factory,count=2);r.begin_test('case')
    r._ordinary_apb_access_evidence=SimpleNamespace()
    def broken(*args):raise OSError('diagnostic drain failure')
    monkeypatch.setattr(r,'_append_external_events',broken)
    r.finalize();r.finalize()
    assert all(c._process is None for c in r.sessions.values())
    assert r.failure_status=='environment_error'

@pytest.mark.parametrize('file',[False,True])
def test_interleaved_callback_rows_preserve_true_original_ids(session_factory,monkeypatch,file):
    r=runner(session_factory,file);r.begin_test('case')
    append=r._events.append
    def interleave(row,**kw):
        append(row,**kw)
        if row.get('kind')=='reduced_axi_raw':
            append(dict(event_id=len(r._events)+1,kind='scheduler_interleave',component='scheduler'))
    monkeypatch.setattr(r._events,'append',interleave)
    r._step_once('alias-0');r.finalize()
    assert r.reduced_axi_observation_reports()['alias-0']['status']=='complete'
    raw=next(e for e in r.events if e.get('kind')=='reduced_axi_raw')
    side=next(e for e in r.events if e.get('kind')=='reduced_axi_journal_binding')
    assert side['observation_event_id']==raw['event_id']
    assert side['event_id']==raw['event_id']+2

@pytest.mark.parametrize('file',[False,True])
def test_preload_prefix_is_consumed_without_control_or_reindex(session_factory,file):
    from myfuzz.scenario.genome import MemoryImage
    r=runner(session_factory,file)
    r.preload_image(MemoryImage('boot','alias-0',0,'00000000'))
    assert r.events[0]['event_id']==1
    r.begin_test('case');r._step_once('alias-0');r.finalize()
    assert not any(e.get('kind')=='observation_stream_control' for e in r.events)
    binding=next(e for e in r.events if e.get('kind')=='reduced_axi_stream_binding')
    assert binding['producer_event_id']==1
    assert r.reduced_axi_observation_reports()['alias-0']['journal_event_id']==len(r.events)


@pytest.mark.parametrize('cap',[100,1000,5000])
def test_r4_1_individual_source_cap_refuses_before_effect(session_factory,cap):
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'source':{'max_operation_bytes':cap}}})
    with pytest.raises(Exception):r.begin_test('case');r._step_once('a')
    assert getattr(c,'starts',0)==0
    assert getattr(c,'transports',0)==0
    r.finalize()


def prospective_begin_bytes(factory, testcase='case'):
    # Independent oracle: use the actual accepted producer to make its empty
    # lifecycle envelope, then add the maximum supported failure slot. UUID is
    # fixed32hex, so its particular value cannot affect the encoded byte count.
    c=factory();s=c.admit_observation_stream(session_id='probe',observer_stream_id='probe')
    c.begin_case(testcase)
    operation=s.lookup(s.pending()[0]);c.end_case()
    operation['payload']['failure']={'type':'LocalCommandDeadlineExceeded','detail':'\U0010ffff'*512}
    return len(json.dumps(operation,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii'))


@pytest.mark.parametrize('delta',[-1,0,1])
def test_r4_1_empty_begin_cap_boundary_before_launch(session_factory,delta):
    required=prospective_begin_bytes(session_factory,'scope-😀')
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'source':{'max_operation_bytes':required+delta}}})
    if delta<0:
        with pytest.raises(Exception):r.begin_test('scope-😀')
        assert not getattr(c,'starts',0)
    else:
        r.begin_test('scope-😀');assert c.starts==1
        begin=next(e['operation'] for e in r.events if e.get('kind')=='reduced_axi_source_operation')
        assert begin['observations']==[]
    assert not getattr(c,'transports',0)
    r.finalize()


def test_r4_1_useful_smaller_cap_and_sample_budget_are_independent(session_factory):
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'source':{'max_operation_bytes':65536}}})
    r.begin_test('case');r._step_once('a');r.reset_all('warm_all');r._step_once('a');r.finalize()
    assert c.starts==2 and c.transports==2
    assert r.reduced_axi_observation_reports()['a']['status']=='complete'
    assert r.identity_document()['reduced_axi_observation_streams'][0]['source_envelope_admission']=='reduced_axi_source_envelope_fit.v1'

@pytest.mark.parametrize('module',['myfuzz.scenario.runner','myfuzz.scenario','myfuzz.scenario.reduced_axi_journal'])
def test_fresh_interpreter_import_has_no_runner_cycle(module):
    import subprocess,sys,os
    result=subprocess.run([sys.executable,'-c',f'import {module}'],
        env=dict(os.environ,PYTHONPATH='src:.'),capture_output=True,text=True)
    assert result.returncode==0,result.stderr


@pytest.mark.parametrize('delta',[-1,0,1])
def test_r4_1_receipt_cap_boundary_before_command(session_factory,delta):
    # Independent fixed reference value for the frozen actual42backend-port,
    # empty-physical-export driver, short scope and first command. The formula
    # is documented in task-4-envelope-bound-notes.md; digest text is fixed64.
    required=32074
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'source':{'max_operation_bytes':required+delta}}})
    r.begin_test('case')
    assert r._reduced_axi_streams.source_operation_fit('a','receipt')['operation_bytes']==[required]
    if delta<0:
        with pytest.raises(Exception):r._step_once('a')
        assert not getattr(c,'transports',0)
    else:
        r._step_once('a');assert c.transports==1
    r.finalize()


@pytest.mark.parametrize('delta',[-1,0,1])
def test_r4_1_reset_cap_boundary_before_teardown_or_relaunch(session_factory,delta):
    required=7543
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'source':{'max_operation_bytes':required+delta}}})
    r.begin_test('case')
    assert r._reduced_axi_streams.source_operation_fit('a','reset')['operation_bytes']==[7543,6747]
    if delta<0:
        with pytest.raises(Exception):r.reset_all('warm_all')
        assert c.starts==1 and not getattr(c,'ends',0)
    else:
        r.reset_all('warm_all');assert c.starts==2 and c.ends==1
    assert not getattr(c,'transports',0)
    r.finalize()


@pytest.mark.parametrize('delta',[-1,0,1])
def test_r4_1_sample_budget_uses_independent_driver_shape(session_factory,delta):
    from myfuzz.scenario.reduced_axi_events import ReducedAxiObserver
    # Actual renderer snapshot has both backend and physical, even when the
    # physical export map is empty. Observer counts DEFAULT spaced ASCII JSON.
    backend={p+'_'+role:(1 << width)-1 for p,shape in SHAPES.items()
             for role,(_,width) in shape.items()}
    snapshot=dict(backend=backend,physical={})
    sample=dict(local_tick=1,pre=snapshot,post=snapshot)
    required=len(json.dumps(sample,sort_keys=True,allow_nan=False).encode())
    c=session_factory()
    c._axi_observer=ReducedAxiObserver(component_id=c.source_component,max_bytes=required+delta)
    c.runtime_events=c._axi_observer.events
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=())
    r.begin_test('case')
    assert r._reduced_axi_streams.source_operation_fit('a','receipt')['sample_bytes']==required
    if delta<0:
        with pytest.raises(Exception):r._step_once('a')
        assert not getattr(c,'transports',0)
    else:r._step_once('a');assert c.transports==1
    r.finalize()


def test_r4_1_empty_seal_exact_source_size(session_factory):
    c=session_factory();r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=())
    r.begin_test('case')
    predicted=r._reduced_axi_streams.source_operation_fit('a','seal')['operation_bytes'][0]
    r.finalize()
    seal=next(e['operation'] for e in r.events if e.get('kind')=='reduced_axi_source_operation' and e['operation']['kind']=='seal')
    assert seal['observations']==[]
    assert len(json.dumps(seal,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii'))==predicted

@pytest.mark.parametrize('delta',[-1,0,1])
def test_r4_1_reset_fifo_exact_batch_bound_before_restart(session_factory,delta):
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'source':{
            'max_operation_bytes':65536,'max_pending_bytes':14290+delta}}})
    r.begin_test('case')
    if delta<0:
        with pytest.raises(Exception):r.reset_all('warm_all')
        assert c.starts==1 and not getattr(c,'ends',0)
    else:r.reset_all('warm_all');assert c.starts==2
    r.finalize()


@pytest.mark.parametrize('slot',['read','aw','w','write'])
def test_r4_1_pending_reset_and_receipt_envelopes_fit_proven_bounds(session_factory,slot):
    c=session_factory()
    r=ScenarioRunner(sessions={'a':c},ownership=OwnershipMap({}),bindings=(),
        reduced_axi_stream_limits={'a':{'source':{'max_operation_bytes':65536}}})
    r.begin_test('case')
    signals={}
    if slot=='read':signals.update(i_arvalid=1,i_araddr=12,i_arsize=2)
    if slot in ('aw','write'):signals.update(d_awvalid=1,d_awaddr=16,d_awsize=2)
    if slot in ('w','write'):signals.update(d_wvalid=1,d_wlast=1,d_wstrb=15)
    c.signals=signals
    receipt_bound=r._reduced_axi_streams.source_operation_fit('a','receipt')['operation_bytes'][0]
    r._step_once('a')
    reset_bounds=r._reduced_axi_streams.source_operation_fit('a','reset')['operation_bytes']
    r.reset_all('warm_all');r.finalize()
    operations=[e['operation'] for e in r.events if e.get('kind')=='reduced_axi_source_operation']
    sizes=lambda operation:len(json.dumps(operation,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii'))
    assert sizes(operations[1])<=receipt_bound
    assert sizes(operations[2])<=reset_bounds[0] and sizes(operations[3])<=reset_bounds[1]
    assert r.reduced_axi_observation_reports()['a']['status']=='complete'
