"""Source-only controls; no generated DUT construction or subprocess execution."""
import copy
import importlib.util
from pathlib import Path
import pytest

SCRIPT=Path(__file__).parents[2]/'scripts/verify_cvw_ahb_startup.py'

def gate():
    spec=importlib.util.spec_from_file_location('cvw_ahb_gate',SCRIPT)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def test_default_source_freeze_does_not_construct_or_execute(monkeypatch):
    import subprocess
    import myfuzz.local_harness.build  # establish producer baselines before guard
    def refuse(*a,**k):raise AssertionError('source-only subprocess')
    monkeypatch.setattr(subprocess,'Popen',refuse)
    g=gate();doc=g.prepare_freeze(SCRIPT.parents[1])
    assert doc['native_run'] is False and doc['cpu_step_limit']==20000
    assert doc['memory_seed']==17 and doc['program_bytes']==1024
    g.verify_freeze(SCRIPT.parents[1],doc)
    doc['memory_seed']=True
    with pytest.raises(ValueError):g.verify_freeze(SCRIPT.parents[1],doc)

def test_only_cpu_is_advanced_and_stop_requires_flag_and_backend_empty():
    g=gate()
    class Recorder:
        def __init__(self):self.calls=[]
        def advance(self,schedule):self.calls.append(schedule)
    class Cpu:pending_responses=1
    class Service:events=[{'kind':'memory_write','address':0xc0001040}]
    cpu=Cpu();cpu.service=Service();r=Recorder()
    assert g.advance_until_flag(r,cpu,limit=3)==False
    assert r.calls==[('cpu',)]*3
    cpu.pending_responses=0;r.calls=[]
    assert g.advance_until_flag(r,cpu,limit=3)==True
    assert r.calls==[('cpu',)]

def test_scope_normalization_rejects_unknown_and_preserves_payload():
    g=gate();nonce='a'*32
    event={'schema_version':g.EVENT_SCHEMA,'scope':g.expected_scope(nonce),
           'raw_sample':{'literal':nonce}}
    normal=g.normalize_observer([event],nonce)
    assert normal[0]['raw_sample']['literal']==nonce
    assert normal[0]['scope']['execution_id']=='DECLARED_CPU_EXECUTION'
    event['scope']['execution_id']='b'*32
    with pytest.raises(ValueError):g.normalize_observer([event],nonce)

def test_runner_exactly_once_and_global_refs():
    g=gate();row={'schema_version':g.EVENT_SCHEMA,'observer_record_index':3}
    imported={**row,'component':'cpu','event_id':'e1'}
    g.assert_imported_once([row],[imported])
    with pytest.raises(ValueError):g.assert_imported_once([row],[imported,imported])

def test_standard_historical_three_pin_raw_cannot_pass_projection():
    g=gate()
    with pytest.raises((KeyError,ValueError)):
        g.project_rows({'pre':{'protocol_taps':{}},'post':{'protocol_taps':{}}},
                       {name:name for name in ('haddr','hwdata','hrdata')})

from tests.local_harness.test_ahb_cpu_contract import generated

def test_receipt_bound_software_prefix_replay_and_fault_controls(generated,monkeypatch):
    from tests.local_harness.test_ahb_startup import transport_fixture
    from dataclasses import asdict
    artifact,cpu=generated;g=gate();transport_fixture(cpu,monkeypatch,pipeline=True)
    records=[];original=cpu.command
    def command(operation,fields):
        receipt=original(operation,fields)
        records.append(dict(operation=operation,fields=list(fields),receipt=asdict(receipt)))
        return receipt
    cpu.command=command
    cpu.begin_case(g.CASE_ID)
    for _ in range(3):cpu.step_local({})
    document=dict(native_execution=cpu._execution,artifact=artifact.runtime_document,
                  driver_receipts=records,runtime_events=copy.deepcopy(cpu.runtime_events),
                  counts=copy.deepcopy(cpu._ahb_observer.counts),pending=cpu._ahb_observer.pending)
    g.replay_actual_prefix(document)
    assert cpu._ahb_observer.measured_reset_to_command_prefix
    for mutate in (
        lambda d:d['driver_receipts'][0]['receipt'].update(new_ticks=1),
        lambda d:d['driver_receipts'].pop(0),
        lambda d:d['driver_receipts'][-1]['receipt'].update(sequence=999),
        lambda d:d['runtime_events'][0]['scope'].update(execution_id='wrong'),
        lambda d:d['driver_receipts'][-1]['fields'].__setitem__(0,7)):
        bad=copy.deepcopy(document);mutate(bad)
        with pytest.raises((ValueError,KeyError)):g.replay_actual_prefix(bad)

def test_lifecycle_and_typed_receipt_comparison_controls():
    g=gate();execution='a'*32
    receipt=dict(execution=execution,status='result',payload={'literal':execution})
    rows=[dict(operation='ACCESS_AHB_REG',fields=[0,0,0,15],receipt=receipt)]
    normalized=g.normalize_receipts(rows,execution,'sha')
    assert normalized[0]['receipt']['execution']=='DECLARED_SHA_EXECUTION'
    assert normalized[0]['receipt']['payload']['literal']==execution
    rows[0]['receipt']['execution']='b'*32
    with pytest.raises(ValueError):g.normalize_receipts(rows,execution,'sha')
    lifecycle=[dict(pid=123,ready=True,closed=True,returncode=0,poll_after_close=0,execution=execution)]
    g.validate_lifecycle(lifecycle,execution)
    lifecycle[0]['returncode']=-9
    with pytest.raises(ValueError):g.validate_lifecycle(lifecycle,execution)

def test_passive_capture_preserves_calls_and_survives_inplace_drain(tmp_path):
    from types import SimpleNamespace
    from dataclasses import dataclass
    g=gate();binary=tmp_path/'driver';binary.write_bytes(b'fixture-not-executable')
    (tmp_path/'manifest.json').write_text('{}')
    class FakeProcess:
        pid=10;args=[str(binary)];returncode=None
        def poll(self):return self.returncode
    g.subprocess=SimpleNamespace(Popen=FakeProcess)
    @dataclass
    class Receipt:execution:str='a'*32
    class Session:
        _process=None;_execution='a'*32;local_ticks=0
        runtime_events=[]
        def __init__(self):self.service=SimpleNamespace(events=[]);self.calls=[]
        def command(self,op,fields):self.calls.append((op,fields));return Receipt()
        def begin_case(self,case):self._process=FakeProcess()
        def step_local(self,inputs):
            self.local_ticks+=1
            self.service.events.append({'kind':'memory_write','address':g.RESULT+64})
            return self.command('STEP_MEMORY',(1,0,0,0))
        def _abort(self):self._process.returncode=0;self._process=None
        def end_case(self):self._abort()
    session=Session();capture=g.Capture(session,'cpu',{'failed':False})
    session.begin_case('case');session.step_local({});session.service.events.clear()
    session.step_local({});session.end_case()
    assert len(capture.service_events)==2 and len(capture.receipts)==2
    assert len(session.calls)==2
    g.validate_lifecycle(capture.lifecycle,session._execution)

def test_native_entry_requires_explicit_canonical_lock(tmp_path):
    g=gate()
    with pytest.raises(ValueError):g.validate_native_paths(tmp_path,tmp_path/'out',tmp_path/'lock')

def test_service_import_exact_rows_reject_duplicate_and_changed_commit():
    g=gate();commit={'kind':'memory_write','address':g.RESULT+64,'value':1}
    document={'service_events':[commit],'deliveries':[],'acceptances':[],
              'runner_events':[{**commit,'component':'cpu','event_id':1,'producer_event_id':0}]}
    g.assert_service_imports(document)
    document['runner_events'][0]['value']=2
    with pytest.raises(ValueError):g.assert_service_imports(document)

def test_target_access_receipt_tick_and_delivery_binding():
    g=gate();execution='b'*32
    receipt={'execution':execution,'sequence':1,'status':'result',
      'tick_before':0,'tick_after':4,'new_ticks':4,
      'payload':{'kind':'ahb_lite_register_observe','rdata':7,'error':0,
                 'samples':[{'local_tick':i} for i in range(1,5)]}}
    document={'target_execution':execution,'target_local_ticks':4,
      'target_driver_receipts':[{'operation':'ACCESS_AHB_REG','fields':[0,0x18,0,15],'receipt':receipt}],
      'deliveries':[{'write':False,'offset':0x18,'write_value':None,'read_value':7}]}
    g.validate_target_receipts(document)
    for change in (lambda d:d['target_driver_receipts'][0]['receipt'].update(sequence=2),
                   lambda d:d['target_driver_receipts'][0]['receipt']['payload'].update(rdata=8),
                   lambda d:d['target_driver_receipts'][0].update(operation='STEP_AHB_REG')):
        bad=copy.deepcopy(document);change(bad)
        with pytest.raises(ValueError):g.validate_target_receipts(bad)

def test_historical_saved_chain_payload_binding_only_not_new_13tap_evidence():
    import gzip,json
    g=gate();path=SCRIPT.parents[1]/'docs/reports/evidence/cvw-ahb-source-audit-20261017/first.json.gz'
    historical=json.loads(gzip.decompress(path.read_bytes()))
    document={**historical,'backend_pending':historical['pending_responses'],'stop_reached':True,
      'driver_receipts':[{'receipt':{'payload':{'samples':[s]}}} for s in historical['cpu_samples']]}
    g.validate_chain(document)
    bad=copy.deepcopy(document);bad['outputs'][0]['data_rsp_rdata']^=1
    # Select an actual MMIO read response, rather than changing an unrelated RAM beat.
    sequence=next(d['source_sequence'] for d in bad['deliveries'] if not d['write'])
    output=next(o for o in bad['outputs'] if o['data_rsp_consumed'] and o['data_rsp_source_sequence']==sequence)
    output['data_rsp_rdata']^=1
    with pytest.raises(ValueError):g.validate_chain(bad)

@pytest.mark.parametrize('mutation',[
 lambda d:d['build_manifest'].update(binary_sha256='bad'),
 lambda d:d['executable'].update(sha256='bad'),
 lambda d:d.update(build_manifest_sha256='bad'),
 lambda d:d['lifecycle'][0].update(args=['other']),
 lambda d:d['lifecycle'][0].update(ready=False),
 lambda d:d['lifecycle'][0].update(closed=False),
 lambda d:d['lifecycle'][0].update(execution='wrong'),
 lambda d:d['lifecycle'][0].update(poll_after_close=None),
 lambda d:d['build_manifest']['identity'].update(flag=1),
])
def test_binary_manifest_lifecycle_crosslinks(mutation):
    g=gate();nonce='c'*32;identity={'build_identity':{'flag':True}}
    manifest=dict(schema_version='local_harness_build_cache.v1',identity=identity['build_identity'],binary_sha256='a'*64)
    raw=g.encoded(manifest).decode();digest=g.sha(raw.encode())
    document=dict(build_manifest=copy.deepcopy(manifest),build_manifest_raw=raw,
      build_manifest_sha256=digest,executable={'path':'/native/driver','sha256':'a'*64},
      lifecycle=[dict(pid=1,execution=nonce,args=['/native/driver'],ready=True,closed=True,
      returncode=0,poll_after_close=0,binary_sha256_at_capture='a'*64,build_manifest_sha256_at_capture=digest)])
    g.validate_binary(document,identity,nonce)
    mutation(document)
    with pytest.raises(ValueError):g.validate_binary(document,identity,nonce)


def test_default_main_source_only_and_unknown_scope_not_hidden(tmp_path,monkeypatch):
    import myfuzz.local_harness.build
    import subprocess,json
    g=gate();path=tmp_path/'freeze.json'
    def refuse(*a,**k):raise AssertionError('source-only must not invoke tools/model')
    monkeypatch.setattr(subprocess,'Popen',refuse)
    assert g.main(['--write-freeze',str(path)])==0
    g.verify_freeze(SCRIPT.parents[1],json.loads(path.read_text()))
    row={'schema_version':g.EVENT_SCHEMA,'scope':g.expected_scope('a'*32)}
    with pytest.raises(ValueError):g.normalize_runner([row],'b'*32)

from tests.local_harness.test_ahb_register_identity import target

def test_actual_two_session_manifest_entry_without_frontend_or_build(generated,target,monkeypatch):
    import hashlib
    from myfuzz.local_harness import build,session,plan,runtime_renderer
    from myfuzz.composition.component_profile import PhysicalFacts
    from myfuzz.composition.source_crawler import ElaboratedPortFact
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.scenario.contracts import ResourceBudget
    g=gate();cpu_art,cpu=generated;target_art,sha=target
    facts={art.plan.profile.source.top_module:art.plan.facts for art in (cpu_art,target_art)}
    def source_identity(artifact,**kw):
        return dict(software_fixture=True,artifact_digest=artifact.runtime_document['artifact_digest'],
          inputs=[dict(path=p,sha256=hashlib.sha256((SCRIPT.parents[1]/p).read_bytes()).hexdigest())
                  for p in sorted(build._discover_host_sources())])
    monkeypatch.setattr(build,'local_build_identity',source_identity)
    monkeypatch.setattr(session,'local_build_identity',source_identity)
    monkeypatch.setattr(plan,'elaborate_profile',lambda profile,**kw:facts[profile.source.top_module])
    monkeypatch.setattr(runtime_renderer,'elaborate_profile',lambda profile,**kw:facts[profile.source.top_module])
    runner=ScenarioRunner(sessions={'cpu':cpu,'sha':sha},ownership=compile_ownership((),()),bindings=())
    runner.set_resource_budget(ResourceBudget())
    manifest=g.manifest_for_runner(runner,runner.identity_document())
    assert set(manifest.to_document()['runner_identity']['sessions'])=={'cpu','sha'}

def test_original_stream_context_is_current_cpu_receipt_not_old_flag():
    g=gate();document=dict(service_events=[{'kind':'memory_write'}],deliveries=[],acceptances=[],
      driver_receipts=[{'receipt':{'payload':{'samples':[]},'tick_after':0}},
                       {'receipt':{'payload':{'samples':[{}]},'tick_after':1}}],
      stream_contexts=[dict(stream='service_events',stream_index=0,step_index=1,local_tick=1,receipt_index=1)])
    g.validate_stream_contexts(document)
    document['stream_contexts'][0]['receipt_index']=0
    with pytest.raises(ValueError):g.validate_stream_contexts(document)

def test_step_failure_preserves_original_exception_partial_rows_and_poison():
    from types import SimpleNamespace
    from dataclasses import dataclass
    g=gate();failure=OSError('software injected service failure after receipt')
    @dataclass
    class Receipt:execution:str='a'*32
    class Session:
        _process=None;local_ticks=1;runtime_events=[]
        def __init__(self):self.service=SimpleNamespace(events=[]);self.calls=0
        def command(self,*args):self.calls+=1;return Receipt()
        def begin_case(self,*args):pass
        def end_case(self):pass
        def _abort(self):pass
        def step_local(self,inputs):
            self.command('STEP_MEMORY',(1,0,0,0))
            self.service.events.append({'kind':'memory_write','address':g.RESULT+64})
            raise failure
    session=Session();shared={'failed':False};capture=g.Capture(session,'cpu',shared)
    with pytest.raises(OSError) as caught:session.step_local({})
    assert caught.value is failure and len(capture.service_events)==1
    assert capture.stream_contexts[0]['receipt_index']==0
    with pytest.raises(RuntimeError):session.command('STEP_MEMORY',(1,0,0,0))
    assert session.calls==1

@pytest.mark.parametrize('mutation',[
 lambda d:d.update(native_execution='a'*32),
 lambda d:d['binaries']['cpu']['lifecycle'][0].update(pid=10),
 lambda d:d['runtime_events'][0]['scope'].update(execution_id='unknown'),
 lambda d:d['runtime_events'][0]['raw_sample'].update(value=99),
 lambda d:d['runner_events'].append(copy.deepcopy(d['runner_events'][0])),
 lambda d:d['driver_receipts'][0]['receipt']['payload'].update(literal='changed'),
 lambda d:d['target_driver_receipts'][0]['receipt'].update(execution='unknown'),
 lambda d:d['binaries']['sha'].update(build_manifest_sha256='changed'),
 lambda d:d['deliveries'].append({'new':'row'}),
])
def test_whole_prefix_comparator_is_typed_not_recursive_uuid_rewrite(monkeypatch,mutation):
    g=gate();validated=[]
    # Exercise comparison separately from native admission. These small model
    # documents deliberately lack native artifacts and cannot pass admission.
    monkeypatch.setattr(g,'validate_native_run',lambda d:validated.append(d))
    def model(cpu_nonce,sha_nonce,pid):
        row=dict(schema_version=g.EVENT_SCHEMA,scope=g.expected_scope(cpu_nonce),raw_sample={'value':1})
        doc={key:[] for key in ('program','memory_seed','identity','artifact','target_artifact','counts','pending','backend_pending','result',
          'service_events','deliveries','acceptances','outputs','stream_contexts','commands','target_local_ticks','cpu_local_ticks','prefix_state')}
        doc.update(native_execution=cpu_nonce,target_execution=sha_nonce,
          binaries={c:{'build_manifest_sha256':'same','lifecycle':[{'pid':pid+i}]} for i,c in enumerate(('cpu','sha'))},
          runtime_events=[row],runner_events=[{**copy.deepcopy(row),'event_id':1,'component':'cpu'}],
          driver_receipts=[{'operation':'STEP_MEMORY','receipt':{'execution':cpu_nonce,'payload':{'literal':'unchanged'}}}],
          target_driver_receipts=[{'operation':'ACCESS_AHB_REG','receipt':{'execution':sha_nonce,'payload':{}}}])
        return doc
    first=model('a'*32,'b'*32,10);fresh=model('c'*32,'d'*32,20)
    g.compare_prefixes(first,fresh);assert len(validated)==2
    mutation(fresh)
    with pytest.raises(ValueError):g.compare_prefixes(first,fresh)

@pytest.mark.parametrize('role',['haddr','hwdata','hrdata','hresp'])
def test_saved_actual_target_physical_roles_bind_deliveries_and_reject_tamper(role):
    import gzip,json
    g=gate();root=SCRIPT.parents[1]
    historical=json.loads(gzip.decompress((root/'docs/reports/evidence/cvw-ahb-source-audit-20261017/first.json.gz').read_bytes()))
    artifact=json.loads(gzip.decompress((root/'docs/reports/evidence/ahb-register-identity-20261017/old-caliptra-target-artifact.json.gz').read_bytes()))
    document=dict(target_artifact=artifact,deliveries=historical['deliveries'],
                  target_driver_receipts=[{'receipt':{'payload':{'samples':historical['sha_samples']}}}])
    g.validate_target_physical(document)
    pins=artifact['base_protocol_trace']['signals'];samples=document['target_driver_receipts'][0]['receipt']['payload']['samples']
    address=next(i for i,s in enumerate(samples) if s['pre']['backend'][pins['hsel']] and s['pre']['backend'][pins['hreadyin']] and s['pre']['backend'][pins['htrans']]&2
                 and (role!='hrdata' or not s['pre']['backend'][pins['hwrite']]))
    index=address if role=='haddr' else address+1
    samples[index]['pre']['backend'][pins[role]]^=1
    with pytest.raises(ValueError):g.validate_target_physical(document)

def test_target_physical_wait_data_and_same_edge_next_address_controls():
    import gzip,json
    g=gate();root=SCRIPT.parents[1]
    artifact=json.loads(gzip.decompress((root/'docs/reports/evidence/ahb-register-identity-20261017/old-caliptra-target-artifact.json.gz').read_bytes()))
    pins=artifact['base_protocol_trace']['signals']
    def sample(tick,**changes):
        row=dict.fromkeys(pins,0);row.update(hreadyin=1,hreadyout=1,hsize=2);row.update(changes)
        data={'backend':{pins[role]:value for role,value in row.items()}}
        return dict(local_tick=tick,pre=data,post=copy.deepcopy(data))
    samples=[sample(1,hsel=1,htrans=2,haddr=0x80,hwrite=1),
      sample(2,hreadyin=0,hreadyout=0,hwdata=42),
      sample(3,hwdata=42,hsel=1,htrans=2,haddr=0x100,hwrite=0),
      sample(4,hrdata=7)]
    document=dict(target_artifact=artifact,deliveries=[dict(offset=0x80,write=True,write_value=42),dict(offset=0x100,write=False,read_value=7)],
      target_driver_receipts=[{'receipt':{'payload':{'samples':samples}}}])
    assert len(g.validate_target_physical(document))==2
    stalled=copy.deepcopy(document)
    bad_sample=sample(3,hreadyin=0,hreadyout=0,hwdata=43)
    stalled['target_driver_receipts'][0]['receipt']['payload']['samples'].insert(2,bad_sample)
    for i,row in enumerate(stalled['target_driver_receipts'][0]['receipt']['payload']['samples'],1):row['local_tick']=i
    with pytest.raises(ValueError):g.validate_target_physical(stalled)
    samples[2]['pre']['backend'][pins['hwdata']]=43
    with pytest.raises(ValueError):g.validate_target_physical(document)
    samples[2]['pre']['backend'][pins['hwdata']]=42
    samples.append(sample(5,hsel=1,htrans=2,haddr=0x100))
    with pytest.raises(ValueError):g.validate_target_physical(document)
    samples.pop();artifact['structural_abi']['ports'][1]['width']=31
    with pytest.raises(ValueError):g.validate_target_physical(document)
