"""Production decoder dispatch and fresh audit software controls, no RTL."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from tests.integration.test_compiled_candidate_layout import compiled_path
from tests.integration.test_compiled_f4_build_join import admitted
from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout, CandidateLayoutError
from myfuzz.integration.compiled_f4 import CompiledF4Runtime


def changed_pins(path, widths):
    path=deepcopy(path);pin=path['sources'][-1];mirror=path['constraints']['source_constraints'][-1]
    path['sources'].pop();path['constraints']['source_constraints'].pop()
    for index,width in enumerate(widths):
        source=deepcopy(pin);source.update(source_id=f'pin{index}',port=f'port{index}',width=width,mask=(1<<width)-1)
        constraint=deepcopy(mirror);constraint.update({k:source[k] for k in ('source_id','width','mask')})
        path['sources'].append(source);path['constraints']['source_constraints'].append(constraint)
    return path


class AfterPins(Exception):pass


def submit_until_pins(path,raw):
    runtime=CompiledF4Runtime.__new__(CompiledF4Runtime)
    runtime._mixed_flows=False;runtime._memory_flows=False
    runtime._f5_preparation=None
    runtime.path=path;runtime.layout=compile_candidate_layout(path)
    runtime._stable=lambda:None;runtime.records=[];runtime.max_cases=4
    runtime.stream=next(s for s in path['sources'] if s['kind']=='cpu_mmio_stream')
    runtime.register_name=runtime.stream['register_access']['register']
    runtime.inputs={'request':object(),'compiled':object()};runtime.result=0x3fffc;runtime.cursor=0x10080
    runtime.run_id='unit';runtime.target_id='peripheral'
    seen=[]
    runtime.session=SimpleNamespace(submit_case=lambda case:seen.append(case) or SimpleNamespace(violations=()))
    runtime.runner=SimpleNamespace(sessions={'peripheral':SimpleNamespace(reset_epoch=0)})
    def stop_before_live_version(**kwargs):
        assert kwargs==dict(register=runtime.register_name,reset_epoch=0)
        raise AfterPins
    # Stop before any live authority is issued; these checks cover pin decoding.
    runtime.authority=SimpleNamespace(consume=lambda value:value,issue=stop_before_live_version)
    with patch('myfuzz.integration.compiled_f4.declare_writer',return_value={'code_hex':'13000000'}):
        with pytest.raises(AfterPins):runtime.submit(raw)
    return [case.source.value for case in seen]


def test_production_submit_uses_independent_d3_pin_slices(compiled_path):
    path=changed_pins(compiled_path,[32,32]);layout=compile_candidate_layout(path)
    ids=[s.source_id for s in layout.slices]
    assert submit_until_pins(path,layout.encode(dict(zip(ids,[85,0x12345678,0xaabbccdd]))))==[0x12345678,0xaabbccdd]


def test_production_submit_accepts_declared_narrow_pin_length(compiled_path):
    path=changed_pins(compiled_path,[3]);layout=compile_candidate_layout(path)
    ids=[s.source_id for s in layout.slices]
    assert layout.byte_length==5
    assert submit_until_pins(path,layout.encode(dict(zip(ids,[85,5]))))==[5]


@pytest.mark.parametrize('kind',['padding','mask'])
def test_invalid_record_rejected_before_any_source(compiled_path,kind):
    path=changed_pins(compiled_path,[3])
    if kind=='mask':
        path['sources'][-1]['mask']=1;path['constraints']['source_constraints'][-1]['mask']=1
    runtime=CompiledF4Runtime.__new__(CompiledF4Runtime);runtime.path=path;runtime.layout=compile_candidate_layout(path)
    runtime._mixed_flows=False;runtime._memory_flows=False
    runtime._stable=lambda:None;runtime.records=[];runtime.max_cases=4
    with patch('myfuzz.integration.compiled_f4.declare_writer',side_effect=AssertionError('must decode all sources first')):
        with pytest.raises(CandidateLayoutError,match='record-padding' if kind=='padding' else 'value-mask'):
            runtime.submit(bytes(4)+bytes([128 if kind=='padding' else 2]))


def test_fake_layout_digest_refused(compiled_path):
    runtime=CompiledF4Runtime.__new__(CompiledF4Runtime);runtime.path=compiled_path
    runtime.layout=replace(compile_candidate_layout(compiled_path),digest='forged')
    with pytest.raises(ValueError,match='layout-identity-changed'):
        runtime._decode_candidate(bytes(8))


def identities(pid=100,nonce='1'):
    return {'cpu':dict(component='cpu',role='cpu',pid=pid,execution_nonce=nonce*32,artifact_digest='artifact')}


@pytest.mark.parametrize('actual',[identities(100,'2'),identities(101,'1')])
def test_fresh_pid_or_nonce_reuse_refused(actual):
    from myfuzz.integration.compiled_f4 import _check_fresh_identities
    with pytest.raises(ValueError,match='fresh-process-identity-reused'):
        _check_fresh_identities([identities()],actual)


def test_fresh_reuse_of_earlier_replay_refused():
    from myfuzz.integration.compiled_f4 import _check_fresh_identities
    with pytest.raises(ValueError,match='fresh-process-identity-reused'):
        _check_fresh_identities([identities(),identities(101,'2')],identities(102,'2'))


def test_comparison_reports_actual_path_without_broad_normalization():
    from myfuzz.integration.compiled_f4 import _compare_prefixes
    expected={'semantic_hash':'a','online_plan':{'value':1},'records':[]}
    actual=deepcopy(expected);actual['online_plan']['value']=2
    comparison=_compare_prefixes(expected,actual)
    assert comparison['matches'] is False
    assert comparison['first_difference']=='/online_plan/value'


class SoftwareBuiltSession:
    """Receipt/launch documents only; never a builder, child process or issuer."""
    def __init__(self,receipt,row,process):
        self.receipt=deepcopy(receipt);self.row=deepcopy(row)
        self._execution=row['execution_nonce'];self.process=process
    def validate_built_executable_receipt(self):return deepcopy(self.receipt)
    def built_executable_receipt_document(self):return deepcopy(self.receipt)
    def build_preparation_observation_document(self):return {'outcome':'software_fixture_no_build'}
    def built_executable_launch_observations(self):
        code=self.process.poll()
        return (dict(self.row,returncode=code,reaped=code is not None),)


def attach_software_audit(runtime,admitted,*,pid,nonce,poll):
    """Use source-backed artifacts and schema-valid fixture receipts/joins.

    The existing pure build-join fixture supplies synthetic build receipts.
    Production validation methods still perform every receipt/process join;
    none of these software documents grants native execution authority.
    """
    artifacts,binding,_=admitted
    document=binding.document()
    runtime.artifacts=dict(artifacts);runtime.cpu_id=document['cpu']['instance_id']
    runtime._built_receipts=deepcopy(document['built_executable_receipts'])
    runtime._build_sessions={};runtime._native_processes={}
    from myfuzz.integration.compiled_f4_build_join import built_receipt_sha256
    for index,(component,receipt) in enumerate(sorted(runtime._built_receipts.items())):
        component_pid=pid if component==runtime.cpu_id else pid+100+index
        process=SimpleNamespace(pid=component_pid,poll=poll)
        row=dict(pid=component_pid,execution_nonce=f'{nonce}:{component}',
            artifact_digest=receipt['artifact_digest'],build_digest=receipt['build_digest'],
            binary_sha256=receipt['binary_sha256'],
            built_receipt_sha256=built_receipt_sha256(receipt),
            observed_executable_sha256=receipt['binary_sha256'],
            ready_artifact_digest=receipt['artifact_digest'])
        runtime._native_processes[component]=process
        runtime._build_sessions[component]=SoftwareBuiltSession(receipt,row,process)
    runtime._process_identities=runtime._validated_build_process_identities()


def test_native_exit_audit_uses_process_poll_returncode(admitted):
    runtime=CompiledF4Runtime.__new__(CompiledF4Runtime)
    runtime.finished=True
    with patch('subprocess.Popen',side_effect=AssertionError('software fixture cannot start native')):
        attach_software_audit(runtime,admitted,pid=100,nonce='original',poll=lambda:-9)
        audit=runtime.execution_audit()
    assert audit['exits'][runtime.cpu_id]['returncode']==-9
    assert audit['exits'][runtime.cpu_id]['reaped'] is True
    assert audit['identities']==runtime._validated_build_process_identities()


@pytest.mark.parametrize('kind',['receipt','launch'])
def test_software_audit_fixture_preserves_identity_drift_refusal(admitted,kind):
    runtime=CompiledF4Runtime.__new__(CompiledF4Runtime);runtime.finished=True
    attach_software_audit(runtime,admitted,pid=100,nonce='original',poll=lambda:0)
    local=runtime._build_sessions[runtime.cpu_id]
    if kind=='receipt':local.receipt['binary_sha256']='f'*64
    else:local.row['observed_executable_sha256']='f'*64
    with pytest.raises(ValueError,match='built-receipt-identity-changed' if kind=='receipt'
                       else 'built-process-identity-mismatch'):
        runtime.execution_audit()


def test_replay_exports_actual_prefix_events_and_close_receipt(admitted):
    plan=dict(records=[{'raw':'00','certificate':{'prerequisite':{},'postcondition':{}}}],semantic_hash='same',online_plan={'actual':True})
    class SoftwareRuntime(CompiledF4Runtime):
        def __init__(self,**kw):
            self.finished=False
            self._mixed_flows=False;self._memory_flows=False
            self._f5_preparation=None
            attach_software_audit(self,admitted,pid=101 if kw else 100,
                nonce='fresh' if kw else 'original',poll=lambda:0 if self.finished else None)
            if kw:
                assert kw['expected_built_receipts']==self._built_receipts
                kw['build_audit_sink'](self.build_audit_snapshot())
            self.runner=SimpleNamespace(events_since=lambda index:[{'event_id':1,'actual':True}])
        def _stable(self,**kw):pass
        def submit(self,raw,**kw):assert raw==b'\0'
        def finish(self):self.finished=True;return deepcopy(plan)
    original=SoftwareRuntime()
    original._replay_identities=[];original.inputs={}
    original.base_dir='.';original.cache_dir='.';original.run_id='unit';original.rounds=1;original.max_cases=1
    saved=[]
    with patch('subprocess.Popen',side_effect=AssertionError('software fixture cannot start native')):
        result=original.replay(plan,audit_sink=saved.append)
    assert result['matches'] is True
    assert saved[0]['actual_prefix']==plan
    assert saved[0]['actual_events']==[{'event_id':1,'actual':True}]
    assert saved[0]['execution_audit']['exits'][original.cpu_id]=={'returncode':0,'reaped':True}
    assert saved[0]['execution_audit']['identities'][original.cpu_id]['pid']==101
    assert saved[0]['fresh_build']['receipts']==original._built_receipts
    assert saved[0]['fresh_build']['unavailable']=={}
    with pytest.raises(ValueError,match='fresh-process-identity-reused'):
        original.replay(plan,audit_sink=saved.append)
    assert saved[-1]['error_type']=='ValueError'


def test_primary_failure_audit_survives_events_save_failure(tmp_path):
    from myfuzz.integration.compiled_execution_files import _save_runtime_failure
    import json
    runtime=SimpleNamespace(runner=SimpleNamespace(events_since=lambda _:(_ for _ in ()).throw(RuntimeError('event read failed'))),
        execution_audit=lambda:{'exits':{'cpu':{'returncode':-9,'reaped':True}}})
    failures=_save_runtime_failure(tmp_path,runtime)
    assert failures['partial_events']=='event read failed'
    assert json.loads((tmp_path/'execution_audit.json').read_text())['exits']['cpu']['returncode']==-9
