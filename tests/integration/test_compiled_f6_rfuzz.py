"""F6 transport tests use static source-backed inputs; no native execution."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from tests.integration.test_compiled_f6_contract import source_inputs, ROOT, f6
from tests.integration.test_compiled_f6_layout import raw

@pytest.fixture(scope='module')
def declared():
    from myfuzz.scenario.ownership import compile_ownership
    request, compiled, artifacts = source_inputs()
    return dict(request=request, compiled=compiled, ownership=compile_ownership((),()), physical_port_map={}), artifacts

def shell(declared):
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    inputs, artifacts = declared
    path=deepcopy(f6(inputs['compiled']))
    return SimpleNamespace(compiled_inputs=inputs, artifacts=artifacts, base_dir=ROOT,
        path=path, contract=path['execution_contract'], layout=compile_f6_candidate_layout(path),
        program=build_f6_firmware(path['execution_contract']), run_id='f6-wire', cursor=0,
        max_cases=16, attempts=[], records=[], finished=False)

def test_decoder_four_source_operands_and_exact_program(declared):
    from myfuzz.scenario.compiled_f6_decoder import CompiledF6Decoder
    runtime=shell(declared); decoder=CompiledF6Decoder.from_runtime(runtime)
    candidate,=decoder.decode_sequence((raw((0,1,1024,2047)),),cursor=0,case_index=0)
    assert candidate.words==(0,1,1024,2047)
    doc=candidate.document()
    assert doc['raw8_hex']==raw((0,1,1024,2047)).hex()
    assert doc['case_id']=='f6-wire:case:0'
    assert doc['prefix_hex']==runtime.program.prefix(candidate.candidate,case_index=0).hex()
    assert doc['source_ids']==[s['source_id'] for s in runtime.path['sources']]
    assert decoder.max_input_bytes==8
    assert not runtime.attempts

@pytest.fixture(scope='module')
def static_decoder(declared):
    from myfuzz.scenario.compiled_f6_decoder import CompiledF6Decoder
    return CompiledF6Decoder.from_runtime(shell(declared))

@pytest.mark.parametrize('count',range(2,201))
def test_raw2_through_200_refused_without_case(static_decoder,count):
    from myfuzz.scenario.compiled_f6_decoder import CompiledF6CandidateRefused
    decoder=static_decoder;runtime=decoder.runtime
    with pytest.raises(CompiledF6CandidateRefused,match='record-count'):
        decoder.decode_sequence((raw((1,2,3,4)),)*count,cursor=0,case_index=0)
    assert runtime.cursor==0 and runtime.attempts==[]

@pytest.mark.parametrize('mode',['cursor','path','compiled','reserved','duplicate'])
def test_decoder_rejects_drift_and_invalid_candidate(declared,mode):
    from myfuzz.scenario.compiled_f6_decoder import CompiledF6Decoder
    runtime=shell(declared); decoder=CompiledF6Decoder.from_runtime(runtime)
    record=raw((1,2,3,4)); cursor=0
    if mode=='cursor': cursor=1
    elif mode=='path':runtime.path['path_id']='other'
    elif mode=='compiled':
        runtime.compiled_inputs=dict(runtime.compiled_inputs,compiled=deepcopy(runtime.compiled_inputs['compiled']))
        runtime.compiled_inputs['compiled']['paths'][0]['reason']='changed'
    elif mode=='reserved':record=(1<<44).to_bytes(8,'little')
    elif mode=='duplicate':record=bytes(8)
    with pytest.raises(ValueError):decoder.decode_sequence((record,),cursor=cursor,case_index=0)

@pytest.fixture
def executor(static_decoder):
    from myfuzz.integration.compiled_f6_rfuzz import CompiledF6RfuzzExecutor
    from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
    from myfuzz.scenario.feedback import CoverageTarget
    from myfuzz.integration.compiled_f6_runtime_path import restore_prepared_runtime_paths
    runtime=static_decoder.runtime
    runtime.session=SimpleNamespace(runtime_contract=restore_prepared_runtime_paths(static_decoder.runtime_path_admission).contract)
    runtime.runner=SimpleNamespace(local_ticks={})
    return CompiledF6RfuzzExecutor(runtime=runtime,decoder=static_decoder,
        targets=tuple(CoverageTarget(e,'cpu','f6_evidence',1,1) for e in EXPECTATION_IDS),run_id=runtime.run_id)

def batch(records,buffer_id=1):
    from myfuzz.integration.rfuzz_wire import InputBatch
    return InputBatch(buffer_id,8,(tuple(records),))

def test_duplicate_slot_returns_cached_refusal_and_changed_slot_stops(executor):
    original=batch((bytes(8),))
    assert executor.execute_batch(original)==(bytes(5),)
    assert executor.receipts[0].status=='input_invalid'
    assert executor.online_decisions[0]['case_ids']==[]
    assert executor.execute_batch(original)==(bytes(5),)
    assert len(executor.receipts)==1
    with pytest.raises(ValueError,match='slot identity'):
        executor.execute_batch(batch((raw((1,2,3,4)),)))
    assert executor._session_stop_reason=='slot_identity_changed'

def test_finalizer_preserves_first_primary_notes_and_attempts_all_exports(executor):
    primary=RuntimeError('first execution');primary.add_note('original note')
    secondary=RuntimeError('finish failure')
    calls=[]
    def finish():calls.append('finish');raise secondary
    def trace():calls.append('trace');return object()
    def plan():calls.append('plan');return b'{}'
    executor.runtime.finish=finish
    executor.runtime.session.trace=trace
    executor.runtime.session.encode_plan=plan
    executor._online_primary_error=primary
    for _ in range(2):
        with pytest.raises(RuntimeError) as caught:executor._finish_online_session()
        assert caught.value is primary
    assert calls==['finish','trace','plan']
    assert primary.__notes__[0]=='original note'
    assert any('finish failure' in n for n in primary.__notes__)

def test_finalizer_caches_exact_trace_and_plan_pair(executor):
    trace=object();calls=[]
    executor.runtime.trace=trace
    executor.runtime.finish=lambda:calls.append('finish') or {'scope':'full'}
    executor.runtime.session.encode_plan=lambda:calls.append('plan') or b'{}'
    assert executor._finish_online_session()==(trace,b'{}'.hex())
    assert executor._finish_online_session()==(trace,b'{}'.hex())
    assert calls==['finish','plan']

@pytest.fixture(scope='module')
def pure_online_material(static_decoder):
    from dataclasses import asdict
    from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding
    from myfuzz.scenario.session_runtime import BoundOnlineInstruction
    from myfuzz.integration.compiled_f6_runtime_path import restore_prepared_runtime_paths
    runtime=static_decoder.runtime;contract=runtime.contract;admission=static_decoder.runtime_path_admission
    resource=contract['memory']['resource']
    binding=InstructionImageSourceBinding(path_id=admission['runtime_path_ids'][1],direction='CPU_TO_IP',
        source_id=contract['instruction_source_id'],logical_source_id=contract['instruction_source_id'],
        component=contract['cpu']['instance_id'],memory_id=resource['resource_id'],
        base=resource['base'],size=resource['size'],readable=True,writable=True)
    runtime.session=SimpleNamespace(instruction_image_binding_documents=(binding.document(),))
    decoder=static_decoder.document()
    candidate=runtime.layout.decode(raw((1,2,3,4)))
    source=BoundOnlineInstruction(contract['instruction_source_id']+':0',contract['cpu']['instance_id'],
        contract['program_contract']['slot_base'],runtime.program.prefix(candidate,case_index=0).hex(),contract['instruction_source_id'])
    manifest=dict(instruction_image_bindings=[binding.document()],runtime_paths=dict(
        declaration=restore_prepared_runtime_paths(admission).document()))
    plan=dict(schema_version=24,instruction_image_bindings=[binding.document()],runtime_paths=deepcopy(manifest['runtime_paths']),
        instruction_slots=[[contract['cpu']['instance_id'],address,count] for address,count in runtime.program.instruction_slots],
        cases=[dict(case_id=runtime.run_id+':case:0',direction='CPU_TO_IP',path_id=binding.path_id,
            source=dict(kind='bound_instruction',**asdict(source)))])
    return decoder,manifest,plan

@pytest.mark.parametrize('change',[None,'fixed_opcode','duplicate_operand','address','case','path','binding','layout','feedback','empty_cases','cases_type'])
def test_f6_online_material_has_its_own_program_source_and_binding_join(pure_online_material,change):
    from myfuzz.integration.scenario_rfuzz_live import _verify_instruction_image_material
    decoder,manifest,plan=deepcopy(pure_online_material)
    source=plan['cases'][0]['source']
    if change=='fixed_opcode':
        data=bytearray.fromhex(source['data_hex']);data[0]^=1;source['data_hex']=data.hex()
    elif change=='duplicate_operand':
        data=bytearray.fromhex(source['data_hex']);data[48:52]=data[40:44];source['data_hex']=data.hex()
    elif change=='address':source['address']+=256
    elif change=='case':plan['cases'][0]['case_id']='borrowed'
    elif change=='path':plan['cases'][0]['path_id']='borrowed'
    elif change=='binding':manifest['instruction_image_bindings'][0]['logical_source_id']='borrowed'
    elif change=='layout':decoder['candidate_layout']['record_limit']=2
    elif change=='feedback':decoder['feedback_projection']['counter_count']=4
    elif change=='empty_cases':plan['cases']=[]
    elif change=='cases_type':plan['cases']=()
    if change:
        with pytest.raises(ValueError):_verify_instruction_image_material(decoder,manifest,plan)
    else:_verify_instruction_image_material(decoder,manifest,plan)

@pytest.mark.parametrize('result_failure',['failed','expected_error','missing_status','missing_observations'])
def test_failed_case_never_contributes_case_or_cumulative_feedback(executor,monkeypatch,result_failure):
    """Isolated software projection/status disagreement; no RTL claim."""
    from myfuzz.integration import compiled_f6_rfuzz as module
    runtime=executor.runtime;runtime.cursor=0;runtime.attempts=[];runtime.records=[]
    candidate,=executor.online_decoder.decode_sequence((raw((1,2,3,4)),),cursor=0,case_index=0)
    def submit(record):
        assert record==candidate.raw
        runtime.attempts.append({'case_id':candidate.case_id});runtime.cursor+=1
        result=dict(candidate.document(),status='passed',observations={})
        if result_failure in ('failed','expected_error'):result['status']=result_failure
        elif result_failure=='missing_status':result.pop('status')
        else:result.pop('observations')
        return result
    monkeypatch.setattr(runtime,'submit',submit,raising=False)
    # This deliberate projection injection isolates the executor's conservative
    # status gate. The source-backed principal keeps the genuine builder intact.
    marker=object()
    monkeypatch.setattr(module,'build_f6_assertion_material',lambda owner:marker)
    def all_passed(material,*,case_ids):
        assert material is marker and case_ids==(candidate.case_id,)
        return bytes([1]*5)
    monkeypatch.setattr(module,'f6_case_feedback',all_passed)
    assert executor.execute_batch(batch((candidate.raw,)))==(bytes(5),)
    receipt=executor.receipts[0]
    assert receipt.status==('execution_failed' if result_failure in ('failed','expected_error') else 'environment_error')
    assert receipt.coverage_hex==bytes(5).hex() and receipt.applied_source_ids==()
    assert executor._target_hits==set()
