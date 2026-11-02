from copy import deepcopy
import pytest
from tests.integration.f2_rfuzz_support import transport_case, f2_transport_inputs
from myfuzz.integration.rfuzz_wire import InputBatch

@pytest.mark.parametrize('kind',['invalid','case','slot',9,64,200])
def test_whole_test_preflight_is_atomic(transport_case,kind):
    executor,runtime,valid=transport_case
    records=(valid,bytes(8)) if kind=='invalid' else (valid,valid)
    if kind=='case':runtime.max_cases=1
    if kind=='slot':runtime.cursor=runtime.result-32
    if isinstance(kind,int):records=(valid,)*kind
    before=(runtime.cursor,deepcopy(runtime.runner.local_ticks),len(runtime.records),len(runtime.attempts))
    assert executor.execute_batch(InputBatch(1,8,(records,)))==(bytes(executor.counter_count),)
    assert runtime.submits==[]
    assert before==(runtime.cursor,runtime.runner.local_ticks,len(runtime.records),len(runtime.attempts))
    assert executor.receipts[-1].status=='input_invalid'
    assert executor._online_primary_error is None


def test_tuple_duplicate_and_changed_slot(transport_case):
    executor,runtime,valid=transport_case
    batch=InputBatch(1,8,((valid,valid),))
    result=executor.execute_batch(batch)
    assert type(result) is tuple and len(result)==1
    assert len(runtime.submits)==2
    assert executor.execute_batch(batch)==result and len(runtime.submits)==2
    with pytest.raises(ValueError,match='identity reused'):
        executor.execute_batch(InputBatch(1,8,((valid[:-1]+b'X',valid),)))
    assert executor._session_stop_reason is not None


def test_second_runtime_failure_retains_partial_inventory(transport_case):
    executor,runtime,valid=transport_case;runtime.fail_at=1
    executor.execute_batch(InputBatch(1,8,((valid,valid),(valid,))))
    assert len(runtime.submits)==2 and len(runtime.records)==1 and len(runtime.attempts)==2
    assert executor.receipts[0].status=='environment_error'
    assert executor.online_decisions[0]['case_ids']==['synthetic-transport:0','synthetic-transport:1']
    assert executor.online_decisions[0]['committed'] is False
    primary = executor._online_primary_error
    with pytest.raises(RuntimeError) as caught:
        executor._finish_online_session()
    assert caught.value is primary
    assert executor._finish_online_session() == (runtime.trace, b'synthetic-plan'.hex())


def test_finish_and_shared_surface(transport_case):
    from myfuzz.integration.compiled_rfuzz import CompiledRfuzzExecutor
    executor,runtime,_=transport_case
    assert executor._SHARED_SURFACE==CompiledRfuzzExecutor._SHARED_SURFACE
    result=executor._finish_online_session()
    assert type(result) is tuple and result==(runtime.trace,b'synthetic-plan'.hex())
    assert executor._finish_online_session()==result and runtime.finish_calls==1
    assert executor.mutation_hint()['energy']==1


def test_returned_instruction_identity_is_checked(transport_case):
    executor,runtime,valid=transport_case
    submit=runtime.submit
    def corrupt(raw):
        certificate=submit(raw)
        certificate['instruction_address']=-1
        return certificate
    runtime.submit=corrupt
    executor.execute_batch(InputBatch(8,8,((valid,),)))
    assert executor.receipts[-1].status=='environment_error'


def test_finish_failure_preserves_both_partial_exports(transport_case):
    executor,runtime,_=transport_case
    def fail():raise RuntimeError('synthetic-finish-fault')
    runtime.finish=fail
    with pytest.raises(RuntimeError,match='synthetic-finish-fault'):executor._finish_online_session()
    assert executor._finish_online_session()==(runtime.trace,b'synthetic-plan'.hex())
    assert executor._online_primary_error is None


def test_runtime_typed_refusal_is_environment_error(transport_case):
    from myfuzz.scenario.compiled_f2_decoder import CompiledF2CandidateRefused
    executor,runtime,valid=transport_case
    def fail(raw):raise CompiledF2CandidateRefused('synthetic-post-preflight')
    runtime.submit=fail
    executor.execute_batch(InputBatch(9,8,((valid,),)))
    assert executor.receipts[-1].status=='environment_error'


def test_finish_failure_still_exports_plan_when_trace_fails(transport_case):
    executor,runtime,_=transport_case
    def fail():raise RuntimeError('synthetic-finish-fault')
    def trace_fail():raise RuntimeError('synthetic-trace-fault')
    runtime.finish=fail;runtime.session.trace=trace_fail
    with pytest.raises(RuntimeError,match='synthetic-finish-fault'):executor._finish_online_session()
    assert executor._online_final_plan_hex==b'synthetic-plan'.hex()


@pytest.mark.parametrize('field',['runtime_contract','runtime_path_document','instruction_image_binding_documents'])
def test_builder_checks_live_session_admission(transport_case,field):
    from myfuzz.integration.compiled_f2_rfuzz import build_compiled_f2_rfuzz_executor
    _,runtime,_=transport_case
    setattr(runtime.session,field,None)
    with pytest.raises(ValueError,match='session-mismatch'):
        build_compiled_f2_rfuzz_executor(runtime,run_id=runtime.run_id)


def test_builder_checks_full_compiled_digest(transport_case):
    from myfuzz.integration.compiled_f2_rfuzz import build_compiled_f2_rfuzz_executor
    _,runtime,_=transport_case
    runtime.compiled_digest='0'*64
    with pytest.raises(ValueError,match='compiled-mismatch'):
        build_compiled_f2_rfuzz_executor(runtime,run_id=runtime.run_id)


def test_saved_failure_uses_final_case_inventory(transport_case, tmp_path):
    import json
    executor, runtime, valid = transport_case
    executor.evidence_dir = tmp_path
    runtime.fail_at = 1
    executor.execute_batch(InputBatch(21, 8, ((valid, valid),)))
    saved = json.loads((tmp_path / 'compiled-f2-failure-21-0.json').read_text())
    decision = executor.online_decisions[-1]
    assert saved['decision'] == decision
    assert saved['decision']['status'] == 'environment_error'
    assert saved['decision']['case_ids'] == [row['case_id'] for row in runtime.attempts]
    assert len(executor.receipts[-1].online_case['source']['candidates']) == 2


@pytest.mark.parametrize('typed', [False, True])
@pytest.mark.parametrize('successful_prefix', [0, 1])
def test_pre_admission_submit_failure_has_no_invented_case(transport_case, typed, successful_prefix):
    from myfuzz.scenario.compiled_f2_decoder import CompiledF2CandidateRefused
    executor, runtime, valid = transport_case
    submit = runtime.submit
    def fail_before_admission(raw):
        if len(runtime.attempts) < successful_prefix:
            return submit(raw)
        if typed:
            raise CompiledF2CandidateRefused('synthetic-before-admission')
        raise RuntimeError('synthetic-before-admission')
    runtime.submit = fail_before_admission
    vectors = executor.execute_batch(InputBatch(22, 8, ((valid,) * (successful_prefix + 1),)))
    assert vectors == (bytes(executor.counter_count),)
    receipt = executor.receipts[-1]
    assert receipt.status == 'environment_error'
    actual_ids = [row['case_id'] for row in runtime.attempts]
    assert executor.online_decisions[-1]['case_ids'] == actual_ids
    assert [row['case_id'] for row in receipt.online_case['source']['candidates']] == actual_ids
    assert len(runtime.records) == successful_prefix
