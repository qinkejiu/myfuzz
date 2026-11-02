"""Synthetic transport records join source-backed declarations; no native authority."""
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import importlib.util
import json
from types import SimpleNamespace
import pytest
from tests.integration.f2_rfuzz_support import transport_case, f2_transport_inputs
from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.compiled_f2 import CompiledF2Runtime


def joiner():
    assert importlib.util.find_spec('myfuzz.integration.compiled_f2_receipts'), 'F2 receipt join missing'
    from myfuzz.integration.compiled_f2_receipts import join_compiled_f2_receipts
    return join_compiled_f2_receipts


@pytest.fixture
def receipt_case(transport_case,tmp_path,request):
    executor,runtime,valid=transport_case
    binding={'runtime_path_admission':runtime.runtime_path_admission.document()}
    runtime.execution_binding=SimpleNamespace(digest='a'*64,document=lambda:deepcopy(binding))
    original_submit=runtime.submit
    def submit(raw):
        certificate=original_submit(raw)
        certificate['execution_binding_sha256']=runtime.execution_binding.digest
        runtime.records[-1]['certificate']=deepcopy(certificate)
        return certificate
    runtime.submit=submit
    runtime.assertion_case_evidence=lambda:CompiledF2Runtime.assertion_case_evidence(runtime)
    runtime.assertion_results=lambda:CompiledF2Runtime.assertion_results(runtime)
    cursor=runtime.cursor
    candidates=executor.online_decoder.decode_sequence((valid,valid,valid),cursor=cursor,case_index=0)
    tests=((bytes(8),),(b'\xff'*8,),(valid,valid),(valid,)) if getattr(request,'param',False) else ((valid,valid),(valid,))
    executor.execute_batch(InputBatch(1,8,tests))
    for attempt,record,candidate in zip(runtime.attempts,runtime.records,candidates):
        attempt['assertions']={a['expectation_id']:dict(status='passed',reason='synthetic transport only',evidence={}) for a in binding['runtime_path_admission']['selected_path']['assertions']}
        record['raw']=candidate.candidate_bytes.hex()
        record['certificate']['assertions']=[dict(expectation_id=k,status='passed',evidence={}) for k in attempt['assertions']]
    online_cases=[]
    for candidate in candidates:
        source=asdict(candidate.case.source);source['kind']='bound_instruction'
        online_cases.append(dict(case_id=candidate.case.case_id,direction=candidate.case.direction,path_id=candidate.case.path_id,source=source))
    plan=dict(run_id=runtime.run_id,compiled_sha256=runtime.compiled_digest,
        execution_binding_sha256=runtime.execution_binding.digest,execution_binding=binding,
        records=deepcopy(runtime.records),assertions=runtime.assertion_results(),online_plan={'cases':online_cases})
    replay=dict(matches=True,first_difference=None,verification_scope='full',actual_prefix=deepcopy(plan))
    rows=[]
    for receipt,decision in zip(executor.receipts,executor.online_decisions):
        row=asdict(receipt);row.pop('trace');row.pop('online_case')
        row.update(online_source=receipt.online_case['source'],online_raw_records_hex=decision['raw_records_hex'])
        row.update({k:decision.get(k) for k in ('case_id','direction','flow_id','target_id','source_id','operator_id','candidate_id','candidate_disposition','candidate_disposition_reason','wire_cycle_count','candidate_count','rejection')})
        rows.append(deepcopy(row))
    path=tmp_path/'receipts.jsonl'
    def save():path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
    save()
    return dict(receipts_path=path,compiled_inputs=runtime.inputs,runtime=runtime,executor=executor,plan=plan,replay=replay),rows,save


def test_multiple_candidates_join_transport_projection_and_fresh(receipt_case):
    kwargs,rows,_=receipt_case
    result=joiner()(**kwargs)
    assert result['status']=='ok' and result['case_count']==3
    assert result['raw_record_count']==3 and result['candidate_bytes']==4
    assert len(rows[0]['online_raw_records_hex'])==2


@pytest.mark.parametrize('change',['flow','source','run','raw','suffix_coherent','projected','omit_case','duplicate_case','reorder','instruction','fresh','binding','typed'])
def test_substitutions_refuse_even_with_coherent_saved_hashes(receipt_case,change):
    kwargs,rows,save=receipt_case;row=rows[0];plan=kwargs['plan']
    if change=='flow':row['flow_id']='F4'
    elif change=='source':row['source_id']='borrowed'
    elif change=='run':row['run_id']='borrowed'
    elif change in ('raw','suffix_coherent'):
        row['online_raw_records_hex'][0]=row['online_raw_records_hex'][0][:-2]+'ff'
        if change=='suffix_coherent':row['raw_sha256']=sha256(b''.join(bytes.fromhex(r) for r in row['online_raw_records_hex'])).hexdigest()
    elif change=='projected':row['online_source']['candidates'][0]['candidate_bytes_hex']='00000000'
    elif change=='omit_case':plan['records'].pop()
    elif change=='duplicate_case':plan['records'].append(deepcopy(plan['records'][0]))
    elif change=='reorder':plan['records'].reverse()
    elif change=='instruction':plan['online_plan']['cases'][0]['source']['address']+=4
    elif change=='fresh':kwargs['replay']['actual_prefix']['records'][0]['raw']='00000000'
    elif change=='binding':plan['execution_binding_sha256']='0'*64
    else:plan['assertions']['cases'][0]['assertions'].pop()
    save()
    with pytest.raises(ValueError):joiner()(**kwargs)


def test_actual_live_writer_omits_internal_feedback_fields(receipt_case):
    kwargs,rows,save=receipt_case
    for row in rows:
        for key in ('interaction_feedback','closed_loop_feedback','online_plan_hex'):
            row.pop(key,None)
    save()
    assert joiner()(**kwargs)['status']=='ok'


def test_coherent_online_instruction_owner_swap_refused(receipt_case):
    kwargs,_,_=receipt_case
    for prefix in (kwargs['plan'],kwargs['replay']['actual_prefix']):
        prefix['online_plan']['cases'][0]['source']['component']='borrowed'
    with pytest.raises(ValueError):joiner()(**kwargs)


def test_persisted_test_order_must_match_actual_transport(receipt_case):
    kwargs,rows,save=receipt_case
    rows.reverse();save()
    with pytest.raises(ValueError):joiner()(**kwargs)


@pytest.mark.parametrize('receipt_case',[True],indirect=True)
def test_two_distinct_invalid_rows_cannot_swap_before_valid_rows(receipt_case):
    kwargs,rows,save=receipt_case
    assert [r['status'] for r in rows[:2]]==['input_invalid','input_invalid']
    assert rows[0]['raw_sha256']!=rows[1]['raw_sha256']
    assert joiner()(**kwargs)['status']=='ok'
    rows[0],rows[1]=rows[1],rows[0];save()
    with pytest.raises(ValueError,match='order'):joiner()(**kwargs)
