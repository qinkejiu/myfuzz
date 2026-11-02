"""Strict saved F2 transport joins. Returned JSON grants no native authority."""
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path

from myfuzz.scenario.compiled_f2_decoder import CompiledF2Decoder, CompiledF2CandidateRefused
from myfuzz.scenario.compiled_paths import compiled_document_sha256
from myfuzz.scenario.compiled_assertion_results import validate_assertion_results


def _require(condition, code):
    if not condition:
        raise ValueError('compiled-F2-receipt-'+code)


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False)


def _equal(left,right,code):
    _require(_json(left)==_json(right),code)


def _normalized_records(records):
    result=deepcopy(records)
    # Existing full-prefix comparison permits only these process-local scopes.
    for row in result:
        for key in ('prerequisite','postcondition'):
            if key in row['certificate']:
                row['certificate'][key].pop('process_scope',None)
    return result


def join_compiled_f2_receipts(receipts_path, *, compiled_inputs, runtime, executor, plan, replay):
    raw=Path(receipts_path).read_bytes()
    rows=[]
    for line in raw.splitlines():
        if line.strip():
            try:row=json.loads(line)
            except ValueError as error:raise ValueError('compiled-F2-receipt-invalid-json') from error
            _require(type(row) is dict,'row-type');rows.append(row)
    _require(executor.runtime is runtime,'runtime-identity')
    _require(executor.run_id==runtime.run_id,'run-identity')
    _require(type(plan) is dict and type(replay) is dict,'complete-prefix-required')
    _require(replay.get('matches') is True and replay.get('first_difference') is None
        and replay.get('verification_scope')=='full','full-fresh-required')
    fresh=replay.get('actual_prefix');_require(type(fresh) is dict,'actual-prefix-required')
    digest=compiled_document_sha256(compiled_inputs['compiled'])
    _require(digest==runtime.compiled_digest,'compiled-identity')
    binding=runtime.execution_binding.document()
    selected=binding['runtime_path_admission']['selected_path']
    for prefix in (plan,fresh):
        _require(prefix.get('run_id')==runtime.run_id and prefix.get('compiled_sha256')==digest,'prefix-identity')
        _require(prefix.get('execution_binding_sha256')==runtime.execution_binding.digest,'binding-identity')
        _equal(prefix.get('execution_binding'),binding,'binding-document')
    _equal(plan.get('records'),runtime.records,'original-live-records')
    _equal(_normalized_records(fresh.get('records',[])),_normalized_records(runtime.records),'fresh-records')
    _equal(plan.get('online_plan'),fresh.get('online_plan'),'fresh-online-plan')
    evidence=runtime.assertion_case_evidence();typed=runtime.assertion_results()
    validate_assertion_results(typed,compiled_document_sha256=digest,
        binding_sha256=runtime.execution_binding.digest,path=selected,run_id=runtime.run_id,cases=evidence)
    _equal(plan.get('assertions'),typed,'original-typed-results')
    _equal(fresh.get('assertions'),typed,'fresh-typed-results')
    live_receipts={}
    for receipt in executor.receipts:
        key=(receipt.run_id,receipt.buffer_id,receipt.slot)
        _require(key not in live_receipts,'duplicate-live-slot');live_receipts[key]=receipt
    decisions={}
    for decision in executor.online_decisions:
        key=(runtime.run_id,decision['buffer_id'],decision['slot'])
        _require(key not in decisions,'duplicate-live-decision');decisions[key]=decision
    _require(len(rows)==len(live_receipts),'receipt-count')
    _equal([(r.get('run_id'),r.get('buffer_id'),r.get('slot')) for r in rows],
        list(live_receipts),'persisted-receipt-order')
    decoder=CompiledF2Decoder.from_request(request=compiled_inputs['request'],compiled=compiled_inputs['compiled'],
        run_id=runtime.run_id,schedule=tuple(runtime.runner.sessions),rounds=runtime.rounds,result_address=runtime.result)
    ordered_records=runtime.records
    cursor=(ordered_records[0]['certificate']['instruction_address'] if ordered_records else runtime.cursor)
    seen=set();case_ids=[];mappings=[];expected_sources=[];raw_record_count=0;record_index=0;rejected=0
    for row in rows:
        key=(row.get('run_id'),row.get('buffer_id'),row.get('slot'))
        _require(key not in seen and key in live_receipts and key in decisions,'slot-bijection');seen.add(key)
        receipt=live_receipts[key];decision=decisions[key]
        # Every persisted receipt field is compared with its same-call source.
        for field,value in asdict(receipt).items():
            if field in ('trace','online_case','online_plan_hex','interaction_feedback','closed_loop_feedback'):continue
            _require(field in row,'receipt-field-required:'+field)
            _equal(row[field],value,'same-call-receipt:'+field)
        for field in ('case_id','direction','flow_id','target_id','source_id','operator_id','candidate_id',
                'candidate_disposition','candidate_disposition_reason','wire_cycle_count','candidate_count','rejection'):
            _equal(row.get(field),decision.get(field),'same-call-decision:'+field)
        _require(row.get('flow_id')=='F2' and row.get('source_id')==decoder.source_id
            and row.get('path_id')==decoder.path_id,'F2-path-source')
        _equal(row.get('online_raw_records_hex'),decision['raw_records_hex'],'same-call-raw8')
        _equal(row.get('online_source'),receipt.online_case['source'],'same-call-source')
        try:records=tuple(bytes.fromhex(item) for item in row['online_raw_records_hex'])
        except (ValueError,TypeError) as error:raise ValueError('compiled-F2-receipt-raw8-invalid') from error
        _require(all(type(record) is bytes and len(record)==8 for record in records),'raw8-width')
        _require(1<=len(records)<=200,'wire-count')
        raw_record_count+=len(records)
        _require(sha256(b''.join(records)).hexdigest()==row['raw_sha256'],'raw8-hash')
        try:
            if not 1<=len(records)<=8:
                raise CompiledF2CandidateRefused('sequence-count','/wire/records',{'observed':len(records)})
            if record_index+len(records)>runtime.max_cases:
                raise CompiledF2CandidateRefused('case-budget-exhausted','/cases',
                    {'admitted':record_index,'requested':len(records),'max_cases':runtime.max_cases})
            candidates=decoder.decode_sequence(records,cursor=cursor,case_index=record_index)
        except CompiledF2CandidateRefused as error:
            _require(row['status']=='input_invalid','invalid-status')
            _equal(row.get('rejection'),dict(code=error.code,pointer=error.pointer,detail=error.detail),'typed-rejection')
            _require(not decision.get('case_ids') and not row['online_source']['candidates'],'refusal-has-case')
            rejected+=1;continue
        _require(row['status']=='certified','incomplete-execution')
        _equal(row['online_source']['candidates'],[c.document() for c in candidates],'independent-projection')
        _require(sha256(b''.join(c.candidate_bytes for c in candidates)).hexdigest()==row['genome_sha256'],'projected4-hash')
        _equal(decision.get('case_ids'),[c.case.case_id for c in candidates],'decision-case-order')
        for candidate in candidates:
            _require(record_index<len(ordered_records),'missing-record')
            record=ordered_records[record_index];certificate=record['certificate']
            _require(record.get('raw')==candidate.candidate_bytes.hex(),'record-projection')
            expected=dict(case_id=candidate.case.case_id,path_id=decoder.path_id,source_id=decoder.source_id,
                execution_binding_sha256=runtime.execution_binding.digest,
                runtime_path_id=candidate.case.path_id,runtime_path_admission_sha256=decoder.runtime_path_admission.digest,
                instruction_address=candidate.case.source.address,instruction_source_id=decoder.image['source_id'],
                instruction_sha256=sha256(bytes.fromhex(candidate.declaration['code_hex'])).hexdigest())
            _require(all(certificate.get(k)==v for k,v in expected.items()),'certificate-identity')
            case_ids.append(candidate.case.case_id)
            expected_sources.append((candidate.case.direction,candidate.case.path_id,asdict(candidate.case.source)))
            mappings.append(dict(case_id=candidate.case.case_id,source_id=candidate.source_id,
                instruction_source_id=candidate.case.source.source_id,runtime_path_id=candidate.case.path_id,
                raw8_sha256=sha256(candidate.raw).hexdigest(),projected4_sha256=sha256(candidate.candidate_bytes).hexdigest()))
            cursor+=len(bytes.fromhex(candidate.declaration['code_hex']));record_index+=1
    _require(record_index==len(ordered_records),'record-bijection')
    _equal(case_ids,[a['case_id'] for a in runtime.attempts],'attempt-bijection')
    _equal(case_ids,[a['case_id'] for a in evidence],'typed-case-bijection')
    online_cases=plan.get('online_plan',{}).get('cases',[])
    _equal(case_ids,[c['case_id'] for c in online_cases],'online-case-bijection')
    for case,record,expected_source in zip(online_cases,ordered_records,expected_sources):
        certificate=record['certificate'];source=case['source']
        direction,path_id,source_fields=expected_source
        _require(case.get('direction')==direction and case.get('path_id')==path_id
            and source.get('kind')=='bound_instruction','online-case-identity')
        _require(all(source.get(k)==v for k,v in source_fields.items()),'online-source-identity')
        _require(source.get('address')==certificate['instruction_address']
            and sha256(bytes.fromhex(source['data_hex'])).hexdigest()==certificate['instruction_sha256']
            and case.get('path_id')==certificate['runtime_path_id'],'online-instruction-binding')
    return dict(schema_version='compiled_F2_receipt_join.v1',status='ok',run_id=runtime.run_id,
        path_id=decoder.path_id,source_id=decoder.source_id,compiled_sha256=digest,
        execution_binding_sha256=runtime.execution_binding.digest,receipts_sha256=sha256(raw).hexdigest(),
        rows=len(rows),case_count=len(case_ids),raw_record_count=raw_record_count,
        candidate_bytes=4,wire_record_bytes=8,rejected_tests=rejected,cases=mappings)
