"""Join original raw8 transport to F6 source operands, program, typed and fresh cases."""
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from myfuzz.scenario.f6_assertion_evidence import build_f6_assertion_material

def _json(v):return json.dumps(v,sort_keys=True,separators=(',', ':'),allow_nan=False)
def _require(ok,code):
    if not ok:raise ValueError('compiled-F6-receipt-'+code)

def join_compiled_f6_receipts(*,runtime,executor,receipts_path,replay):
    _require(executor.runtime is runtime,'runtime-owner')
    plan=runtime.finish(); fresh=replay.get('actual_prefix')
    scope='full' if plan.get('completed') else 'failed_prefix_full'
    _require(replay.get('matches') is True and replay.get('first_difference') is None
        and replay.get('verification_scope')==scope and type(fresh) is dict,'fresh-scope')
    _require(_json(plan['records'])==_json(runtime.records),'live-records')
    _require(_json(fresh['records'])==_json(runtime.records),'fresh-records')
    material=build_f6_assertion_material(runtime)
    _require(_json(plan['assertion_material'])==_json(material),'typed-inventory')
    from .compiled_f6 import _normalized_f6_prefix
    _require(_json(_normalized_f6_prefix(fresh)['assertion_material'])==
        _json(_normalized_f6_prefix(plan)['assertion_material']),'fresh-typed-inventory')
    raw=Path(receipts_path).read_bytes();rows=[json.loads(line) for line in raw.splitlines() if line.strip()]
    _require(len(rows)==len(executor.receipts),'count')
    decisions={(d['buffer_id'],d['slot']):d for d in executor.online_decisions}
    seen=set();cases=[];mappings=[];rejected=0;raw_count=0
    for row,receipt in zip(rows,executor.receipts):
        key=(row.get('buffer_id'),row.get('slot'))
        _require(key not in seen and key in decisions,'slot-bijection');seen.add(key)
        decision=decisions[key]
        for field,value in asdict(receipt).items():
            if field in ('trace','online_case','online_plan_hex','interaction_feedback','closed_loop_feedback'):continue
            _require(field in row and _json(row[field])==_json(value),'same-call-'+field)
        _require(row.get('online_raw_records_hex')==decision['raw_records_hex'],'raw8-source')
        _require(row.get('online_source')==receipt.online_case['source'],'source-material')
        _require(row.get('flow_id')=='F6' and row.get('case_id')==decision['case_id'],'decision-scope')
        records=tuple(bytes.fromhex(s) for s in row['online_raw_records_hex']);raw_count+=len(records)
        _require(sha256(b''.join(records)).hexdigest()==receipt.raw_sha256,'raw-hash')
        if row['status']=='input_invalid':
            _require(not decision['case_ids'] and not receipt.online_case['source']['candidates'],'refusal-case')
            refused=False
            if len(records)!=1:refused=True
            else:
                try:runtime.layout.decode(records[0])
                except ValueError:refused=True
            if not refused:refused=len(cases)>=runtime.max_cases
            _require(refused,'refusal-redecode');rejected+=1;continue
        _require(len(records)==1 and len(decision['case_ids'])==1,'single-case')
        candidate=runtime.layout.decode(records[0]);index=len(cases)
        _require(index<len(runtime.records),'missing-record')
        record=runtime.records[index];cid=decision['case_ids'][0]
        _require(cid==record['case_id']==f'{runtime.run_id}:case:{index}','case-identity')
        _require(record['raw8_hex']==candidate.raw.hex() and record['words']==list(candidate.words),'operands')
        prefix=runtime.program.prefix(candidate,case_index=index).hex()
        _require(record.get('prefix_hex')==prefix,'program')
        projected=receipt.online_case['source']['candidates']
        _require(len(projected)==1 and projected[0]['prefix_hex']==prefix and projected[0]['words']==list(candidate.words),'decoded-program')
        cases.append(cid);mappings.append(dict(case_id=cid,raw8_hex=candidate.raw.hex(),words=list(candidate.words),
            prefix_hex=prefix,source_ids=list(executor.online_decoder.source_ids),instruction_address=record['instruction_address']))
    _require(cases==[r['case_id'] for r in runtime.records]==[a['case_id'] for a in runtime.attempts]
        ==[c['case_id'] for c in material['assertions']['cases']],'case-bijection')
    online=plan['online_plan']['cases']
    _require(cases==[c['case_id'] for c in online],'online-case-bijection')
    for case,mapping in zip(online,mappings):
        _require(case['source']['data_hex']==mapping['prefix_hex'] and case['source']['address']==mapping['instruction_address'],'online-program')
    return dict(schema_version='compiled_F6_receipt_join.v1',status='ok',scope=scope,
        run_id=runtime.run_id,path_id=runtime.path['path_id'],source_id=executor.online_decoder.source_id,
        source_ids=list(executor.online_decoder.source_ids),execution_binding_sha256=runtime.execution_binding_sha256,
        receipts_sha256=sha256(raw).hexdigest(),rows=len(rows),case_count=len(cases),
        raw_record_count=raw_count,rejected_tests=rejected,wire_record_bytes=8,candidate_bytes=8,cases=mappings)
