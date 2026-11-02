"""Join live service issuance to native four-word F6 observations.

Raw journals and attempts select evidence; they never enroll read authority.
Each lookup closes component, complete transaction key and raw event identity.
Only known missing/contradictory evidence is typed here. Host/checker exceptions
propagate to the runtime, which owns terminal cleanup and partial export.
"""
from copy import deepcopy
from .shared_f6_slots import f6_slot, f6_mapping, projection_context
from .compiled_f4 import _borrow_events
from dataclasses import asdict
from hashlib import sha256
import json

from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
from myfuzz.scenario.f6_assertion_evidence import _scope, _record_case, f6_case_feedback
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.f6_ram_dma_policy import _key
from myfuzz.integration.compiled_f6_irq import f6_dma_irq_runtime_name


class _EvidenceIssue(ValueError):
    def __init__(self,reason,details=None):
        super().__init__(reason)
        self.details=details or {}


class _Missing(_EvidenceIssue):pass
class _Contradiction(_EvidenceIssue):pass


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False,ensure_ascii=False)


def _require(condition,reason):
    if not condition:raise _Contradiction(reason)


def _present(condition,reason):
    if not condition:raise _Missing(reason)


def _configuration_values(contract):
    program=contract['program_contract'];dma=contract['dma'];csr=dma['csr']
    length=csr['length_words'] * (4 if dma.get('behavior',{}).get('length_unit','words')=='bytes' else 1)
    return [program['source_address'],program['destination_address'],length,csr['start_word']]


def _irq_low_reference(level, level_clear, expiry):
    if level:
        _present(type(level_clear) is dict and type(level_clear.get('low_cpu_sample_event_id')) is int
            and level_clear['low_cpu_sample_event_id']>0, 'level IRQ low sample reference unavailable')
        return level_clear['low_cpu_sample_event_id']
    return expiry


def _requires_runner_backed_protocol_report(runtime):
    """Only the real compiled F6 runtime may never use fixture fallback."""
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    return isinstance(runtime, CompiledF6Runtime)


def _same(a,b,reason):
    _require(_json(a)==_json(b),reason)


def _transaction(value):
    _require(type(value) is dict and set(value)==set(TransactionKey.__dataclass_fields__),
             'incomplete transaction reference')
    try:return _key(TransactionKey(**value))
    except ValueError as error:raise _Contradiction(str(error)) from error


def _raw(row):
    return {k:v for k,v in row.items()
            if k not in ('event_id','producer_event_id','runner_event_id')}


def _f6_take_receipts_match(runtime, cpu, cpu_id, returned, take):
    original = returned.get('take_receipt_id')
    observed = take.get('receipt_id')
    if (type(original) is not dict or type(observed) is not dict
            or set(original) != {'execution', 'sequence'}
            or set(observed) != {'execution', 'sequence'}
            or type(original['execution']) is not str
            or not original['execution']
            or original['execution'] != cpu._execution
            or type(original['sequence']) is not int or original['sequence'] <= 0
            or type(observed['sequence']) is not int
            or observed['sequence'] != original['sequence']):
        return False
    if observed == original:
        return True
    from myfuzz.scenario.runner import ScenarioRunner
    runner = getattr(runtime, 'runner', None)
    if (type(runner) is not ScenarioRunner
            or type(getattr(runner, 'sessions', None)) is not dict
            or runner.sessions.get(cpu_id) is not cpu):
        return False
    scopes = getattr(runner, '_source_transport_scopes', None)
    cpu_scopes = scopes.get(cpu_id) if type(scopes) is dict else None
    mapped = cpu_scopes.get(original['execution']) if type(cpu_scopes) is dict else None
    return (type(mapped) is str and bool(mapped)
        and type(observed.get('execution')) is str
        and observed['execution'] == mapped)


def _runner_provenance_is_exact(row,attempt,*,session_case_index=None):
    provenance=row.get('provenance')
    fields={'schema_version','observed_case','origin_admission_ids',
        'origin_status','unknown_writer_ids','invalid_origin_references',
        'proof_scope','edge_candidates','resource'}
    if type(provenance) is not dict or set(provenance)!=fields:
        return False
    case={'case_id':attempt.get('case_id'),
        'case_index':(attempt.get('case_index') if session_case_index is None else session_case_index)}
    known=provenance.get('origin_admission_ids')
    unknown=provenance.get('unknown_writer_ids')
    invalid=provenance.get('invalid_origin_references')
    if (provenance.get('schema_version')!='event_source_provenance.v1'
            or provenance.get('observed_case')!=case
            or type(known) is not list
            or any(type(item) is not str or not item for item in known)
            or known!=sorted(set(known))
            or type(unknown) is not list
            or any(type(item) is not str or not item for item in unknown)
            or len(unknown)!=len(set(unknown))
            or type(invalid) is not int or invalid<0
            or type(provenance.get('edge_candidates')) is not list
            or type(provenance.get('resource')) is not dict
            or provenance.get('proof_scope')!='memory_writer_snapshot'):
        return False
    expected_status=('partial' if known and (unknown or invalid)
        else 'known' if known else 'unknown')
    if provenance.get('origin_status')!=expected_status:
        return False
    resource_fields=('memory_id','generation','byte_offset','address',
        'width_bytes','byte_enable','transaction','version','versions',
        'writer_event_id','writer_event_ids','writer_kinds')
    resource={name:list(row[name]) if type(row.get(name)) is tuple
        else row[name] for name in resource_fields if name in row}
    try:
        return _json(provenance['resource'])==_json(resource)
    except (TypeError,ValueError):
        return False


_F6_FETCH_ROOT_FIELDS = {
    'admission':'admission_event_id',
    'service':'service_event_id',
    'memory_read':'memory_read_event_id',
    'instr_response':'instr_response_event_id',
    'request_pre':'request_pre_event_id',
    'request_producer':'request_producer_event_id',
    'backend_response_pre':'backend_response_pre_event_id',
    'backend_response_producer':'backend_response_producer_event_id',
    'backend_response_post':'backend_response_post_event_id',
    'response_pre':'response_pre_event_id',
    'response_producer':'response_producer_event_id',
    'response_post':'response_post_event_id',
}


def _f6_fetch_completion_document(receipt):
    """Serialize the original Task9 object in its closed Runner row shape."""
    document=asdict(receipt)
    document['snapshot']['data_hex']=document['snapshot'].pop('data').hex()
    document['acceptance']['data_hex']=document['acceptance'].pop('data').hex()
    document['admission']=receipt.admission.document()
    return document


def _f6_live_fetch_evidence(runtime,attempt,events,local_by_id):
    """Join current issuer objects to their exact original Runner receipt rows."""
    from myfuzz.scenario.f6_instruction_fetch_receipt import (
        f6_instruction_fetch_receipts, validate_f6_instruction_fetch)
    from myfuzz.scenario.ledger import TransactionKey

    cpu=runtime.cpu;cpu_id=runtime.contract['cpu']['instance_id']
    program=runtime.contract['program_contract']
    source_id=runtime.contract['instruction_source_id']
    run_id=runtime.run_id;binding=runtime.execution_binding_sha256
    case_id=attempt.get('case_id');case_index=attempt.get('case_index')
    _require(type(case_id) is str and type(case_index) is int and case_index>=0,
        'invalid F6 instruction receipt attempt scope')
    _require(case_id==run_id+':case:'+str(case_index),
        'F6 instruction receipt attempt case/run scope mismatch')
    try:
        prefix=bytes.fromhex(attempt['prefix_hex'])
    except (KeyError,TypeError,ValueError) as error:
        raise _Contradiction('invalid F6 instruction receipt prefix') from error
    _require(len(prefix)==128,'F6 instruction receipt prefix must cover 32 words')
    path_ids=runtime.runtime_path_admission.get('runtime_path_ids')
    _present(type(path_ids) is list and len(path_ids)>1,
        'F6 instruction receipt runtime path unavailable')
    prefix_path=path_ids[1]
    slot=program['slot_base']+program['slot_bytes']*f6_slot(runtime, attempt)

    runner={}
    for row in events:
        _require(type(row) is dict and type(row.get('event_id')) is int
            and row['event_id']>0 and row['event_id'] not in runner,
            'duplicate or invalid F6 Runner event identity')
        runner[row['event_id']]=row

    def root(event_id,kind):
        _present(type(event_id) is int and event_id>0,
            'F6 instruction receipt '+str(kind)+' Runner reference unavailable')
        row=runner.get(event_id)
        _present(type(row) is dict,
            'F6 instruction receipt '+str(kind)+' Runner event is dangling')
        owner_ok=(('component' not in row) if kind=='source_admission'
            else row.get('component')==cpu_id)
        _require(row.get('event_id')==event_id and owner_ok
            and row.get('kind')==kind,
            'F6 instruction receipt '+str(kind)+' Runner identity mismatch')
        return row

    def step_root(receipt,refs,phase_name,phase,scope_name,producer_name):
        sample_id=refs[phase_name]
        producer_id=refs[producer_name]
        sample=root(sample_id,'local_tick_sample')
        scope=getattr(receipt,scope_name)
        expected=getattr(receipt,phase_name)
        phase_kind=phase
        _require(sample.get('phase')==phase_kind
            and sample.get('f6_obi_scope')==list(scope)
            and sample.get('local_tick')==scope[3]
            and sample.get('reset_epoch')==receipt.reset_epoch
            and _json(sample.get('outputs'))==_json(expected),
            'F6 instruction receipt '+phase_name+' PRE/POST sample mismatch')
        producer=root(producer_id,None)
        _require(producer.get('kind') is None
            and producer.get('local_tick')==scope[3]
            and type(producer.get('inputs')) is dict
            and type(producer.get('outputs')) is dict
            and sample.get('producer_event_id')==producer_id,
            'F6 instruction receipt '+producer_name+' identity mismatch')
        driver_samples=producer['outputs'].get('driver_samples')
        actual_sample=(driver_samples[0].get(phase_kind)
            if type(driver_samples) in (list,tuple) and len(driver_samples)==1 else None)
        sample_diff=({key:(actual_sample.get(key),expected.get(key))
            for key in set(actual_sample)|set(expected)
            if actual_sample.get(key)!=expected.get(key)}
            if type(actual_sample) is dict and type(expected) is dict else None)
        _require(type(driver_samples) in (list,tuple) and len(driver_samples)==1
            and _json(actual_sample)==_json(expected),
            'F6 instruction receipt '+phase_name+' producer sample mismatch: '+repr(sample_diff))
        return sample,producer

    try:
        receipts=f6_instruction_fetch_receipts(cpu)
    except ValueError as error:
        raise _Contradiction('F6 original instruction receipt issuer refused access') from error
    _present(type(receipts) is tuple,'F6 original instruction receipt collection unavailable')
    keys=set();current=[];all_runner_ids=set()
    completion_rows=[row for row in events
        if type(row) is dict and row.get('kind')=='compiled_F6_instruction_fetch_completion'
        and row.get('component')==cpu_id]
    rows_by_key={}
    for row in completion_rows:
        key=row.get('key')
        if type(key) is dict:
            rows_by_key.setdefault(_json(key),[]).append(row)

    for receipt in receipts:
        try:
            validate_f6_instruction_fetch(cpu,receipt)
        except ValueError as error:
            raise _Contradiction('original F6 instruction receipt issuer rejected a completion') from error
        _require(type(receipt.key) is TransactionKey,
            'F6 instruction receipt requires a complete TransactionKey')
        key=asdict(receipt.key);key_id=_json(key)
        _require(key_id not in keys,'duplicate F6 instruction completion TransactionKey')
        keys.add(key_id)
        index=receipt.case_index
        _require(type(index) is int and index>=0
            and receipt.run_id==run_id
            and receipt.execution_binding_sha256==binding
            and receipt.case_id==run_id+':case:'+str(index)
            and receipt.execution==cpu._execution
            and receipt.testcase_id==runtime.session.template.testcase_id
            and key['execution_id']=='local-execution'
            and receipt.testcase_id==key['testcase_id']
            and receipt.reset_epoch==key['source_epoch']
            and key['source_component']==cpu_id and key['channel_id']=='instr',
            'F6 instruction completion receipt run/execution/key scope mismatch')
        source=receipt.source;admission=receipt.admission
        acceptance=receipt.acceptance;snapshot=receipt.snapshot
        mapping = (f6_mapping(runtime, index) if 'shared_slots' in program else None)
        receipt_slot=program['slot_base']+program['slot_bytes']*(mapping['slot_index'] if mapping else index)
        action=source_id+':'+str(index)
        _require(source.action_id==action and source.source_id==source_id
            and source.component==cpu_id and source.address==receipt_slot
            and type(source.data) is bytes and source.data==acceptance.data
            and acceptance.address==receipt_slot and acceptance.source_event_id==action
            and len(acceptance.data)==128
            and type(admission.case_id) is str
            and admission.case_id==receipt.case_id
            and admission.case_index==(mapping['session_case_index'] if mapping else index) and admission.path_id==prefix_path
            and admission.direction=='CPU_TO_IP' and admission.component==cpu_id
            and admission.action_id==action and admission.source_id==source_id
            and admission.role=='fuzz_source' and admission.input_kind=='instruction',
            'F6 instruction completion source/admission/slot mismatch')
        offset=receipt.address-receipt_slot
        _require(type(receipt.address) is int and receipt.address%4==0
            and 0<=offset<=len(acceptance.data)-4 and offset%4==0
            and snapshot.transaction_id==str(receipt.key)
            and snapshot.memory_id==acceptance.memory_id
            and snapshot.generation==acceptance.generation
            and snapshot.byte_offset==acceptance.byte_offset+offset
            and snapshot.data==acceptance.data[offset:offset+4]
            and snapshot.versions==acceptance.versions[offset:offset+4]
            and snapshot.writer_event_ids==acceptance.writer_event_ids[offset:offset+4]
            and snapshot.writer_kinds==acceptance.writer_kinds[offset:offset+4]
            and snapshot.writer_kinds==('INSTRUCTION_SOURCE',)*4,
            'F6 instruction receipt snapshot/version chain mismatch')
        if index==case_index:
            _require(receipt.case_id==case_id and acceptance.data==prefix
                and receipt.address==slot+offset,
                'F6 instruction receipt belongs to a different prefix slot')

        matching=rows_by_key.get(key_id,[])
        _present(bool(matching),
            'F6 original completion Runner event is missing for an issued receipt')
        _require(len(matching)==1,
            'duplicate F6 completion Runner event for a TransactionKey')
        completion=matching[0]
        completion_id=completion['event_id']
        _require(completion.get('run_id')==receipt.run_id
            and completion.get('execution_binding_sha256')==binding
            and completion.get('case_id')==receipt.case_id
            and completion.get('case_index')==index
            and completion.get('execution')==receipt.execution
            and completion.get('testcase_id')==receipt.testcase_id
            and completion.get('address')==receipt.address,
            'F6 completion Runner event has cross-case/fresh/wrong-slot scope')
        refs={name:completion.get(field)
            for name,field in _F6_FETCH_ROOT_FIELDS.items()}
        _require(all(type(value) is int and value>0 for value in refs.values()),
            'F6 completion Runner event has missing root references')
        serialized=_f6_fetch_completion_document(receipt)
        serialized.update(kind='compiled_F6_instruction_fetch_completion',
            component=cpu_id,event_id=completion_id,
            producer_event_id=refs['response_pre'])
        serialized.update({field:refs[name]
            for name,field in _F6_FETCH_ROOT_FIELDS.items()})
        for name,value in serialized.items():
            _require(_json(completion.get(name))==_json(value),
                'F6 original completion Runner row differs from its issuer receipt: '+name)

        admission_row=root(refs['admission'],'source_admission')
        _require(_json(admission_row.get('admission'))==_json(admission.document()),
            'F6 source admission Runner root differs from issuer receipt')
        service_row=root(refs['service'],'instruction_source')
        _require(service_row.get('producer_event_id')==refs['admission']
            and service_row.get('address')==acceptance.address
            and service_row.get('data_hex')==acceptance.data.hex()
            and service_row.get('source_event_id')==action
            and service_row.get('generation')==acceptance.generation,
            'F6 instruction source service Runner root mismatch')
        read_row=root(refs['memory_read'],'memory_read')
        _require(read_row.get('transaction')==key
            and read_row.get('address')==receipt.address
            and read_row.get('width_bytes')==4
            and read_row.get('memory_id')==snapshot.memory_id
            and read_row.get('generation')==snapshot.generation
            and read_row.get('byte_offset')==snapshot.byte_offset
            and read_row.get('value')==snapshot.value
            and read_row.get('data_hex')==snapshot.data.hex()
            and _json(read_row.get('versions'))==_json(snapshot.versions)
            and _json(read_row.get('writer_event_ids'))==_json(snapshot.writer_event_ids)
            and _json(read_row.get('writer_kinds'))==_json(snapshot.writer_kinds),
            'F6 original memory read Runner root differs from snapshot')
        response_row=root(refs['instr_response'],'instr_response')
        _require(response_row.get('transaction')==key
            and response_row.get('producer_event_id')==refs['backend_response_producer']
            and response_row.get('rdata')==snapshot.value
            and response_row.get('response_boundary')=='obi_adapter_backend_acceptance',
            'F6 backend instruction response Runner root mismatch')

        samples={}
        for sample_name,scope_name,producer_name,phase in (
                ('request_pre','request_scope','request_producer','pre'),
                ('backend_response_pre','backend_response_scope','backend_response_producer','pre'),
                ('backend_response_post','backend_response_scope','backend_response_producer','post'),
                ('response_pre','response_scope','response_producer','pre'),
                ('response_post','response_scope','response_producer','post')):
            sample,producer=step_root(receipt,refs,sample_name,phase,
                scope_name,producer_name)
            samples[sample_name]=sample
        _require(refs['request_producer']<refs['request_pre']
            <refs['backend_response_pre']
            and refs['admission']<refs['service']<refs['memory_read']
            <refs['backend_response_producer']<refs['instr_response']
            <refs['backend_response_pre']
            <refs['backend_response_post']<refs['response_producer']
            <refs['response_pre']<refs['response_post']<completion_id
            and response_row.get('event_id')<refs['backend_response_pre']
            and refs['backend_response_pre']<refs['backend_response_post'],
            'F6 OBI completion Runner chronology mismatch')

        completion_observers=[row for row in local_by_id.values()
            if row.get('component')==cpu_id
            and row.get('runner_event_id')==completion_id]
        _present(len(completion_observers)==1,
            'F6 completion Observer projection is missing or duplicated')
        observer=completion_observers[0]
        projected={key:value for key,value in observer.items()
            if key not in ('event_id','runner_event_id')}
        original={key:value for key,value in completion.items()
            if key not in ('event_id','runner_event_id')}
        _require(observer.get('kind')=='compiled_F6_instruction_fetch_completion'
            and _json(projected)==_json(original),
            'F6 completion Observer row differs from original Runner event')

        live_row=dict(address=receipt.address,key=key,
            completion_event_id=completion_id,root_refs=refs)
        root_ids=set(refs.values())|{completion_id}
        if index==case_index:
            current.append(live_row)
            all_runner_ids.update(root_ids)

    # The live archive may contain several already-admitted cases, but every
    # completion in this Runner must come from exactly one cumulative issuer row.
    issued_keys={_json(asdict(receipt.key)) for receipt in receipts}
    for row in completion_rows:
        if (row.get('run_id')==run_id
                and row.get('execution_binding_sha256')==binding):
            _require(type(row.get('key')) is dict
                and _json(row['key']) in issued_keys,
                'Runner contains a completion with no original F6 issuer receipt')
    _present(current,'no original F6 instruction fetch completions for this case')
    service_event_id=current[0]['root_refs']['service']
    service_observers=[row for row in local_by_id.values()
        if row.get('component')==cpu_id
        and row.get('runner_event_id')==service_event_id]
    _present(len(service_observers)==1,
        'F6 instruction source service Observer projection is missing or duplicated')
    service_observer=service_observers[0]
    _require(service_observer.get('kind')=='instruction_source',
        'F6 instruction source Observer projection kind mismatch')
    return dict(outcome='passed' if {row['address'] for row in current}
            ==set(range(slot,slot+len(prefix),4)) else 'missing',
        evidence=sorted(current,key=lambda row:row['completion_event_id']),
        runner_event_ids=sorted(all_runner_ids),
        completion_event_ids=sorted(row['completion_event_id'] for row in current),
        raw_references=[dict(component=cpu_id,event_id=service_observer['event_id'],
            kind='instruction_source')]+[dict(component=cpu_id,event_id=next(observer['event_id']
            for observer in local_by_id.values()
            if observer.get('component')==cpu_id
            and observer.get('runner_event_id')==row['completion_event_id']),
            kind='compiled_F6_instruction_fetch_completion') for row in current],
        raw_evidence=[deepcopy(runner[service_event_id])]
            +[deepcopy(runner[row['completion_event_id']]) for row in current],
        issues=[] if {row['address'] for row in current}
            ==set(range(slot,slot+len(prefix),4)) else [dict(outcome='missing',
                reason='F6 original OBI receipts do not cover all 32 prefix addresses')])


def _combine_evidence_outcomes(*statuses):
    return ('failed' if 'failed' in statuses
        else 'missing' if 'missing' in statuses else 'passed')


def _saved_projection_inputs(events, local_by_id):
    """Present live facts in the exact JSON value domain used by saved evidence."""
    return (json.loads(_json(list(events))),
            {key: json.loads(_json(row)) for key, row in local_by_id.items()})


def _close_live_f6_fetch_projection(runtime,attempt,events,local_by_id,projection):
    """Require saved edge-3 facts to match the current original issuer objects."""
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    if not isinstance(runtime,CompiledF6Runtime):
        return projection
    prior_outcome=projection['outcome']
    details=projection['details'];edge=details['edges'][3]
    saved_outcome=edge.get('outcome','missing')
    issues=[]
    try:
        live=_f6_live_fetch_evidence(runtime,attempt,events,local_by_id)
        live_outcome=live['outcome'];live_evidence=live['evidence']
    except _Missing as error:
        live_outcome='missing';live_evidence=[]
        live=dict(evidence=[],runner_event_ids=[],completion_event_ids=[],
            raw_references=[],raw_evidence=[],issues=[])
        issues.append(dict(outcome='missing',reason=str(error)))
    except _Contradiction as error:
        live_outcome='failed';live_evidence=[]
        live=dict(evidence=[],runner_event_ids=[],completion_event_ids=[],
            raw_references=[],raw_evidence=[],issues=[])
        issues.append(dict(outcome='failed',reason=str(error)))
    except (KeyError,TypeError,ValueError,AttributeError,OverflowError,IndexError) as error:
        live_outcome='failed';live_evidence=[]
        live=dict(evidence=[],runner_event_ids=[],completion_event_ids=[],
            raw_references=[],raw_evidence=[],issues=[])
        issues.append(dict(outcome='failed',reason='invalid live F6 receipt: '+str(error)))

    issues.extend(deepcopy(live.get('issues',[])))
    saved_evidence=edge.get('evidence')
    if type(saved_evidence) is not list or _json(saved_evidence)!=_json(live_evidence):
        live_outcome=_combine_evidence_outcomes(live_outcome,'failed')
        issues.append(dict(outcome='failed',
            reason='saved edge-3 receipts differ from original live issuer receipts'))

    saved_ids=edge.get('runner_event_ids')
    if type(saved_ids) is not list or any(type(value) is not int for value in saved_ids):
        saved_ids=[];live_outcome='failed'
        issues.append(dict(outcome='failed',reason='saved edge-3 Runner ID inventory is invalid'))
    elif not set(live.get('runner_event_ids',())).issubset(set(saved_ids)):
        live_outcome='failed'
        issues.append(dict(outcome='failed',
            reason='saved edge-3 omits original Runner receipt roots'))
    edge['runner_event_ids']=sorted(set(saved_ids)|set(live.get('runner_event_ids',())))

    raw_refs=details.get('raw_references')
    if type(raw_refs) is not list:
        raw_refs=[];details['raw_references']=raw_refs
        live_outcome='failed'
        issues.append(dict(outcome='failed',reason='graph raw reference inventory is invalid'))
    else:
        if any(type(reference) is not dict
                or set(reference)!={'component','event_id','kind'}
                for reference in raw_refs):
            live_outcome='failed'
            issues.append(dict(outcome='failed',
                reason='graph raw references must be exact Observer component/event/kind rows'))
        available={_json(reference) for reference in raw_refs if type(reference) is dict}
        expected={_json(reference) for reference in live.get('raw_references',[])}
        if not expected.issubset(available):
            live_outcome='failed'
            issues.append(dict(outcome='failed',
                reason='saved graph omits a live completion Observer reference'))
        for reference in live.get('raw_references',[]):
            if reference not in raw_refs:
                raw_refs.append(deepcopy(reference))

    saved_raw=details.get('raw_evidence')
    if type(saved_raw) is not list:
        saved_raw=[];details['raw_evidence']=saved_raw
        live_outcome='failed'
        issues.append(dict(outcome='failed',reason='saved graph Runner evidence is invalid'))
    else:
        by_id={row.get('event_id'):row for row in saved_raw
            if type(row) is dict and type(row.get('event_id')) is int}
        for event_id in live.get('runner_event_ids',[]):
            original=next((row for row in events
                if row.get('event_id')==event_id),None)
            archived=by_id.get(event_id)
            if type(original) is not dict or type(archived) is not dict:
                live_outcome='failed'
                issues.append(dict(outcome='failed',
                    reason='saved graph Runner evidence omits a live receipt root'))
                continue
            if _json(original)!=_json(archived):
                live_outcome='failed'
                issues.append(dict(outcome='failed',
                    reason='saved graph Runner root differs from the live journal'))
        for row in live.get('raw_evidence',[]):
            if not any(type(candidate) is dict
                    and candidate.get('event_id')==row.get('event_id')
                    for candidate in saved_raw):
                saved_raw.append(deepcopy(row))

    edge['evidence']=deepcopy(live_evidence)
    edge['issues']=list(edge.get('issues',[]))+issues
    edge['outcome']=_combine_evidence_outcomes(saved_outcome,live_outcome)
    details['issues']=list(details.get('issues',[]))+issues
    projection['outcome']=_combine_evidence_outcomes(
        prior_outcome, *(row.get('outcome','missing') for row in details['edges']))
    return projection


class _EdgeEvidence:
    """Collect independent raw edges before any dependency join can stop.

    A missing dependency never erases a present edge or prevents that edge's
    own checks. Raw rows here are documentary comparison data, not enrollment.
    """
    def __init__(self,case,index=None,*,scope='word'):
        self.case=case;self.index=index;self.scope=scope
        self.edges={};self.values={};self.issues=[]

    def issue(self,name,error):
        status='failed' if isinstance(error,_Contradiction) else 'missing'
        row=self.edges[name]
        row['checks'].append(dict(status=status,reason=str(error)))
        if row['status']!='failed':row['status']=status
        self.issues.append((name,error))

    def edge(self,name,section,kind,owner):
        refs=self.case.attempt.get(section)
        reference=(refs if self.index is None else
            refs[self.index] if type(refs) is list and self.index<len(refs) else None)
        self.reference(name,reference,kind,owner,
                       lambda:self.case.event(section,kind,owner,self.index))

    def reference(self,name,reference,kind,owner,resolve=None):
        raw=self.case.index.get((owner,reference),[]) if type(reference) is int else []
        self.case.remember(raw)
        self.edges[name]=dict(edge_id=name,component=owner,reference=reference,
            raw_rows=json.loads(_json(raw)),status='passed',checks=[])
        # Record even invalid-kind/duplicate present rows before validation.
        for row in raw:
            self.case.used.append(dict(component=owner,event_id=row['event_id'],kind=row.get('kind',kind)))
        try:self.values[name]=resolve() if resolve else self.case.reference(reference,kind,owner)
        except (_Missing,_Contradiction) as error:self.issue(name,error)

    def check(self,name,check):
        if name not in self.values:return
        try:check(self.values[name])
        except (_Missing,_Contradiction) as error:self.issue(name,error)

    def document(self):
        return {self.scope+'_index':self.index,'edges':list(self.edges.values())}


class _Case:
    def __init__(self,runtime,attempt):
        self.runtime=runtime;self.attempt=attempt;self.contract=runtime.contract
        self.cpu=runtime.cpu;self.dma=runtime.dma
        self.cpu_id=self.contract['cpu']['instance_id'];self.dma_id=self.contract['dma']['instance_id']
        self._irq_runtime_name=f6_dma_irq_runtime_name(self.dma,self.contract['irq'])
        self.p=self.contract['program_contract'];self.index={};self.used=[]
        self.raw_evidence=[];self.seen_raw=set()
        _require(type(runtime.observer_view) in (list,tuple),'journal is not a recorded sequence')
        for row in runtime.observer_view:
            _require(type(row) is dict and type(row.get('event_id')) is int
                and row['event_id']>0 and type(row.get('component')) is str,'invalid composite raw event identity')
            self.index.setdefault((row['component'],row['event_id']),[]).append(row)
        self.cpu_tick_samples=self._index_cpu_tick_samples()

    def _index_cpu_tick_samples(self):
        runner=getattr(self.runtime,'runner',None)
        if runner is None:
            groups={}
            samples=getattr(self.cpu,'_physical_tick_samples',())
            _require(type(samples) in (list,tuple),'CPU physical sample stream is unavailable')
            for sample in samples:
                _require(type(sample) is dict and type(sample.get('local_tick')) is int
                    and sample['local_tick']>0,'invalid CPU physical sample identity')
                groups.setdefault(sample['local_tick'],[]).append(sample)
            return ('session',groups)

        from myfuzz.scenario.runner import ScenarioRunner
        read=getattr(runner,'events_since',None)
        event_count=getattr(runner,'event_count',None)
        sessions=getattr(runner,'sessions',None)
        _require(type(runner) is ScenarioRunner and type(sessions) is dict
            and sessions.get(self.cpu_id) is self.cpu,
            'Runner CPU source identity mismatch')
        _require(callable(read) and type(event_count) is int and event_count>=0,
            'Runner physical sample journal is unavailable')
        event_start=self.attempt.get('_runner_event_start')
        _require(type(event_start) is int and 0<=event_start<=event_count,
            'Runner case event start is invalid')
        # Case slice: every sample this index can use is journaled after the
        # case start (the producer join below already requires that), so the
        # read is borrowed rather than a detached copy of the slice.
        events=_borrow_events(runner,event_start)
        _require(type(events) in (list,tuple)
            and len(events)==event_count-event_start,
            'Runner physical sample journal is incomplete')
        groups={};event_ids=set();events_by_id={}
        for expected_event_id,row in enumerate(events,
                start=event_start+1):
            _require(type(row) is dict,'Runner event journal contains a non-record')
            event_id=row.get('event_id')
            if (type(event_id) is not int or event_id!=expected_event_id
                    or event_id in event_ids):
                raise _Contradiction('Runner event journal identity is discontinuous')
            event_ids.add(event_id)
            events_by_id[event_id]=row
            if row.get('kind')!='local_tick_sample' or row.get('component')!=self.cpu_id:
                continue
            producer=row.get('producer_event_id')
            tick=row.get('local_tick');phase=row.get('phase');outputs=row.get('outputs')
            if (type(producer) is not int or producer<1 or producer>=event_id
                    or type(tick) is not int or tick<1 or phase not in ('pre','post')
                    or type(outputs) is not dict):
                raise _Contradiction('invalid Runner CPU physical sample identity')
            phases=groups.setdefault(tick,{})
            if phase in phases:
                raise _Contradiction('duplicate Runner CPU physical sample phase')
            phases[phase]=row
        for tick,phases in groups.items():
            if set(phases)=={'pre','post'}:
                pre,post=phases['pre'],phases['post']
                _require(pre['producer_event_id']==post['producer_event_id']
                    and pre['event_id']<post['event_id'],
                    'Runner CPU physical sample phase identity/order mismatch')
                producer=events_by_id.get(pre['producer_event_id'])
                if (type(producer) is not dict
                        or producer.get('component')!=self.cpu_id
                        or producer.get('local_tick')!=tick
                        or type(producer.get('inputs')) is not dict
                        or type(producer.get('outputs')) is not dict
                        or 'kind' in producer):
                    raise _Contradiction(
                        'Runner CPU sample producer mismatch '
                        f'(tick={tick}, producer_event_id={pre["producer_event_id"]}, '
                        f'producer_component={producer.get("component") if type(producer) is dict else None}, '
                        f'producer_tick={producer.get("local_tick") if type(producer) is dict else None}, '
                        f'input_shape={type(producer.get("inputs")) is dict if type(producer) is dict else False}, '
                        f'output_shape={type(producer.get("outputs")) is dict if type(producer) is dict else False}, '
                        f'kind_present={"kind" in producer if type(producer) is dict else False})')
        return ('runner',groups)

    def cpu_tick_sample(self,tick):
        source,groups=self.cpu_tick_samples
        phases=groups.get(tick)
        if not phases:raise _Missing('actual CPU native bus samples unavailable')
        if source=='session':
            _require(len(phases)==1,'duplicate CPU native sample')
            return phases[0]
        if set(phases)!= {'pre','post'}:
            raise _Missing('complete Runner CPU physical sample unavailable')
        pre,post=phases['pre'],phases['post']
        for row in (pre,post):
            self.remember([row])
            self.used.append(dict(source='runner',component=self.cpu_id,
                event_id=row['event_id'],kind='local_tick_sample'))
        # ``pre``/``post`` are borrowed journal rows; the returned sample is
        # retained by the case evidence, so detach exactly those outputs.
        return dict(local_tick=tick,pre=deepcopy(pre['outputs']),post=deepcopy(post['outputs']))

    def _validated_irq_runtime_name(self):
        runtime_name=f6_dma_irq_runtime_name(self.dma,self.contract['irq'])
        _require(runtime_name==self._irq_runtime_name,
            'DMA IRQ runtime export changed during evidence consumption')
        return runtime_name

    def remember(self,rows):
        """Retain every encountered journal row, including failed/duplicate rows.

        The JSON round-trip stays: it detaches the row in the saved-evidence
        JSON value domain (tuples become lists), and on these rows it is
        measured cheaper than ``copy.deepcopy`` (19-52 us/row versus
        23-86 us/row), so it is not a cost site to trade away.
        """
        for row in rows:
            if id(row) not in self.seen_raw:
                self.raw_evidence.append(json.loads(_json(row)))
                self.seen_raw.add(id(row))

    def event(self,section,kind,owner,index=None):
        ref=self.attempt.get(section)
        if index is not None:
            if type(ref) is not list or index>=len(ref):raise _Missing(section+' word reference unavailable')
            ref=ref[index]
        return self.reference(ref,kind,owner)

    def reference(self,ref,kind,owner):
        if ref is None:raise _Missing(kind+' reference unavailable')
        _require(type(ref) is int and ref>0,'raw reference is not a typed event id')
        rows=self.index.get((owner,ref),[])
        self.remember(rows)
        if not rows:raise _Missing(kind+' raw event unavailable')
        _require(len(rows)==1,'duplicate composite raw event reference')
        row=rows[0]
        _require(row.get('kind',row.get('schema_version'))==kind,'raw reference kind mismatch')
        self.used.append(dict(component=owner,event_id=ref,kind=kind))
        return row

    def unique(self,owner,kind,transaction,*,nested=None):
        matches=[]
        for (component,_),rows in self.index.items():
            if component!=owner:continue
            for row in rows:
                actual=row.get(nested,{}) if nested else row
                key=actual.get('transaction',actual.get('source_transaction')) if type(actual) is dict else None
                if row.get('kind')==kind and key==transaction:matches.append(row)
        self.remember(matches)
        if not matches:raise _Missing(kind+' transaction edge unavailable')
        _require(len(matches)==1,'duplicate '+kind+' transaction edge')
        return matches[0]

    def live_cpu(self,row):
        actual = self.live_owner_event(row, self.cpu_id)
        if row.get('kind')=='cpu_external_irq_taken':
            runner = getattr(self.runtime,'runner',None)
            binding = getattr(self.runtime,'_irq_binding',None)
            group_for = getattr(runner,'irq_group_for',None)
            group = group_for(binding) if callable(group_for) and binding is not None else None
            if group is not None:
                qualified = runner.irq_group_delivery(binding,cpu_tick=row.get('local_tick'))
                _require(type(qualified) is dict
                    and qualified.get('unique_source')==binding.source_component+'.'+binding.source_port
                    and qualified.get('native_take_event_id')==actual['event_id']
                    and qualified.get('group_id')==group.group_id,
                    'F6 take lacks unique actual DMA IRQ-group membership')

    def live_dma(self,row):
        self.live_owner_event(row, self.dma_id)

    def live_memory_service_event(self,row,owner,service):
        """Resolve service events through Runner journal, or their owning stream in fixtures."""
        _require(type(row) is dict and row.get('component')==owner,
            'memory service event component does not match its owner')
        runner=getattr(self.runtime,'runner',None)
        lookup=getattr(runner,'event_by_id',None)
        if callable(lookup):
            return self.live_owner_event(row,owner)
        _require(runner is None and 'runner_event_id' not in row,
            'Runner-backed memory service event identity cannot be resolved')
        _require(type(row.get('event_id')) is int and row['event_id']>0,
            'synthetic memory service event local identity is invalid')
        stream=getattr(service,'events',None)
        _require(type(stream) is list,'memory service event stream is unavailable')
        expected={key:value for key,value in row.items()
            if key not in ('event_id','component')}
        matches=[event for event in stream
            if type(event) is dict and _json(event)==_json(expected)]
        _require(len(matches)==1,
            owner+' memory service event differs from actual producer observation')
        return matches[0]

    def callback_event(self,row,actual,owner,kind):
        """Compare callback DTOs without mistaking authenticated Runner provenance for callback data."""
        expected=dict(actual,component=owner)
        runner=getattr(self.runtime,'runner',None)
        lookup=getattr(runner,'event_by_id',None)
        if callable(lookup):
            self.live_owner_event(row,owner)
            envelope={'event_id','producer_event_id','runner_event_id','provenance'}
            _require(set(row)==set(expected)|envelope
                and row.get('kind')==kind
                and type(row.get('event_id')) is int and row['event_id']>0
                and type(row.get('producer_event_id')) is int
                and 0<row['producer_event_id']<row['runner_event_id']
                and _runner_provenance_is_exact(row,self.attempt, session_case_index=
                    self._session_case_index()),
                'Runner callback projection envelope is invalid')
            projected={key:value for key,value in row.items()
                if key not in envelope}
        else:
            service=(self.cpu.service if owner==self.cpu_id
                else self.dma.memory_service if owner==self.dma_id else None)
            _require(service is not None,
                'callback event owner has no memory service')
            self.live_memory_service_event(row,owner,service)
            projected=_raw(row)
        _same(projected,expected,
            'read snapshot raw event differs from actual callback')

    def live_owner_event(self,row,owner):
        runner=getattr(self.runtime,'runner',None)
        runner_event_id=row.get('runner_event_id')
        lookup=getattr(runner,'event_by_id',None)
        if callable(lookup):
            if type(runner_event_id) is not int or runner_event_id <= 0:
                raise _Contradiction('Runner journal event identity is unavailable')
            source=lookup(runner_event_id)
            source_identity=({key:value for key,value in source.items()
                if key not in ('event_id','runner_event_id')}
                if type(source) is dict else None)
            projected_identity={key:value for key,value in row.items()
                if key not in ('event_id','runner_event_id')}
            _require(type(source) is dict
                and source.get('event_id')==runner_event_id
                and source.get('component')==owner
                and _json(source_identity)==_json(projected_identity),
                'Runner journal event identity differs from projected '+owner+' event')
            return source
        if runner_event_id is not None:
            raise _Contradiction('Runner journal event identity cannot be resolved')

        stream=(self.cpu.cpu_events if owner==self.cpu_id else self.dma.events)
        expected=_raw(row)
        if stream and 'component' not in stream[0]:
            expected.pop('component',None)
        matches=[event for event in stream
            if _json(_raw(event))==_json(expected)]
        _require(len(matches)==1,
            owner+' event differs from actual producer observation')
        return matches[0]

    def _session_case_index(self):
        f6_slot(self.runtime, self.attempt)
        return (f6_mapping(self.runtime, self.attempt['case_index'])['session_case_index']
            if 'shared_slots' in self.p else self.attempt['case_index'])

    def owner_event_in_current_case(self,row,actual):
        runner=getattr(self.runtime,'runner',None)
        if not callable(getattr(runner,'event_by_id',None)):
            return True
        provenance=actual.get('provenance')
        observed=(provenance.get('observed_case')
            if type(provenance) is dict else None)
        return observed==dict(case_id=self.attempt.get('case_id'),
            case_index=self._session_case_index())

    def owner_events(self,owner,kind=None,*,predicate=None,domain_predicate=None,
            domain_scope_predicate=None,reject_domain_extras=False):
        rows=[row for row in self.runtime.observer_view
            if row.get('component')==owner
            and (kind is None or row.get('kind')==kind)]
        # Authenticate rows in the queried domain, including rows whose primary
        # selector was contradicted but whose independent domain marker still
        # makes them relevant to this query.
        in_domain=[row for row in rows if
            (predicate is None or predicate(row))
            or (domain_predicate is not None and domain_predicate(row))]
        authenticated=[(row,self.live_owner_event(row,owner)) for row in in_domain]
        if domain_scope_predicate is not None:
            authenticated=[(row,actual) for row,actual in authenticated
                if domain_scope_predicate(row,actual)]
        if reject_domain_extras and predicate is not None and any(
                not predicate(row) for row,_ in authenticated):
            raise _Contradiction('extra same-scope owner event outside declared receipt')
        if predicate is not None:
            authenticated=[(row,actual) for row,actual in authenticated
                if predicate(row)]
        return [actual for _,actual in authenticated]

    def owners(self):
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        from myfuzz.local_harness.wishbone_dma_session import (
            _f6_dma_session_instance_data_is_canonical,
            _f6_dma_session_type_allowlist,
        )
        from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
        from myfuzz.scenario.native_f6_isr_return import _issuer_state
        from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
        _require(type(self.cpu) is GeneratedCve2Session,'original registered CPU required')
        try:
            allowed_dma_types = _f6_dma_session_type_allowlist()
            registered_dma = (type(self.dma) in allowed_dma_types
                and _f6_dma_session_instance_data_is_canonical(self.dma))
        except (AttributeError, ImportError, TypeError, ValueError):
            registered_dma = False
        _require(registered_dma,'original registered DMA required')
        issuer=getattr(self.cpu,'_f6_isr_return',None)
        try:state=_issuer_state(issuer)
        except ValueError as error:raise _Contradiction(str(error)) from error
        _require(issuer._owner() is self.cpu and state['service'] is self.cpu.service
            and state['memory'] is self.cpu.memory and self.cpu.memory is self.dma.memory_service.memory
            and self.cpu.service is not self.dma.memory_service
            and self.cpu.service.ledger is not self.dma.memory_service.ledger,
            'CPU issuer/service/shared memory identity mismatch')
        admission=self.runtime.route_admission
        _require(type(admission) is DmaMasterRouteAdmission
            and self.dma._dma_route_admission is admission
            and type(admission._beat_policy) is F6RamDmaPolicy,
            'original configured F6 route admission required')
        _same(admission._beat_policy.identity_document()['contract'],self.contract,'F6 policy contract drift')
        _same(self.runtime.path['execution_contract'],self.contract,'F6 admitted path contract drift')

    def cpu_key(self,row,channel='data'):
        key=_transaction(row.get('transaction'))
        _require(key.source_component==self.cpu_id and key.source_epoch==self.cpu.reset_epoch
            and key.execution_id=='local-execution' and key.testcase_id==self.cpu._case_id
            and key.channel_id==channel,'CPU transaction owner/case/epoch/channel mismatch')
        return key

    def cpu_response(self,row,*,address,write,value=None,channel='data'):
        self.live_cpu(row);key=self.cpu_key(row,channel)
        _require(type(row.get('be')) is int and row['be']==15
            and type(row.get('write')) is int and row['write']==int(write)
            and row.get('address')==address and row.get('raw_address')==address
            and row.get('aligned_address')==address and type(row.get('error')) is int
            and row['error']==0 and type(row.get('response_tick')) is int
            and type(row.get('acceptance_tick')) is int and row['response_tick']>row['acceptance_tick'],
            'CPU response shape/address/BE/chronology mismatch')
        if value is not None:_require(row.get('wdata' if write else 'rdata')==value,'CPU response payload mismatch')
        response=self.unique(self.cpu_id,'instr_response' if channel=='instr' else 'data_response',asdict(key))
        _same(response,row,'CPU response reference differs')
        tag='i' if channel=='instr' else 'd'
        accept=self.cpu_tick_sample(row['acceptance_tick'])
        consume=self.cpu_tick_sample(row['response_tick'])
        pre=accept.get('pre',{}).get('backend')
        post=consume.get('pre',{}).get('backend')
        if type(pre) is not dict or type(post) is not dict:
            raise _Missing('CPU native bus backend sample unavailable')
        _require(all(type(pre.get(tag+n)) is int for n in ('_req_valid','_req_ready','_req_write','_req_addr','_req_be','_req_wdata'))
            and pre[tag+'_req_valid']==pre[tag+'_req_ready']==1
            and pre[tag+'_req_write']==int(write) and pre[tag+'_req_addr']==address
            and pre[tag+'_req_be']==15 and pre[tag+'_req_wdata']==row['wdata']
            and post.get(tag+'_rsp_valid')==post.get(tag+'_rsp_ready')==1
            and post.get(tag+'_rsp_rdata')==row['rdata'] and post.get(tag+'_rsp_error')==0,
            'CPU event does not join native accepted/consumed handshake')
        return key

    def commit(self,event,service,*,key,address,value):
        _require(event.get('transaction')==asdict(key),'commit transaction owner/key mismatch')
        return self.completed_write_commit(event,service,key=key,
            address=address,value=value)

    def completed_write_commit(self,event,service,*,key,address,value):
        """Join a write commit to its journaled issuance and completed ledger receipt.

        Runner acknowledges commit streams after journaling them. A native
        consumer must therefore use that retained source row plus the ledger's
        completed receipt, rather than treating an acknowledged stream item as
        if the producer had never issued it.
        """
        owner=key.source_component
        from myfuzz.scenario.ledger import TransactionKey
        expected_service=(getattr(self.cpu,'service',None)
            if owner==self.cpu_id else getattr(self.dma,'memory_service',None)
            if owner==self.dma_id else None)
        _require(type(event) is dict and event.get('transaction')==asdict(key),
            'commit transaction owner/key mismatch')
        _require(type(key) is TransactionKey and expected_service is service,
            'commit service does not own the selected component')
        selected=self.unique(owner,'memory_write_commit',asdict(key))
        _same(_raw(event),_raw(selected),'commit reference differs from unique journal row')
        runner=getattr(self.runtime,'runner',None)
        lookup=getattr(runner,'event_by_id',None)
        if callable(lookup):
            issued=self.live_owner_event(event,owner)
            selected_source=self.live_owner_event(selected,owner)
            _same(_raw(issued),_raw(selected_source),
                'commit journal row differs from selected source event')
        else:
            try:_receipt,issued=service.lookup_pending_commit(event.get('commit_id'))
            except ValueError as error:raise _Contradiction(str(error)) from error
        _same(_raw(event),dict(_raw(issued),component=owner),
            'commit differs from service-owned issuance')

        from myfuzz.scenario.ledger import TransactionLedger
        from myfuzz.scenario.memory_service import WriteReceipt
        ledger=getattr(service,'ledger',None)
        entries=getattr(ledger,'_entries',None)
        entry=entries.get(key) if type(entries) is dict else None
        receipt=getattr(entry,'receipt',None)
        frozen=(getattr(receipt,'__dict__',{}).get('_commit_json')
            if type(receipt) is WriteReceipt else None)
        _require(entry is not None and entry.status=='complete'
            and type(entry.payload_digest) is str
            and type(receipt) is WriteReceipt
            and receipt.transaction_id==key
            and type(receipt.byte_enable) is int
            and receipt.byte_enable==15
            and type(receipt.version) is tuple
            and len(receipt.version)==2
            and all(type(part) is int for part in receipt.version)
            and type(frozen) is bytes,
            'completed write receipt is unavailable or has wrong identity')
        document=issued.get('commit_document') if type(issued) is dict else None
        _require(type(document) is dict,'journaled write commit document is unavailable')
        expected_document_fields={'schema_version','fullkey','memory_kind',
            'memory_id','generation','byte_offset','width_bytes','byte_enable',
            'version','payload_sha256','commit_status','performed_effect',
            'enabled_byte_cells','commit_id'}
        _require(set(document)==expected_document_fields
            and issued.get('kind')=='memory_write_commit'
            and issued.get('schema_version')=='memory_write_commit.v1'
            and issued.get('transaction')==asdict(key)
            and type(issued.get('service_commit_sequence')) is int
            and issued['service_commit_sequence']>0,
            'journaled write commit shape/identity mismatch')
        try:receipt_document=json.loads(frozen)
        except (UnicodeDecodeError,TypeError,ValueError) as error:
            raise _Contradiction('completed write receipt JSON is invalid') from error
        _same(receipt_document,document,
            'journaled write commit differs from completed receipt bytes')
        _require(type(address) is int and type(value) is int
            and 0 <= value < 1 << 32,
            'completed write payload types are invalid')
        payload=dict(op='write',address=address,value=value,width_bytes=4,
            byte_enable=15)
        payload_digest=TransactionLedger._digest(payload)
        unsigned=dict(document)
        claimed_commit_id=unsigned.pop('commit_id',None)
        encoded=json.dumps(unsigned,sort_keys=True,separators=(',',':'),
            allow_nan=False).encode('utf-8')
        region,generation,offset=service.memory.resolve_span(address,4,write=True)
        version=document.get('version')
        cells=[dict(byte_offset=offset+lane,
            value=value>>(8*lane)&255,version=version,
            writer_kind='STORE',writer_event_id=str(key)) for lane in range(4)]
        _require(document.get('schema_version')=='memory_write_commit_receipt.v1'
            and document.get('fullkey')==asdict(key)
            and document.get('commit_id')==event.get('commit_id')
            and type(claimed_commit_id) is str
            and sha256(encoded).hexdigest()==claimed_commit_id
            and document.get('payload_sha256')==payload_digest
            and entry.payload_digest==payload_digest
            and document.get('memory_kind')=='modeled_host_persistent_memory'
            and document.get('memory_id')==region
            and type(document.get('generation')) is int
            and document.get('generation')==generation==service.memory.generation
            and type(document.get('byte_offset')) is int
            and document.get('byte_offset')==offset
            and document.get('commit_status')=='complete'
            and document.get('performed_effect') is True
            and type(document.get('width_bytes')) is int
            and document.get('width_bytes')==4
            and type(document.get('byte_enable')) is int
            and document.get('byte_enable')==15
            and type(version) is list and len(version)==2
            and all(type(part) is int for part in version)
            and version==list(receipt.version)
            and version[0]==generation and version[1]>0
            and type(document.get('payload_sha256')) is str
            and type(document.get('enabled_byte_cells')) is list
            and len(document['enabled_byte_cells'])==4,
            'completed write receipt identity/payload/version mismatch')
        _same(document['enabled_byte_cells'],cells,
            'commit per-byte cells do not match actual writer/value/version')
        return document

    def cpu_store(self,event,*,address,value,commit_ref=None):
        _require(event.get('width_bytes')==4 and type(event.get('byte_enable')) is int
            and event['byte_enable']==15 and event.get('address')==address and event.get('value')==value,
            'CPU store address/value/BE mismatch')
        key=self.cpu_key(event)
        response=self.unique(self.cpu_id,'data_response',asdict(key))
        self.cpu_response(response,address=address,write=True,value=value)
        acceptance=self.unique(self.cpu_id,'data_accept',asdict(key));self.live_cpu(acceptance)
        _require(acceptance.get('wdata')==value and acceptance.get('be')==15,'CPU store acceptance mismatch')
        commit=(self.reference(commit_ref,'memory_write_commit',self.cpu_id) if commit_ref is not None
                else self.unique(self.cpu_id,'memory_write_commit',asdict(key)))
        doc=self.commit(commit,self.cpu.service,key=key,address=address,value=value)
        _require(event.get('memory_id')==doc['memory_id'] and event.get('generation')==doc['generation']
            and event.get('byte_offset')==doc['byte_offset'],'CPU write raw memory owner/span/generation mismatch')
        _require(event.get('version')==tuple(doc['version']) or event.get('version')==doc['version'],'CPU memory write version differs')
        return key,doc,response

    def finish_component(self,collections,join):
        """Retain all independent leaves; evaluate the original join once."""
        issues=[error for collection in collections for _,error in collection.issues]
        result={};join_error=None
        try:result=join()
        except (_Missing,_Contradiction) as error:
            join_error=error;issues.append(error)
        documents=[collection.document() for collection in collections]
        if issues:
            # Keep authenticated branch-specific explanations when available.
            error=(join_error if isinstance(join_error,_Contradiction) else
                   next((e for e in issues if isinstance(e,_Contradiction)),issues[0]))
            details=dict(join_error.details if join_error else result,
                independent_edges=documents,
                independent_issues=[dict(status='failed' if isinstance(e,_Contradiction) else 'missing',
                                         reason=str(e)) for e in issues])
            raise type(error)(str(error),details)
        return dict(result,independent_edges=documents)

    def _mmio_delivery_projection(self,row):
        runner=getattr(self.runtime,'runner',None)
        runner_backed=callable(getattr(runner,'event_by_id',None))
        if runner_backed:
            self.live_cpu(row)
            projected=_raw(row)
            projected.pop('provenance',None)
            return projected
        _require('producer_event_id' not in row and 'runner_event_id' not in row,
            'synthetic router delivery carries unauthenticated Runner identity')
        return _raw(row)

    def independent_delivery(self,row):
        projected=self._mmio_delivery_projection(row)
        actual=[dict(e,source_transaction=(asdict(e['source_transaction'])
            if type(e.get('source_transaction')) is TransactionKey else e.get('source_transaction')),
            kind='mmio_delivery',component=self.cpu_id) for e in self.cpu.router.deliveries]
        _require(sum(_json(_raw(e))==_json(projected) for e in actual)==1,
                 'present router delivery contradicts original completed callback')

    def independent_configuration_accept(self,row,*,address,value):
        self.live_cpu(row);key=self.cpu_key(row)
        _require(row.get('address')==address and row.get('write')==1 and row.get('wdata')==value
            and type(row.get('be')) is int and row['be']==15,'present configuration write contradicts contract')
        response=self.unique(self.cpu_id,'data_response',asdict(key))
        self.cpu_response(response,address=address,write=True,value=value)

    def configuration(self):
        self.owners();collections=[]
        slot=self.p['slot_base']+256*f6_slot(self.runtime, self.attempt)
        values=_configuration_values(self.contract)
        for i,(name,value) in enumerate(zip(self.contract['control']['configuration_order'],values)):
            book=_EdgeEvidence(self,i,scope='configuration');collections.append(book)
            book.edge('operand','operands','instr_response',self.cpu_id)
            book.edge('configuration_accept','configuration','data_accept',self.cpu_id)
            book.edge('configuration_delivery','deliveries','mmio_delivery',self.cpu_id)
            address=self.contract['control']['base']+self.contract['dma']['csr']['offsets'][name]
            book.check('operand',lambda row,_address=slot+self.p['operand_instruction_offsets'][i]:
                self.cpu_response(row,address=_address,write=False,channel='instr'))
            book.check('configuration_accept',lambda row,_address=address,_value=value:
                self.independent_configuration_accept(row,address=_address,value=_value))
            book.check('configuration_delivery',self.independent_delivery)
        return self.finish_component(collections,self.configuration_join)

    def configuration_join(self):
        from .compiled_f6_firmware import build_f6_firmware
        from .compiled_f6_layout import compile_f6_candidate_layout
        try:
            candidate=compile_f6_candidate_layout(self.runtime.path).decode(bytes.fromhex(self.attempt['raw8_hex']))
            firmware=build_f6_firmware(self.contract)
            firmware.validate_prefix(bytes.fromhex(self.attempt['prefix_hex']),candidate,case_index=self.attempt['case_index'])
        except ValueError as error:raise _Contradiction(str(error)) from error
        slot=self.p['slot_base']+256*f6_slot(self.runtime, self.attempt);prefix=bytes.fromhex(self.attempt['prefix_hex'])
        operands=[]
        for i,offset in enumerate(self.p['operand_instruction_offsets']):
            row=self.event('operands','instr_response',self.cpu_id,i)
            self.cpu_response(row,address=slot+offset,write=False,value=int.from_bytes(prefix[offset:offset+4],'little'),channel='instr')
            snapshot=row.get('snapshot',{})
            _require(snapshot.get('value')==row['rdata'] and snapshot.get('data_hex')==prefix[offset:offset+4].hex()
                and snapshot.get('writer_kinds') in (['INSTRUCTION_SOURCE']*4,('INSTRUCTION_SOURCE',)*4),
                'candidate operand has no actual instruction-source snapshot')
            operands.append(row['event_id'])
        names=self.contract['control']['configuration_order']
        values=_configuration_values(self.contract)
        ticks=[];config=[]
        for i,(name,value) in enumerate(zip(names,values)):
            accept=self.event('configuration','data_accept',self.cpu_id,i);self.live_cpu(accept)
            key=self.cpu_key(accept);address=self.contract['control']['base']+self.contract['dma']['csr']['offsets'][name]
            _require(accept.get('write')==1 and accept.get('wdata')==value and accept.get('address')==address
                and type(accept.get('be')) is int and accept['be']==15,'configuration native CPU write mismatch')
            response=self.unique(self.cpu_id,'data_response',asdict(key))
            self.cpu_response(response,address=address,write=True,value=value)
            delivery=self.event('deliveries','mmio_delivery',self.cpu_id,i)
            self.control_delivery(delivery,key=key,address=address,write=True,value=value,response=response)
            ticks.append(accept['acceptance_tick']);config.append(asdict(key))
        _require(ticks==sorted(ticks) and len(set(ticks))==4,'configuration write order mismatch')
        return dict(operands=operands,configuration_transactions=config)

    def _other_control_ticks(self,key,address,write):
        """Only a separately completed CPU transaction can claim another strobe."""
        claimed=set()
        for rows in self.index.values():
            for row in rows:
                tx=row.get('source_transaction')
                if (row.get('component')!=self.cpu_id or row.get('kind')!='mmio_delivery'
                        or tx==asdict(key) or row.get('device_id')!=self.contract['control']['device_id']
                        or row.get('address')!=address or row.get('write') is not write):continue
                receipt=row.get('dma_control_receipt');value=row.get('write_value') if write else 0
                if (type(tx) is not dict or type(receipt) is not dict
                        or receipt.get('source_transaction')!=tx or receipt.get('address')!=address
                        or receipt.get('offset')!=address-self.contract['control']['base']
                        or receipt.get('write') is not write or receipt.get('value')!=value
                        or row.get('byte_enable')!=15 or receipt.get('byte_enable')!=15):continue
                ticks=receipt.get('edge_ticks')
                if (type(ticks) not in (list,tuple) or not ticks or any(type(t) is not int or t<0 for t in ticks)
                        or len(set(ticks))!=len(ticks)):continue
                try:
                    _transaction(tx)
                    accept=self.unique(self.cpu_id,'mmio_acceptance',tx)
                    cpu_accept=self.unique(self.cpu_id,'data_accept',tx)
                    response=self.unique(self.cpu_id,'data_response',tx)
                    self.live_cpu(cpu_accept);self.live_cpu(response)
                    callback=self._mmio_delivery_projection(row)
                except (_EvidenceIssue,ValueError,KeyError,TypeError):continue
                if not all(self.owner_event_in_current_case(event,event)
                        for event in (row,cpu_accept,response)):
                    continue
                expected=dict(device_id=row['device_id'],address=address,write=write,byte_enable=15)
                if (any(accept.get(k)!=v for k,v in expected.items())
                        or accept.get('source_transaction')!=tx
                        or cpu_accept.get('transaction')!=tx or response.get('transaction')!=tx
                        or any(r.get('address')!=address or r.get('write')!=int(write)
                            or r.get('be')!=15 for r in (cpu_accept,response))
                        or response.get('error')!=0
                        or write and (accept.get('write_value')!=value
                            or cpu_accept.get('wdata')!=value or response.get('wdata')!=value)):
                    continue
                callbacks=[dict(e,source_transaction=(asdict(e['source_transaction'])
                    if type(e.get('source_transaction')) is TransactionKey else e.get('source_transaction')),
                    kind='mmio_delivery',component=self.cpu_id) for e in self.cpu.router.deliveries]
                if not any(_json(_raw(e))==_json(callback) for e in callbacks):continue
                claimed.update(ticks)
        return claimed

    def control_delivery(self,delivery,*,key,address,write,value,response):
        callback_projection=self._mmio_delivery_projection(delivery)
        _require(delivery.get('source_transaction')==asdict(key),
            'present router delivery contradicts the selected CPU key')
        self.unique(self.cpu_id,'mmio_delivery',asdict(key))
        accept=self.unique(self.cpu_id,'mmio_acceptance',asdict(key))
        _require(delivery.get('source_transaction')==asdict(key) and accept.get('source_transaction')==asdict(key)
            and delivery.get('device_id')==self.contract['control']['device_id']
            and delivery.get('address')==accept.get('address')==address
            and delivery.get('write') is write and accept.get('write') is write
            and delivery.get('byte_enable')==accept.get('byte_enable')==15
            and delivery.get('write_value' if write else 'read_value')==value,'router control A/delivery/D mismatch')
        receipt=delivery.get('dma_control_receipt',{})
        _require(receipt.get('source_transaction')==asdict(key) and receipt.get('address')==address
            and receipt.get('offset')==address-self.contract['control']['base']
            and receipt.get('write') is write and receipt.get('byte_enable')==15,
            'control native receipt owner/key/address mismatch')
        if write:_require(receipt.get('value')==value,'control receipt payload mismatch')
        _require(any(_json(_raw(e))==_json(callback_projection) for e in
            [dict(e,source_transaction=(asdict(e['source_transaction'])
                if type(e.get('source_transaction')) is TransactionKey else e.get('source_transaction')),
                kind='mmio_delivery',component=self.cpu_id) for e in self.cpu.router.deliveries]),
            'delivery is not actual completed router callback')
        edge_ticks=receipt.get('edge_ticks')
        _require(type(edge_ticks) in (list,tuple)
            and all(type(tick) is int and tick >= 0 for tick in edge_ticks)
            and len(set(edge_ticks)) == len(edge_ticks),
            'control receipt edge ticks are invalid')
        edge_ticks=set(edge_ticks)
        other_ticks=self._other_control_ticks(key,address,write)
        _require(not (edge_ticks & other_ticks),'overlapping control receipt edge ticks')
        control_word_address=receipt['offset']//4
        def control_edge_domain(row):
            payload=row.get('payload')
            pre=(payload.get('pre_backend',{}) if type(payload) is dict else {})
            return (row.get('tick') in edge_ticks
                or row.get('tick') not in other_ticks and pre.get('swb_stb')==1
                and pre.get('swb_adr')==control_word_address
                and pre.get('swb_we')==int(write))
        def control_edge_scope(row,actual):
            return self.owner_event_in_current_case(row,actual)
        edges=self.owner_events(self.dma_id,'dma_edge',
            predicate=lambda row: row.get('tick') in edge_ticks,
            domain_predicate=control_edge_domain,
            domain_scope_predicate=control_edge_scope,
            reject_domain_extras=True)
        if not edges:raise _Missing('native DMA control edge unavailable')
        ordered=sorted(edges,key=lambda e:e['tick'])
        req=[e for e in ordered if e['payload']['pre_backend'].get('swb_stb')==1
             and e['payload']['pre_backend'].get('swb_stall')==0]
        ack=[e for e in edges if e['payload']['pre_backend'].get('swb_ack')==1]
        _require(len(req)==1 and len(ack)==1 and req[0]['tick']<ack[0]['tick'],
            'control receipt has no unique native request/response')
        pre=req[0]['payload']['pre_backend']
        _require(pre.get('swb_cyc')==1 and pre.get('swb_we')==int(write)
            and pre.get('swb_adr')==receipt['offset']//4
            and (not write or pre.get('swb_dat_w')==value),'native DMA control acceptance differs')
        if self.dma.artifact.runtime_document.get('dma_edge_contract',{}).get('control_byte_enable_signal') == 'swb_sel':
            _require(pre.get('swb_sel')==receipt['byte_enable'],
                'native DMA control SEL differs from routed transaction')
        for edge in ordered:
            sample=edge['payload']['pre_backend']; tick=edge['tick']
            if tick<=req[0]['tick']:
                _require(sample.get('swb_cyc')==sample.get('swb_stb')==1
                    and sample.get('swb_we')==int(write)
                    and sample.get('swb_adr')==receipt['offset']//4
                    and (not write or sample.get('swb_dat_w')==value)
                    and (tick==req[0]['tick'] or sample.get('swb_stall')==1),
                    'native DMA held request differs')
                if self.dma.artifact.runtime_document.get('dma_edge_contract',{}).get('control_byte_enable_signal') == 'swb_sel':
                    _require(sample.get('swb_sel')==receipt['byte_enable'], 'native DMA held SEL differs')
            else:
                _require(sample.get('swb_stb')==0,'native DMA control repeated acceptance')
        if not write:_require(any(e['payload']['pre_backend'].get('swb_dat_r')==response['rdata'] for e in ack),
            'native DMA status response differs from consumed CPU response')

    def dma_beat(self,section,index,*,write,address,value):
        event=self.event(section,'dma_edge',self.dma_id,index);accepted=event.get('accepted',{})
        key=_transaction(accepted.get('transaction'))
        _require((key.execution_id,key.testcase_id,key.source_component,key.source_epoch,key.channel_id)==
            (self.dma._execution,self.dma._case_id,self.dma_id,self.dma.reset_epoch,'dma-memory'),
            'DMA full transaction owner/case/epoch mismatch')
        _require(accepted.get('write') is write and type(accepted.get('byte_enable')) is int
            and accepted['byte_enable']==15 and accepted.get('address')==address
            and accepted.get('word_address')==address>>2
            and type(accepted.get('value')) is int and 0 <= accepted['value'] < 2**32
            and (not write or accepted['value']==value),'DMA address/value/BE/operation mismatch')
        pre=event['payload']['pre_backend']
        _require(pre.get('mwb_cyc')==pre.get('mwb_stb')==1 and pre.get('mwb_we')==int(write)
            and pre.get('mwb_adr')==address>>2
            and pre.get('mwb_dat_w')==accepted['value'],
            'DMA acceptance differs from native PRE payload')
        if self.dma.artifact.runtime_document.get('dma_edge_contract',{}).get('master_byte_enable_signal') == 'mwb_sel':
            _require(type(pre.get('mwb_sel')) is int and pre['mwb_sel']==accepted['byte_enable'],
                'native DMA master SEL differs from accepted transaction')
        self.unique(self.dma_id,'dma_edge',asdict(key),nested='accepted')
        self.live_dma(event)
        matches=[r for r in self.runtime.route_admission.route_matches if r['transaction']==asdict(key)]
        _require(len(matches)==1,'DMA key has no unique live route match')
        match=matches[0];route=self.runtime.route_admission._write_route if write else self.runtime.route_admission._read_route
        expected=self.runtime.route_admission._match_document(
            self.runtime.route_admission._bound_topology.match_dma_master_route(
                self.runtime.route_admission.identity_document()['path_id'],
                initiator_component=route.initiator_component,endpoint_id=route.endpoint_id,
                target_kind=route.target_kind,target_component=route.target_component,target_id=route.target_id,
                base=route.base,size=route.size,operation=route.operation,address=address,byte_enable=15,
                transaction_key=key,value=value if write else None))
        _same(match,expected,'live route identity/key/address mismatch')
        return event,key,match

    def dma_response(self,section,index,key,*,value,accepted):
        event=self.event(section,'dma_edge',self.dma_id,index)
        _require(event.get('response',{}).get('transaction')==asdict(key),
                 'present DMA response contradicts the selected transaction')
        self.unique(self.dma_id,'dma_edge',asdict(key),nested='response')
        response=event.get('response',{})
        _require(response.get('transaction')==asdict(key) and type(response.get('error')) is int
            and response['error']==0 and response.get('rdata')==value
            and event['tick']>accepted['tick'],'DMA native response key/value/error/order mismatch')
        self.live_dma(event)
        return event

    def dma_key(self,event,*,nested=None):
        payload=event.get(nested,{}) if nested else event
        _require(type(payload) is dict,'DMA edge payload is not an object')
        key=_transaction(payload.get('transaction'))
        _require((key.execution_id,key.testcase_id,key.source_component,key.source_epoch,key.channel_id)==
            (self.dma._execution,self.dma._case_id,self.dma_id,self.dma.reset_epoch,'dma-memory'),
            'DMA independent edge full owner/case/epoch mismatch')
        return key

    def independent_response(self,event,*,address,write,value):
        """Check a present response without requiring its journal acceptance."""
        key=self.dma_key(event,nested='response');response=event['response']
        _require(type(response.get('error')) is int and response['error']==0
            and type(response.get('rdata')) is int and response['rdata']==value,
            'present native DMA response reports error or contradictory data')
        self.unique(self.dma_id,'dma_edge',asdict(key),nested='response')
        self.live_dma(event)
        word_address=address>>2
        accepted=self.owner_events(self.dma_id,'dma_edge',
            predicate=lambda row: row.get('accepted',{}).get('transaction')==asdict(key),
            domain_predicate=lambda row:
                row.get('accepted',{}).get('transaction')==asdict(key)
                or row.get('accepted',{}).get('word_address')==word_address
                and row.get('accepted',{}).get('write') is write)
        _require(len(accepted)==1,'present response has no unique original accepted request')
        request=accepted[0]['accepted']
        _require(request.get('address')==address and request.get('write') is write
            and type(request.get('byte_enable')) is int and request['byte_enable']==15
            and type(event.get('tick')) is int and event['tick']>accepted[0]['tick'],
            'present response belongs to a different word/request/order')

    def independent_source(self,event,*,address,value):
        self.live_memory_service_event(event,self.cpu_id,self.cpu.service)
        key=self.cpu_key(event)
        _require(event.get('address')==address and type(event.get('value')) is int
            and event['value']==value and event.get('width_bytes')==4
            and type(event.get('byte_enable')) is int and event['byte_enable']==15,
            'present CPU source store address/value/BE mismatch')
        runner=getattr(self.runtime,'runner',None)
        if callable(getattr(runner,'event_by_id',None)):
            commit=self.unique(self.cpu_id,'memory_write_commit',asdict(key))
            doc=self.completed_write_commit(commit,self.cpu.service,key=key,
                address=address,value=value)
        else:
            # The synthetic no-Runner fixture still exercises the producer's
            # unacknowledged service stream directly.
            actual=[e for e in self.cpu.service.drain_commit_events()
                if e['transaction']==asdict(key)]
            _require(len(actual)==1,'present CPU source has no original issued write effect')
            doc=actual[0]['commit_document']
        _same({k:event.get(k) for k in ('memory_id','generation','byte_offset','version')},
            {k:doc[k] for k in ('memory_id','generation','byte_offset','version')},
            'present CPU source memory owner/span/version contradicts issuance')
        _same(doc['enabled_byte_cells'],[dict(byte_offset=doc['byte_offset']+lane,
            value=value>>(8*lane)&255,version=doc['version'],writer_kind='STORE',writer_event_id=str(key))
            for lane in range(4)],'present CPU store bytes contradict original issued effect')

    def independent_snapshot(self,event,*,issued,address,value):
        from myfuzz.scenario.memory_service import _validate_f6_dma_read
        key=self.dma_key(event)
        selected=[row for row in issued if asdict(row[0])==asdict(key)]
        _require(len(selected)==1,'present read snapshot has no original issued handle')
        actual_key,snapshot,handle=selected[0]
        try:actual=_validate_f6_dma_read(self.dma,self.dma.memory_service,actual_key,snapshot,handle)
        except ValueError as error:raise _Contradiction(str(error)) from error
        self.callback_event(event,actual,self.dma_id,'memory_read')
        _require(actual.get('address')==address and actual.get('width_bytes')==4
            and snapshot.value==value and snapshot.data==value.to_bytes(4,'little')
            and snapshot.writer_kinds==('STORE',)*4,
            'present read snapshot belongs to a different source word')

    def collect_word(self,i,word,issued,*,validate=True):
        evidence=_EdgeEvidence(self,i)
        for name,section,kind,owner in (
            ('source_store','sources','memory_write',self.cpu_id),
            ('source_commit','source_commits','memory_write_commit',self.cpu_id),
            ('read_accept','reads','dma_edge',self.dma_id),
            ('read_snapshot','read_snapshots','memory_read',self.dma_id),
            ('read_response','read_responses','dma_edge',self.dma_id),
            ('write_accept','writes','dma_edge',self.dma_id),
            ('write_commit','word_commits','memory_write_commit',self.dma_id),
            ('write_response','write_responses','dma_edge',self.dma_id)):
            evidence.edge(name,section,kind,owner)
        if not validate:return evidence
        source=self.p['source_address']+4*i;destination=self.p['destination_address']+4*i
        evidence.check('source_store',lambda row:self.independent_source(row,address=source,value=word))
        evidence.check('source_store',lambda row:self.cpu_response(
            self.unique(self.cpu_id,'data_response',asdict(self.cpu_key(row))),address=source,write=True,value=word))
        evidence.check('source_store',lambda row:self.live_cpu(
            self.unique(self.cpu_id,'data_accept',asdict(self.cpu_key(row)))))
        evidence.check('source_commit',lambda row:self.commit(row,self.cpu.service,
            key=self.cpu_key(row),address=source,value=word))
        evidence.check('read_accept',lambda row:self.dma_beat('reads',i,write=False,address=source,value=0))
        evidence.check('read_snapshot',lambda row:self.independent_snapshot(row,issued=issued,address=source,value=word))
        evidence.check('read_response',lambda row:self.independent_response(row,address=source,write=False,value=word))
        evidence.check('write_accept',lambda row:self.dma_beat('writes',i,write=True,address=destination,value=word))
        evidence.check('write_commit',lambda row:self.commit(row,self.dma.memory_service,
            key=self.dma_key(row),address=destination,value=word))
        evidence.check('write_response',lambda row:self.independent_response(row,address=destination,write=True,value=0))
        return evidence

    def words(self):
        self.owners()
        from myfuzz.scenario.memory_service import _f6_dma_read_results,_validate_f6_dma_read
        words=tuple((int.from_bytes(bytes.fromhex(self.attempt['raw8_hex']),'little')>>(11*i))&2047 for i in range(4))
        faults=[e for e in self.runtime.observer_view if e.get('component')==self.dma_id
            and e.get('environment_error_receipt',{}).get('execution_binding_sha256')==self.runtime.execution_binding_sha256]
        try:issued=_f6_dma_read_results(self.dma)
        except ValueError as error:raise _Contradiction(str(error)) from error
        if faults:
            partial=dict(issued_read_transactions=[asdict(r[0]) for r in issued],
                destination_commit_ids=[e['commit_id'] for e in self.dma.memory_service.drain_commit_events()],
                native_error_receipts=[e['environment_error_receipt'] for e in faults])
            evidence=[self.collect_word(i,word,issued,validate=False).document() for i,word in enumerate(words)]
            raise _Contradiction('native expected ERR retained prior effects; no four-word success certificate',
                                 dict(partial_effects=partial,word_evidence=evidence,
                                      word_validation_scope='raw_references_only_for_expected_ERR'))
        joins=[];read_ticks=[];write_ticks=[];read_sequences=[];write_sequences=[]
        issues=[];word_evidence=[]
        for i,word in enumerate(words):
            evidence=self.collect_word(i,word,issued)
            joined=None
            try:
                result=self.word(i,word,issued)
            except (_Missing,_Contradiction) as error:
                evidence.issues.append(('dependent_join',error))
            else:
                joined,read_tick,write_tick,read_sequence,write_sequence=result
            document=evidence.document()
            document['join_issues']=[dict(edge_id=name,status='failed' if isinstance(error,_Contradiction) else 'missing',
                reason=str(error)) for name,error in evidence.issues]
            word_evidence.append(document)
            if evidence.issues:
                issues.extend((i,error) for _,error in evidence.issues)
                continue
            joins.append(joined);read_ticks.append(read_tick);write_ticks.append(write_tick)
            read_sequences.append(read_sequence);write_sequences.append(write_sequence)
        if issues:
            error=next((e for _,e in issues if isinstance(e,_Contradiction)),issues[0][1])
            raise type(error)(str(error),dict(partial_word_joins=joins,word_evidence=word_evidence,
                issues=[dict(word_index=i,status='failed' if isinstance(e,_Contradiction) else 'missing',reason=str(e)) for i,e in issues]))
        ordered=(read_ticks==sorted(set(read_ticks)) and write_ticks==sorted(set(write_ticks))
            and max(read_ticks)<min(write_ticks) and read_sequences==sorted(set(read_sequences))
            and write_sequences==sorted(set(write_sequences)) and max(read_sequences)<min(write_sequences))
        if not ordered:raise _Contradiction('four read/four write word order mismatch',
            dict(partial_word_joins=joins,word_evidence=word_evidence))
        return dict(words=joins,word_evidence=word_evidence)

    def word(self,i,word,issued):
        from myfuzz.scenario.memory_service import _validate_f6_dma_read
        source=self.event('sources','memory_write',self.cpu_id,i)
        source_ref=self.attempt.get('source_commits',[])
        if i>=len(source_ref):raise _Missing('source commit reference unavailable')
        source_key,source_doc,source_response=self.cpu_store(source,address=self.p['source_address']+4*i,
            value=word,commit_ref=source_ref[i])
        read,key,route=self.dma_beat('reads',i,write=False,address=self.p['source_address']+4*i,value=0)
        selected=[r for r in issued if asdict(r[0])==asdict(key)]
        _require(len(selected)==1,'DMA read has no service-owned issued snapshot/handle')
        actual_key,snapshot,handle=selected[0]
        try:actual=_validate_f6_dma_read(self.dma,self.dma.memory_service,actual_key,snapshot,handle)
        except ValueError as error:raise _Contradiction(str(error)) from error
        observed=self.event('read_snapshots','memory_read',self.dma_id,i)
        self.callback_event(observed,actual,self.dma_id,'memory_read')
        _require(actual['memory_id']==source_doc['memory_id'] and actual['generation']==source_doc['generation']
            and actual['byte_offset']==source_doc['byte_offset'] and actual['width_bytes']==4
            and snapshot.value==word and snapshot.data==word.to_bytes(4,'little')
            and list(snapshot.versions)==[tuple(source_doc['version'])]*4
            and snapshot.writer_event_ids==(str(source_key),)*4 and snapshot.writer_kinds==('STORE',)*4,
            'read snapshot per-byte source writer/version/data mismatch')
        read_response=self.dma_response('read_responses',i,key,value=word,accepted=read)
        write,write_key,write_route=self.dma_beat('writes',i,write=True,address=self.p['destination_address']+4*i,value=word)
        commit=self.event('word_commits','memory_write_commit',self.dma_id,i)
        destination=self.commit(commit,self.dma.memory_service,key=write_key,address=self.p['destination_address']+4*i,value=word)
        write_response=self.dma_response('write_responses',i,write_key,value=0,accepted=write)
        _require(source_response['event_id']<read['event_id'] and read_response['tick']<write['tick']
            and source_doc['generation']==destination['generation']
            and source_doc['version'][1]<destination['version'][1], 'source/read/write/commit chronology mismatch')
        joined=dict(word_index=i,value=word,source_transaction=asdict(source_key),
            source_version=source_doc['version'],read_transaction=asdict(key),
            source_byte_versions=list(snapshot.versions),source_byte_writers=list(snapshot.writer_event_ids),
            read_route_sha256=route['route_sha256'],write_transaction=asdict(write_key),
            write_route_sha256=write_route['route_sha256'],destination_commit_id=commit['commit_id'],
            destination_version=destination['version'],byte_enable=15,
            read_response_event_id=read_response['event_id'],write_response_event_id=write_response['event_id'])
        return joined,read['tick'],write['tick'],key.source_sequence,write_key.source_sequence

    def independent_cpu_store(self,row,*,address,value):
        self.independent_source(row,address=address,value=value)
        key=self.cpu_key(row)
        self.cpu_response(self.unique(self.cpu_id,'data_response',asdict(key)),
                          address=address,write=True,value=value)

    def independent_irq_output(self,row):
        key=row.get('source_output_key')
        source_port=self.contract['irq']['producer_port']
        _require(type(key) is list and len(key)==4 and key[:3]==[self.dma_id,self.dma.reset_epoch,source_port]
            and type(key[1]) is int and type(key[3]) is int and key[3]>0,'present IRQ output scope mismatch')
        raw=self.reference(row.get('producer_event_id'),'dma_edge',self.dma_id)
        self.live_dma(raw)
        _require(type(raw.get('tick')) is int and raw['tick']>0
            and type(raw.get('reset_epoch')) is int
            and raw['reset_epoch']==self.dma.reset_epoch
            and key==[self.dma_id,raw['reset_epoch'],source_port,raw['tick']],
            'IRQ output key tick/epoch differs from original native edge')
        runtime_name=self._validated_irq_runtime_name()
        physical_value=raw['payload']['observations']['physical'].get(runtime_name)
        _require(type(physical_value) is int and physical_value==1,
                 'present IRQ source has no original native pulse')

    def independent_irq_delivery(self,row):
        level=self.contract['irq'].get('delivery_policy')=='level'
        start=row.get('start_local_tick');end=row.get('end_local_tick')
        window=(type(start) is int and 0<=start<1<<64 and
            (end is None if level else type(end) is int and end==start+16 and end<1<<64))
        _require(row.get('delivery_id')==self.contract['irq']['delivery_id']
            and row.get('target_component')==self.cpu_id and type(row.get('target_epoch')) is int
            and row['target_epoch']==self.cpu.reset_epoch
            and window
            and row.get('source_event_id')==self.attempt.get('irq_output'),
            'present IRQ delivery contradicts binding/window/scope')
        key=row.get('source_output_key')
        _require(type(key) is list and len(key)==4 and key[:3]==[self.dma_id,self.dma.reset_epoch,
            self.contract['irq']['producer_port']]
            and type(key[1]) is int and type(key[3]) is int and key[3]>0,
            'present IRQ delivery has a different source owner/epoch/port')
        output=self.reference(self.attempt.get('irq_output'),'source_start',self.dma_id)
        _require(row.get('source_event_id')==output.get('event_id')
            and key==output.get('source_output_key'),
            'IRQ delivery source key differs from the original output event')

    def independent_irq_input(self,row,delivery):
        """Authenticate AND check the interval predicate without an output ref."""
        # Preserve a present sample's contradictions even if its declared
        # source_start row is missing. A valid sample will still require the
        # complete delivery-to-output join below.
        start=delivery.get('start_local_tick') if type(delivery) is dict else None
        end=delivery.get('end_local_tick') if type(delivery) is dict else None
        level=self.contract['irq'].get('delivery_policy')=='level'
        key=delivery.get('source_output_key') if type(delivery) is dict else None
        source_port=self.contract['irq']['producer_port']
        _require(type(delivery) is dict and type(delivery.get('event_id')) is int
            and delivery.get('delivery_id')==self.contract['irq']['delivery_id']
            and delivery.get('source_event_id')==self.attempt.get('irq_output')
            and delivery.get('target_component')==self.cpu_id
            and type(delivery.get('target_epoch')) is int
            and delivery['target_epoch']==self.cpu.reset_epoch
            and type(start) is int and 0<=start<1<<64
            and (end is None if level else type(end) is int and end==start+16 and end<1<<64)
            and type(key) is list and len(key)==4
            and type(key[0]) is str and key[0]==self.dma_id
            and type(key[1]) is int and key[1]==self.dma.reset_epoch
            and type(key[2]) is str and key[2]==source_port
            and type(key[3]) is int and key[3]>0,
            'present IRQ delivery/window/source shape mismatch')
        self.live_cpu(row)
        tick=row.get('local_tick')
        runner = getattr(self.runtime,'runner',None)
        binding = getattr(self.runtime,'_irq_binding',None)
        group_for = getattr(runner,'irq_group_for',None)
        group = group_for(binding) if callable(group_for) and binding is not None else None
        if group is not None:
            qualified = runner.irq_group_delivery(binding,cpu_tick=tick)
            high = start <= tick if level else start <= tick < end
            _require(type(qualified) is dict and qualified.get('value')==int(high)
                and (not high or qualified.get('unique_source')==binding.source_component+'.'+binding.source_port),
                'F6 IRQ sample lacks actual unique DMA OR delivery')
        receipt=row.get('receipt_id')
        receipt_execution=(receipt.get('execution') if type(receipt) is dict else None)
        native_execution=self.cpu._execution
        execution_matches=(type(receipt_execution) is str and bool(receipt_execution)
            and type(native_execution) is str and bool(native_execution)
            and receipt_execution==native_execution)
        if not execution_matches:
            from myfuzz.scenario.runner import ScenarioRunner
            runner=getattr(self.runtime,'runner',None)
            scopes=getattr(runner,'_source_transport_scopes',None)
            cpu_scopes=(scopes.get(self.cpu_id) if type(scopes) is dict else None)
            mapped_execution=(cpu_scopes.get(native_execution)
                if type(cpu_scopes) is dict and type(native_execution) is str
                else None)
            execution_matches=(type(runner) is ScenarioRunner
                and type(getattr(runner,'sessions',None)) is dict
                and runner.sessions.get(self.cpu_id) is self.cpu
                and type(cpu_scopes) is dict and native_execution in cpu_scopes
                and type(mapped_execution) is str and bool(mapped_execution)
                and type(receipt_execution) is str and bool(receipt_execution)
                and mapped_execution==receipt_execution)
        command_scope=row.get('command_scope')
        receipt=row.get('receipt_id')
        receipt_sequence=(receipt.get('sequence') if type(receipt) is dict else None)
        _require(type(tick) is int and start<=tick and (level or tick<=end)
            and row.get('component')==self.cpu_id and type(row.get('reset_epoch')) is int
            and row['reset_epoch']==self.cpu.reset_epoch
            and execution_matches and type(command_scope) is dict
            and command_scope.get('component')==self.cpu_id
            and command_scope.get('reset_epoch')==self.cpu.reset_epoch
            and type(command_scope.get('command_sequence')) is int
            and command_scope['command_sequence']>0
            and type(receipt_sequence) is int
            and receipt_sequence==command_scope['command_sequence'],
            'present IRQ input sample has a different native scope/tick')
        active=1 if level else int(tick<end)
        _require(all(type(row.get(name)) is int and row[name]==active
            for name in ('expected_input','actual_pre_input','actual_post_input')),
            'present IRQ input contradicts asserted interval/deasserted expiry')
        context=row.get('input_context')
        if active:
            _require(row.get('binding_delivery_event_id')==delivery.get('event_id')
                and row.get('source_output_key')==key
                and type(context) is dict and context.get('binding_delivery_event_id')==delivery.get('event_id')
                and context.get('source_output_key')==key
                and context.get('target_component')==self.cpu_id
                and type(context.get('target_epoch')) is int and context['target_epoch']==self.cpu.reset_epoch
                and type(context.get('expected_input')) is int and context['expected_input']==1,
                'present IRQ input context belongs to a different delivery/source')
        self.independent_irq_delivery(delivery)

    def level_irq_clear(self,delivery,take,returned):
        """Join real level deassertion to the CPU's completed clear transaction."""
        from .compiled_f6 import _f6_level_clear_tick
        runner=getattr(self.runtime,'runner',None)
        start=self.attempt.get('_runner_event_start')
        observer_start=self.attempt.get('_observer_event_start')
        _present(runner is not None and type(start) is int and type(observer_start) is int,
            'level IRQ case journal scope unavailable')
        journal=_borrow_events(runner,start)
        end=_f6_level_clear_tick(self.runtime,delivery,journal,observer_start)
        _present(type(end) is int,'level IRQ clear transaction or actual low sample unavailable')
        clear=self.contract['dma']['behavior']['irq_clear']
        address=self.contract['control']['base']+clear['offset']
        candidates=[row for rows in self.index.values() for row in rows
            if row.get('component')==self.cpu_id and row.get('kind')=='data_accept'
            and take['event_id']<row.get('event_id',0)<returned['event_id'] and row.get('address')==address
            and row.get('write')==1 and row.get('wdata')==clear['value']]
        _present(bool(candidates),'level IRQ clear CPU access unavailable')
        _require(len(candidates)==1,'level IRQ clear CPU access is ambiguous')
        accept=self.reference(candidates[0]['event_id'],'data_accept',self.cpu_id)
        self.live_cpu(accept);key=self.cpu_key(accept)
        response=self.unique(self.cpu_id,'data_response',asdict(key))
        self.cpu_response(response,address=address,write=True,value=clear['value'])
        delivered=self.unique(self.cpu_id,'mmio_delivery',asdict(key))
        self.control_delivery(delivered,key=key,address=address,write=True,value=clear['value'],response=response)
        _require(type(response.get('response_tick')) is int and response['response_tick']<returned['local_tick'],
            'level IRQ clear response must precede MRET')
        low=[row for rows in self.index.values() for row in rows
            if row.get('component')==self.cpu_id and row.get('kind')=='cpu_external_irq_sample'
            and row.get('local_tick')==end and row.get('reset_epoch')==self.cpu.reset_epoch]
        _present(bool(low),'level IRQ CPU low sample unavailable')
        _require(len(low)==1,'level IRQ CPU low sample is ambiguous')
        sample=self.reference(low[0]['event_id'],'cpu_external_irq_sample',self.cpu_id)
        self.live_cpu(sample)
        _require(all(type(sample.get(name)) is int and sample[name]==0
            for name in ('expected_input','actual_pre_input','actual_post_input')),
            'level IRQ actual CPU low sample contradicts deassertion')
        _require(end<returned['local_tick'], 'level IRQ low sample must precede MRET')
        return {'clear_transaction':asdict(key), 'clear_delivery_event_id':delivered['event_id'],
            'low_cpu_sample_event_id':sample['event_id'], 'low_cpu_tick':end}

    def independent_return(self,row,status):
        events=self.cpu._f6_isr_return.events
        _require(sum(_json(event)==_json(_raw(row)) for event in events)==1,
                 'present MRET has no original sealed issuance')
        _require(row.get('case_id')==self.attempt['case_id'] and row.get('case_index')==self.attempt['case_index']
            and row.get('execution_binding_sha256')==self.runtime.execution_binding_sha256,
            'present MRET case/binding mismatch')
        if status is not None and type(status.get('rdata')) is int:
            from .compiled_f6_firmware import build_f6_firmware
            error=bool(status['rdata']&self.contract['dma']['csr']['status_error_mask'])
            _require(row.get('pc_rdata')==build_f6_firmware(self.contract).document()['isr']['mret_addresses'][int(error)],
                     'MRET branch site contradicts present actual status')

    def independent_boundary(self,row):
        request=self.cpu._request_evidence.get('instr')
        _require(request is not None and row.get('execution')==self.cpu._execution
            and row.get('reset_epoch')==self.cpu.reset_epoch and row.get('native_testcase_id')==self.cpu._case_id
            and row.get('transaction')==request.get('transaction')
            and row.get('address')==request.get('address')
            and row.get('local_tick')==request.get('acceptance_tick'),
            'present next fetch contradicts actual pending CPU request')

    def irq_completion(self):
        self.owners();book=_EdgeEvidence(self,scope='irq')
        for name,section,kind,owner in (
            ('output','irq_output','source_start',self.dma_id),
            ('delivery','irq_delivery','binding_delivery',self.cpu_id),
            ('take','irq','cpu_external_irq_taken',self.cpu_id),
            ('return','return','native_f6_isr_return.v1',self.cpu_id),
            ('status','status','data_response',self.cpu_id),
            ('status_store','status_store','memory_write',self.cpu_id),
            ('terminal','terminal','memory_write',self.cpu_id),
            ('boundary','next_fetch','native_fetch_boundary',self.cpu_id)):
            book.edge(name,section,kind,owner)
        for section,kind in (('readbacks','data_response'),('results','memory_write'),
                             ('word_commits','memory_write_commit')):
            refs=self.attempt.get(section,[])
            if type(refs) is list:
                for i,reference in enumerate(refs):
                    book.reference(section+'.'+str(i),reference,kind,
                                   self.dma_id if section=='word_commits' else self.cpu_id)
        delivery=book.values.get('delivery');sample_names=[];sample_rows={}
        if delivery is not None:
            # An explicit binding is relevant even when its tick/owner/epoch is
            # wrong. Never discard those facts using the predicate we check.
            for rows in self.index.values():
                for row in rows:
                    context=row.get('input_context')
                    source=delivery.get('source_output_key')
                    same_source=(type(source) is list and len(source)==4
                        and (row.get('source_output_key')==source
                             or type(context) is dict and context.get('source_output_key')==source))
                    if (row.get('kind')=='cpu_external_irq_sample'
                            and (row.get('binding_delivery_event_id')==delivery['event_id']
                                 or type(context) is dict and context.get('binding_delivery_event_id')==delivery['event_id']
                                 or same_source)):
                        name='input_sample.bound.'+str(row['event_id']);sample_names.append(name)
                        book.reference(name,row['event_id'],'cpu_external_irq_sample',row['component'])
                        sample_rows[id(row)]=name
        if (delivery is not None and type(delivery.get('start_local_tick')) is int
                and type(delivery.get('end_local_tick')) is int
                and delivery['end_local_tick']-delivery['start_local_tick']==16):
            for tick in range(delivery['start_local_tick'],delivery['end_local_tick']+1):
                rows=[row for rows in self.index.values() for row in rows
                    if row.get('kind')=='cpu_external_irq_sample' and row.get('local_tick')==tick
                    and (row.get('component')==self.cpu_id or row.get('source_component')==self.cpu_id
                         or row.get('binding_delivery_event_id')==delivery['event_id']
                         or row.get('receipt_id',{}).get('execution')==self.cpu._execution
                         or (type(row.get('input_context')) is dict
                             and row['input_context'].get('target_component')==self.cpu_id))]
                if not rows:
                    name='input_sample.'+str(tick);sample_names.append(name)
                    book.reference(name,None,'cpu_external_irq_sample',self.cpu_id)
                for j,row in enumerate(rows):
                    name=sample_rows.get(id(row))
                    if name is None:
                        name='input_sample.'+str(tick)+'.'+str(j);sample_names.append(name)
                        book.reference(name,row['event_id'],'cpu_external_irq_sample',row['component'])
                        sample_rows[id(row)]=name
                    if len(rows)!=1:
                        book.issue(name,_Contradiction('duplicate/ambiguous IRQ input samples at declared tick'))
        book.check('output',self.independent_irq_output)
        book.check('delivery',self.independent_irq_delivery)
        book.check('take',self.live_cpu)
        status_address=self.contract['control']['base']+self.contract['dma']['csr']['offsets']['control']
        book.check('status',lambda row:self.cpu_response(row,address=status_address,write=False))
        book.check('return',lambda row:self.independent_return(row,book.values.get('status')))
        result_base=self.p['result_base']+24*self.attempt['case_index']
        status=book.values.get('status')
        book.check('status_store',lambda row:self.independent_cpu_store(row,address=result_base,
            value=status['rdata'] if status is not None and type(status.get('rdata')) is int else row.get('value')))
        book.check('terminal',lambda row:self.independent_cpu_store(row,address=result_base+20,value=1))
        book.check('boundary',self.independent_boundary)
        for name in sample_names:
            book.check(name,lambda row:self.independent_irq_input(row,delivery))
        words=tuple((int.from_bytes(bytes.fromhex(self.attempt['raw8_hex']),'little')>>(11*i))&2047 for i in range(4))
        for i,word in enumerate(words):
            book.check('readbacks.'+str(i),lambda row,_i=i,_word=word:
                self.cpu_response(row,address=self.p['destination_address']+4*_i,write=False,value=_word))
            book.check('results.'+str(i),lambda row,_i=i,_word=word:
                self.independent_cpu_store(row,address=result_base+4+4*_i,value=_word))
            book.check('word_commits.'+str(i),lambda row,_i=i,_word=word:
                self.commit(row,self.dma.memory_service,key=self.dma_key(row),
                            address=self.p['destination_address']+4*_i,value=_word))
        return self.finish_component([book],self.irq_completion_join)

    def irq_completion_join(self):
        from myfuzz.scenario.native_f6_isr_return import _issuer_state
        from .compiled_f6_firmware import build_f6_firmware
        output=self.event('irq_output','source_start',self.dma_id)
        delivery=self.event('irq_delivery','binding_delivery',self.cpu_id)
        self.independent_irq_delivery(delivery)
        take=self.event('irq','cpu_external_irq_taken',self.cpu_id);self.live_cpu(take)
        returned=self.event('return','native_f6_isr_return.v1',self.cpu_id)
        issuer=getattr(self.cpu,'_f6_isr_return',None)
        try:state=_issuer_state(issuer);events=issuer.events
        except ValueError as error:raise _Contradiction(str(error)) from error
        _require(state['service'] is self.cpu.service and state['memory'] is self.dma.memory_service.memory,
            'CPU/DMA shared memory/service ownership mismatch')
        _require(sum(_json(e)==_json(_raw(returned)) for e in events)==1,'MRET has no sealed original issuance')
        _require(returned.get('case_id')==self.attempt['case_id'] and returned.get('case_index')==self.attempt['case_index']
            and returned.get('execution_binding_sha256')==self.runtime.execution_binding_sha256
            and returned.get('irq_take_key')==take.get('take_key')
            and _f6_take_receipts_match(self.runtime, self.cpu, self.cpu_id,
                returned, take), 'MRET/take case/key/receipt mismatch')
        status=self.event('status','data_response',self.cpu_id)
        status_address=self.contract['control']['base']+self.contract['dma']['csr']['offsets']['control']
        status_key=self.cpu_response(status,address=status_address,write=False)
        _require(type(status.get('rdata')) is int,'actual ISR status is not a typed word')
        has_error=bool(status['rdata']&self.contract['dma']['csr']['status_error_mask'])
        firmware=build_f6_firmware(self.contract)
        _require(returned.get('pc_rdata')==firmware.document()['isr']['mret_addresses'][int(has_error)],
            'MRET branch site contradicts actual ISR status/terminal branch')
        from myfuzz.local_harness.f6_dma_response_fault import _validate_f6_response_fault
        fault=_validate_f6_response_fault(self.dma)
        fault_document=fault.document() if fault is not None else None
        selected=(fault_document is not None and fault_document['selected_transaction'] is not None
            and fault_document['selector']['case_index']==self.attempt['case_index'])
        _require(has_error==selected,'actual ISR status contradicts selected native response fault')
        if has_error:
            _require(fault_document['execution_binding_sha256']==self.runtime.execution_binding_sha256,
                'native error completion binding mismatch')
            selector=fault_document['selector'];operation=selector['operation'];index=selector['word_index']
            accepted,error_key,_=self.dma_beat('reads' if operation=='read' else 'writes',index,
                write=operation=='write',address=self.p['source_address' if operation=='read' else 'destination_address']+4*index,
                value=0 if operation=='read' else (int.from_bytes(bytes.fromhex(self.attempt['raw8_hex']),'little')>>(11*index))&2047)
            _same(asdict(error_key),fault_document['selected_transaction'],'native fault selected key mismatch')
            actual=self.owner_events(self.dma_id,'dma_edge',predicate=lambda row:
                row.get('environment_error_receipt',{}).get('source_transaction')==asdict(error_key))
            _require(len(actual)==1,'native error has no original selector receipt')
            error_receipt=actual[0]['environment_error_receipt']
            entry=self.dma.memory_service.ledger._entries.get(error_key)
            _require(entry is not None and entry.status=='complete' and entry.receipt is error_receipt
                and error_receipt.get('target_effect') is False,'native error ledger/effect owner mismatch')
            _require(not self.attempt.get('readbacks') and not self.attempt.get('results'),
                'native error ISR cannot claim success readbacks/results')
        key=output.get('source_output_key')
        source_port=self.contract['irq']['producer_port']
        _require(type(key) is list and len(key)==4 and key[:3]==[self.dma_id,self.dma.reset_epoch,source_port]
            and type(key[1]) is int and type(key[3]) is int and key[3]>0,'IRQ output owner/epoch/source mismatch')
        raw=self.reference(output.get('producer_event_id'),'dma_edge',self.dma_id)
        self.live_dma(raw)
        raw_tick=raw.get('tick');raw_epoch=raw.get('reset_epoch')
        _require(type(raw_tick) is int and raw_tick>0 and type(raw_epoch) is int
            and raw_epoch==self.dma.reset_epoch
            and key==[self.dma_id,raw_epoch,source_port,raw_tick],
            'IRQ output key tick/epoch differs from original native edge')
        runtime_name=self._validated_irq_runtime_name()
        physical_value=raw['payload']['observations']['physical'].get(runtime_name)
        _require(type(physical_value) is int and physical_value==1,
            'IRQ output lacks actual native high sample')
        final_response=(self.event('read_responses' if operation=='read' else 'write_responses',
            'dma_edge',self.dma_id,index) if has_error else self.event('write_responses','dma_edge',self.dma_id,3))
        if has_error:
            _require(final_response.get('response',{}).get('transaction')==asdict(error_key)
                and type(final_response['response'].get('error')) is int and final_response['response']['error']==1
                and final_response['tick']>accepted['tick'],'selected native ERR response key/order mismatch')
            self.live_dma(final_response)
        _require(type(raw.get('tick')) is int and raw['tick']>=final_response['tick'],
            'native DMA IRQ precedes final native destination response')
        level=self.contract['irq'].get('delivery_policy')=='level'
        _require(delivery.get('source_event_id')==output['event_id'] and delivery.get('source_output_key')==key
            and delivery.get('delivery_id')==self.contract['irq']['delivery_id']
            and delivery.get('target_component')==self.cpu_id and type(delivery.get('target_epoch')) is int
            and delivery.get('target_epoch')==self.cpu.reset_epoch
            and type(delivery.get('start_local_tick')) is int and type(take.get('local_tick')) is int
            and delivery['start_local_tick']<=take['local_tick']
            and (delivery.get('end_local_tick') is None if level else
                 delivery.get('end_local_tick')==delivery['start_local_tick']+16
                 and take['local_tick']<delivery['end_local_tick'])
            and take.get('binding_delivery_event_id')==delivery['event_id']
            and take.get('source_output_key')==key and take.get('actual_pre_input')==take.get('actual_post_input')==1
            and take.get('irq_masked_pre')==0 and take.get('irq_taken_pre')==1,'IRQ delivery/window/native take mismatch')
        input_samples=[];expiry=None
        level_clear=self.level_irq_clear(delivery,take,returned) if level else None
        final_tick=take['local_tick'] if level else delivery['end_local_tick']
        for tick in range(delivery['start_local_tick'],final_tick+1):
            rows=[e for rows in self.index.values() for e in rows
                if e.get('component')==self.cpu_id and e.get('kind')=='cpu_external_irq_sample'
                and e.get('local_tick')==tick and e.get('reset_epoch')==self.cpu.reset_epoch]
            if not rows:raise _Missing('actual IRQ input interval/expiry sample unavailable')
            _require(len(rows)==1,'duplicate actual IRQ input sample')
            sample=self.reference(rows[0]['event_id'],'cpu_external_irq_sample',self.cpu_id)
            self.live_cpu(sample)
            active=1 if level else int(tick<delivery['end_local_tick'])
            _require(all(type(sample.get(n)) is int and sample[n]==active
                for n in ('actual_pre_input','actual_post_input')),
                'actual IRQ input contradicts fixed delivery interval/expiry')
            if active:
                _require(sample.get('binding_delivery_event_id')==delivery['event_id']
                    and sample.get('source_output_key')==key,
                    'actual IRQ interval sample belongs to a different delivery/source')
                input_samples.append(sample['event_id'])
            else:expiry=sample['event_id']
        expiry=_irq_low_reference(level,level_clear,expiry)
        status_delivery=self.unique(self.cpu_id,'mmio_delivery',asdict(status_key))
        self.control_delivery(status_delivery,key=status_key,address=status_address,write=False,value=status['rdata'],response=status)
        store=self.event('status_store','memory_write',self.cpu_id)
        self.cpu_store(store,address=self.p['result_base']+24*self.attempt['case_index'],value=status['rdata'])
        _require(take['local_tick']<status['acceptance_tick']<returned['local_tick'],'ISR status does not follow take and precede MRET')
        results=[]
        words=tuple((int.from_bytes(bytes.fromhex(self.attempt['raw8_hex']),'little')>>(11*i))&2047 for i in range(4))
        for i,word in enumerate(words if not has_error else ()):
            read=self.event('readbacks','data_response',self.cpu_id,i)
            read_key=self.cpu_response(read,address=self.p['destination_address']+4*i,write=False,value=word)
            snapshot=read.get('snapshot',{})
            commit=self.event('word_commits','memory_write_commit',self.dma_id,i);doc=commit['commit_document']
            _require(snapshot.get('versions') in ([doc['version']]*4,tuple(tuple(doc['version']) for _ in range(4)))
                and snapshot.get('writer_event_ids') in ([str(TransactionKey(**doc['fullkey']))]*4,(str(TransactionKey(**doc['fullkey'])),)*4)
                and snapshot.get('writer_kinds') in (['STORE']*4,('STORE',)*4)
                and take['local_tick']<read['acceptance_tick']<returned['local_tick'],
                'ISR readback lacks corresponding destination byte writer/version/order')
            result=self.event('results','memory_write',self.cpu_id,i)
            _,result_doc,result_response=self.cpu_store(result,address=self.p['result_base']+24*self.attempt['case_index']+4+4*i,value=word)
            _require(result_response['acceptance_tick']>read['response_tick'],'ISR result precedes corresponding consumed read')
            results.append(dict(read_transaction=asdict(read_key),result_commit_id=result_doc['commit_id']))
        terminal=self.event('terminal','memory_write',self.cpu_id)
        marker=2 if has_error else 1
        _,_,terminal_response=self.cpu_store(terminal,address=self.p['result_base']+24*self.attempt['case_index']+20,value=marker)
        _require(terminal_response['response_tick']<returned['local_tick'],'terminal store does not precede MRET')
        boundary=self.event('next_fetch','native_fetch_boundary',self.cpu_id)
        expected=(self.p['slot_base']+256*f6_slot(self.runtime, self.attempt)+128 if has_error else
            self.p['slot_base']+256*(f6_slot(self.runtime, self.attempt)+1)
            if f6_slot(self.runtime, self.attempt)+1<self.p['slot_count'] else self.p['park_address'])
        _require(boundary.get('address')==expected and boundary.get('execution')==self.cpu._execution
            and boundary.get('reset_epoch')==self.cpu.reset_epoch and boundary.get('native_testcase_id')==self.cpu._case_id
            and boundary.get('local_tick')>returned['successor_local_tick'], 'next fetch scope/address/order mismatch')
        # A detached boundary cannot replace the actual original CPU pending fetch.
        request=self.cpu._request_evidence.get('instr')
        _require(request is not None and request.get('transaction')==boundary.get('transaction')
            and request.get('address')==expected and request.get('acceptance_tick')==boundary.get('local_tick'),
            'next fetch has no live original pending CPU request')
        sample=self.cpu_tick_sample(boundary['local_tick'])
        backend=sample.get('pre',{}).get('backend')
        _require(type(backend) is dict and backend.get('i_req_valid')==1
            and backend.get('i_req_ready')==1 and backend.get('i_req_addr')==expected,
            'next fetch has no actual native handshake')
        firmware=build_f6_firmware(self.contract)
        pc=returned['successor_pc_rdata'];canonical=firmware.initial_images.get(self.p['slot_base']+256*f6_slot(self.runtime, self.attempt)+128)
        if self.p['slot_base']+256*f6_slot(self.runtime, self.attempt)<=pc<self.p['slot_base']+256*f6_slot(self.runtime, self.attempt)+128:
            offset=pc-self.p['slot_base']-256*f6_slot(self.runtime, self.attempt);word=bytes.fromhex(self.attempt['prefix_hex'])[offset:offset+4]
        else:
            offset=pc-(self.p['slot_base']+256*f6_slot(self.runtime, self.attempt)+128);word=canonical[offset:offset+4]
        _require(len(word)==4 and returned['successor_instruction']==int.from_bytes(word,'little'),
            'actual resumed instruction differs from canonical candidate/preload bytes')
        details=dict(irq_take_key=take['take_key'],return_receipt_id=returned['return_receipt_id'],
            actual_status_word=status['rdata'],status_transaction=asdict(status_key),
            irq_input_samples=input_samples,irq_expiry_sample=expiry,
            mret_pc=returned['pc_rdata'],terminal_marker=marker,next_address=expected,
            successor_receipt_id=returned['successor_receipt_id'],next_fetch=boundary['event_id'],results=results)
        if level:
            details['level_clear']=level_clear
        if has_error:
            raise _Contradiction('native expected ERR completed the authenticated error ISR branch',
                dict(error_completion=details))
        return details


def capture_f6_case(runtime,attempt):
    scope=_scope(runtime)
    _require(type(attempt) is dict and type(attempt.get('case_id')) is str,'F6 admitted attempt required')
    _require(any(a['case_id']==attempt['case_id'] for a in runtime.admitted_attempts),'case is outside admitted attempts')
    findings=runtime.checker_findings()  # Unexpected checker/host exceptions propagate.
    _require(type(findings) is list,'checker findings must be a recorded list')
    material=dict(case_id=attempt['case_id'],observations={},evidence_inventory={})
    case=_Case(runtime,attempt)
    def protocol():
        checker_report=getattr(runtime,'protocol_checker_case_report',None)
        if checker_report is None:
            # Small synthetic consumer fixtures do not own a Runner and do not
            # claim that a live protocol checker was installed. Production F6
            # runtime always installs this report before begin(); a missing
            # report on a Runner-backed runtime is therefore fail-closed.
            if (getattr(runtime,'runner',None) is not None
                    or _requires_runner_backed_protocol_report(runtime)):
                raise _Missing('dual-endpoint Wishbone checker report unavailable')
            _require(not findings,'protocol checker reported receipt violations')
            if not runtime.observer_view:raise _Missing('native observations unavailable')
            return dict(findings=findings,observation_count=len(runtime.observer_view),
                checker_mode='synthetic_no_runner_fixture')
        _require(type(checker_report) is dict
            and checker_report.get('schema_version')==
                'wishbone_dma_protocol_checker_report.v1',
            'invalid dual-endpoint Wishbone checker report')
        _require(checker_report.get('case_id')==attempt['case_id']
            and checker_report.get('case_index')==attempt['case_index']
            and checker_report.get('run_id')==runtime.run_id
            and checker_report.get('execution_binding_sha256')==runtime.execution_binding_sha256,
            'Wishbone checker report case/binding mismatch')
        trace_set=runtime.dma.artifact.runtime_document.get('protocol_checker_trace_set')
        _require(type(trace_set) is dict and trace_set.get('schema_version')==
            'wishbone_dma_protocol_checker.v1' and type(trace_set.get('traces')) is list,
            'admitted dual-endpoint Wishbone trace set unavailable')
        expected_traces={row.get('endpoint_id'):row for row in trace_set['traces']
            if type(row) is dict}
        expected_ids=sorted(expected_traces)
        _require(len(expected_ids)==2 and checker_report.get('installed_endpoint_ids')==expected_ids
            and checker_report.get('component_id')==runtime.dma.artifact.plan.profile.component_id
            and checker_report.get('instance_id')==runtime.dma.artifact.plan.request.instance_id,
            'Wishbone checker endpoint/artifact scope mismatch')
        identity=checker_report.get('artifact_identity')
        from myfuzz.local_harness.renderer import _sha as _artifact_sha
        _require(type(identity) is dict
            and identity.get('component_id')==checker_report['component_id']
            and identity.get('instance_id')==checker_report['instance_id']
            and identity.get('artifact_digest')==runtime.dma.artifact.runtime_document.get('artifact_digest')
            and identity.get('profile_fingerprint')==runtime.dma.artifact.plan.profile.profile_fingerprint
            and identity.get('source_verification_sha256')==_artifact_sha(
                runtime.dma.artifact.source_verification)
            and identity.get('runtime_artifact_sha256')==_artifact_sha(
                runtime.dma.artifact.runtime_document),
            'Wishbone checker artifact identity mismatch')
        expected_trace_digest=sha256(_json(trace_set).encode()).hexdigest()
        _require(checker_report.get('trace_set_sha256')==expected_trace_digest,
            'Wishbone checker trace-set digest mismatch')
        endpoints=checker_report.get('endpoints')
        _require(type(endpoints) is list and len(endpoints)==2,
            'Wishbone checker endpoint report inventory mismatch')
        by_endpoint={row.get('endpoint_id'):row for row in endpoints if type(row) is dict}
        _require(set(by_endpoint)==set(expected_ids),
            'Wishbone checker endpoint report coverage mismatch')
        runner=runtime.runner
        read=getattr(runner,'events_since',None)
        event_count=getattr(runner,'event_count',None)
        start=checker_report.get('runner_event_start')
        end=checker_report.get('runner_event_end')
        attempt_start=attempt.get('_runner_event_start')
        _present(callable(read) and type(event_count) is int,
            'Runner protocol sample journal unavailable')
        _require(type(attempt_start) is int and attempt_start>=0
            and type(start) is int and start==attempt_start
            and type(end) is int and 0<=start<=end==event_count,
            'Runner protocol report event range does not match admitted attempt')
        # Case slice (start==attempt start, end==current event count): the
        # report above pins that range, and only int identities, sample ids and
        # int-valued payloads leave this function, so borrow it instead of
        # copying the slice.
        journal=_borrow_events(runner,start)
        _present(type(journal) in (list,tuple) and len(journal)==end-start,
            'Runner protocol sample slice unavailable')
        for index,row in enumerate(journal,start=start+1):
            _require(type(row) is dict and row.get('event_id')==index,
                'Runner protocol sample event identity mismatch')
        samples=[row for row in journal if row.get('kind')=='local_tick_sample'
            and row.get('component')==case.dma_id and row.get('phase')=='pre']
        sample_ids=[row['event_id'] for row in samples]
        for endpoint_id,expected_trace in expected_traces.items():
            endpoint_report=by_endpoint[endpoint_id]
            _require(endpoint_report.get('trace')==expected_trace
                and endpoint_report.get('sample_event_ids')==sample_ids
                and endpoint_report.get('pre_sample_count')==len(sample_ids),
                'Wishbone checker did not consume the complete endpoint sample slice')
            signal_names=tuple(expected_trace['signals'].values())
            for sample in samples:
                backend=sample.get('outputs',{}).get('backend')
                _require(type(backend) is dict and all(name in backend
                    and type(backend[name]) is int and backend[name]>=0
                    for name in signal_names),
                    'Wishbone checker raw sample is incomplete')
                _require(type(sample.get('reset_epoch')) is int
                    and sample['reset_epoch']==endpoint_report.get('reset_epoch'),
                    'Wishbone checker raw sample reset scope mismatch')
        report_findings=checker_report.get('findings')
        _require(type(report_findings) is list,
            'Wishbone checker findings are not a recorded list')
        violation_rows=[row for row in journal
            if row.get('kind')=='protocol_violation'
            and row.get('endpoint_id') in expected_ids]
        event_ids=[]
        for finding in report_findings:
            endpoint=finding.get('endpoint_id') if type(finding) is dict else None
            raw_id=finding.get('raw_event_id') if type(finding) is dict else None
            code=(finding.get('payload',{}).get('violation_code')
                if type(finding) is dict else None)
            matches=[row for row in violation_rows
                if row.get('endpoint_id')==endpoint and raw_id in row.get('raw_event_refs',[])
                and row.get('payload',{}).get('violation_code')==code]
            _require(len(matches)==1,'Wishbone checker finding lacks exact Runner event')
            event_ids.append(matches[0]['event_id'])
        _require(checker_report.get('runner_violation_event_ids')==event_ids
            and not findings and not report_findings and not violation_rows,
            'protocol checker reported receipt violations')
        counts=checker_report.get('pre_sample_counts')
        _require(type(counts) is dict and set(counts)==set(expected_ids)
            and all(type(counts[key]) is int and counts[key]==len(sample_ids)
                    and counts[key]>0 for key in expected_ids),
            'dual-endpoint Wishbone checker has incomplete PRE sampling')
        pending=checker_report.get('pending')
        _require(type(pending) is dict and set(pending)==set(expected_ids)
            and all(type(pending[key]) is dict
                and pending[key].get('offers')==0
                and pending[key].get('outstanding')==0 for key in expected_ids),
            'dual-endpoint Wishbone checker ended with pending transaction')
        _require(checker_report.get('status')=='clean',
            'dual-endpoint Wishbone checker did not close cleanly')
        if not runtime.observer_view:raise _Missing('native observations unavailable')
        return dict(findings=findings,observation_count=len(runtime.observer_view),
            checker_mode='runner_dual_endpoint_wishbone',
            checker_report=checker_report,
            endpoint_pre_sample_counts=counts,
            raw_sample_event_ids=sample_ids,
            protocol_violation_event_ids=event_ids)

    def edge_projection_unavailable(outcome,reason):
        relations=('dma_master_route','causal_order','dma_master_route','persistent_state')
        nodes=(('F6.runtime_ram_source_words','F6.runtime_dma_read_words'),
            ('F6.runtime_dma_read_words','F6.runtime_dma_write_words'),
            ('F6.runtime_dma_write_words','F6.runtime_ram_destination_words'),
            (runtime.contract['instruction_source_id'],
                'F6.runtime_online_instruction_prefixes'))
        issue=dict(outcome=outcome,reason=reason)
        return dict(kind='cross_component.declared_edge_hops',outcome=outcome,
            details=dict(schema_version='compiled_F6_declared_edge_hops.v1',
                edges=[dict(rule_index=index,prerequisite_index=0,
                    source_node_id=nodes[index][0],target_node_id=nodes[index][1],
                    relation=relations[index],outcome=outcome,runner_event_ids=[],
                    evidence=[],issues=[issue]) for index in range(4)],
                component_evidence={},raw_references=[],raw_evidence=[],issues=[issue]))

    def declared_edges():
        """Reconstruct the four admitted runtime hops from the raw Runner archive."""
        runner=getattr(runtime,'runner',None)
        read=getattr(runner,'events_since',None)
        count=getattr(runner,'event_count',None)
        if not callable(read) or type(count) is not int:
            return edge_projection_unavailable('missing',
                'Runner raw event archive unavailable')
        # Whole archive, borrowed: in a shared campaign the projection re-checks
        # every earlier flow record's source admission (f6_saved_slot_mapping
        # 'actual-source-admission') and maps the attempt's slot through the
        # whole flow ledger, so a case slice would drop rows it needs.  Only
        # the detaching copy is removed; both consumers below detach whatever
        # they keep (_saved_projection_inputs and the live-receipt deepcopies).
        events=_borrow_events(runner)
        _present(type(events) in (list,tuple) and len(events)==count,
            'Runner cross-component event archive is incomplete')
        local_by_id={}
        for row in runtime.observer_view:
            key=(row['component'],row['event_id'])
            _require(key not in local_by_id,'duplicate Observer component/event identity')
            local_by_id[key]=row
        artifacts=getattr(runtime,'artifacts',None)
        cpu_id=runtime.contract['cpu']['instance_id']
        _present(type(artifacts) is dict and cpu_id in artifacts,
            'bound CPU artifact unavailable for declared runtime-edge projection')
        cpu_artifact=artifacts[cpu_id]
        from myfuzz.integration.compiled_f6_saved_semantics import \
            project_saved_cross_component_edges
        saved_events,saved_local_by_id=_saved_projection_inputs(events,local_by_id)
        projection=project_saved_cross_component_edges(attempt=attempt,
            contract=runtime.contract,binding=runtime.execution_binding,
            events=saved_events,local_by_id=saved_local_by_id,
            cpu_artifact=cpu_artifact, shared_context=projection_context(runtime, attempt))
        _require(type(projection) is dict
            and projection.get('kind')=='cross_component.declared_edge_hops'
            and projection.get('outcome') in ('passed','failed','missing')
            and type(projection.get('details')) is dict,
            'invalid declared runtime-edge projection')
        rows=projection['details'].get('edges')
        _require(type(rows) is list and len(rows)==4
            and [(row.get('rule_index'),row.get('prerequisite_index')) for row in rows]
                ==[(index,0) for index in range(4)],
            'declared runtime-edge projection is incomplete')
        return _close_live_f6_fetch_projection(runtime,attempt,list(events),
            local_by_id,projection)

    def cross():
        # Each component can contribute independent contradictions even when a
        # prior component is missing. Preserve all known outcomes and the
        # independently reconstructed declared graph before reducing.
        components={};issues=[]
        for name,check in (('configuration',case.configuration),('words',case.words),
                           ('irq',case.irq_completion)):
            start=len(case.used)
            try:
                details=check();status='passed';reason='complete source-bound component evidence'
            except (_Missing,_Contradiction) as error:
                status='failed' if isinstance(error,_Contradiction) else 'missing'
                reason=str(error);details=error.details;issues.append(error)
            components[name]=dict(status=status,reason=reason,details=details,
                                 raw_references=list(case.used[start:]))
        # The graph expectation owns its own source references. Component
        # evidence was already retained in component_evidence above and has
        # separate expectation records; do not carry that reference union into
        # this graph edge inventory.
        case.used=[]
        case.raw_evidence=[]
        case.seen_raw=set()
        try:
            projection=declared_edges()
        except _Missing as error:
            projection=edge_projection_unavailable('missing',str(error))
        except _Contradiction as error:
            projection=edge_projection_unavailable('failed',str(error))
        projection_details=projection['details']
        for reference in projection_details.get('raw_references',[]):
            if type(reference) is not dict:
                continue
            component,event_id,kind=(reference.get('component'),
                reference.get('event_id'),reference.get('kind'))
            identity=dict(component=component,event_id=event_id,kind=kind)
            if (type(component) is str and type(event_id) is int
                    and type(kind) is str and (component,event_id) in case.index
                    and identity not in case.used):
                case.reference(event_id,kind,component)
        # Keep source service and completed OBI receipts in the ordinary
        # Observer -> Runner projection form. Source admissions have no
        # component/Observer row; they remain nested Runner-only evidence.
        for raw in projection_details.get('raw_evidence',[]):
            if (type(raw) is not dict or raw.get('kind') not in (
                    'instruction_source',
                    'compiled_F6_instruction_fetch_completion')):
                continue
            owner=raw.get('component')
            runner_event_id=raw.get('event_id')
            if type(owner) is not str or type(runner_event_id) is not int:
                continue
            candidates=[row for rows in case.index.values() for row in rows
                if row.get('component')==owner
                and row.get('runner_event_id')==runner_event_id]
            if len(candidates)!=1 or candidates[0].get('kind')!='instruction_source':
                continue
            observer=candidates[0]
            actual=case.live_owner_event(observer,owner)
            _require(_json(actual)==_json(raw),
                'F6 graph Observer row differs from selected Runner event')
            kind=raw['kind']
            identity=(owner,observer['event_id'],kind)
            if not any((row.get('component'),row.get('event_id'),
                    row.get('kind',row.get('schema_version')))==identity
                    for row in case.raw_evidence):
                case.raw_evidence.append(deepcopy(observer))
            reference=dict(component=owner,event_id=observer['event_id'],
                kind=kind)
            if reference not in case.used:
                case.used.append(reference)
        details=dict(component_evidence=components,
            edges=projection_details['edges'],
            declared_edge_projection=projection_details)
        if projection['outcome']!='passed':
            projection_issues=projection_details.get('issues',[])
            reason=(projection_issues[0].get('reason')
                if projection_issues and type(projection_issues[0]) is dict
                else 'declared runtime graph edge evidence '+projection['outcome'])
            issue_type=_Contradiction if projection['outcome']=='failed' else _Missing
            issues.append(issue_type(reason,details))
        if issues:
            error=next((e for e in issues if isinstance(e,_Contradiction)),issues[0])
            raise type(error)(str(error),details)
        return dict(details,configuration=components['configuration']['details'],
                    words=components['words']['details'],irq=components['irq']['details'])
    for eid,check in zip(EXPECTATION_IDS,(protocol,cross,case.configuration,case.words,case.irq_completion)):
        case.used=[];case.raw_evidence=[];case.seen_raw=set()
        try:details=check();status='passed';reason='complete source-bound F6 evidence'
        except _Missing as error:status='missing';reason=str(error);details=error.details
        except _Contradiction as error:status='failed';reason=str(error);details=error.details
        details=dict(details,raw_references=list(case.used),raw_evidence=list(case.raw_evidence))
        reference=sha256(_json(dict(scope,case_id=attempt['case_id'],expectation_id=eid,details=details,status=status)).encode()).hexdigest()
        material['evidence_inventory'][reference]=dict(kind=eid,outcome=status,
            scope=dict(scope,case_id=attempt['case_id'],expectation_id=eid),details=details)
        material['observations'][eid]=dict(status=status,reason=reason,evidence_refs=[reference])
    _record_case(runtime,material)
    return json.loads(_json(material))


from myfuzz.scenario.f6_assertion_evidence import _seal_f6_collector
_seal_f6_collector(capture_f6_case)
