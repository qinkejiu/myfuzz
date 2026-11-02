"""Independent immutable five-expectation inventories and documentary audit.

Saved JSON can be audited against an externally retained inventory. Neither
this validator nor feedback enrollment creates native/service authority.
"""
from hashlib import sha256
import json
import re
from weakref import ref

from .f6_execution_contract import EXPECTATION_IDS

_SCOPE_KEYS=('compiled_document_sha256','binding_sha256','path_sha256',
             'execution_binding_sha256','path_id','run_id')


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False,ensure_ascii=False)


def _copy(value):
    return json.loads(_json(value))


def _scope(runtime):
    return _binding_scope(dict(compiled_document_sha256=runtime.compiled_document_sha256,
        binding_sha256=runtime.binding_sha256,path_sha256=sha256(_json(runtime.path).encode()).hexdigest(),
        execution_binding_sha256=runtime.execution_binding_sha256,
        path_id=runtime.path['path_id'],run_id=runtime.run_id))


def _binding_scope(binding):
    if type(binding) is not dict or not set(_SCOPE_KEYS) <= set(binding):
        raise ValueError('F6 evidence requires complete external execution scope')
    result={k:binding[k] for k in _SCOPE_KEYS}
    for k,v in result.items():
        if type(v) is not str or not v or v.strip()!=v:
            raise ValueError('invalid F6 evidence scope')
        if k.endswith('sha256') and re.fullmatch('[0-9a-f]{64}',v) is None:
            raise ValueError('invalid F6 evidence SHA256')
    return result


def _inventory_registry():
    owners={}
    collector=None
    def seal(function):
        nonlocal collector
        if collector is not None:raise ValueError('F6 collector already sealed')
        collector=(function,function.__code__)
    def records(runtime):
        row=owners.get(id(runtime))
        if row is None or row[0]() is not runtime:
            owner_id=id(runtime)
            def expired(reference):
                current=owners.get(owner_id)
                if current is not None and current[0] is reference:owners.pop(owner_id)
            row=(ref(runtime,expired),_json(_scope(runtime)),{})
            owners[owner_id]=row
        if row[1]!=_json(_scope(runtime)):
            raise ValueError('F6 runtime evidence scope drift')
        return row[2]
    def save(runtime,material):
        # Only the original collector can publish. Ordinary JSON has no enroll API.
        import sys
        from myfuzz.integration.compiled_f6_consumer import capture_f6_case
        frame=sys._getframe(1)
        if (collector is None or capture_f6_case is not collector[0]
                or capture_f6_case.__code__ is not collector[1]
                or frame.f_code is not collector[1]
                or frame.f_globals is not capture_f6_case.__globals__
                or frame.f_locals.get('runtime') is not runtime
                or frame.f_locals.get('material') is not material):
            raise ValueError('F6 inventory requires the original actual collector')
        saved=records(runtime);cid=material['case_id'];frozen=_json(material)
        if cid in saved and saved[cid]!=frozen:
            raise ValueError('F6 independent case inventory is immutable after capture')
        saved[cid]=frozen
    def inventory(runtime):
        attempts=runtime.admitted_attempts
        if type(attempts) is not tuple:
            raise ValueError('F6 admitted attempts must retain an immutable sequence')
        result=[];seen=set();saved=records(runtime)
        for attempt in attempts:
            cid=attempt.get('case_id') if type(attempt) is dict else None
            if type(cid) is not str or not cid or cid in seen:
                raise ValueError('invalid or duplicate F6 admitted case')
            seen.add(cid)
            result.append(json.loads(saved[cid]) if cid in saved else dict(case_id=cid,
                observations={eid:dict(status='missing',reason='case observation unavailable',evidence_refs=[])
                              for eid in EXPECTATION_IDS},evidence_inventory={}))
        if set(saved)-seen:raise ValueError('captured case is outside admitted case inventory')
        return result
    return seal,save,inventory


_seal_f6_collector,_record_case,_case_inventory=_inventory_registry()


def _build(scope,cases):
    if type(cases) is not list:raise ValueError('F6 case inventory must be a list')
    expected=[];seen=set()
    for case in cases:
        if type(case) is not dict or set(case)!={'case_id','observations','evidence_inventory'}:
            raise ValueError('invalid F6 case inventory fields')
        cid=case['case_id'];inventory=case['evidence_inventory'];observations=case['observations']
        if type(cid) is not str or not cid or cid in seen:raise ValueError('duplicate or invalid F6 case')
        seen.add(cid)
        if (type(inventory) is not dict or type(observations) is not dict
                or set(observations)!=set(EXPECTATION_IDS)):
            raise ValueError('F6 inventory requires exactly five expectations')
        for key,row in inventory.items():
            if (type(key) is not str or not key or type(row) is not dict
                    or set(row)!={'kind','outcome','scope','details'}
                    or row['kind'] not in EXPECTATION_IDS
                    or row['outcome'] not in ('passed','failed','missing')
                    or type(row['details']) is not dict
                    or _json(row['scope'])!=_json(dict(scope,case_id=cid,expectation_id=row['kind']))):
                raise ValueError('F6 evidence identity/kind/outcome/scope mismatch')
            _validate_raw_evidence(row, cid)
        rows=[]
        for eid in EXPECTATION_IDS:
            obs=observations[eid]
            if (type(obs) is not dict or set(obs)!={'status','reason','evidence_refs'}
                    or obs['status'] not in ('passed','failed','missing')
                    or type(obs['reason']) is not str or not obs['reason']
                    or type(obs['evidence_refs']) is not list
                    or any(type(r) is not str for r in obs['evidence_refs'])
                    or len(set(obs['evidence_refs']))!=len(obs['evidence_refs'])):
                raise ValueError('invalid F6 observation')
            available={r for r,v in inventory.items() if v['kind']==eid}
            refs=set(obs['evidence_refs'])
            if not refs <= available:raise ValueError('borrowed or missing F6 evidence reference')
            failed={r for r in available if inventory[r]['outcome']=='failed'}
            missing={r for r in available if inventory[r]['outcome']=='missing'}
            if (obs['status']=='passed' and (not refs or failed or missing
                    or any(inventory[r]['outcome']!='passed' for r in refs))
                    or obs['status']=='failed' and (not failed or not failed<=refs)
                    or obs['status']=='missing' and failed):
                raise ValueError('F6 observation contradicts independent inventory')
            rows.append(dict(expectation_id=eid,**_copy(obs)))
        expected.append(dict(case_id=cid,assertions=rows))
    return dict(assertions=dict(schema_version='compiled_F6_assertion_results.v1',**scope,cases=expected),
        assertion_evidence=dict(schema_version='compiled_F6_assertion_evidence.v1',**scope,cases=_copy(cases)))


def _validate_raw_evidence(item, case_id):
    """Require passed typed rows to cite their captured rows and references.

    The protocol-checker expectation is the only pass that has no event
    references: its evidence is the empty findings list plus the observation
    count. The saved-run auditor separately joins all other references to the
    attempt and authoritative Runner trace.
    """
    details = item['details']
    rows = details.get('raw_evidence')
    references = details.get('raw_references')
    if type(rows) is not list or type(references) is not list:
        raise ValueError('F6 raw evidence and references must be lists')

    row_ids = set()
    for raw in rows:
        if type(raw) is not dict:
            raise ValueError('invalid F6 raw evidence row')
        component = raw.get('component')
        event_id = raw.get('event_id')
        kind = raw.get('kind', raw.get('schema_version'))
        if (type(component) is not str or not component or type(event_id) is not int
                or event_id <= 0 or type(kind) is not str or not kind):
            raise ValueError('invalid F6 raw evidence identity')
        row_ids.add((component, event_id, kind))

    ref_ids = []
    for reference in references:
        if type(reference) is not dict:
            raise ValueError('invalid F6 raw evidence reference')
        component = reference.get('component')
        event_id = reference.get('event_id')
        kind = reference.get('kind')
        if (type(component) is not str or not component
                or type(kind) is not str or not kind
                or (event_id is not None and
                    (type(event_id) is not int or event_id <= 0))):
            raise ValueError('invalid F6 raw evidence reference identity')
        if event_id is not None:
            ref_ids.append((component, event_id, kind))

    if item['kind'] == 'protocol_checker.receipt_violations':
        if item['outcome'] == 'passed':
            count = details.get('observation_count')
            if (rows or references or details.get('findings') != []
                    or type(count) is not int or count <= 0):
                raise ValueError('protocol pass lacks empty findings evidence')
        return

    if item['outcome'] == 'passed':
        if not rows or not references:
            raise ValueError('passed F6 expectation requires raw evidence')
        if any(reference not in row_ids for reference in ref_ids):
            raise ValueError('passed F6 raw evidence reference is not closed')
        if len(ref_ids) != len(references):
            raise ValueError('passed F6 raw evidence reference is incomplete')
    elif any(reference not in row_ids for reference in ref_ids):
        raise ValueError(f'F6 raw evidence reference is not closed for {case_id}')


def build_f6_assertion_material(runtime):
    return _build(_scope(runtime),_case_inventory(runtime))


def validate_f6_assertion_evidence(document,*,execution_binding,case_inventory):
    expected=_build(_binding_scope(execution_binding),case_inventory)
    if _json(document)!=_json(expected):
        raise ValueError('F6 evidence differs from complete independent case inventory')
    return _copy(expected)


def f6_case_feedback(material,*,case_ids):
    """Five conjunction targets; every target requires every complete case."""
    if type(case_ids) is not tuple or not case_ids or len(set(case_ids))!=len(case_ids):return bytes(5)
    try:
        if 'assertion_evidence' in material:
            evidence=material['assertion_evidence'];scope=_binding_scope(evidence)
            rebuilt=_build(scope,evidence['cases'])
            if _json(rebuilt)!=_json(material):return bytes(5)
            cases=evidence['cases']
        else:
            cases=[material]
        indexed={c['case_id']:c for c in cases}
        if len(indexed)!=len(cases):return bytes(5)
        for cid in case_ids:
            case=indexed[cid];observations=case['observations'];inventory=case['evidence_inventory']
            if set(observations)!=set(EXPECTATION_IDS):return bytes(5)
            for eid in EXPECTATION_IDS:
                row=observations[eid];refs=row['evidence_refs']
                if row['status']!='passed' or not refs or len(set(refs))!=len(refs):return bytes(5)
                for reference in refs:
                    ev=inventory[reference]
                    if ev['kind']!=eid or ev['outcome']!='passed' or ev['scope']['case_id']!=cid:return bytes(5)
                if any(v['kind']==eid and v['outcome']!='passed' for v in inventory.values()):return bytes(5)
        return bytes([1]*5)
    except (KeyError,TypeError,ValueError):
        return bytes(5)
