"""Pure assertion inventory joins; JSON evidence does not confer native authority.

Cases are lists of {case_id, observations, evidence_inventory}. Observations map
expectation IDs to {status, reason, evidence_refs}; inventory maps reference IDs
to {kind, outcome, scope, details}. Kind is the exact expectation ID; outcome is
passed/failed/missing. Scope contains compiled_document_sha256, binding_sha256,
path_sha256, run_id, case_id and expectation_id. Details is a JSON object supplied
by the runtime's independent evidence collector. The caller must authenticate
that collector separately. Output retains the inventory and emits ordered
assertions, including missing observations. Checker bug classes remain outside
this document. Admission must precede use of this API.
"""
import hashlib
import json
import re

SCHEMA = 'compiled_assertion_results.v1'
KINDS = {'protocol_checker.receipt_violations', 'cross_component.declared_edge_hops'}
STATUSES = {'passed', 'failed', 'missing'}


def _json(value):
    def check(obj):
        if type(obj) is dict:
            if any(type(k) is not str for k in obj):
                raise ValueError('JSON object keys must be strings')
            for v in obj.values(): check(v)
        elif type(obj) is list:
            for v in obj: check(v)
        elif obj is not None and type(obj) not in (str, int, float, bool):
            raise ValueError('non JSON value')
    check(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True)
    except (ValueError, TypeError) as exc:
        raise ValueError('invalid JSON') from exc


def _identity(value):
    if type(value) is not str or not value or value.strip() != value:
        raise ValueError('invalid identity')
    return value


def _keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError('invalid record fields')


def build_assertion_results(*, compiled_document_sha256, binding_sha256, path, run_id, cases):
    for digest in (compiled_document_sha256, binding_sha256):
        if type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None:
            raise ValueError('invalid SHA256')
    _identity(run_id)
    if type(path) is not dict:
        raise ValueError('invalid path')
    path_id = _identity(path.get('path_id'))
    path_hash = hashlib.sha256(_json(path).encode()).hexdigest()
    declarations = path.get('assertions')
    if type(declarations) is not list or not declarations:
        raise ValueError('no admitted assertions')
    expected = []
    for declaration in declarations:
        if type(declaration) is not dict:
            raise ValueError('invalid assertion declaration')
        eid = declaration.get('expectation_id')
        if type(eid) is not str or eid not in KINDS or eid in expected:
            raise ValueError('unknown or duplicate expectation')
        expected.append(eid)
    identity = dict(compiled_document_sha256=compiled_document_sha256,
                    binding_sha256=binding_sha256, path_sha256=path_hash, run_id=run_id)
    if type(cases) is not list:
        raise ValueError('invalid cases')
    rows, seen = [], set()
    for case in cases:
        _keys(case, ('case_id', 'observations', 'evidence_inventory'))
        cid = _identity(case['case_id'])
        if cid in seen: raise ValueError('duplicate case')
        seen.add(cid)
        observations, inventory = case['observations'], case['evidence_inventory']
        if type(observations) is not dict or set(observations)-set(expected):
            raise ValueError('unknown observation')
        if type(inventory) is not dict: raise ValueError('invalid inventory')
        _json(inventory)
        for ref, evidence in inventory.items():
            _identity(ref)
            _keys(evidence, ('kind', 'outcome', 'scope', 'details'))
            eid = evidence['kind']
            if type(eid) is not str or eid not in expected:
                raise ValueError('invalid evidence kind')
            if type(evidence['outcome']) is not str or evidence['outcome'] not in STATUSES:
                raise ValueError('invalid evidence outcome')
            scope = dict(identity, case_id=cid, expectation_id=eid)
            if _json(evidence['scope']) != _json(scope): raise ValueError('evidence scope mismatch')
            if type(evidence['details']) is not dict: raise ValueError('invalid evidence details')
        assertions = []
        for eid in expected:
            available = [r for r,e in inventory.items() if e['kind']==eid]
            contradictions = [r for r in available if inventory[r]['outcome']=='failed']
            observation = observations.get(eid)
            if observation is None:
                status = 'failed' if contradictions else 'missing'
                reason = 'observed contradictory evidence' if contradictions else 'observation unavailable'
                refs = contradictions
            else:
                _keys(observation, ('status', 'reason', 'evidence_refs'))
                status, reason, refs = (observation[k] for k in ('status','reason','evidence_refs'))
                if type(status) is not str or status not in STATUSES: raise ValueError('invalid status')
                _identity(reason)
                if type(refs) is not list or any(type(r) is not str for r in refs) or len(set(refs))!=len(refs):
                    raise ValueError('invalid evidence references')
                if any(r not in available for r in refs): raise ValueError('unscoped evidence reference')
                if status=='passed' and (not refs or contradictions or any(inventory[r]['outcome']!='passed' for r in refs) or any(inventory[r]['outcome']=='missing' for r in available)):
                    raise ValueError('unsupported passed claim')
                if status=='failed' and (not contradictions or not set(contradictions).issubset(refs)):
                    raise ValueError('unsupported failed claim')
                if status=='missing' and contradictions: raise ValueError('hidden contradiction')
            assertions.append(dict(expectation_id=eid,status=status,reason=reason,evidence_refs=list(refs)))
        rows.append(dict(case_id=cid, assertions=assertions, evidence_inventory=json.loads(_json(inventory))))
    return dict(schema=SCHEMA, **identity, path_id=path_id, cases=rows)


def validate_assertion_results(document, *, compiled_document_sha256, binding_sha256, path, run_id, cases):
    expected = build_assertion_results(compiled_document_sha256=compiled_document_sha256,
        binding_sha256=binding_sha256,path=path,run_id=run_id,cases=cases)
    if _json(document) != _json(expected):
        raise ValueError('assertion results differ from rebuilt inventory')
