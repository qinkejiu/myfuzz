"""Versioned evidence records classify claims; they do not grant witnesses."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json

import pytest

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.dependency_evidence import DependencyEvidence, DependencyEvidenceLedger
from myfuzz.scenario.runtime_path_contract import (
    PreparedRuntimePathContract, RuntimeEdgeContract, RuntimeNode, RuntimePathContract)


def record(kind='candidate', *, declaration_ref=None, **changes):
    values = dict(evidence_type=kind, relation='direct_binding',
                  source='a.out', target='b.pin', scope='event_correlation',
                  evidence_refs=('event:1', 'event:2'),
                  rule_id='observed-value', rule_version='1',
                  epochs=(('a', 0), ('b', 0)), declaration_ref=declaration_ref)
    if kind == 'declared':
        values.update(scope='declared_topology', evidence_refs=('contract:' + 'a' * 64,), epochs=())
    if kind == 'verified':
        values.update(scope='binding_delivery_sample', evidence_refs=('event:1', 'event:2', 'event:3'),
                      rule_id='exact-binding-sample')
    values.update(changes)
    return DependencyEvidence(**values)


def test_types_are_separate_records_and_schema_does_not_prove_execution():
    ledger = DependencyEvidenceLedger()
    declaration = record('declared')
    candidate = record(declaration_ref=declaration.evidence_id)
    verified = record('verified', declaration_ref=declaration.evidence_id)
    for row in (declaration, candidate, verified):
        assert ledger.append(row) is True
        assert ledger.append(row) is False
    doc = ledger.document()
    assert doc['record_counts'] == {'declared': 1, 'candidate': 1, 'verified': 1}
    assert doc['records']['declared'] == [declaration.document()]
    assert doc['records']['candidate'] == [candidate.document()]
    assert doc['records']['verified'] == [verified.document()]
    assert doc['proof_scope'] == 'classified_records_only'
    assert declaration.evidence_id != candidate.evidence_id != verified.evidence_id
    assert not hasattr(ledger, 'satisfies_prerequisite')
    with pytest.raises(FrozenInstanceError):
        candidate.evidence_type = 'verified'


def test_detached_json_storage_round_trip_and_order(tmp_path):
    ledger = DependencyEvidenceLedger(max_records_per_type=3)
    for kind in ('declared', 'candidate', 'verified'):
        ledger.append(record(kind))
    before = ledger.document()
    path = tmp_path / 'evidence.json'
    ledger.save(path)
    restored = DependencyEvidenceLedger.load(path)
    assert restored.document() == before == json.loads(path.read_text())
    doc = ledger.document()
    doc['records']['candidate'][0]['evidence_refs'].append('event:forged')
    doc['record_counts']['verified'] = 99
    assert ledger.document() == before


@pytest.mark.parametrize('change', (
    {'evidence_type': 'certified'}, {'relation': 'magic'}, {'scope': 'functional_consumption'},
    {'epochs': (('a', True),)}, {'epochs': (('a', 0), ('a', 1))},
    {'evidence_refs': ()}, {'evidence_refs': ('event:1', 'event:1')},
    {'rule_version': ''}, {'source': ' a'}, {'target': ''},
    {'declaration_ref': 'not-a-digest'}, {'validity': 'invalidated'},
))
def test_bad_or_inflated_claim_is_rejected(change):
    with pytest.raises(ValueError):
        record(**change)


def test_verified_requires_proof_scope_references_and_local_epochs():
    for change in ({'scope': 'event_correlation'}, {'evidence_refs': ('event:1',)},
                   {'epochs': ()}, {'scope': 'declared_topology'}):
        with pytest.raises(ValueError):
            record('verified', **change)


def test_history_validity_does_not_change_evidence_type():
    verified = record('verified')
    stale = replace(verified, validity='invalidated', invalidation_reason='reset')
    assert stale.evidence_type == 'verified'
    assert stale.evidence_id != verified.evidence_id
    assert stale.document()['validity'] == 'invalidated'
    with pytest.raises(ValueError):
        record('candidate', invalidation_reason='reset')


@pytest.mark.parametrize('fault', ('missing', 'endpoint', 'relation'))
def test_runtime_record_link_must_resolve_exact_declared_relation(fault):
    ledger = DependencyEvidenceLedger()
    declaration = record('declared')
    ledger.append(declaration)
    changes = {'declaration_ref': declaration.evidence_id}
    if fault == 'missing':
        changes['declaration_ref'] = '0' * 64
    elif fault == 'endpoint':
        changes['target'] = 'other.pin'
    else:
        changes['relation'] = 'causal_order'
    with pytest.raises(ValueError, match='declaration-mismatch'):
        ledger.append(record(**changes))


def test_linked_storage_round_trip_and_caller_cannot_mutate_appended_record(tmp_path):
    ledger = DependencyEvidenceLedger()
    declaration = record('declared')
    ledger.append(declaration)
    candidate = record(declaration_ref=declaration.evidence_id)
    ledger.append(candidate)
    before = ledger.document()
    object.__setattr__(candidate, 'source', 'forged')
    assert ledger.document() == before
    path = tmp_path / 'linked.json'
    ledger.save(path)
    assert DependencyEvidenceLedger.load(path).document() == before


@pytest.mark.parametrize('fault', ('type', 'hash', 'unknown', 'counts', 'group'))
def test_stored_category_and_identity_tampering_is_rejected(fault):
    ledger = DependencyEvidenceLedger()
    ledger.append(record())
    doc = ledger.document()
    if fault == 'type':
        doc['records']['candidate'][0]['evidence_type'] = 'verified'
    elif fault == 'hash':
        doc['records']['candidate'][0]['evidence_id'] = '0' * 64
    elif fault == 'unknown':
        doc['records']['candidate'][0]['script'] = 'grant_verified()'
    elif fault == 'counts':
        doc['record_counts']['verified'] = 1
    else:
        doc['records']['verified'] = doc['records']['candidate']
        doc['records']['candidate'] = []
    with pytest.raises(ValueError):
        DependencyEvidenceLedger.from_document(doc)


def test_records_and_details_are_bounded_without_silent_eviction():
    ledger = DependencyEvidenceLedger(max_records_per_type=1)
    ledger.append(record())
    with pytest.raises(ValueError, match='capacity'):
        ledger.append(record(rule_id='another-rule'))
    assert ledger.document()['record_counts']['candidate'] == 1
    with pytest.raises(ValueError):
        record(evidence_refs=tuple(f'event:{i}' for i in range(65)))
    with pytest.raises(ValueError):
        record(source='a' * 1025)
    for value in (0, True, 65537):
        with pytest.raises(ValueError):
            DependencyEvidenceLedger(max_records_per_type=value)


def test_runtime_contract_stays_topology_and_yields_only_declarations():
    graph = DependencyGraph(
        sources=(FuzzableSource('source', 'a', 'pin', 0, 1, ('IP_TO_IP',)),),
        rules=(DependencyRule('output', ('source',), 'EVENT_ORDER'),
               DependencyRule('consume', ('output',), 'DATA_BINDING')))
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
                                       separators=(',', ':')).encode()).hexdigest()
    contract = RuntimePathContract(digest, (
        RuntimeNode('source', 'a', 'physical', 'pin', 0, 1),
        RuntimeNode('output', 'a', 'physical', 'out', 0, 1),
        RuntimeNode('consume', 'b', 'physical', 'pin', 0, 1)),
        (RuntimeEdgeContract(1, 0, 'direct_binding'),))
    paths = tuple(('IP_TO_IP', p) for p in graph.edge_paths_to('consume', direction='IP_TO_IP'))
    prepared = PreparedRuntimePathContract(graph, contract, paths)
    before = deepcopy(prepared.document())
    ledger = DependencyEvidenceLedger.from_prepared_contract(prepared)
    doc = ledger.document()
    assert doc['record_counts'] == {'declared': 1, 'candidate': 0, 'verified': 0}
    row = doc['records']['declared'][0]
    assert row['source'] == 'output' and row['target'] == 'consume'
    assert row['relation'] == 'direct_binding'
    assert row['epochs'] == {} and row['declaration_ref'] is None
    assert prepared.document() == before and contract.identity_sha256 in row['evidence_refs'][0]
