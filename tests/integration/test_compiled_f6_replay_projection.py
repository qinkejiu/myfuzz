"""F6 replay normalizes only owned process identities, never transaction facts."""

from copy import deepcopy
from hashlib import sha256
import json

import pytest

from myfuzz.integration.compiled_f6 import _first_difference, _normalized_f6_prefix
from myfuzz.scenario.ledger import TransactionKey


def _prefix(nonce, **key_changes):
    key = dict(execution_id=nonce, testcase_id='run:native', source_component='dma',
               source_epoch=0, channel_id='dma-memory', source_sequence=1)
    key.update(key_changes)
    return {'original_execution_audit': {'identities': {
        'dma': {'component': 'dma', 'role': 'bound_target', 'execution_nonce': nonce}}},
        'actual_events': [{'kind': 'state_dependency', 'source': 'writer',
            'target': str(TransactionKey(**key)), 'version': [0, 4]}]}


def _difference(left, right):
    return _first_difference(_normalized_f6_prefix(left), _normalized_f6_prefix(right))


def test_owned_transaction_repr_normalizes_only_execution_identity():
    original = _prefix('a' * 32)
    fresh = _prefix('b' * 32)
    before = deepcopy((original, fresh))
    assert _difference(original, fresh) is None
    assert (original, fresh) == before


@pytest.mark.parametrize('field,value', [
    ('testcase_id', 'run:other'), ('source_component', 'cpu'),
    ('source_epoch', 1), ('channel_id', 'data'), ('source_sequence', 2),
    ('execution_id', 'unowned-execution'),
])
def test_transaction_fields_or_unowned_execution_cannot_be_normalized(field, value):
    original = _prefix('a' * 32)
    fresh = _prefix('b' * 32, **{field: value})
    assert _difference(original, fresh) is not None


def test_transaction_version_and_non_transaction_text_remain_strict():
    original = _prefix('a' * 32)
    fresh = _prefix('b' * 32)
    fresh['actual_events'][0]['version'] = [0, 5]
    assert _difference(original, fresh) is not None
    fresh['actual_events'][0]['version'] = [0, 4]
    original['note'] = 'literal ' + 'a' * 32
    fresh['note'] = 'literal ' + 'b' * 32
    assert _difference(original, fresh) is not None


@pytest.mark.parametrize('audit_change', ['wrong-owner', 'duplicate-nonce'])
def test_unowned_or_ambiguous_nonce_cannot_normalize_transaction(audit_change):
    original = _prefix('a' * 32)
    fresh = _prefix('b' * 32)
    identities = fresh['original_execution_audit']['identities']
    if audit_change == 'wrong-owner':
        identities['dma']['component'] = 'cpu'
    else:
        identities['cpu'] = {'component': 'cpu', 'role': 'cpu',
                             'execution_nonce': 'b' * 32}
    assert _difference(original, fresh) is not None


def _with_commit(nonce):
    prefix = _prefix(nonce)
    key = dict(execution_id=nonce, testcase_id='run:native', source_component='dma',
               source_epoch=0, channel_id='dma-memory', source_sequence=5)
    commit = {'schema_version': 'memory_write_commit_receipt.v1', 'fullkey': key,
        'version': [0, 8], 'enabled_byte_cells': [{
            'value': 7, 'writer_event_id': str(TransactionKey(**key))}]}
    encoded = json.dumps(commit, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    commit['commit_id'] = sha256(encoded).hexdigest()
    prefix['commit_document'] = commit
    prefix['destination_commit_id'] = commit['commit_id']
    return prefix


def test_commit_digest_and_references_are_recomputed_after_owned_normalization():
    assert _difference(_with_commit('a' * 32), _with_commit('b' * 32)) is None


def test_target_access_ids_normalize_without_mutating_input():
    prefix = _with_commit('a' * 32)
    prefix['actual_events'][0]['target_access_id'] = 'apb-storage:ephemeral:12'
    # Values beneath a non-string target_access_id were not projected by the
    # original process-local pass; their nested keys must remain unchanged.
    prefix['nested'] = {'target_access_id': {'target_access_id': 'apb-storage:keep:7'}}
    before = deepcopy(prefix)
    result = _normalized_f6_prefix(prefix)
    assert result['actual_events'][0]['target_access_id'] == 'apb-storage:<compiled-f4-process-execution>:12'
    assert result['nested']['target_access_id']['target_access_id'] == 'apb-storage:keep:7'
    assert prefix == before


def test_replay_projection_does_not_copy_the_entire_prefix_twice(monkeypatch):
    from myfuzz.integration import compiled_f4
    prefix = _with_commit('a' * 32)
    original = compiled_f4._project_process_local
    def reject_prefix_copy(value):
        assert value is not prefix, 'whole prefix was copied before normalization'
        return original(value)
    monkeypatch.setattr(compiled_f4, '_project_process_local', reject_prefix_copy)
    assert _normalized_f6_prefix(prefix)['commit_document']['version'] == [0, 8]


def test_commit_authentication_retains_process_local_projection():
    from myfuzz.integration.compiled_f4 import _project_process_local
    prefix = _with_commit('a' * 32)
    commit = prefix['commit_document']
    commit['target_access_id'] = 'apb-storage:ephemeral:12'
    body = _project_process_local({k: v for k, v in commit.items() if k != 'commit_id'})
    commit['commit_id'] = sha256(json.dumps(body, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    prefix['destination_commit_id'] = commit['commit_id']
    assert _normalized_f6_prefix(prefix)['commit_document']['target_access_id'] == (
        'apb-storage:<compiled-f4-process-execution>:12')
    commit['target_access_id'] = 'apb-storage:ephemeral:13'
    with pytest.raises(ValueError, match='commit-digest-invalid'):
        _normalized_f6_prefix(prefix)


@pytest.mark.parametrize('change', ['bad-digest', 'missing-reference', 'changed-value',
                                   'wrong-owner'])
def test_bad_or_different_commit_facts_do_not_compare_equal(change):
    original = _with_commit('a' * 32)
    fresh = _with_commit('b' * 32)
    if change == 'bad-digest':
        fresh['commit_document']['version'] = [0, 9]
    elif change == 'missing-reference':
        fresh['destination_commit_id'] = 'f' * 64
    else:
        commit = fresh['commit_document']
        if change == 'wrong-owner':
            commit['fullkey']['source_component'] = 'cpu'
        else:
            commit['enabled_byte_cells'][0]['value'] = 8
        body = {key: value for key, value in commit.items() if key != 'commit_id'}
        commit['commit_id'] = sha256(json.dumps(body, sort_keys=True,
            separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        fresh['destination_commit_id'] = commit['commit_id']
    try:
        difference = _difference(original, fresh)
    except ValueError:
        return
    assert difference is not None


def test_reset_history_normalizes_only_owned_epoch_nonces():
    first, second, other_first, other_second = ('a'*32, 'b'*32, 'c'*32, 'd'*32)
    left={'actual_events':[{'f6_obi_scope':[first,1,0,1]}, {'f6_obi_scope':[second,1,1,2]}]}
    right={'actual_events':[{'f6_obi_scope':[other_first,1,0,1]}, {'f6_obi_scope':[other_second,1,1,2]}]}
    histories=({'cpu':(first,second)}, {'cpu':(other_first,other_second)})
    assert _normalized_f6_prefix(left,execution_history=histories[0]) == _normalized_f6_prefix(right,execution_history=histories[1])
    right['actual_events'][0]['f6_obi_scope'][0]='f'*32
    assert _normalized_f6_prefix(left,execution_history=histories[0]) != _normalized_f6_prefix(right,execution_history=histories[1])


def test_reset_history_requires_real_distinct_audited_launches():
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6 import _f6_replay_execution_history
    fields=dict(artifact_digest='a',build_digest='b',binary_sha256='c',
        built_receipt_sha256='d',observed_executable_sha256='c',ready_artifact_digest='a')
    def row(pid,nonce):return dict(fields,pid=pid,execution_nonce=nonce,
        failure_stage=None,returncode=0,reaped=True)
    launches=[row(1,'a'*32),row(2,'b'*32)]
    session=SimpleNamespace(reset_epoch=1,built_executable_launch_observations=lambda:launches)
    runtime=SimpleNamespace(_build_sessions={'cpu':session})
    prefix={'original_execution_audit':{'identities':{'cpu':dict(launches[-1],component='cpu')}},
            'online_plan':{'reset_operations':[{}]}}
    assert _f6_replay_execution_history(runtime,prefix)=={'cpu':('a'*32,'b'*32)}
    launches[0]['execution_nonce']=launches[1]['execution_nonce']
    with pytest.raises(ValueError,match='epoch-history-unverified'):
        _f6_replay_execution_history(runtime,prefix)
    launches[0]['execution_nonce']='a'*32
    launches[0]['observed_executable_sha256']='forged'
    with pytest.raises(ValueError,match='epoch-history-unverified'):
        _f6_replay_execution_history(runtime,prefix)
