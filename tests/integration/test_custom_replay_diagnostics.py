from types import SimpleNamespace
from copy import deepcopy

from myfuzz.integration.compiled_f6 import CompiledF6Runtime
from myfuzz.scenario import session_runtime


def test_custom_replay_publishes_both_events_and_difference_context(monkeypatch):
    expected = {'kind': 'dma_transfer', 'value': 1}
    actual = {'kind': 'dma_transfer', 'value': 2}
    comparison = SimpleNamespace(matches=False, first_difference=42,
        expected_event=expected, actual_event=actual,
        difference_context={'event_index': 42, 'expected': expected, 'actual': actual},
        differences=({'event_index': 42, 'expected': expected, 'actual': actual},))
    received = {}
    def replay(*args, **kwargs):
        received.update(kwargs)
        return comparison
    monkeypatch.setattr(session_runtime, 'replay_online_session', replay)
    prefix = {'status': 'observed'}
    runtime = SimpleNamespace(_custom_online=True, finish=lambda: prefix, dma_id='dma',
        dma=SimpleNamespace(_execution='a'*32),
        _custom_plan=b'plan', _custom_trace=object(), _custom_plan_identity='identity')
    published = []
    result = CompiledF6Runtime.replay(runtime, prefix, audit_sink=published.append)
    assert result['matches'] is False
    assert result['first_difference'] == 42
    assert result['expected_event'] == expected
    assert result['actual_event'] == actual
    assert result['difference_context'] == comparison.difference_context
    assert result['differences'] == list(comparison.differences)
    assert published == [result]
    assert result['certificate'] == 'not_granted'
    assert received['dma_reference_execution'] == ('dma', 'a'*32)
    assert received['max_differences'] == 16


def test_replay_differences_are_bounded_and_keep_raw_events():
    from myfuzz.scenario.session_runtime import _collect_replay_event_differences
    left = [{'kind': 'sample', 'value': index} for index in range(20)]
    right = [{'kind': 'sample', 'value': index + 1} for index in range(20)]
    before = deepcopy((left, right))
    differences = _collect_replay_event_differences(left, right, max_differences=16)
    assert len(differences) == 16
    assert [item['event_index'] for item in differences] == list(range(16))
    assert differences[0]['expected'] == left[0]
    assert differences[0]['actual'] == right[0]
    assert (left, right) == before
    assert _collect_replay_event_differences(left, left, max_differences=16) == []


def test_later_diagnostic_error_preserves_first_mismatch(monkeypatch):
    def normalize(event, execution, *args, **kwargs):
        if event['value'] == 2:
            raise ValueError('later-invalid-commit')
        return event
    monkeypatch.setattr(session_runtime, '_normalize_dma_replay_event', normalize)
    result = session_runtime._collect_replay_event_differences(
        [{'value': 0}, {'value': 2}], [{'value': 1}, {'value': 2}],
        max_differences=16, dma_ids=('a'*32, 'b'*32, 'dma'))
    assert result[0]['event_index'] == 0
    assert result[1]['diagnostic_error'] == 'later-invalid-commit'


def test_dma_replay_identity_preserves_real_memory_data_and_other_ids():
    from myfuzz.scenario.session_runtime import _normalize_dma_replay_event
    reference = {'kind': 'memory_read', 'component': 'dma', 'value': 1,
        'transaction': {'execution_id': 'a'*32, 'source_component': 'dma', 'source_sequence': 1},
        'provenance': {'resource': {'transaction': {'execution_id': 'a'*32,
            'source_component': 'dma', 'source_sequence': 1}}}}
    actual = deepcopy(reference)
    actual['transaction']['execution_id'] = 'b'*32
    actual['provenance']['resource']['transaction']['execution_id'] = 'b'*32
    left = _normalize_dma_replay_event(reference, 'a'*32)
    right = _normalize_dma_replay_event(actual, 'b'*32)
    assert left == right
    actual['value'] = 2
    assert left != _normalize_dma_replay_event(actual, 'b'*32)
    actual['value'] = 1
    actual['transaction']['execution_id'] = 'c'*32
    assert left != _normalize_dma_replay_event(actual, 'b'*32)
    assert reference['transaction']['execution_id'] == 'a'*32


def test_dma_commit_digest_is_verified_before_normalizing_nonce():
    import hashlib
    import json
    import pytest
    from myfuzz.scenario.session_runtime import _normalize_dma_replay_event

    def event(execution, value):
        body = {'schema_version': 'memory_write_commit_receipt.v1',
            'fullkey': {'source_component': 'dma', 'execution_id': execution,
                        'source_epoch': 0, 'channel_id': 'dma-memory', 'source_sequence': 5},
            'enabled_byte_cells': [{'value': value,
                'writer_event_id': "TransactionKey(execution_id='%s', testcase_id='case')" % execution}]}
        digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':'),
                                           allow_nan=False).encode()).hexdigest()
        return {'kind': 'memory_write_commit', 'component': 'dma', 'commit_id': digest,
                'commit_document': {**body, 'commit_id': digest}}

    a, b = event('a'*32, 1), event('b'*32, 1)
    left_map, right_map = {}, {}
    left = _normalize_dma_replay_event(a, 'a'*32, left_map)
    assert left == _normalize_dma_replay_event(b, 'b'*32, right_map)
    assert _normalize_dma_replay_event({'destination_commit_id': a['commit_id']}, 'a'*32, left_map) == \
        _normalize_dma_replay_event({'destination_commit_id': b['commit_id']}, 'b'*32, right_map)
    assert left != _normalize_dma_replay_event(event('b'*32, 2), 'b'*32, {})
    corrupt = deepcopy(b)
    corrupt['commit_document']['enabled_byte_cells'][0]['value'] = 2
    with pytest.raises(ValueError, match='commit-digest-invalid'):
        _normalize_dma_replay_event(corrupt, 'b'*32, {})
    assert _normalize_dma_replay_event({'commit_id': 'unknown'}, 'a'*32, left_map)['commit_id'] == 'unknown'
    assert _normalize_dma_replay_event({'commit_id': 'unknown-a'}, 'a'*32, left_map) != \
        _normalize_dma_replay_event({'commit_id': 'unknown-b'}, 'b'*32, right_map)
    foreign = deepcopy(b)
    assert _normalize_dma_replay_event(foreign, 'b'*32, {}, component='other')['commit_id'] == b['commit_id']
