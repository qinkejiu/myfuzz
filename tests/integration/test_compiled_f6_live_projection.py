"""Live-to-saved F6 projection preserves raw facts and failure outcomes."""

from copy import deepcopy

import pytest

from tests.integration.test_compiled_f6_saved_semantics import (
    archive, word_transfer_archive, word_projector,
)


def test_saved_word_projector_accepts_live_tuple_snapshot_at_json_boundary(
        word_transfer_archive):
    from myfuzz.integration.compiled_f6_consumer import _saved_projection_inputs

    source = deepcopy(word_transfer_archive)
    affected = [row for row in source['events']
                if row.get('kind') == 'instr_response' and row.get('snapshot')]
    assert affected
    for row in affected:
        row['snapshot']['writer_kinds'] = tuple(row['snapshot']['writer_kinds'])
        for observer in source['local_by_id'].values():
            if observer.get('runner_event_id') == row['event_id']:
                observer['snapshot']['writer_kinds'] = tuple(observer['snapshot']['writer_kinds'])
    assert word_projector()(**source)['outcome'] == 'failed'
    events, local = _saved_projection_inputs(source['events'], source['local_by_id'])
    result = word_projector()(**dict(source, events=events, local_by_id=local))
    assert result['outcome'] == 'passed'
    assert all(type(row['snapshot']['writer_kinds']) is tuple for row in affected)


@pytest.mark.parametrize('prior', ['failed', 'missing'])
def test_live_fetch_close_never_upgrades_existing_projection_failure(monkeypatch, prior):
    from myfuzz.integration import compiled_f6_consumer as consumer
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime

    runtime = object.__new__(CompiledF6Runtime)
    monkeypatch.setattr(consumer, '_f6_live_fetch_evidence', lambda *args: {
        'outcome': 'passed', 'evidence': [], 'runner_event_ids': [],
        'raw_references': [], 'raw_evidence': [], 'issues': []})
    projection = {'outcome': prior, 'details': {
        'edges': [{'outcome': 'passed', 'evidence': [], 'runner_event_ids': [],
                   'issues': []} for _ in range(4)],
        'issues': [{'outcome': prior, 'reason': 'independent evidence'}],
        'raw_references': [], 'raw_evidence': []}}
    result = consumer._close_live_f6_fetch_projection(runtime, {}, [], {}, projection)
    assert result['outcome'] == prior
