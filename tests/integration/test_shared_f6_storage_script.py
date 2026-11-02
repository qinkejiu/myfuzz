"""A failed fresh execution must retain the completed original and stage."""
import json
from types import SimpleNamespace
import pytest
from scripts import run_shared_f6_storage as script


def test_prefix_is_written_before_fresh_can_fail(tmp_path):
    prefix = dict(status='complete', records=[dict(raw8_hex='0000000000000000')])
    def replay(value, *, audit_sink):
        assert json.loads((tmp_path/'prefix.json').read_text()) == prefix
        audit_sink(dict(matches=False, actual_prefix=dict(status='complete'),
            error='synthetic fresh failure'))
        raise ValueError('synthetic fresh failure')
    runtime = SimpleNamespace(begin=lambda: None, submit=lambda raw: None,
        finish=lambda: prefix, replay=replay, storage_support_raw={})
    phases = []
    with pytest.raises(ValueError, match='synthetic fresh failure'):
        script.execute_original_fresh(runtime, ['0000000000000000'], tmp_path,
            lambda phase, **fields: phases.append(phase))
    assert phases[-1] == 'fresh_replay'
    assert (tmp_path/'prefix.json').is_file()
    assert (tmp_path/'storage_support_raw.json').is_file()
    failed_replay = json.loads((tmp_path/'replay.json').read_text())
    assert failed_replay['matches'] is False
    assert failed_replay['actual_prefix']['status'] == 'complete'


def test_exception_preserves_stage_and_reason(tmp_path, monkeypatch):
    def fail(args, state, checkpoint):
        checkpoint('original_submit')
        raise ValueError('synthetic native receipt mismatch')
    monkeypatch.setattr(script, 'run', fail)
    with pytest.raises(ValueError, match='synthetic native receipt mismatch'):
        script.main(['--output', str(tmp_path)])
    summary = json.loads((tmp_path/'summary.json').read_text())
    assert summary['status'] == 'failed'
    assert summary['failed_stage'] == 'original_submit'
    assert summary['error']['message'] == 'synthetic native receipt mismatch'
    assert 'synthetic native receipt mismatch' in (tmp_path/'failure.txt').read_text()


def test_failure_diagnostic_keeps_first_protocol_failure_and_bounded_tail():
    events = [dict(event_id=index) for index in range(1, 101)]
    runner = SimpleNamespace(failure_status='protocol_violation', _status='failed',
        local_ticks=dict(cpu=44, dma=43, peripheral=1), event_count=100,
        events_since=lambda index: events[index:])
    diagnostic = script.failure_diagnostic(SimpleNamespace(runner=runner))
    assert diagnostic['failure_status'] == 'protocol_violation'
    assert diagnostic['local_ticks']['peripheral'] == 1
    assert len(diagnostic['events']) == 40
    assert diagnostic['events'][0]['event_id'] == 61


def test_cache_option_is_explicit_and_default_remains_output_cache(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(script, 'run', lambda args, state, checkpoint: seen.append(args.cache))
    script.main(['--output', str(tmp_path), '--cache', str(tmp_path/'shared-cache')])
    assert seen == [tmp_path/'shared-cache']
