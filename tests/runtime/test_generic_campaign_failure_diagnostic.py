import json
from types import SimpleNamespace

from myfuzz.runtime.generic_campaign import _write_runtime_failure


def test_failure_report_keeps_actual_runner_status_and_recent_events(tmp_path):
    events = [{'event_id': i, 'kind': 'tick'} for i in range(60)]
    events[-2] = {'event_id': 58, 'kind': 'harness_failure', 'error_type': 'ValueError'}
    runner = SimpleNamespace(failure_status='uncertain_effect', _status='failed',
        local_ticks={'cpu': 7}, event_count=len(events),
        events_since=lambda start: tuple(events[start:]))
    runtime = SimpleNamespace(runner=runner, session=SimpleNamespace(
        _terminal_failure={'phase': 'step', 'case_index': 0}))
    _write_runtime_failure(tmp_path, RuntimeError('scenario is not running'), runtime)
    doc = json.loads((tmp_path / 'failure.json').read_text())
    assert doc['failure_status'] == 'uncertain_effect'
    assert doc['runner_status'] == 'failed'
    assert doc['terminal_failure']['phase'] == 'step'
    assert len(doc['events']) == 40 and doc['events'][-2]['kind'] == 'harness_failure'
    assert doc['error'] == 'scenario is not running'
