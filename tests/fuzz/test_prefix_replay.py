"""Pure-Python tests for the saved prefix/replay contract (Task 5).

No RTL: the tests cover the comparable observation projection, the streaming
recorders and the replay comparison.  The real replay run is separate evidence.
"""
import io
import json

import pytest

from myfuzz.fuzz.strategy import Input
from scripts.run_inprocess_f1f6 import (_ObservationRecorder, _PrefixRecorder,
                                       _RecordingStrategy, compare_replay,
                                       main, replay_view)

CASE = dict(flow='F5', status='observations_passed', record='F5:1:2:3',
            ticks=42, seconds=0.001, trigger_writes=3, irq_edges=1, irq_takes=1,
            isr_flag=1, isr_result=7, apb_read_data=7, apb_read_offset=0,
            isr_read_register_kind='status', wait_timeout=0)


def test_the_replay_view_keeps_key_observations_and_drops_wall_clock():
    view = replay_view(CASE)
    assert view['flow'] == 'F5' and view['record'] == 'F5:1:2:3'
    assert view['irq_edges'] == 1 and view['isr_result'] == 7
    assert view['trigger_writes'] == 3
    assert 'ticks' not in view and 'seconds' not in view


def test_an_identical_replay_matches():
    observed = [replay_view(CASE), replay_view(dict(CASE, record='F5:1:2:4'))]
    expected = [replay_view(CASE), replay_view(dict(CASE, record='F5:1:2:4'))]
    assert compare_replay(expected, observed) is None


def test_a_different_key_observation_is_named():
    observed = [replay_view(dict(CASE, isr_result=8))]
    message = compare_replay([replay_view(CASE)], observed)
    assert 'case 0 isr_result differs' in message
    assert 'saved 7' in message and 'replay 8' in message


def test_a_different_record_is_named():
    message = compare_replay([replay_view(CASE)],
                             [replay_view(dict(CASE, record='F5:9'))])
    assert 'record differs' in message


def test_a_short_replay_is_reported():
    message = compare_replay([replay_view(CASE), replay_view(CASE)],
                             [replay_view(CASE)])
    assert 'replay stopped after 1 of 2' in message


def test_an_unsupported_flow_is_refused():
    with pytest.raises(ValueError, match='unsupported replay flow'):
        replay_view({'flow': 'F9', 'status': 'failed'})


def test_the_prefix_recorder_streams_one_line_per_input(tmp_path):
    path = tmp_path / 'prefix.txt'
    with path.open('w') as handle:
        recorder = _PrefixRecorder(handle)
        recorder.write(Input('F1', (1,), 'F1:00000001', 'CASE F1 00000001'))
        recorder.write(Input('F2', (2,), 'F2:00000002', 'CASE F2 00000002'))
        recorder.close()
    assert path.read_text().splitlines() == ['F1:00000001', 'F2:00000002']


def test_the_observation_recorder_writes_json_lines(tmp_path):
    path = tmp_path / 'observations.jsonl'
    with path.open('w') as handle:
        recorder = _ObservationRecorder(handle)
        recorder.write(CASE)
        recorder.write(dict(CASE, irq_edges=0))
        recorder.close()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0]['irq_edges'] == 1 and rows[1]['irq_edges'] == 0


class Stub:
    flows = ('F1',)

    def __init__(self):
        self.count = 0

    def seed_inputs(self):
        return [Input('F1', (1,), 'F1:00000001', 'CASE F1 00000001')]

    def next_input(self):
        self.count += 1
        text = 'F1:%08x' % (self.count + 1)
        return Input('F1', (self.count + 1,), text, 'CASE F1 %08x' % (self.count + 1))


def test_the_recording_strategy_delegates_and_keeps_order(tmp_path):
    path = tmp_path / 'prefix.txt'
    with path.open('w') as handle:
        recorder = _PrefixRecorder(handle)
        strategy = _RecordingStrategy(Stub(), recorder)
        assert strategy.flows == ('F1',)
        seeds = strategy.seed_inputs()
        first = strategy.next_input()
        second = strategy.next_input()
        recorder.close()
    assert [row.text for row in seeds] == ['F1:00000001']
    assert [first.text, second.text] == ['F1:00000002', 'F1:00000003']
    assert path.read_text().splitlines() == ['F1:00000001', 'F1:00000002',
                                             'F1:00000003']


def test_replay_requires_its_observations_before_touching_the_config(tmp_path):
    with pytest.raises(SystemExit):
        main(['--config', str(tmp_path / 'missing.json'),
              '--cache', str(tmp_path / 'cache'), '--output', str(tmp_path / 'out'),
              '--replay-prefix', str(tmp_path / 'prefix.txt')])


def test_replay_and_records_are_alternatives(tmp_path):
    prefix = tmp_path / 'prefix.txt'
    prefix.write_text('F1:00000001\n')
    observations = tmp_path / 'observations.jsonl'
    observations.write_text('{}\n')
    with pytest.raises(SystemExit):
        main(['--config', str(tmp_path / 'missing.json'),
              '--cache', str(tmp_path / 'cache'), '--output', str(tmp_path / 'out'),
              '--records', 'F1:00000001',
              '--replay-prefix', str(prefix),
              '--replay-observations', str(observations)])
