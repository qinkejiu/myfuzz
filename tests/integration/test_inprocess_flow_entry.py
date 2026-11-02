"""Unit tests for the thin F5/F6 dispatch entry; no RTL or Verilator is run.

The delegate is replaced by a tiny script so the tests cover log parsing, argv
mapping, the ``unknown`` rules and the failure-summary guarantee only.
"""
import json
from pathlib import Path

import pytest

from scripts import run_inprocess_flow as entry

#: Stand-in delegate: records argv, then optionally writes summary.json/run.log.
FAKE = '''\
import json, os, pathlib, sys
argv = sys.argv[1:]
out = pathlib.Path(argv[argv.index('--output') + 1])
pathlib.Path(os.environ['FAKE_ARGV']).write_text(json.dumps(argv))
if os.environ.get('FAKE_WRITE', '1') == '1':
    out.mkdir(parents=True, exist_ok=True)
    (out / 'summary.json').write_text(os.environ.get('FAKE_SUMMARY', '{}'))
    (out / 'run.log').write_text(os.environ.get('FAKE_LOG', ''))
raise SystemExit(int(os.environ.get('FAKE_RC', '0')))
'''

FIVE_LOG = (
    'NEED_RECORD 0 tick 0\n'
    'CASE_INSTALLED 0\n'
    'mmio 49 write 40001004 0\n'
    'case 0 observations_passed irq_sources 1 takes 1 result 0\n'
    '\n'
    '   \n'
    'case 1 observations_passed irq_sources 1 takes 1 result 31\n'
    'summary observations_passed cases 2 ticks 231 irqs 1 takes 1 writes 3 reads 1'
    ' result 31 apb_transfers 4 mret 1 successor 1 runtime_seconds 0.00785607\n'
)

FIVE_SUMMARY = {
    'status': 'observations_passed', 'returncode': 0, 'link_seconds': 0.5,
    'run_seconds': 0.2, 'total_seconds': 0.9,
    'submitted': [[0, 0, 0xffffffff], [1, 0, 0xfffffffe]],
}


@pytest.fixture
def fake(monkeypatch, tmp_path):
    """Point the entry at a throw-away delegate and return a setter for it."""
    script = tmp_path / 'fake_delegate.py'
    script.write_text(FAKE)
    monkeypatch.setattr(entry, 'ROOT', tmp_path)
    monkeypatch.setattr(entry, 'DELEGATES', {'F5': script.name, 'F6': script.name})
    monkeypatch.setenv('FAKE_ARGV', str(tmp_path / 'argv.json'))

    def arrange(**environment):
        for key, value in environment.items():
            if key in ('FAKE_SUMMARY', 'FAKE_LOG'):
                value = value if isinstance(value, str) else json.dumps(value)
            monkeypatch.setenv(key, str(value))
    return arrange


def _main(tmp_path, flow='F5', *extra):
    return entry.main(['--flow', flow, '--config', str(tmp_path / 'scenario.json'),
                       '--cache', str(tmp_path / 'cache'),
                       '--output', str(tmp_path / 'run'), *extra])


def _normalize(tmp_path, flow='F5', **overrides):
    arguments = dict(flow=flow, delegate='scripts/fake', returncode=0,
                     raw_summary={'status': 'observations_passed', 'link_seconds': 1.0,
                                  'run_seconds': 2.0, 'total_seconds': 3.0},
                     raw_summary_error=None, cases=[{'case': 0, 'status': 'observations_passed'}],
                     summary={'status': 'observations_passed', 'cases': 1, 'takes': 1},
                     config=tmp_path / 'scenario.json', output=tmp_path / 'run',
                     inputs=[[0, 0, 0xffffffff]], input_source='summary.json:submitted',
                     input_mode='online', entry_seconds=1.5)
    arguments.update(overrides)
    return entry.normalize(**arguments)


def test_parse_keeps_case_rows_summary_and_floats():
    cases, summary = entry.parse_run_log(FIVE_LOG)
    assert [row['case'] for row in cases] == [0, 1]
    assert [row['status'] for row in cases] == ['observations_passed'] * 2
    assert cases[1]['result'] == 31 and cases[0]['takes'] == 1
    assert summary['status'] == 'observations_passed'
    assert summary['cases'] == 2 and summary['ticks'] == 231
    assert summary['runtime_seconds'] == pytest.approx(0.00785607)


def test_parse_tolerates_missing_summary_blank_lines_and_odd_tokens():
    cases, summary = entry.parse_run_log('mmio 1 write a b\n\ncase 0 failed reads 4 odd\n')
    assert cases == [{'reads': 4, 'odd': None, 'case': 0, 'status': 'failed'}]
    assert summary is None
    assert entry.parse_run_log('') == ([], None)


def test_unknown_keeps_retirement_and_inputs_honest_for_f5():
    result = _normalize(Path('/tmp'))
    assert 'retirement' in result['unknown']
    assert 'irq_take' not in result['unknown']          # the summary prints takes
    assert 'per_case_observations' not in result['unknown']
    assert result['status'] == 'observations_passed'
    assert result['unknown_reasons']['retirement']


def test_unknown_drops_retirement_when_the_loop_observed_it():
    result = _normalize(Path('/tmp'), flow='F6',
                        summary={'status': 'observations_passed', 'cases': 1,
                                 'irq_takes': 1, 'irq_take_evidence': 'observed',
                                 'retirement_evidence': 'observed'})
    assert 'retirement' not in result['unknown'] and 'irq_take' not in result['unknown']


def test_unknown_reports_unobserved_irq_take_and_missing_case_rows():
    result = _normalize(Path('/tmp'), flow='F6', cases=[],
                        summary={'status': 'observations_passed', 'cases': 2,
                                 'irq_take_evidence': 'unknown',
                                 'retirement_evidence': 'unknown'})
    assert {'retirement', 'irq_take', 'per_case_observations'} <= set(result['unknown'])


def test_unknown_reports_missing_or_unreadable_delegate_summary():
    result = _normalize(Path('/tmp'), raw_summary=None, summary=None)
    assert {'delegate_summary', 'summary_line'} <= set(result['unknown'])
    result = _normalize(Path('/tmp'), raw_summary=None,
                        raw_summary_error='summary.json is unreadable: bad')
    assert result['unknown_reasons']['delegate_summary'].endswith('bad')
    result = _normalize(Path('/tmp'), inputs=[], input_source=None)
    assert 'case_inputs' in result['unknown']


def test_status_follows_the_real_exit_code_not_only_the_summary():
    failed = _normalize(Path('/tmp'), returncode=3)
    assert failed['status'] == 'failed' and failed['delegate']['returncode'] == 3
    unknown = _normalize(Path('/tmp'), raw_summary=None, summary=None)
    assert unknown['status'] == 'unknown'
    contradictory = _normalize(Path('/tmp'), summary={'status': 'failed', 'cases': 1, 'takes': 1})
    assert contradictory['status'] == 'failed'


def test_argv_maps_f5_online_and_preloaded():
    parser = entry._parser()
    common = dict(config=Path('/tmp/scenario.json'), cache=Path('/tmp/cache'),
                  output=Path('/tmp/run'))
    online = parser.parse_args(['--flow', 'F5', '--config', 'c', '--cache', 'x',
                                '--output', 'o', '--online', '--max-ticks', '77'])
    argv = entry._delegate_argv('F5', online, **common)
    assert argv[1].endswith('scripts/run_inprocess_irq.py')
    assert argv[-2:] == ['--max-ticks', '77'] or argv[-3:] == ['--max-ticks', '77', '--online']
    assert '--online' in argv and '--record' not in argv and '--records' not in argv
    preloaded = parser.parse_args(['--flow', 'F5', '--config', 'c', '--cache', 'x', '--output', 'o'])
    argv = entry._delegate_argv('F5', preloaded, **common)
    assert '--online' not in argv and argv[-2:] == ['--max-ticks', '3000']


def test_argv_maps_f6_online_records_record_and_lockstep():
    parser = entry._parser()
    common = dict(config=Path('/tmp/scenario.json'), cache=Path('/tmp/cache'),
                  output=Path('/tmp/run'))
    online = parser.parse_args(['--flow', 'F6', '--config', 'c', '--cache', 'x',
                                '--output', 'o', '--online', '--assume-lockstep'])
    argv = entry._delegate_argv('F6', online, **common)
    assert argv[1].endswith('scripts/run_inprocess_f6.py')
    assert '--online' in argv and '--assume-lockstep' in argv and '--max-ticks' not in argv
    records = parser.parse_args(['--flow', 'F6', '--config', 'c', '--cache', 'x',
                                 '--output', 'o', '--records', 'aa,bb'])
    argv = entry._delegate_argv('F6', records, **common)
    assert argv[-2:] == ['--records', 'aa,bb'] and '--online' not in argv
    record = parser.parse_args(['--flow', 'F6', '--config', 'c', '--cache', 'x',
                                '--output', 'o', '--record', '0110c00008000000'])
    argv = entry._delegate_argv('F6', record, **common)
    assert argv[-2:] == ['--record', '0110c00008000000'] and '--records' not in argv
    default = parser.parse_args(['--flow', 'F6', '--config', 'c', '--cache', 'x', '--output', 'o'])
    argv = entry._delegate_argv('F6', default, **common)
    assert '--online' not in argv and '--records' not in argv and '--record' not in argv


def test_argv_rejects_flags_of_the_other_flow():
    parser = entry._parser()
    common = dict(config=Path('/tmp/c'), cache=Path('/tmp/x'), output=Path('/tmp/o'))
    with pytest.raises(SystemExit, match='F6 only'):
        entry._delegate_argv('F5', parser.parse_args(
            ['--flow', 'F5', '--config', 'c', '--cache', 'x', '--output', 'o',
             '--record', 'aa']), **common)
    with pytest.raises(SystemExit, match='F6 only'):
        entry._delegate_argv('F5', parser.parse_args(
            ['--flow', 'F5', '--config', 'c', '--cache', 'x', '--output', 'o',
             '--assume-lockstep']), **common)
    with pytest.raises(SystemExit, match='F5 only'):
        entry._delegate_argv('F6', parser.parse_args(
            ['--flow', 'F6', '--config', 'c', '--cache', 'x', '--output', 'o',
             '--max-ticks', '5']), **common)
    with pytest.raises(SystemExit, match='cannot be combined'):
        entry._delegate_argv('F6', parser.parse_args(
            ['--flow', 'F6', '--config', 'c', '--cache', 'x', '--output', 'o',
             '--online', '--records', 'aa']), **common)


def test_main_dispatches_online_inputs_and_writes_flow_summary(fake, tmp_path):
    fake(FAKE_SUMMARY=FIVE_SUMMARY, FAKE_LOG=FIVE_LOG)
    assert _main(tmp_path, 'F5', '--online') == 0
    document = json.loads((tmp_path / 'run' / 'flow_summary.json').read_text())
    assert document['flow'] == 'F5' and document['path'] == 'F5'
    assert document['input_mode'] == 'online'
    assert document['input_source'] == 'summary.json:submitted'
    assert document['inputs'] == [[0, 0, 0xffffffff], [1, 0, 0xfffffffe]]
    assert document['observations']['case_count'] == 2
    assert [row['case'] for row in document['observations']['cases']] == [0, 1]
    assert document['status'] == 'observations_passed'
    assert document['timings']['link_seconds'] == 0.5
    assert document['timings']['run_seconds'] == 0.2
    assert document['timings']['total_seconds'] == 0.9
    assert document['delegate']['script'] == 'fake_delegate.py'
    assert document['config'] == str(tmp_path / 'scenario.json')
    argv = json.loads((tmp_path / 'argv.json').read_text())
    assert '--online' in argv and '--max-ticks' in argv and '--record' not in argv


def test_main_derives_f5_preloaded_inputs_from_the_config(fake, tmp_path):
    (tmp_path / 'scenario.json').write_text(json.dumps(
        {'trigger_writes': [[4, 0], [8, 0], [0, 0xffffffff]]}))
    fake(FAKE_SUMMARY={'status': 'observations_passed', 'returncode': 0},
         FAKE_LOG='summary observations_passed cases 1 ticks 10 runtime_seconds 0.01\n')
    assert _main(tmp_path, 'F5') == 0
    document = json.loads((tmp_path / 'run' / 'flow_summary.json').read_text())
    assert document['input_mode'] == 'preloaded'
    assert document['input_source'] == 'config.json:trigger_writes'
    assert document['inputs'] == [[0, 0, 0xffffffff]]
    assert 'per_case_observations' in document['unknown']
    assert '--online' not in json.loads((tmp_path / 'argv.json').read_text())


def test_main_maps_f6_records_and_keeps_unknowns(fake, tmp_path):
    fake(FAKE_SUMMARY={'status': 'observations_passed', 'returncode': 0,
                       'input_mode': 'preloaded',
                       'records': ['0110c00008000000', '0530c00110000000']},
         FAKE_LOG='case 0 observations_passed reads 4 writes 4 irq_takes 1\n'
                  'case 1 observations_passed reads 4 writes 4 irq_takes 1\n'
                  'summary observations_passed cases 2 ticks 33 reads 8 writes 8'
                  ' irq_takes 2 irq_take_evidence observed retirement_evidence observed'
                  ' simulated_lockstep_assumed 1 runtime_seconds 0.05\n')
    assert _main(tmp_path, 'F6', '--records', '0110c00008000000,0530c00110000000') == 0
    document = json.loads((tmp_path / 'run' / 'flow_summary.json').read_text())
    assert document['flow'] == 'F6' and document['input_mode'] == 'preloaded'
    assert document['input_source'] == 'summary.json:records'
    assert document['inputs'] == ['0110c00008000000', '0530c00110000000']
    assert 'retirement' not in document['unknown'] and 'irq_take' not in document['unknown']
    assert document['observations']['summary']['simulated_lockstep_assumed'] == 1


def test_main_writes_a_failure_summary_even_if_the_delegate_created_nothing(fake, tmp_path):
    fake(FAKE_WRITE='0', FAKE_RC='3')
    assert _main(tmp_path, 'F5', '--online') == 3
    document = json.loads((tmp_path / 'run' / 'flow_summary.json').read_text())
    assert document['status'] == 'failed'
    assert document['delegate']['returncode'] == 3
    assert document['observations']['cases'] == [] and document['inputs'] == []
    assert {'delegate_summary', 'summary_line', 'case_inputs'} <= set(document['unknown'])
    assert document['timings']['link_seconds'] is None


def test_main_reports_an_unreadable_delegate_summary(fake, tmp_path):
    fake(FAKE_SUMMARY='not json', FAKE_LOG='')
    assert _main(tmp_path, 'F5') == 0
    document = json.loads((tmp_path / 'run' / 'flow_summary.json').read_text())
    assert document['status'] == 'unknown'
    assert 'delegate_summary' in document['unknown']
    assert document['unknown_reasons']['delegate_summary'].startswith('summary.json is unreadable')


def test_main_refuses_an_existing_output_directory(fake, tmp_path):
    (tmp_path / 'run').mkdir()
    (tmp_path / 'run' / 'keep.txt').write_text('keep')
    with pytest.raises(SystemExit, match='already exists'):
        _main(tmp_path, 'F5', '--online')
    assert (tmp_path / 'run' / 'keep.txt').read_text() == 'keep'
    assert not (tmp_path / 'run' / 'flow_summary.json').exists()
    assert not (tmp_path / 'argv.json').exists()
