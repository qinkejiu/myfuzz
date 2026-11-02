import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/run_search_comparison.py'

def test_plan_only_is_side_effect_free_and_has_shared_budget(tmp_path):
    output = tmp_path / 'not-created'
    result = subprocess.run([sys.executable, str(SCRIPT), '--plan-only', '--seeds', '1,2',
                             '--cases','4','--seconds','2','--output',str(output)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    import json
    plan = json.loads(result.stdout)
    assert len(plan['runs']) == 14
    assert all('--cases' in row['argv'] and '--seconds' in row['argv'] for row in plan['runs'])
    assert not output.exists()

def test_failed_child_is_recorded_without_shell(tmp_path):
    import importlib.util
    import os
    import json
    spec = importlib.util.spec_from_file_location('comparison_runner', SCRIPT)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    execution = runner.execute([sys.executable, '-c', 'import sys; print(sys.argv[1]); sys.exit(7)',
                                '$(touch must-not-exist)'], tmp_path, 5, dict(os.environ))
    assert execution['returncode'] == 7
    assert '$(touch must-not-exist)' in (tmp_path/'stdout.txt').read_text()
    assert json.loads((tmp_path/'execution.json').read_text())['argv'][-1] == '$(touch must-not-exist)'
    assert not (ROOT/'must-not-exist').exists()


def test_fresh_failure_is_not_an_accepted_original_result():
    import importlib.util
    spec = importlib.util.spec_from_file_location('comparison_runner_fresh', SCRIPT)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    assert not runner.fresh_verified({'returncode': 0, 'timed_out': True},
                                     {'replay_matches': True, 'status': 'completed'})
    assert not runner.fresh_verified({'returncode': 1, 'timed_out': False},
                                     {'replay_matches': True, 'status': 'completed'})
    assert not runner.fresh_verified({'returncode': 0, 'timed_out': False},
                                     {'replay_matches': False, 'status': 'completed'})
    assert runner.fresh_verified({'returncode': 0, 'timed_out': False},
                                 {'replay_matches': True, 'status': 'completed'})

def runner_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location('comparison_runner_timeout', SCRIPT)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


def test_original_timeout_exit_zero_is_failed(tmp_path, monkeypatch):
    import json
    runner = runner_module()
    def fake_execute(argv, directory, timeout, env):
        output = Path(argv[argv.index('--output') + 1])
        output.mkdir()
        (output / 'summary.json').write_text('{}')
        return {'returncode': 0, 'timed_out': True}
    monkeypatch.setattr(runner, 'execute', fake_execute)
    monkeypatch.setattr(sys, 'argv', ['runner', '--output', str(tmp_path/'matrix'), '--seeds','1'])
    assert runner.main() == 1
    report = json.loads((tmp_path/'matrix/comparison.json').read_text())
    assert all(row['status'] == 'failed' for row in report['results'])


def test_timeout_kills_stubborn_descendant_after_leader_exits_zero(tmp_path):
    import os
    import signal
    import time
    runner = runner_module()
    ready = tmp_path / 'child-ready'
    child_code = ('import os,signal,time,pathlib,sys; '
                  'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                  'pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)')
    leader_code = ('import subprocess,sys,time,signal,pathlib; '
                   'signal.signal(signal.SIGTERM, lambda *args: sys.exit(0)); '
                   'subprocess.Popen([sys.executable,"-c",sys.argv[1],sys.argv[2]]); '
                   'time.sleep(30)')
    def alive(pid):
        path = Path(f'/proc/{pid}/stat')
        try:
            return path.read_text().rsplit(')', 1)[1].split()[0] != 'Z'
        except (FileNotFoundError, ProcessLookupError):
            return False
    child_pid = None
    try:
        result = runner.execute([sys.executable,'-c',leader_code,child_code,str(ready)],
                                tmp_path, 1, dict(os.environ))
        assert ready.exists(), 'child must install TERM handler before timeout'
        child_pid = int(ready.read_text())
        deadline = time.monotonic() + 1
        while alive(child_pid) and time.monotonic() < deadline:
            time.sleep(.02)
        assert result['timed_out']
        assert result['returncode'] == 0
        assert not alive(child_pid), 'TERM-ignoring descendant survived leader exit'
        assert result['leader_reaped']
        assert result['descendant_cleanup'] == 'group-term-then-kill-requested'
    finally:
        if child_pid is None and ready.exists():
            child_pid = int(ready.read_text())
        if child_pid is not None and alive(child_pid):
            os.kill(child_pid, signal.SIGKILL)

def test_plan_only_accepts_closed_variant_subset_and_rejects_invalid(tmp_path):
    import json
    argv = [sys.executable, str(SCRIPT), '--plan-only', '--seeds', '1,2',
            '--output', str(tmp_path/'not-created'), '--record-local-commands', '--variants']
    result = subprocess.run(argv + ['state,uniform,legacy'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert len(plan['runs']) == 6
    assert plan['record_local_commands'] is True
    assert all('--record-local-commands' in row['argv'] for row in plan['runs'])
    assert {row['policy'] for row in plan['runs']} == {'state','uniform','legacy'}
    assert all(row['ablation'] == 'none' for row in plan['runs'])
    for invalid in ('unknown', '', 'state,', 'state,state', ',uniform', 'state,,legacy'):
        rejected = subprocess.run(argv + [invalid], capture_output=True, text=True)
        assert rejected.returncode == 2, invalid
    assert not (tmp_path/'not-created').exists()

def valid_summary():
    return {'status':'completed', 'mode':'original', 'seed':1, 'policy':'state','ablation':'none',
        'identity': {'target':'gpio','source':'digest','profile':'p','catalog_sha256':'catalog',
                     'coverage_metric':'certified-interaction.v1'},
        'budget': {'cases':100,'seconds':60.0},
        'metrics': {'certified_events': [], 'useful_case_events': []},
        'coverage': {'status':'unavailable'}}


def test_imported_terminal_status_and_fresh_replay_are_mandatory(tmp_path, monkeypatch):
    import json
    runner = runner_module()
    records = []
    fixtures = [('failed', 'original', None), ('refused','original',None),
                ('mismatch','original',None), (None,'original',None),
                ('completed','fresh',False), ('completed','fresh',None),
                ('completed','fresh',True), ('budget-ended','original',None)]
    for index, (status, mode, replay) in enumerate(fixtures):
        row = valid_summary()
        row.update(mode=mode)
        if status is None:
            row.pop('status')
        else:
            row['status'] = status
        if replay is not None:
            row['replay_matches'] = replay
        path = tmp_path/f'import-{index}.json'
        path.write_text(json.dumps(row))
        records.extend(['--import-result',str(path)])
    monkeypatch.setattr(runner, 'execute', lambda *args: {'returncode':1, 'timed_out':False})
    monkeypatch.setattr(sys, 'argv', ['runner','--output',str(tmp_path/'output'),
                                    '--seeds','1','--variants','state', *records])
    assert runner.main() == 1
    result = json.loads((tmp_path/'output/comparison.json').read_text())
    imports = [row for row in result['results'] if row.get('imported')]
    assert len(imports) == 8
    assert all(row['status'] != 'ok' and row.get('reason') and row.get('summary')
               for row in imports[:6])
    assert all(row['status'] == 'ok' for row in imports[6:])
    assert len(result['comparisons']) == 1


def test_original_failed_summary_is_excluded_despite_successful_exit(tmp_path, monkeypatch):
    import json
    runner = runner_module()
    def fake_execute(argv, directory, timeout, env):
        output = Path(argv[argv.index('--output')+1])
        output.mkdir()
        row = valid_summary()
        row['status'] = 'failed'
        (output/'summary.json').write_text(json.dumps(row))
        return {'returncode':0,'timed_out':False}
    monkeypatch.setattr(runner, 'execute', fake_execute)
    monkeypatch.setattr(sys, 'argv', ['runner','--output',str(tmp_path/'output'),
                                    '--seeds','1','--variants','state'])
    assert runner.main() == 1
    result = json.loads((tmp_path/'output/comparison.json').read_text())
    assert result['results'][0]['status'] == 'invalid-summary'
    assert result['results'][0]['summary']['status'] == 'failed'
    assert result['results'][0]['reason']
    assert not result['comparisons']


def test_record_local_commands_is_preserved_in_fresh_argv(tmp_path, monkeypatch):
    import json
    runner = runner_module()
    observed = []
    def fake_execute(argv, directory, timeout, env):
        observed.append(list(argv))
        output = Path(argv[argv.index('--output')+1])
        output.mkdir()
        row = valid_summary()
        row.update(mode=argv[argv.index('--mode')+1], replay_matches=True)
        (output/'summary.json').write_text(json.dumps(row))
        return {'returncode':0,'timed_out':False}
    monkeypatch.setattr(runner, 'execute', fake_execute)
    monkeypatch.setattr(sys, 'argv', ['runner','--output',str(tmp_path/'output'), '--seeds','1',
                                    '--variants','state','--fresh','--record-local-commands'])
    assert runner.main() == 0
    assert len(observed) == 2
    assert all('--record-local-commands' in argv for argv in observed)
    assert observed[1][observed[1].index('--mode')+1] == 'fresh'

def test_import_only_never_starts_matrix_or_creates_cache(tmp_path, monkeypatch, capsys):
    import json
    import pytest
    runner = runner_module()
    source = tmp_path/'summary.json'
    source.write_text(json.dumps(valid_summary()))
    cache = tmp_path/'no-cache'
    def forbidden(*args, **kwargs):
        raise AssertionError('import-only started a search')
    monkeypatch.setattr(runner, 'execute', forbidden)
    args = ['--import-only','--import-result',str(source),'--cache',str(cache),
            '--output',str(tmp_path/'comparison')]
    assert runner.main(args + ['--plan-only']) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan['runs'] == []
    assert plan['imports'] == [str(source)]
    assert not (tmp_path/'comparison').exists()
    assert runner.main(args) == 0
    report = json.loads((tmp_path/'comparison/comparison.json').read_text())
    assert len(report['results']) == 1
    assert report['results'][0]['imported'] is True
    assert not cache.exists()
    with pytest.raises(SystemExit) as error:
        runner.main(['--import-only','--output',str(tmp_path/'bad')])
    assert error.value.code == 2


def test_scenario_plan_uses_production_driver_case_root_and_identity(tmp_path, capsys):
    import json
    runner = runner_module()
    scenario = ROOT / 'configs/search/timer.json'
    # Use the repository's actual Timer scenario, independent of filename aliases.
    candidates = list((ROOT/'configs/search').glob('*.json'))
    scenario = next(path for path in candidates if 'timer' in path.name.lower())
    assert runner.main(['--plan-only','--scenario',str(scenario),'--variants','state,uniform,legacy',
                        '--seeds','1','--output',str(tmp_path/'matrix')]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan['scenario']['source_sha']
    assert plan['scenario']['scenario_identity']
    for row in plan['runs']:
        argv = row['argv']
        assert argv[1] == str(ROOT/'scripts/run_dependency_search.py')
        assert argv[argv.index('--scenario')+1] == str(scenario.resolve())
        assert Path(argv[argv.index('--output')+1]).name == row['name']
    assert not (tmp_path/'matrix').exists()


def test_non_gpio_scenario_default_ablations_refused_before_output(tmp_path):
    import pytest
    runner = runner_module()
    scenario = next(path for path in (ROOT/'configs/search').glob('*.json') if 'timer' in path.name.lower())
    with pytest.raises(SystemExit) as exc:
        runner.main(['--plan-only','--scenario',str(scenario),'--output',str(tmp_path/'matrix')])
    assert exc.value.code == 2
    assert not (tmp_path/'matrix').exists()


def test_raw_storage_adapter_does_not_invent_timed_certification():
    runner = runner_module()
    raw = {'schema_version':'dependency_search_r0.v1','status':'mechanism-pass',
           'mode':'original','seed':1,'strategy':'state','cases':3,'completed_targets':2,
           'rounds':32,'source_files':[{'path':'src/myfuzz/search/native.py','sha256':'a'*64}]}
    row = runner.normalize_summary(raw)
    assert row['policy'] == 'state'
    assert row['metrics']['certified_events'] is None
    assert row['metrics']['interaction_status'] == 'unknown-no-timed-certified-evidence'
    assert row['identity']['coverage_metric'] is None
    assert row['budget']['seconds'] is None


def test_scenario_fresh_uses_same_case_root_and_original_subdirectory(tmp_path, monkeypatch):
    import json
    runner = runner_module()
    scenario = next(path for path in (ROOT/'configs/search').glob('*.json') if 'timer' in path.name.lower())
    observed = []
    def fake_execute(argv, directory, timeout, env):
        observed.append(list(argv))
        case_root = Path(argv[argv.index('--output')+1])
        mode = argv[argv.index('--mode')+1]
        out = case_root / mode
        out.mkdir(exist_ok=True)
        raw = {'schema_version':'dependency_search_r0.v1','status':'mechanism-pass'}
        (out/'summary.json').write_text(json.dumps(raw))
        row = valid_summary()
        row.update(mode=mode, replay_matches=True)
        row['budget'].update(max_cases=100, elapsed_seconds=1 if mode == 'original' else 2)
        (out/'search-summary.json').write_text(json.dumps(row))
        return {'returncode':0,'timed_out':False}
    monkeypatch.setattr(runner, 'execute', fake_execute)
    assert runner.main(['--scenario',str(scenario),'--variants','state','--seeds','1',
                        '--fresh','--output',str(tmp_path/'matrix')]) == 0
    original, fresh = observed
    original_root = original[original.index('--output')+1]
    assert fresh[fresh.index('--output')+1] == original_root
    assert fresh[fresh.index('--original')+1] == str(Path(original_root)/'original')
    assert '--scenario' in fresh
    report = json.loads((tmp_path/'matrix/comparison.json').read_text())
    assert report['results'][0]['metrics']['fresh']['status'] == 'verified'


def test_all_checked_in_scenarios_have_side_effect_free_case_budget_plans(tmp_path, capsys):
    import json
    runner = runner_module()
    scenarios = list((ROOT/'configs/search').glob('*.json'))
    assert len(scenarios) >= 4
    for path in scenarios:
        out = tmp_path/path.stem
        assert runner.main(['--scenario',str(path),'--variants','state,uniform,legacy',
                            '--seeds','1','--cases','2','--seconds','0.25','--plan-only','--output',str(out)]) == 0
        plan = json.loads(capsys.readouterr().out)
        assert len(plan['runs']) == 3
        assert plan['scenario']['scenario_identity']
        assert plan['scenario']['source_sha']
        assert plan['scenario']['preflight']['capabilities']['wall_budget'] is True
        assert all(row['argv'][row['argv'].index('--seconds')+1] == '0.25' for row in plan['runs'])
        assert not out.exists()


def test_standalone_default_case_budget_is_refused_before_launch(tmp_path, capsys):
    import pytest
    runner = runner_module()
    for name in ('gpio-f5', 'dma-f6'):
        scenario = ROOT/f'configs/search/{name}.json'
        with pytest.raises(SystemExit) as error:
            runner.main(['--scenario',str(scenario),'--variants','state','--plan-only',
                         '--output',str(tmp_path/name)])
        assert error.value.code == 2
        assert 'at most 16 cases' in capsys.readouterr().err
        assert not (tmp_path/name).exists()


def test_record_catalog_strict_fresh_plan_is_supported(tmp_path, capsys):
    import json
    runner = runner_module()
    for name in ('gpio-f5', 'dma-f6', 'memory-mixed-ibex'):
        scenario = ROOT/f'configs/search/{name}.json'
        assert runner.main(['--scenario',str(scenario),'--variants','state','--plan-only',
                            '--cases','16','--fresh','--output',str(tmp_path/name)]) == 0
        plan = json.loads(capsys.readouterr().out)
        assert plan['scenario']['preflight']['capabilities']['strict_cross_invocation_replay'] is True
        assert len(plan['runs']) == 20
        assert not (tmp_path/name).exists()


def test_successful_descriptor_without_timed_certificate_is_incomparable(tmp_path, monkeypatch):
    import json
    runner = runner_module()
    scenario = ROOT/'configs/search/timer-ibex.json'
    def fake_execute(argv, directory, timeout, env):
        out = Path(argv[argv.index('--output')+1])/'original'
        out.mkdir()
        raw = {'schema_version':'dependency_search_r0.v1','status':'mechanism-pass',
               'mode':'original','seed':1,'strategy':argv[argv.index('--policy')+1],
               'cases':100,'completed_targets':3}
        (out/'summary.json').write_text(json.dumps(raw))
        normalized = dict(raw, status='completed', policy=raw['strategy'],ablation='none',
                          budget={'cases':100,'seconds':60.0},replay_matches=True,
                          identity={'target':'timer','source':'s','profile':'p','catalog_sha256':'c','coverage_metric':None})
        (out/'search-summary.json').write_text(json.dumps(normalized))
        return {'returncode':0,'timed_out':False}
    monkeypatch.setattr(runner,'execute',fake_execute)
    assert runner.main(['--scenario',str(scenario),'--variants','state,uniform',
                        '--seeds','1','--output',str(tmp_path/'matrix')]) == 0
    report = json.loads((tmp_path/'matrix/comparison.json').read_text())
    assert len(report['comparisons']) == 1
    assert report['comparisons'][0]['primary_status'] == 'incomparable'
    assert all(row['status'] == 'observed' for row in report['results'])
    assert all(row['metrics']['auc_count_seconds'] is None for row in report['results'])
    assert all(row['metrics']['unique_certified_interactions'] is None for row in report['results'])


def test_import_unknown_attested_coverage_pairs_without_certified_claim(tmp_path):
    import json
    runner = runner_module()
    inputs = []
    for index in range(2):
        row = valid_summary()
        row['identity']['coverage_metric'] = None
        row['metrics']['certified_events'] = None
        row['metrics']['useful_case_events'] = None
        row['coverage'] = {'status':'available','metric':'line','denominator_sha256':'a'*64,
                           'total':4,'covered':index+1,'attestation':'recorded-prefix-replay.v1'}
        path = tmp_path/f'unknown-{index}.json'
        path.write_text(json.dumps(row))
        inputs += ['--import-result',str(path)]
    assert runner.main(['--import-only','--output',str(tmp_path/'report'), *inputs]) == 0
    report = json.loads((tmp_path/'report/comparison.json').read_text())
    assert all(row['status'] == 'observed' for row in report['results'])
    assert all(row['metrics']['interaction_status'] == 'unavailable' for row in report['results'])
    assert report['comparisons'][0]['coverage_comparable'] is True
    assert report['comparisons'][0]['primary_status'] == 'incomparable'


def test_unknown_summary_still_rejects_wrong_requested_budget(tmp_path, monkeypatch):
    import json
    runner = runner_module()
    def fake_execute(argv, directory, timeout, env):
        out = Path(argv[argv.index('--output')+1])
        out.mkdir()
        row = valid_summary()
        row['metrics']['certified_events'] = None
        row['identity']['coverage_metric'] = None
        row['budget']['cases'] += 1
        (out/'summary.json').write_text(json.dumps(row))
        return {'returncode':0,'timed_out':False}
    monkeypatch.setattr(runner,'execute',fake_execute)
    assert runner.main(['--seeds','1','--variants','state','--output',str(tmp_path/'report')]) == 1
    report = json.loads((tmp_path/'report/comparison.json').read_text())
    assert report['results'][0]['status'] == 'invalid-summary'
    assert report['results'][0]['reason'] == 'requested-run-identity-mismatch'


def test_explicit_verification_rejects_pending_session_and_missing_cross():
    import pytest
    runner = runner_module()
    row = {'status': 'completed', 'mode': 'original',
           'verification': {'session_boundary': {'status': 'pending'}}}
    with pytest.raises(ValueError, match='session-boundary'):
        runner.validate_terminal_summary(row)
    row.update(mode='fresh', replay_matches=True,
               verification={'cross_invocation': {'status': 'not-requested', 'matches': None}})
    assert not runner.fresh_verified({'returncode': 0, 'timed_out': False}, row)


def test_plan_declares_search_execution_mode(tmp_path, capsys):
    runner = runner_module()
    import json
    assert runner.main(['--plan-only', '--output', str(tmp_path/'out')]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert all(row['argv'][row['argv'].index('--execution-mode')+1] == 'search'
               for row in plan['runs'])


def test_acceptance_original_requires_completed_cross_verification():
    import pytest
    runner = runner_module()
    row = {'status': 'completed', 'mode': 'original', 'execution_mode': 'acceptance',
           'verification': {'cross_invocation': {'status': 'pending', 'matches': None}}}
    with pytest.raises(ValueError, match='acceptance'):
        runner.validate_terminal_summary(row)
