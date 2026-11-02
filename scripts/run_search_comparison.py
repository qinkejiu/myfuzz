#!/usr/bin/env python3
"""Run paired dependency search strategies, preserving failures and missing measurements."""
from __future__ import annotations
import argparse
import itertools
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))
from myfuzz.runtime.search_metrics import comparability, summarize

VARIANTS = [('state', 'none'), ('uniform', 'none'), ('legacy', 'none')] + [('state', x) for x in ('frontier', 'state', 'credit', 'cost')]
VARIANT_NAMES = {policy if ablation == 'none' else f'{policy}-{ablation}': (policy, ablation)
                 for policy, ablation in VARIANTS}


def write(path, value):
    with path.open('x', encoding='utf8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def execute(argv, directory, timeout, env):
    start = time.monotonic()
    with (directory / 'stdout.txt').open('x') as out, (directory / 'stderr.txt').open('x') as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err, env=env, cwd=ROOT, start_new_session=True)
        expired = False
        try:
            process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            expired = True
            # Keep the original PGID even if its leader exits on TERM. Waiting
            # for that leader says nothing about TERM-ignoring descendants.
            grace_deadline = time.monotonic() + 1.0
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=max(0, grace_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
            finally:
                time.sleep(max(0, grace_deadline - time.monotonic()))
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
    result = {'argv': argv, 'returncode': process.returncode,
              'wall_seconds': time.monotonic() - start, 'timed_out': expired,
              'leader_reaped': True,
              'descendant_cleanup': 'group-term-then-kill-requested' if expired else 'owned-by-runtime'}
    write(directory / 'execution.json', result)
    return result


def normalize_summary(summary):
    """Expose missing measurements explicitly; admission is not certification."""
    if type(summary) is not dict:
        raise ValueError('summary-must-be-an-object')
    if all(key in summary for key in ('identity', 'budget', 'metrics')):
        return summary
    row = dict(summary)
    row.setdefault('policy', row.get('strategy'))
    row.setdefault('ablation', 'none')
    row.setdefault('budget', {'cases': row.get('cases'), 'seconds': None})
    row.setdefault('identity', {'target': row.get('scenario'), 'source': None,
                               'profile': None, 'catalog_sha256': None,
                               'coverage_metric': None})
    row.setdefault('metrics', {'certified_events': None, 'useful_case_events': None,
                              'interaction_status': 'unknown-no-timed-certified-evidence'})
    row.setdefault('coverage', {'status': 'unavailable'})
    return row


def measured_metrics(row):
    return summarize(row)


def read_summary(directory):
    preferred = directory / 'search-summary.json'
    path = preferred if preferred.exists() else directory / 'summary.json'
    return normalize_summary(json.loads(path.read_text()))


def validate_terminal_summary(summary):
    if type(summary) is not dict or summary.get('status') not in ('completed', 'budget-ended'):
        raise ValueError('summary-status-must-be-completed-or-budget-ended')
    boundary = summary.get('verification', {}).get('session_boundary')
    if boundary is not None and boundary.get('status') != 'verified':
        raise ValueError('session-boundary-not-verified')
    within = summary.get('verification', {}).get('within_invocation', {})
    if (summary.get('execution_mode') == 'acceptance'
            and not cross_verified(summary)
            and not (within.get('status') == 'verified' and within.get('matches') is True)):
        raise ValueError('acceptance-verification-not-complete')
    if summary.get('mode') == 'fresh' and not cross_verified(summary):
        raise ValueError('fresh-summary-replay-not-verified')


def cross_verified(summary):
    if 'verification' not in summary:
        return summary.get('replay_matches') is True
    cross = summary['verification'].get('cross_invocation', {})
    return cross.get('status') == 'verified' and cross.get('matches') is True


def fresh_verified(execution, summary):
    return (execution.get('returncode') == 0 and not execution.get('timed_out')
            and type(summary) is dict and cross_verified(summary)
            and summary.get('verification', {}).get('session_boundary', {'status': 'verified'}).get('status') == 'verified'
            and summary.get('status') in ('completed', 'budget-ended'))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scenario', type=Path, help='Production scenario JSON; output is a case root')
    parser.add_argument('--cache', type=Path, default=ROOT / '.cache/search-comparison')
    parser.add_argument('--seeds', default=','.join(map(str, range(20))))
    parser.add_argument('--variants', default=','.join(VARIANT_NAMES),
                        help='Comma-separated subset: ' + ','.join(VARIANT_NAMES))
    parser.add_argument('--cases', type=int, default=100)
    parser.add_argument('--seconds', type=float)
    parser.add_argument('--process-timeout', type=float, default=1800,
                        help='Includes build/init; separate from fixed search budget')
    parser.add_argument('--plan-only', action='store_true')
    parser.add_argument('--fresh', action='store_true')
    parser.add_argument('--execution-mode', choices=('develop', 'search', 'acceptance'), default='search')
    parser.add_argument('--record-local-commands', action='store_true',
                        help='Record native command artifacts; does not build coverage instrumentation')
    parser.add_argument('--measure-coverage', metavar='COMPONENT',
                        help='Build coverage instrumentation and replay this actual recorded component prefix after each successful search; outside search budget')
    parser.add_argument('--coverage-max-commands',type=int,default=512)
    parser.add_argument('--coverage-max-input-bytes',type=int,default=64*1024*1024)
    parser.add_argument('--coverage-max-output-bytes',type=int,default=64*1024*1024)
    parser.add_argument('--coverage-max-wall-seconds',type=float,default=60)
    parser.add_argument('--import-only', action='store_true',
                        help='Compare imported summaries without executing any searches')
    parser.add_argument('--import-result', type=Path, action='append', default=[])
    args = parser.parse_args(argv)
    from myfuzz.local_harness.coverage import coverage_budget,requested_coverage_overrides
    try:
        coverage_limits=coverage_budget(max_commands=args.coverage_max_commands,
            max_input_bytes=args.coverage_max_input_bytes,max_output_bytes=args.coverage_max_output_bytes,
            max_wall_seconds=args.coverage_max_wall_seconds)
    except ValueError as error:
        parser.error(str(error))
    if args.measure_coverage:
        if args.import_only:
            parser.error('--measure-coverage requires an executed run, not --import-only')
        args.record_local_commands = True
    if args.import_only and not args.import_result:
        parser.error('--import-only requires at least one --import-result')
    selected_variants = args.variants.split(',')
    if (any(name not in VARIANT_NAMES for name in selected_variants)
            or len(set(selected_variants)) != len(selected_variants)):
        parser.error('--variants requires unique nonempty names from: ' + ','.join(VARIANT_NAMES))
    variants = [VARIANT_NAMES[name] for name in selected_variants]
    scenario = None
    if args.scenario:
        from myfuzz.search.config import identity, load_scenario
        from myfuzz.search.cli import source_identity
        from myfuzz.search.descriptor_search import preflight_scenario
        try:
            config = load_scenario(args.scenario, ROOT)
            details = ({'backend': 'gpio', 'capabilities': {'native_started': False,
                         'wall_budget': True, 'strict_cross_invocation_replay': True}}
                       if config['backend'] == 'gpio' else preflight_scenario(config, ROOT))
        except (ValueError, FileNotFoundError) as error:
            parser.error(str(error))
        if config['backend'] != 'gpio' and any(ablation != 'none' for _, ablation in variants):
            parser.error('scenario backend does not support ablations; select --variants state,uniform,legacy')
        scenario = {'path': str(args.scenario.resolve()), 'scenario_identity': identity(config),
                    'source_sha': source_identity(), 'configuration': config, 'preflight': details}
    if args.seconds is None and (scenario is None or scenario['configuration']['backend'] in ('gpio', 'storage')):
        args.seconds = 60.0
    if scenario:
        capabilities = scenario['preflight'].get('capabilities', {})
        max_cases = capabilities.get('max_cases')
        if max_cases is not None and args.cases > max_cases:
            parser.error(f'scenario backend supports at most {max_cases} cases; set --cases explicitly')
        if args.seconds is not None and capabilities.get('wall_budget') is not True:
            parser.error('scenario backend does not support --seconds; use a case budget')
        if args.fresh and capabilities.get('strict_cross_invocation_replay') is not True:
            parser.error('scenario backend does not support strict cross-invocation --fresh')
    try:
        seeds = [int(x) for x in args.seeds.split(',')]
    except ValueError:
        parser.error('seeds must be comma-separated integers')
    if (not seeds or any(seed < 0 for seed in seeds) or len(set(seeds)) != len(seeds)
            or args.cases <= 0 or (args.seconds is not None and (not math.isfinite(args.seconds) or args.seconds <= 0))
            or not math.isfinite(args.process_timeout) or args.process_timeout <= 0):
        parser.error('unique seeds and positive budgets required')
    runs = []
    for seed, (policy, ablation) in itertools.product([] if args.import_only else seeds, variants):
        name = f'seed-{seed}-{policy}-{ablation}'
        case_root = args.output.resolve() / name
        destination = case_root if args.scenario else case_root / 'original'
        argv = [sys.executable, str(ROOT / 'scripts/run_dependency_search.py'), '--mode', 'original',
                '--execution-mode', args.execution_mode, '--policy', policy, '--ablation', ablation, '--seed', str(seed),
                '--cases', str(args.cases),
                '--output', str(destination), '--cache', str(args.cache.resolve())]
        if args.seconds is not None:
            argv.extend(['--seconds', str(args.seconds)])
        if args.scenario:
            argv.extend(['--scenario', str(args.scenario.resolve())])
        if args.record_local_commands:
            argv.append('--record-local-commands')
        runs.append({'name': name, 'argv': argv, 'seed': seed, 'policy': policy, 'ablation': ablation})
    plan = {'schema_version': 'search_comparison_plan.v1', 'runs': runs,
            'execution_mode': args.execution_mode,
            'record_local_commands': args.record_local_commands,
            'coverage_measurement': {'component': args.measure_coverage, 'outside_search_budget': True,
                'scope': 'offline full component prefix including startup/reset and overrun',
                'command_limit': args.coverage_max_commands, 'replay_budget': coverage_limits, 'truncate': False},
            'scenario': scenario, 'import_only': args.import_only, 'imports': [str(path) for path in args.import_result],
            'inference': 'No performance conclusion; formal inference requires frozen design and paired analysis.',
            'unavailable_baselines': {'B2': 'not connected', 'B3': 'not connected', 'B4': 'not connected'}}
    if args.plan_only:
        print(json.dumps(plan, indent=2))
        return 0
    args.output.mkdir(parents=True, exist_ok=False)
    write(args.output / 'plan.json', plan)
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join([str(ROOT / 'src'), env.get('PYTHONPATH', '')])
    results = []
    for run in runs:
        directory = args.output / run['name']
        directory.mkdir()
        execution = execute(run['argv'], directory, args.process_timeout, env)
        record = {**run, 'execution': execution, 'status': 'failed'}
        summary_path = directory / 'original/summary.json'
        if execution['returncode'] == 0 and not execution['timed_out'] and summary_path.exists():
            try:
                row = read_summary(summary_path.parent)
                record['summary'] = row
                validate_terminal_summary(row)
                if row['seed'] != run['seed'] or {key: row['budget'].get(key) for key in ('cases', 'seconds')} != {'cases': args.cases, 'seconds': args.seconds} or row['policy'] != run['policy'] or row['ablation'] != run['ablation']:
                    raise ValueError('requested-run-identity-mismatch')
                comparable = comparability(row, row)
                if comparable['execution_status'] != 'comparable':
                    raise ValueError('missing-run-identity: ' + ','.join(comparable['execution_reasons']))
                record.update(status='ok' if comparable['status'] == 'comparable' else 'observed',
                              summary=row, metrics=measured_metrics(row))
                record['metrics']['fresh'] = {'status': 'not-requested'}
                if comparable['status'] != 'comparable':
                    record['reason'] = comparable['reasons']
                if args.fresh:
                    fresh = directory / 'fresh-execution'
                    fresh.mkdir()
                    argv = list(run['argv'])
                    argv[argv.index('--mode')+1] = 'fresh'
                    argv[argv.index('--execution-mode')+1] = 'acceptance'
                    argv[argv.index('--output')+1] = str(directory.resolve() if args.scenario else directory.resolve() / 'fresh')
                    argv.extend(['--original', str(directory.resolve() / 'original')])
                    record['fresh_execution'] = execute(argv, fresh, args.process_timeout, env)
                    fresh_path = directory / 'fresh/summary.json'
                    record['fresh_summary'] = read_summary(fresh_path.parent) if fresh_path.exists() else None
                    verified = fresh_verified(record['fresh_execution'], record['fresh_summary'])
                    if verified:
                        replay = record['fresh_summary']
                        verified = (replay.get('mode') == 'fresh' and all(
                            replay.get(key) == row.get(key)
                            for key in ('seed', 'policy', 'ablation', 'identity')) and all(
                            replay.get('budget', {}).get(key) == row.get('budget', {}).get(key)
                            for key in ('cases', 'seconds')))
                    record['metrics']['fresh'] = {'status': 'verified' if verified else 'failed'}
                    if not verified:
                        record.update(status='fresh-failed', reason='fresh reconstruction did not verify')
                if args.measure_coverage and record['status'] in ('ok','observed'):
                    try:
                        from myfuzz.search.coverage import measure_search_prefix
                        measured = measure_search_prefix(summary_path.parent,
                            component=args.measure_coverage, cache_root=args.cache,
                            output=directory/'coverage-measurement',**requested_coverage_overrides(coverage_limits))
                        fresh_status=record['metrics']['fresh']
                        row=measured['summary']
                        record.update(summary=row,metrics=measured_metrics(row),
                            automatic_coverage={key:value for key,value in measured.items() if key!='summary'})
                        record['metrics']['fresh']=fresh_status
                    except (OSError,ValueError,KeyError,TypeError,RuntimeError) as error:
                        record.update(status='coverage-failed',coverage_error=str(error))
            except (ValueError, KeyError, TypeError) as error:
                record.update(status='invalid-summary', reason=str(error))
        results.append(record)
    for path in args.import_result:
        row = normalize_summary(json.loads(path.read_text()))
        record = {'name': str(path), 'status': 'invalid-summary', 'summary': row, 'imported': True}
        try:
            validate_terminal_summary(row)
            metrics = measured_metrics(row)
            status = comparability(row, row)
            record.update(status=('ok' if status['status'] == 'comparable' else 'observed'
                                  if status['execution_status'] == 'comparable' else 'incomparable'), metrics=metrics)
            if status['status'] != 'comparable':
                record['reason'] = status['reasons']
        except (ValueError, KeyError, TypeError) as error:
            record['reason'] = str(error)
        results.append(record)
    comparisons = []
    successful = [r for r in results if r['status'] in ('ok', 'observed')]
    for left, right in itertools.combinations(successful, 2):
        if left['summary']['seed'] == right['summary']['seed']:
            comparison = comparability(left['summary'], right['summary'])
            comparisons.append({'left': left['name'], 'right': right['name'], **comparison})
    report = {'schema_version': 'search_comparison.v1', 'results': results, 'comparisons': comparisons,
              'unavailable_baselines': plan['unavailable_baselines'], 'performance_claim': 'not established'}
    write(args.output / 'comparison.json', report)
    return int(any(row['status'] not in ('ok', 'observed') for row in results))


if __name__ == '__main__':
    raise SystemExit(main())
