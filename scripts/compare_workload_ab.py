#!/usr/bin/env python3
"""Compare two same-workload benchmark runs that differ in one explicit option.

Unlike ``verify_shared_benchmark.py`` (which is pinned to the fetch-scan and
topology axes), this tool takes the differing option as a declared label and
verifies that everything else is identical: both runs complete with a matching
full fresh replay, the complete normalized prefix is equal, and the executed
work identity (records, case counts, local ticks, event count and per-kind
event counts) is equal.  Native eval counts are compared when both sides
enabled the timers.

It never claims a speedup: it reports the wall ratio only when every
equivalence check passed, and the ratio is one single pair of runs.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

SCHEMA = 'same_workload_ab.v1'


def read(root, name):
    return json.loads((root / name).read_text())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def main():
    from myfuzz.integration.compiled_f6 import _first_difference, _normalized_f6_prefix
    from myfuzz.integration.runtime_benchmark import workload_identity

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--baseline-option', required=True)
    parser.add_argument('--candidate-option', required=True)
    parser.add_argument('--axis', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--replay-skipped', action='store_true',
                        help='both sides ran the campaign without within-invocation replay')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('comparison output must not exist')
    if not args.axis or not args.baseline_option or not args.candidate_option:
        raise ValueError('declared axis and options are required')
    if args.baseline_option == args.candidate_option:
        raise ValueError('the two runs must differ in the declared option')
    baseline = read(args.baseline, 'performance.json')
    candidate = read(args.candidate, 'performance.json')
    baseline_prefix = read(args.baseline, 'workload/original/prefix.json')
    candidate_prefix = read(args.candidate, 'workload/original/prefix.json')
    checks = {}
    if args.replay_skipped:
        checks['complete_campaign_without_replay'] = all(
            row.get('status') == 'complete' and row.get('replay_skipped') is True
            and not row.get('identity_export_error') for row in (baseline, candidate))
    else:
        checks['complete_full_fresh'] = all(
            row.get('status') == 'complete' and row.get('fresh_matches') is True
            and not row.get('identity_export_error') for row in (baseline, candidate))
    left, right = _normalized_f6_prefix(baseline_prefix), _normalized_f6_prefix(candidate_prefix)
    difference = _first_difference(left, right)
    checks['full_normalized_prefix'] = difference is None
    identities = [workload_identity(prefix) for prefix in (baseline_prefix, candidate_prefix)]
    fields = ('records', 'records_sha256', 'main_case_count', 'session_case_count',
              'local_ticks', 'event_count', 'event_kind_counts')
    checks['executed_work'] = all(identities[0][key] == identities[1][key] for key in fields)

    def eval_counts(report):
        if report.get('native_eval_timers_enabled') is not True:
            return None
        result = {}
        phases = ('original',) if args.replay_skipped else ('original', 'fresh')
        for phase in phases:
            rows = report.get('native_eval', {}).get(phase, {})
            if not rows:
                return None
            result[phase] = {}
            for component, row in rows.items():
                values = (row.get('startup_eval_count'), row.get('runtime_eval_count'))
                if row.get('status') != 'observed' or any(type(value) is not int or value < 0
                                                          for value in values):
                    return None
                result[phase][component] = values
        return result

    first, second = eval_counts(baseline), eval_counts(candidate)
    checks['native_eval_counts'] = first is not None and first == second
    result = dict(
        schema_version=SCHEMA, authority=False,
        axis=args.axis,
        options={args.axis: dict(baseline=args.baseline_option,
                                 candidate=args.candidate_option)},
        equivalent=all(checks.values()), checks=checks,
        first_prefix_difference=difference,
        normalized_prefix_sha256=[
            sha256(canonical(prefix).encode()).hexdigest() for prefix in (left, right)],
        workload=dict(baseline=identities[0], candidate=identities[1]),
        timing=dict(
            wall_seconds=dict(baseline=baseline.get('wall_seconds'),
                              candidate=candidate.get('wall_seconds')),
            execution_seconds=dict(
                baseline=(baseline.get('summary') or {}).get('execution_seconds'),
                candidate=(candidate.get('summary') or {}).get('execution_seconds')),
            replay_seconds=dict(
                baseline=(baseline.get('summary') or {}).get('replay_seconds'),
                candidate=(candidate.get('summary') or {}).get('replay_seconds'))),
        timing_scope='same recorded work; inclusive spans overlap and must not be added')
    if result['equivalent']:
        result['wall_ratio_candidate_over_baseline'] = (
            candidate['wall_seconds'] / baseline['wall_seconds'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(equivalent=result['equivalent'], checks=checks,
                          wall_ratio=result.get('wall_ratio_candidate_over_baseline'))))
    return 0 if result['equivalent'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
