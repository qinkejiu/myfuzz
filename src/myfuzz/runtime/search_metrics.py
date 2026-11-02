"""Budget-aware metrics; unavailable coverage is never a zero observation."""
from __future__ import annotations
import math

IDENTITY_FIELDS = ('target', 'source', 'profile', 'catalog_sha256', 'coverage_metric')


def interaction_metrics(events, seconds, useful_case_events=None):
    if events is None:
        return dict(interaction_status='unavailable', interaction_reason='no-timed-certified-evidence',
                    curve=None, auc_count_seconds=None, auc_mean_count=None,
                    first_hit_seconds=None, first_hit_censored=None,
                    unique_certified_interactions=None, useful_cases_within_budget=None,
                    useful_cases_status='unavailable-no-timed-case-events', useful_cases_per_second=None)
    bounded = seconds is not None
    if bounded and (type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0):
        raise ValueError('invalid-time-budget')
    useful_ids = None
    if useful_case_events is not None:
        if type(useful_case_events) is not list:
            raise ValueError('invalid-useful-case-events')
        useful_ids = set()
        for event in useful_case_events:
            t, case_id = event['seconds'], event['case_id']
            if (type(t) not in (int, float) or not math.isfinite(t) or t < 0
                    or not isinstance(case_id, str) or not case_id):
                raise ValueError('invalid-useful-case-event')
            if not bounded or t <= seconds:
                useful_ids.add(case_id)
    seen = set()
    curve = [{'seconds': 0, 'count': 0}]
    area = 0.0
    last = 0.0
    for event in sorted(events, key=lambda row: row['seconds']):
        t, key = event['seconds'], event['semantic_key']
        if not isinstance(t, (int, float)) or not math.isfinite(t) or t < 0 or not isinstance(key, str) or not key:
            raise ValueError('invalid-certified-event')
        if (bounded and t > seconds) or key in seen:
            continue
        area += len(seen) * (t - last)
        seen.add(key)
        last = t
        curve.append({'seconds': t, 'count': len(seen)})
    if bounded:
        area += len(seen) * (seconds - last)
        curve.append({'seconds': seconds, 'count': len(seen)})
    else:
        return dict(interaction_status='available-counts-only', interaction_reason='no-fixed-time-budget',
            curve=curve, auc_count_seconds=None, auc_mean_count=None,
            first_hit_seconds=curve[1]['seconds'] if seen else None, first_hit_censored=not bool(seen),
            unique_certified_interactions=len(seen), useful_cases_within_budget=None,
            useful_cases_total=len(useful_ids) if useful_ids is not None else None,
            useful_cases_status='observed-no-fixed-time-budget' if useful_ids is not None else 'unavailable-no-timed-case-events',
            useful_cases_per_second=None)
    return {'interaction_status': 'available', 'curve': curve, 'auc_count_seconds': area,
            'auc_mean_count': area / seconds,
            'first_hit_seconds': curve[1]['seconds'] if seen else None,
            'first_hit_censored': not bool(seen),
            'unique_certified_interactions': len(seen),
            'useful_cases_within_budget': len(useful_ids) if useful_ids is not None else None,
            'useful_cases_status': 'available' if useful_ids is not None else 'unavailable-no-timed-case-events',
            'useful_cases_per_second': len(useful_ids) / seconds if useful_ids is not None else None}


def comparability(left, right):
    execution_reasons = []
    if (left.get('execution_mode') is not None and right.get('execution_mode') is not None
            and left['execution_mode'] != right['execution_mode']):
        execution_reasons.append('execution_mode')
    for key in IDENTITY_FIELDS[:-1]:
        a, b = left.get('identity', {}).get(key), right.get('identity', {}).get(key)
        if not a or not b or a != b:
            execution_reasons.append('identity.' + key)
    for key in ('cases', 'seconds'):
        a, b = left.get('budget', {}).get(key), right.get('budget', {}).get(key)
        if key == 'seconds' and a is None and b is None:
            continue
        if type(a) not in (int, float) or not math.isfinite(a) or a <= 0 or a != b:
            execution_reasons.append('budget.' + key)
    if type(left.get('seed')) is not int or left.get('seed') != right.get('seed'):
        execution_reasons.append('seed')
    reasons = list(execution_reasons)
    if left.get('budget', {}).get('seconds') is None or right.get('budget', {}).get('seconds') is None:
        reasons.append('no-fixed-time-budget')
    a, b = left.get('identity', {}).get('coverage_metric'), right.get('identity', {}).get('coverage_metric')
    if not a or not b or a != b:
        reasons.append('identity.coverage_metric')
    if any(row.get('metrics', {}).get('certified_events') is None for row in (left, right)):
        reasons.append('interaction-unavailable')
    lc, rc = left.get('coverage', {}), right.get('coverage', {})
    coverage_reasons = []
    for row in (lc, rc):
        if row.get('status') != 'available':
            coverage_reasons.append('coverage-unavailable')
        # Legacy certified GPIO summaries remain supported. Unknown-primary
        # coverage needs the offline attachment's explicit replay attestation.
        if reasons and row.get('attestation') != 'recorded-prefix-replay.v1':
            coverage_reasons.append('coverage-unattested')
    for key in ('metric', 'denominator_sha256', 'total'):
        if not lc.get(key) or lc.get(key) != rc.get(key):
            coverage_reasons.append('coverage.' + key)
    return {'status': 'incomparable' if reasons else 'comparable',
            'primary_status': 'incomparable' if reasons else 'comparable',
            'execution_status': 'incomparable' if execution_reasons else 'comparable',
            'execution_reasons': execution_reasons, 'reasons': reasons,
            'coverage_comparable': not execution_reasons and not coverage_reasons,
            'coverage_reasons': sorted(set(coverage_reasons))}


def summarize(row):
    coverage = row.get('coverage', {'status': 'unavailable'})
    if coverage.get('status') == 'available':
        total, covered = coverage.get('total'), coverage.get('covered')
        if (type(total) is not int or type(covered) is not int or total <= 0
                or not 0 <= covered <= total or not coverage.get('metric')
                or not isinstance(coverage.get('denominator_sha256'), str)
                or len(coverage['denominator_sha256']) != 64
                or any(c not in '0123456789abcdef' for c in coverage['denominator_sha256'])):
            raise ValueError('invalid-coverage-measurement')
    metrics = row['metrics']
    result = interaction_metrics(metrics['certified_events'], row['budget']['seconds'], metrics.get('useful_case_events'))
    decision = metrics.get('decision_seconds', [])
    if any(not isinstance(x, (int, float)) or not math.isfinite(x) or x < 0 for x in decision):
        raise ValueError('invalid-decision-duration')
    ordered = sorted(decision)
    result.update({'decision_overhead_seconds': sum(decision),
                   'decision_seconds_p50': ordered[len(ordered)//2] if ordered else None,
                   'decision_seconds_p95': ordered[min(len(ordered)-1, int(len(ordered)*.95))] if ordered else None,
                   'search_seconds': metrics.get('search_seconds'),
                   'build_seconds': metrics.get('build_seconds'), 'init_seconds': metrics.get('init_seconds'),
                   'fresh': metrics.get('fresh', {'status': 'not-requested'}),
                   'coverage': row.get('coverage', {'status': 'unavailable'})})
    return result
