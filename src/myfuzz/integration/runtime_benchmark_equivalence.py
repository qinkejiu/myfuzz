"""Independent same-source workload check before comparing benchmark wall time."""
from hashlib import sha256
import json


def compare_benchmarks(baseline,candidate,baseline_prefix,candidate_prefix,*,normalize=None,varying_axis='fetch_scan'):
    from .compiled_f6 import _first_difference, _normalized_f6_prefix
    from .runtime_benchmark import workload_identity
    if varying_axis not in ('fetch_scan','topology_validation'):
        raise ValueError('benchmark varying axis must be fetch_scan or topology_validation')
    normalize=normalize or _normalized_f6_prefix
    checks={}
    checks['complete_full_fresh']=all(r.get('status')=='complete' and r.get('fresh_matches') is True
        and not r.get('identity_export_error') for r in (baseline,candidate))
    if varying_axis=='fetch_scan':
        checks['explicit_ab_modes']=(baseline.get('fetch_scan_mode')=='legacy'
            and candidate.get('fetch_scan_mode')=='snapshot')
        # Older fetch-only reports omit topology mode on both sides.
        modes=[r.get('topology_validation_mode') for r in (baseline,candidate)]
        checks['single_varying_axis']=(modes[0]==modes[1]
            and modes[0] in (None,'legacy','boundary'))
    else:
        checks['explicit_ab_modes']=(baseline.get('topology_validation_mode')=='legacy'
            and candidate.get('topology_validation_mode')=='boundary')
        checks['single_varying_axis']=all(r.get('fetch_scan_mode')=='snapshot'
            for r in (baseline,candidate))
    left=normalize(baseline_prefix);right=normalize(candidate_prefix)
    difference=_first_difference(left,right)
    checks['full_normalized_prefix']=difference is None
    identities=[workload_identity(p) for p in (baseline_prefix,candidate_prefix)]
    fields=('records','records_sha256','main_case_count','session_case_count','local_ticks',
            'event_count','event_kind_counts')
    checks['executed_work']=all(identities[0][key]==identities[1][key] for key in fields)
    def counts(report):
        if report.get('native_eval_timers_enabled') is not True:return None
        result={}
        for phase in ('original','fresh'):
            rows=report.get('native_eval',{}).get(phase,{})
            if not rows:return None
            result[phase]={}
            for component,row in rows.items():
                values=(row.get('startup_eval_count'),row.get('runtime_eval_count'))
                if row.get('status')!='observed' or any(type(v) is not int or v<0 for v in values):return None
                result[phase][component]=values
        return result
    ac,bc=counts(baseline),counts(candidate)
    checks['native_eval_counts']=ac is not None and ac==bc
    result=dict(schema_version='shared_benchmark_equivalence.v1',authority=False,
        equivalent=all(checks.values()),varying_axis=varying_axis,checks=checks,first_prefix_difference=difference,
        normalized_prefix_sha256=[sha256(json.dumps(p,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            for p in (left,right)],
        timing_scope='same recorded work; inclusive spans overlap and must not be added')
    if result['equivalent']:
        result['wall_ratio_candidate_over_baseline']=candidate['wall_seconds']/baseline['wall_seconds']
    return result
