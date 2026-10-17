"""Offline S1a audit: compare the refactored continuous RX run with attempt6.

Reads only saved documents: the tracked attempt6 archive and the gzip bundles
this increment produced. Never starts a model. A difference in the per-case
command/event/tick evidence is reported as a failure; the only tolerated
difference is an artifact identity digest, which changes when the frozen source
tree carries concurrent non-DMA build-input changes.

Usage:
    PYTHONPATH=src python3 audit_attempt6_comparison.py <evidence-dir> <out.json>
"""
import gzip
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
ARCHIVE = ROOT / 'docs/reports/evidence/dma-continuous-20261017/attempt6-complete.tar'
NEW_CASE_FIELDS = ('command_start', 'command_end', 'event_start', 'event_end',
                   'ticks_before', 'ticks_after', 'prefix_sha256', 'fifo_depth_after')


def load_gzip(path):
    return json.loads(gzip.open(path).read())


def load_archive_member(member):
    with tarfile.open(ARCHIVE) as archive:
        handle = archive.extractfile(member)
        return json.loads(gzip.decompress(handle.read()))


def differing_paths(left, right, path=''):
    """Return the normalized JSON paths where two documents differ."""
    found = []
    stack = [(left, right, path)]
    while stack:
        a, b, where = stack.pop()
        if type(a) is not type(b):
            found.append(where + ' <type>')
        elif isinstance(a, dict):
            if set(a) != set(b):
                found.append(where + ' <keys>')
            for key in sorted(set(a) & set(b)):
                stack.append((a[key], b[key], where + '/' + key))
        elif isinstance(a, (list, tuple)):
            if len(a) != len(b):
                found.append(where + ' <length>')
            for index, (x, y) in enumerate(zip(a, b)):
                stack.append((x, y, where + '/*'))
        elif a != b:
            found.append(where)
    return sorted(set(found))


def baseline_case(case):
    return {key: value for key, value in case.items() if key not in NEW_CASE_FIELDS}


def compare(label, new, old, normalize):
    """Compare one saved run pair; returns (report, failed)."""
    ids_new, ids_old = new['execution_ids'], old['execution_ids']
    new_cases = [baseline_case(case) for case in new['cases']]
    old_cases = [baseline_case(case) for case in old['cases']]
    events_new, events_old = normalize(new['events'], ids_new), normalize(
        old['events'], ids_old)
    event_paths = differing_paths(events_new, events_old)
    tolerated = [path for path in event_paths if path.endswith('/artifact_digest')]
    significant = [path for path in event_paths if path not in tolerated]
    report = dict(
        label=label,
        new=dict(events=len(new['events']), commands=len(new['plan']['commands']),
                 local_ticks=new['local_ticks'], cases=len(new['cases']),
                 phase=new['phase'], case_index=new['case_index'],
                 execution_ids=ids_new),
        baseline=dict(events=len(old['events']),
                      commands=len(old['plan']['commands']),
                      local_ticks=old['local_ticks'], cases=len(old['cases']),
                      phase=old['phase'], case_index=old['case_index'],
                      execution_ids=ids_old),
        commands_equal=new['plan']['commands'] == old['plan']['commands'],
        local_ticks_equal=new['local_ticks'] == old['local_ticks'],
        baseline_case_case_fields_equal=new_cases == old_cases,
        normalized_events_equal=events_new == events_old,
        differing_event_paths=event_paths,
        tolerated_artifact_identity_paths=tolerated,
        significant_event_differences=significant,
        new_boundary_fields_present=all(
            set(NEW_CASE_FIELDS) <= set(case) for case in new['cases']),
        new_prefix_digests=[case['prefix_sha256'] for case in new['cases']])
    failed = (not report['commands_equal'] or not report['local_ticks_equal']
              or not report['baseline_case_case_fields_equal']
              or bool(significant)
              or not report['new_boundary_fields_present'])
    return report, failed


def main():
    evidence = Path(sys.argv[1])
    out = Path(sys.argv[2])
    from myfuzz.integration.dma_uart_rx_runtime import _normalize
    pairs = {
        'positive': (load_gzip(evidence / 'positive.json.gz'),
                     load_archive_member('attempt6/evidence/positive.json.gz')),
        'fresh': (load_gzip(evidence / 'fresh.json.gz'),
                  load_archive_member('attempt6/evidence/fresh.json.gz')),
    }
    document = dict(kind='dma-continuous-s1a-attempt6-comparison', runs={}, ok=True)
    for label, (new, old) in pairs.items():
        report, failed = compare(label, new, old, _normalize)
        document['runs'][label] = report
        document['ok'] = document['ok'] and not failed
    new_positive, new_fresh = pairs['positive'][0], pairs['fresh'][0]
    document['new_fresh_pair'] = dict(
        cases_equal=new_positive['cases'] == new_fresh['cases'],
        local_ticks_equal=new_positive['local_ticks'] == new_fresh['local_ticks'],
        plan_equal=new_positive['plan'] == new_fresh['plan'],
        identities_equal=new_positive['identities'] == new_fresh['identities'],
        distinct_execution_ids=all(new_positive['execution_ids'][name]
            != new_fresh['execution_ids'][name] for name in ('cpu', 'dma', 'uart', 'runner')),
        normalized_events_equal=_normalize(new_positive['events'],
            new_positive['execution_ids']) == _normalize(new_fresh['events'],
            new_fresh['execution_ids']))
    document['ok'] = document['ok'] and all(document['new_fresh_pair'][name] for name in (
        'cases_equal', 'local_ticks_equal', 'plan_equal', 'identities_equal',
        'distinct_execution_ids', 'normalized_events_equal'))
    out.write_text(json.dumps(document, sort_keys=True, indent=1), encoding='utf-8')
    print(json.dumps(dict(ok=document['ok'], runs={
        label: dict(commands_equal=run['commands_equal'],
                    ticks_equal=run['local_ticks_equal'],
                    cases_equal=run['baseline_case_case_fields_equal'],
                    normalized_events_equal=run['normalized_events_equal'],
                    tolerated=len(run['tolerated_artifact_identity_paths']),
                    significant=run['significant_event_differences'][:3])
        for label, run in document['runs'].items()},
        new_fresh_pair=document['new_fresh_pair']), indent=1))
    return 0 if document['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
