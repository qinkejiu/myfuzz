"""Offline S1b audit: recompute a saved search bundle with no RTL.

Reads only the gzip bundles the search gate produced and re-derives every
structural claim: plan/decision agreement, per-case command/event/tick
boundaries, ``prefix_sha256``, decision recomputation from recorded feedback,
guided parent/energy trace, and the fresh full-prefix replay equality.

Usage:
    PYTHONPATH=src python3 audit_search_bundle.py <evidence-dir> <out.json>
"""
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def load_gzip(path):
    return json.loads(gzip.open(path).read())


def main():
    evidence = Path(sys.argv[1])
    out = Path(sys.argv[2])
    from myfuzz.integration import dma_uart_rx_search as search
    from myfuzz.integration.dma_uart_rx_runtime import (
        ContinuousRxResult, _command_document, _prefix_digest, _normalize)
    from myfuzz.scenario.batch import BatchSourceEvent

    document = load_gzip(evidence / 'search.json.gz')
    result = search.DmaSearchResult.from_document(document)
    cases = result.cases
    plan = result.result.plan
    seeds = bytes.fromhex(result.seed_hex)
    report = dict(kind='dma-continuous-s1b-saved-audit', ok=True, findings=[])

    def fail(name):
        report['ok'] = False
        report['findings'].append(name)

    # 1. Structural criteria recomputed from the saved documents only.
    stats = search._assert_real_search(result)
    report['search_status'] = stats['search_status']
    report['stats'] = {key: stats[key] for key in (
        'post_seed_cases', 'distinct_effective_specs', 'feedback_influenced',
        'post_seed_completed_chains', 'completed_chains', 'effective_search_seconds',
        'search_wall_seconds', 'executed_cases', 'case_count', 'new_features_total',
        'corpus_entries', 'rejected_prertl', 'session_failed', 'findings')}
    if stats['search_status'] != 'ok':
        fail('search_status')

    # 2. Plan source values must equal the executed spec sequence.
    plan_values = [command.value for command in plan.commands
                   if isinstance(command, BatchSourceEvent)]
    spec_values = [case.source_byte for case in cases]
    report['plan_values'] = plan_values
    report['spec_values'] = spec_values
    if plan_values != spec_values:
        fail('plan_decision_mismatch')

    # 3. Every case prefix digest must recompute from the saved commands/events.
    digests = []
    for case in cases:
        recomputed = _prefix_digest(
            plan.commands[case.command_start:case.command_end],
            list(result.result.events[case.event_start:case.event_end]),
            case.ticks_before, case.ticks_after, result.result.execution_ids)
        digests.append(dict(case_index=case.case_index,
            saved=case.prefix_sha256, recomputed=recomputed,
            equal=recomputed == case.prefix_sha256))
        if recomputed != case.prefix_sha256:
            fail(f'prefix_sha256_case_{case.case_index}')
    report['prefix_digests'] = digests

    # 4. Decisions must recompute from the recorded per-case feedback alone.
    recomputed = search.recompute_decisions(seed=seeds, strategy=result.strategy,
        cases=tuple(case.to_document() for case in cases))
    report['decisions_equal'] = recomputed == result.decisions
    if recomputed != result.decisions:
        fail('decision_recompute')
    report['guided_trace'] = [
        dict(case_index=decision['case_index'], parent_id=decision['parent_id'],
             parent_kind=decision['parent_kind'], energy=decision['energy'],
             operator=decision['operator'], new_features=decision['new_features'],
             duplicate_attempts=decision['duplicate_attempts'],
             draw_offset=decision['draw_offset'])
        for decision in result.decisions]
    for decision in result.decisions[1:]:
        if decision['parent_kind'] == 'corpus' and (
                not decision['new_features'] or decision['energy'] <= 1):
            fail(f'feedback_trace_case_{decision["case_index"]}')

    # 5. No host-written data and no non-spec expectation source.
    host_writes = [event for event in result.result.events
                   if event.get('kind') == 'memory_write'
                   and event.get('component') not in ('cpu', 'dma')
                   and event.get('address') in search.GUARDED_ADDRESSES]
    report['host_writes'] = len(host_writes)
    if host_writes:
        fail('host_wrote_data')
    for case in cases:
        if case.evidence.get('source_byte') != case.source_byte:
            fail(f'expected_from_host_case_{case.case_index}')

    # 6. Corpus entries are bounded, replayable prefixes.
    corpus = result.corpus
    report['corpus'] = dict(entries=len(corpus['entries']),
        max_entries=corpus['max_entries'], max_bytes=corpus['max_bytes'],
        bytes=corpus['bytes'], evictions=len(corpus['evictions']),
        all_prefixes=all(entry['prefix_sha256'] for entry in corpus['entries']),
        operator_yields=corpus['operator_yields'])
    if not report['corpus']['all_prefixes']:
        fail('corpus_not_replayable')

    # 7. Fresh full-prefix replay equality of the whole search boot.
    fresh = ContinuousRxResult.from_document(load_gzip(evidence / 'fresh.json.gz'))
    positive = result.result
    report['fresh_replay'] = dict(
        cases_equal=fresh.cases == positive.cases,
        plan_equal=fresh.plan.commands == positive.plan.commands,
        local_ticks_equal=fresh.local_ticks == positive.local_ticks,
        identities_equal=fresh.identities == positive.identities,
        normalized_events_equal=_normalize(fresh.events, fresh.execution_ids)
            == _normalize(positive.events, positive.execution_ids),
        execution_ids_distinct=all(fresh.execution_ids[name]
            != positive.execution_ids[name]
            for name in ('cpu', 'dma', 'uart', 'runner')),
        phase=fresh.phase, error=fresh.error)
    for name in ('cases_equal', 'plan_equal', 'local_ticks_equal',
                 'identities_equal', 'normalized_events_equal',
                 'execution_ids_distinct'):
        if not report['fresh_replay'][name]:
            fail('fresh_replay_' + name)

    # 8. Failure document and its fresh replay stay identical.
    failure = load_gzip(evidence / 'failure.json.gz')
    failure_fresh = load_gzip(evidence / 'failure-fresh.json.gz')
    report['failure'] = dict(error_equal=failure['error'] == failure_fresh['error'],
        budget_equal=failure['budget'] == failure_fresh['budget'],
        phase=failure['phase'], case_index=failure['case_index'],
        message=failure['error']['message'],
        commands=len(failure['plan']['commands']))
    if not (report['failure']['error_equal'] and report['failure']['budget_equal']):
        fail('failure_replay')

    report['source_pins_count'] = len(positive.source_pins)
    out.write_text(json.dumps(report, sort_keys=True, indent=1), encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'], findings=report['findings'],
        stats=report['stats'], decisions_equal=report['decisions_equal'],
        fresh_replay=report['fresh_replay'], corpus=report['corpus'],
        prefix_digests=[row['equal'] for row in report['prefix_digests']],
        failure=report['failure']), indent=1))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
