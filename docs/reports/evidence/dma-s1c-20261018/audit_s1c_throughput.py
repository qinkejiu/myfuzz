"""Offline S1c before/after throughput and causal audit (read-only).

The script never starts native RTL. It reads the saved continuous/search
bundles, counts UART ticks and commands directly from the documents, compares
the S1a before baseline with the S1c after run, and re-derives the per-case
evidence joins and the fresh-prefix equality from the saved journals.

Usage:
    PYTHONPATH=src python3 audit_s1c_throughput.py <evidence-root> [out.json]
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path
import sys

from myfuzz.integration import dma_uart_rx_search as search
from myfuzz.integration.dma_uart_rx_runtime import ContinuousRxResult, _normalize
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent

EVENT_INDEX_FIELDS = (
    'fifo_read_event_id', 'dma_write_event_id', 'irq_event_id',
    'cpu_load_event_id', 'completed_event_id', 'dma_irq_edge_event_id',
    'bound_source_event_id', 'bound_take_event_id', 'status_delivery_event_id',
    'status_cpu_load_event_id', 'status_cpu_store_event_id')
SEMANTIC_CASE_FIELDS = (
    'counter', 'source_byte', 'action_id', 'fifo_origin', 'proof_grade',
    'status_register_flow', 'fifo_depth_after')


def _load_result(path: Path) -> ContinuousRxResult:
    raw = path.read_bytes()
    if path.suffix == '.gz':
        raw = gzip.decompress(raw)
    return ContinuousRxResult.from_document(json.loads(raw.decode('utf-8')))


def _load_search(path: Path) -> dict:
    raw = path.read_bytes()
    if path.suffix == '.gz':
        raw = gzip.decompress(raw)
    return json.loads(raw.decode('utf-8'))


def _counts(result: ContinuousRxResult) -> dict:
    events = result.events
    uart_samples = [event for event in events
        if event.get('kind') == 'local_tick_sample'
        and event.get('component') == 'uart']
    post = [event for event in uart_samples if event.get('phase') == 'post']
    pre = [event for event in uart_samples if event.get('phase') == 'pre']
    uart_ticks = result.local_ticks['uart']
    if len(post) != uart_ticks or len(pre) != uart_ticks:
        raise ValueError('UART local_tick_sample count does not match local_ticks')
    advances = [command for command in result.plan.commands
        if isinstance(command, BatchAdvance)]
    uart_only = [command for command in advances if tuple(command.schedule) == ('uart',)]
    poll = [command for command in advances if tuple(command.schedule) != ('uart',)]
    poll_uart = [command for command in poll if 'uart' in command.schedule]
    per_case = []
    for case in result.cases:
        rows = events[case['event_start']:case['event_end']]
        commands = result.plan.commands[case['command_start']:case['command_end']]
        case_advances = [command for command in commands
            if isinstance(command, BatchAdvance)]
        case_uart_only = [command for command in case_advances
            if tuple(command.schedule) == ('uart',)]
        case_poll = [command for command in case_advances
            if tuple(command.schedule) != ('uart',)]
        case_poll_uart = [command for command in case_poll
            if 'uart' in command.schedule]
        case_post = [event for event in rows
            if event.get('kind') == 'local_tick_sample'
            and event.get('component') == 'uart'
            and event.get('phase') == 'post']
        uart_delta = case['ticks_after']['uart'] - case['ticks_before']['uart']
        per_case.append(dict(
            counter=case['counter'], source_byte=case['source_byte'],
            commands=case['command_end'] - case['command_start'],
            events=case['event_end'] - case['event_start'],
            uart_ticks=uart_delta,
            uart_local_tick_samples=len(case_post),
            uart_only_waveform_commands=len(case_uart_only),
            poll_advance_commands=len(case_poll),
            poll_uart_steps=len(case_poll_uart),
            uart_register_access_ticks=(uart_delta - len(case_uart_only)
                - len(case_poll_uart)),
            uart_tick_observation=sum(1 for event in rows
                if event.get('kind') == 'uart_tick_observation')))
    return dict(
        phase=result.phase, error=result.error,
        commands=len(result.plan.commands),
        source_events=sum(1 for command in result.plan.commands
            if isinstance(command, BatchSourceEvent)),
        events=len(events), local_ticks=dict(result.local_ticks),
        uart_local_tick_samples=len(uart_samples),
        uart_local_tick_samples_pre=len(pre),
        uart_local_tick_samples_post=len(post),
        uart_tick_observation=sum(1 for event in events
            if event.get('kind') == 'uart_tick_observation'),
        uart_only_waveform_commands=len(uart_only),
        poll_advance_commands=len(poll),
        poll_uart_steps=len(poll_uart),
        per_case=per_case)


def _case_structure(result: ContinuousRxResult) -> list[dict]:
    return [{field: case.get(field) for field in SEMANTIC_CASE_FIELDS}
            for case in result.cases]


def _index_fields(case: dict) -> dict:
    return {field: case.get(field) for field in EVENT_INDEX_FIELDS}


def _check_case_joins(result: ContinuousRxResult) -> list[str]:
    """Re-derive every cited causal join from the saved after journal."""
    problems: list[str] = []
    events = {event['event_id']: event for event in result.events}
    previous_ticks = None
    previous_command_end = None
    previous_event_end = None

    def cited(case, field, kind, expect=None):
        event_id = case.get(field)
        event = events.get(event_id)
        label = f"case {case.get('counter')}:{field}"
        if event is None:
            problems.append(f'{label} cites missing event {event_id!r}')
            return None
        if event.get('kind') != kind:
            problems.append(f'{label} cites {event.get("kind")!r}, expected {kind!r}')
            return None
        for key, value in (expect or {}).items():
            if event.get(key) != value:
                problems.append(f'{label} {key}={event.get(key)!r}, expected {value!r}')
        return event

    for case in result.cases:
        if previous_command_end is not None and case['command_start'] != previous_command_end:
            problems.append(f"case {case['counter']}: command boundary is not contiguous")
        if previous_event_end is not None and case['event_start'] != previous_event_end:
            problems.append(f"case {case['counter']}: event boundary is not contiguous")
        if previous_ticks is not None and case['ticks_before'] != previous_ticks:
            problems.append(f"case {case['counter']}: ticks_before is not the previous ticks_after")
        previous_command_end = case['command_end']
        previous_event_end = case['event_end']
        previous_ticks = case['ticks_after']
        for field in EVENT_INDEX_FIELDS:
            event_id = case.get(field)
            if type(event_id) is not int or event_id not in events:
                problems.append(f"case {case['counter']}:{field} is not a live event id")
                continue
            if not case['event_start'] <= event_id - 1 < case['event_end']:
                problems.append(f"case {case['counter']}:{field} is outside the case slice")
        for field, kind in (
                ('fifo_read_event_id', 'dma_edge'),
                ('dma_write_event_id', 'memory_write'),
                ('irq_event_id', 'cpu_external_irq_taken'),
                ('cpu_load_event_id', 'memory_read'),
                ('completed_event_id', 'memory_write'),
                ('dma_irq_edge_event_id', 'dma_edge'),
                ('bound_source_event_id', 'source_start'),
                ('bound_take_event_id', 'cpu_irq_taken'),
                ('status_delivery_event_id', 'mmio_delivery'),
                ('status_cpu_load_event_id', 'cpu_retire'),
                ('status_cpu_store_event_id', 'cpu_retire')):
            cited(case, field, kind)
        read = cited(case, 'fifo_read_event_id', 'dma_edge')
        write = cited(case, 'dma_write_event_id', 'memory_write')
        take = cited(case, 'irq_event_id', 'cpu_external_irq_taken')
        completed = cited(case, 'completed_event_id', 'memory_write')
        source = cited(case, 'bound_source_event_id', 'source_start')
        bound_take = cited(case, 'bound_take_event_id', 'cpu_irq_taken')
        irq_edge = cited(case, 'dma_irq_edge_event_id', 'dma_edge')
        status_load = cited(case, 'status_cpu_load_event_id', 'cpu_retire')
        status_store = cited(case, 'status_cpu_store_event_id', 'cpu_retire')
        status_delivery = cited(case, 'status_delivery_event_id', 'mmio_delivery')
        if completed is not None and completed.get('value') != case['counter']:
            problems.append(f"case {case['counter']}: completed store is not this case")
        if write is not None and write.get('value') != case['source_byte']:
            problems.append(f"case {case['counter']}: DMA RAM write does not carry the source byte")
        if read is not None:
            delivery = read.get('target_delivery') or {}
            if (delivery.get('write') is not False
                    or delivery.get('value') != case['source_byte']):
                problems.append(f"case {case['counter']}: DMA UART read does not carry the source byte")
        if source is not None and bound_take is not None:
            if source.get('source_event_id') != bound_take.get('source_event_id'):
                problems.append(f"case {case['counter']}: CPU take is not joined to the bound source")
            if take is not None and bound_take.get('cpu_tick') != take.get('local_tick'):
                problems.append(f"case {case['counter']}: CPU take tick differs from external irq tick")
        if irq_edge is not None and source is not None:
            if irq_edge.get('native_local_tick') != source.get('source_tick'):
                problems.append(f"case {case['counter']}: DMA IRQ edge tick differs from bound source tick")
        if status_delivery is not None and status_load is not None and status_store is not None:
            if not status_delivery['event_id'] <= status_load['event_id'] < status_store['event_id']:
                problems.append(f"case {case['counter']}: status register flow is out of order")
        ordering = [case[field] for field in ('fifo_read_event_id', 'dma_write_event_id',
            'irq_event_id', 'cpu_load_event_id', 'completed_event_id')]
        if len(set(ordering)) != len(ordering) or ordering != sorted(ordering):
            problems.append(f"case {case['counter']}: FIFO/DMA/IRQ/ISR ordering is not increasing")
    if result.cases and result.local_ticks != result.cases[-1]['ticks_after']:
        problems.append('final local_ticks differ from the last case ticks_after')
    return problems


def _fresh_equality(positive: ContinuousRxResult,
                    fresh: ContinuousRxResult) -> dict:
    normalized_positive = _normalize(positive.events, positive.execution_ids)
    normalized_fresh = _normalize(fresh.events, fresh.execution_ids)
    executed = {value for value in fresh.execution_ids.values() if value is not None}
    return dict(
        cases=positive.cases == fresh.cases,
        plan_commands=positive.plan.commands == fresh.plan.commands,
        local_ticks=positive.local_ticks == fresh.local_ticks,
        identities=positive.identities == fresh.identities,
        normalized_events=normalized_positive == normalized_fresh,
        distinct_execution_ids=len(executed) == 4,
        phase=positive.phase == fresh.phase and fresh.phase == 'complete',
        error=positive.error is None and fresh.error is None)


def _before_after_structure(before: ContinuousRxResult,
                            after: ContinuousRxResult) -> dict:
    before_cases = _case_structure(before)
    after_cases = _case_structure(after)
    before_keys = [set(case) for case in before.cases]
    after_keys = [set(case) for case in after.cases]
    semantic_equal = before_cases == after_cases
    moved = []
    for old, new in zip(before.cases, after.cases):
        diff = [field for field in EVENT_INDEX_FIELDS if old.get(field) != new.get(field)]
        moved.append(dict(counter=new['counter'], changed_event_ids=diff))
    return dict(
        case_count_equal=len(before.cases) == len(after.cases),
        case_keys_added=sorted(set().union(*after_keys) - set().union(*before_keys)),
        case_keys_removed=sorted(set().union(*before_keys) - set().union(*after_keys)),
        semantic_fields_equal=semantic_equal,
        semantic_diff=[dict(counter=old['counter'], field=field,
            before=old.get(field), after=new.get(field))
            for old, new in zip(before_cases, after_cases) for field in SEMANTIC_CASE_FIELDS
            if old.get(field) != new.get(field)],
        event_index_fields_changed=moved,
        prefix_sha256_changed=all(old.get('prefix_sha256') != new.get('prefix_sha256')
            for old, new in zip(before.cases, after.cases)),
        fifo_origin=[case.get('fifo_origin') for case in after.cases],
        proof_grade=[case.get('proof_grade') for case in after.cases])


def _search_audit(root: Path) -> dict:
    before_path = root / 'before/search-guided-stats.json'
    after_path = root / 'after/search/stats.json'
    if not after_path.exists() or not (root / 'after/search/search.json.gz').exists():
        return dict(status='pending', guided_passed=False,
            recomputed_status='pending', recomputed_findings=['search gate not run'],
            case_fields=dict(all_completed_chains=False, all_prefix_sha256=False),
            comparison={})
    before_stats = json.loads(before_path.read_text())
    after_stats = json.loads(after_path.read_text())
    loaded = search.DmaSearchResult.from_document(
        _load_search(root / 'after/search/search.json.gz'))
    findings, recomputed = search._evaluate_search(loaded)
    after_counts = _counts(loaded.result)
    before_search_path = root / 'before/search-guided-search.json.gz'
    before_counts = None
    if before_search_path.exists():
        before_counts = _counts(search.DmaSearchResult.from_document(
            _load_search(before_search_path)).result)
    def throughput(counts):
        if counts is None:
            return None
        cases = max(1, len(counts['per_case']))
        return dict(
            commands=counts['commands'], events=counts['events'],
            local_ticks=counts['local_ticks'],
            uart_local_tick_samples=counts['uart_local_tick_samples_post'],
            commands_per_case=round(counts['commands'] / cases, 3),
            uart_ticks_per_case=round(counts['local_ticks']['uart'] / cases, 3),
            poll_uart_steps=[case['poll_uart_steps'] for case in counts['per_case']],
            uart_ticks=[case['uart_ticks'] for case in counts['per_case']])
    before_throughput = throughput(before_counts)
    after_throughput = throughput(after_counts)
    throughput_ratio = None
    if before_throughput and after_throughput and after_throughput['uart_ticks_per_case']:
        throughput_ratio = round(before_throughput['uart_ticks_per_case']
            / after_throughput['uart_ticks_per_case'], 4)
    return dict(
        status='audited',
        before=before_stats, after=after_stats,
        search_throughput=dict(
            before=before_throughput, after=after_throughput,
            uart_ticks_per_case_ratio=throughput_ratio),
        case_fields=dict(
            case_count=len(loaded.cases),
            all_completed_chains=all(case.completed_chain for case in loaded.cases),
            all_prefix_sha256=all(case.prefix_sha256 for case in loaded.cases),
            effective_search_seconds=recomputed.get('effective_search_seconds'),
            search_wall_seconds=recomputed.get('search_wall_seconds')),
        recomputed_findings=findings,
        recomputed_status=recomputed.get('search_status'),
        guided_passed=after_stats.get('search_status') == 'ok',
        keys=('case_count', 'executed_cases', 'effective_search_seconds',
              'search_wall_seconds', 'completed_chains',
              'distinct_effective_specs', 'feedback_influenced', 'search_status'),
        comparison={key: dict(before=before_stats.get(key), after=after_stats.get(key))
            for key in ('case_count', 'executed_cases', 'effective_search_seconds',
                        'search_wall_seconds', 'completed_chains',
                        'distinct_effective_specs', 'feedback_influenced',
                        'search_status')})


def _ratio(before, after):
    return None if not after else round(before / after, 4)


def audit(root: Path) -> dict:
    before_positive = _load_result(root / 'before/continuous-positive.json.gz')
    before_fresh = _load_result(root / 'before/continuous-fresh.json.gz')
    after_positive = _load_result(root / 'after/continuous/positive.json.gz')
    after_fresh = _load_result(root / 'after/continuous/fresh.json.gz')
    before_counts = _counts(before_positive)
    after_counts = _counts(after_positive)
    before_case_ticks = [case['uart_ticks'] for case in before_counts['per_case']]
    after_case_ticks = [case['uart_ticks'] for case in after_counts['per_case']]
    before_case_commands = [case['commands'] for case in before_counts['per_case']]
    after_case_commands = [case['commands'] for case in after_counts['per_case']]
    uart_per_case_before = before_counts['local_ticks']['uart'] / max(1, len(before_case_ticks))
    uart_per_case_after = after_counts['local_ticks']['uart'] / max(1, len(after_case_ticks))
    uart_ratio = _ratio(uart_per_case_before, uart_per_case_after)
    command_ratio = _ratio(before_counts['commands'], after_counts['commands'])
    poll_before = [case['poll_uart_steps'] for case in before_counts['per_case']]
    poll_after = [case['poll_uart_steps'] for case in after_counts['per_case']]
    joins = _check_case_joins(after_positive)
    structure = _before_after_structure(before_positive, after_positive)
    fresh = _fresh_equality(after_positive, after_fresh)
    before_fresh_equality = _fresh_equality(before_positive, before_fresh)
    search_audit = _search_audit(root)
    five_x = bool(uart_ratio is not None and uart_ratio >= 5.0)
    report = dict(
        schema_version='dma_s1c_throughput_audit.v1',
        evidence_root=str(root),
        before=dict(counts=before_counts,
                    fresh_equality=before_fresh_equality),
        after=dict(counts=after_counts, fresh_equality=fresh,
                   case_joins=joins),
        comparison=dict(
            uart_ticks_per_case=dict(before=round(uart_per_case_before, 3),
                after=round(uart_per_case_after, 3), ratio=uart_ratio),
            uart_ticks_per_case_list=dict(before=before_case_ticks,
                after=after_case_ticks,
                ratios=[_ratio(old, new) for old, new in
                    zip(before_case_ticks, after_case_ticks)]),
            commands=dict(before=before_counts['commands'],
                after=after_counts['commands'], ratio=command_ratio),
            commands_per_case=dict(before=before_case_commands,
                after=after_case_commands),
            poll_uart_steps=dict(before=poll_before, after=poll_after,
                ratio=_ratio(sum(poll_before), sum(poll_after)),
                removed=sum(poll_before) - sum(poll_after)),
            waveform_uart_only_commands=dict(
                before=before_counts['uart_only_waveform_commands'],
                after=after_counts['uart_only_waveform_commands']),
            local_ticks=dict(before=before_counts['local_ticks'],
                after=after_counts['local_ticks']),
            five_x_uart_ticks_met=five_x,
            five_x_commands_met=bool(command_ratio is not None and command_ratio >= 5.0),
            five_x_conclusion=(
                'met' if five_x else
                'not_met: only poll-phase idle UART ticks were removed; the real '
                'waveform/idle-margin ticks and the one-command-per-tick harness '
                'granularity remain. 5x requires the bounded multi-tick harness '
                'command that the design explicitly excludes from S1c.'),
            case_structure=structure),
        search=search_audit,
        ok=bool(
            not joins
            and all(fresh.values())
            and structure['case_count_equal']
            and structure['semantic_fields_equal']
            and not structure['case_keys_removed']
            and structure['prefix_sha256_changed']
            and search_audit['recomputed_status'] == 'ok'
            and not search_audit['recomputed_findings']
            and search_audit['case_fields']['all_completed_chains']
            and search_audit['case_fields']['all_prefix_sha256']))
    return report


def main(argv):
    if len(argv) not in (2, 3):
        raise SystemExit('usage: audit_s1c_throughput.py <evidence-root> [out.json]')
    root = Path(argv[1]).resolve()
    report = audit(root)
    document = json.dumps(report, indent=1, sort_keys=True)
    if len(argv) == 3:
        Path(argv[2]).write_text(document + '\n', encoding='utf-8')
    print(document)
    print('ok=' + str(report['ok']))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
