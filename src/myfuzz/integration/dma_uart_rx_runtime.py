"""Bounded continuous native UART/DMA cases and full batch-prefix replay.

Execution is explicit: importing this module never builds or starts native RTL.
This directed runtime has no search or live-authority admission claim.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from itertools import islice
from pathlib import Path
from typing import Callable

from myfuzz.scenario.batch import (BatchAdvance, BatchSourceEvent,
    ScenarioBatchPlan, ScenarioBatchRecorder)
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ibex_dma_example import DESTINATION, RESULT
from myfuzz.scenario.ibex_dma_uart_rx_continuous import (
    COMPLETED, UART_STATUS_OFFSET, UART_RXEMPTY_MASK,
    make_continuous_uart_rx_runner)
from myfuzz.scenario.ibex_dma_uart_example import UART_BASE
from myfuzz.scenario.replay import ScenarioTrace
from myfuzz.scenario.runner import ScenarioRunner


@dataclass(frozen=True)
class ContinuousRxResult:
    plan: ScenarioBatchPlan
    trace: ScenarioTrace
    cases: tuple[dict, ...]
    identities: dict
    execution_ids: dict


def _positive(value, name, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f'{name} must be in 1..{maximum}')


def _case_evidence(rows, expected, counter):
    """Correlate native read/pop, DMA write version, CPU load and ISR commit."""
    frames = [e for e in rows if e.get('kind') == 'uart_frame_validation'
        and e.get('waveform_matched') and e.get('byte') == expected]
    if len(frames) != 1:
        raise RuntimeError('case needs one matching native serial frame')
    reads = [e for e in rows if e.get('kind') == 'dma_edge'
        and e.get('target_delivery', {}).get('target_component') == 'uart']
    if len(reads) != 1:
        raise RuntimeError('case needs exactly one native DMA UART read')
    delivery = reads[0]['target_delivery']
    capture = delivery.get('target_uart_access', {}).get('read_capture', {})
    if (delivery.get('address') != UART_BASE + 0x18
            or delivery.get('write') is not False
            or delivery.get('value') != expected
            or capture.get('pre', {}).get('probe_uart_fifo_rdata_re') != 1):
        raise RuntimeError('native FIFO read/pop does not match source byte')
    writes = [e for e in rows if e.get('kind') == 'memory_write'
        and e.get('component') == 'dma' and e.get('address') == DESTINATION]
    if len(writes) != 1 or writes[0].get('value') != expected:
        raise RuntimeError('case needs one accepted DMA RAM write of source byte')
    write = writes[0]
    polls = [e for e in rows if e.get('kind') == 'mmio_delivery'
        and e.get('device_id') == 'uart' and e.get('write') is False
        and e.get('address') == UART_BASE + UART_STATUS_OFFSET
        and type(e.get('read_value')) is int
        and not (e['read_value'] & UART_RXEMPTY_MASK)
        and e['event_id'] < reads[0]['event_id']]
    if not polls:
        raise RuntimeError('CPU must observe actual UART nonempty STATUS before DMA')
    read_key = delivery['source_transaction']
    write_key = write['transaction']
    if (any(read_key.get(k) != write_key.get(k) for k in
            ('execution_id', 'testcase_id', 'source_component', 'source_epoch', 'channel_id'))
            or write_key['source_sequence'] != read_key['source_sequence'] + 1):
        raise RuntimeError('DMA FIFO read and RAM write are not adjacent master transactions')
    loads = [e for e in rows if e.get('kind') == 'memory_read'
        and e.get('component') == 'cpu' and e.get('address') == DESTINATION
        and e.get('transaction', {}).get('channel_id') == 'data'
        and e.get('value') == expected and e['event_id'] > write['event_id']
        and tuple(tuple(v) for v in e.get('versions', ()))
        == (tuple(write['version']),) * 4]
    if len(loads) != 1:
        raise RuntimeError('ISR CPU load must consume the exact DMA RAM version')
    cpu_writes = [e for e in rows if e.get('kind') == 'memory_write'
        and e.get('component') == 'cpu']
    def commit(address, value):
        matches = [e for e in cpu_writes if e.get('address') == address
            and e.get('value') == value]
        if len(matches) != 1:
            raise RuntimeError('missing or duplicate CPU ISR result commit')
        return matches[0]
    cause = commit(RESULT, 0x8000000b)
    status = commit(RESULT + 4, 0)
    value = commit(RESULT + 8, expected)
    completed = commit(COMPLETED, counter)
    irqs = [e for e in rows if e.get('kind') == 'cpu_external_irq_taken']
    if (len(irqs) != 1 or not (reads[0]['event_id'] < write['event_id']
            < irqs[0]['event_id'] < cause['event_id'] < status['event_id']
            < loads[0]['event_id'] < value['event_id'] < completed['event_id'])):
        raise RuntimeError('case native FIFO/DMA/IRQ/ISR ordering is incomplete')
    return dict(counter=counter, source_byte=expected,
        fifo_read_event_id=reads[0]['event_id'], dma_write_event_id=write['event_id'],
        cpu_load_event_id=loads[0]['event_id'], irq_event_id=irqs[0]['event_id'],
        completed_event_id=completed['event_id'])


def _identities(runner):
    return ({n: s.identity_document() for n, s in runner.sessions.items()},
        {**{n: s._execution for n, s in runner.sessions.items()},
         'runner': runner.execution_id})


def _close(runner):
    # Try all peers even if one end command fails.
    for session in runner.sessions.values():
        try:
            session.end_case()
        except Exception:
            pass


def run_continuous_uart_rx(source_bytes, *, cache_dir: Path,
        max_rounds_per_case=4096, max_source_ticks=2048,
        budget: ResourceBudget | None = None,
        factory: Callable[[], ScenarioRunner] | None = None) -> ContinuousRxResult:
    """Record 1..16 byte cases in one boot, with no intervening resets.

    During a serial waveform only UART advances: its native TLUL adapter
    explicitly forbids register access overlapping that waveform. After the
    frame completes, CPU polls the actual STATUS register before launching DMA.
    All advances and source admissions are recorded in one ScenarioBatchPlan.
    """
    values = tuple(islice(iter(source_bytes), 17))
    _positive(len(values), 'case count', 16)
    if any(type(v) is not int or not 0 <= v <= 255 for v in values):
        raise ValueError('source bytes must be integers in 0..255')
    _positive(max_rounds_per_case, 'max_rounds_per_case', 4096)
    _positive(max_source_ticks, 'max_source_ticks', 4096)
    runner = factory() if factory else make_continuous_uart_rx_runner(cache_dir=cache_dir)
    runner.set_resource_budget(budget or ResourceBudget(max_wall_time_ms=300000))
    template = ScenarioGenome('continuous-dma-uart-rx', 'IP_TO_CPU',
        'uart-fifo-dma-ram-cpu-isr', ('dma', 'cpu', 'uart'),
        3 * 512 + len(values) * (max_source_ticks + 3 * max_rounds_per_case), ())
    recorder = ScenarioBatchRecorder(template, runner)
    cases = []
    try:
        recorder.begin()
        uart = runner.sessions['uart']
        router = runner.sessions['cpu'].router
        # Only boot: wait for the CPU's actual UART CTRL acceptance/delivery.
        for _ in range(512):
            recorder.advance(('dma', 'cpu', 'uart'))
            if any(d['device_id'] == 'uart' and d['offset'] == 0x10
                    and d['write'] for d in router.deliveries):
                break
        else:
            raise RuntimeError('CPU UART initialization exceeded boot bound')
        for index, source in enumerate(values, 1):
            start = runner.event_count
            action_id = f'continuous-rx-{index}'
            recorder.submit_source_event(BatchSourceEvent(action_id,
                'uart', 'uart_rx_byte', source, width=8))
            for _ in range(max_source_ticks):
                recorder.advance(('uart',))
                ended = any(e.get('kind') == 'uart_source_frame_end'
                    and e.get('action_id') == action_id and e.get('waveform_matched')
                    for e in uart.source_events)
                if ended and uart.register_access_conflict() is None:
                    break
            else:
                raise RuntimeError('native serial frame exceeded source bound')
            for _ in range(max_rounds_per_case):
                recorder.advance(('dma', 'cpu', 'uart'))
                # A native CPU store is the completion signal, never a host write.
                commits = [e for e in runner.events_since(start)
                    if e.get('kind') == 'memory_write' and e.get('component') == 'cpu'
                    and e.get('address') == COMPLETED]
                if commits:
                    if len(commits) != 1 or commits[0].get('value') != index:
                        raise RuntimeError('CPU completed-case counter is not monotonic')
                    cases.append(_case_evidence(runner.events_since(start), source, index))
                    break
            else:
                raise RuntimeError('CPU ISR completion exceeded per-case bound')
        identities, execution_ids = _identities(runner)
        trace = recorder.finish()
        if trace.status != 'complete':
            raise RuntimeError(f'continuous RX terminal status: {trace.status}')
        return ContinuousRxResult(recorder.plan, trace, tuple(cases), identities, execution_ids)
    finally:
        if not recorder._finished:
            _close(runner)


def _normalize(events, execution_ids):
    serialized = json.dumps(events, sort_keys=True)
    for component, value in execution_ids.items():
        if type(value) is not str or not value:
            raise ValueError('missing native execution identity')
        serialized = serialized.replace(value, 'execution:' + component)
    return json.loads(serialized)


def replay_continuous_uart_rx(reference: ContinuousRxResult, *, cache_dir: Path,
        budget: ResourceBudget | None = None,
        factory: Callable[[], ScenarioRunner] | None = None) -> ContinuousRxResult:
    """Replay the original sources and all recorded boundaries in fresh peers.

    Compare the full finalized journal, normalizing only declared execution
    identities, and recheck every case from the original source records.
    """
    runner = factory() if factory else make_continuous_uart_rx_runner(cache_dir=cache_dir)
    runner.set_resource_budget(budget or ResourceBudget(max_wall_time_ms=300000))
    recorder = ScenarioBatchRecorder(reference.plan.template, runner)
    cases = []
    try:
        recorder.begin()
        identities, execution_ids = _identities(runner)
        if identities != reference.identities:
            raise RuntimeError('fresh native identity documents differ')
        if any(execution_ids[n] == reference.execution_ids[n] for n in execution_ids):
            raise RuntimeError('replay requires fresh native processes and Runner')
        for command in reference.plan.commands:
            if isinstance(command, BatchSourceEvent):
                recorder.submit_source_event(command)
            elif isinstance(command, BatchAdvance):
                recorder.advance(command.schedule)
            else:
                raise ValueError('unknown batch command')
        trace = recorder.finish()
        if (trace.status != reference.trace.status
                or trace.local_ticks != reference.trace.local_ticks
                or _normalize(trace.events, execution_ids)
                != _normalize(reference.trace.events, reference.execution_ids)):
            raise RuntimeError('fresh replay differs from the complete original journal')
        sources = [e for e in trace.events if e.get('kind') == 'source_injection']
        original = [c for c in reference.plan.commands if isinstance(c, BatchSourceEvent)]
        if len(sources) != len(original):
            raise RuntimeError('replay source count differs')
        for i, (event, command) in enumerate(zip(sources, original)):
            if event.get('value') != command.value or event.get('action_id') != command.action_id:
                raise RuntimeError('replay source differs from original record')
            end = sources[i + 1]['event_id'] if i + 1 < len(sources) else float('inf')
            rows = [e for e in trace.events if event['event_id'] <= e['event_id'] < end]
            cases.append(_case_evidence(rows, command.value, i + 1))
        if tuple(cases) != reference.cases:
            raise RuntimeError('replay per-case causal evidence differs')
        return ContinuousRxResult(recorder.plan, trace, tuple(cases), identities, execution_ids)
    finally:
        if not recorder._finished:
            _close(runner)
