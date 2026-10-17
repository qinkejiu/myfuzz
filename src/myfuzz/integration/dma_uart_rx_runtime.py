"""Bounded continuous native UART/DMA cases and full batch-prefix replay.

Execution is explicit: importing this module never builds or starts native RTL.
This directed runtime has no search or live-authority admission claim.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from itertools import islice
from pathlib import Path
from typing import Callable

from myfuzz.local_harness.build import host_source_discovery_scope
from myfuzz.scenario.batch import (BatchAdvance, BatchSourceEvent,
    ScenarioBatchCodec, ScenarioBatchPlan, ScenarioBatchRecorder)
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ibex_dma_example import DMA_BASE, DESTINATION, ISR, RESULT, ROOT
from myfuzz.scenario.ibex_dma_uart_rx_continuous import (
    COMPLETED, UART_STATUS_OFFSET, UART_RXEMPTY_MASK,
    make_continuous_uart_rx_runner)
from myfuzz.scenario.ibex_dma_uart_example import UART_BASE
from myfuzz.scenario.replay import ScenarioTrace
from myfuzz.scenario.runner import ScenarioRunner


@dataclass(frozen=True)
class ContinuousRxResult:
    plan: ScenarioBatchPlan
    trace: ScenarioTrace | None
    cases: tuple[dict, ...]
    identities: dict
    execution_ids: dict
    budget: ResourceBudget
    phase: str
    case_index: int
    error: dict | None
    events: tuple[dict, ...]
    local_ticks: dict
    uncertain_status: dict
    source_pins: dict

    def to_document(self):
        """Portable diagnostic bundle; serialized claims convey no authority."""
        return dict(schema_version='continuous_dma_rx_diagnostic.v1',
            plan=json.loads(ScenarioBatchCodec.encode(self.plan)),
            trace=asdict(self.trace) if self.trace is not None else None,
            cases=self.cases, identities=self.identities, execution_ids=self.execution_ids,
            budget=self.budget.to_document(), phase=self.phase, case_index=self.case_index,
            error=self.error, events=self.events, local_ticks=self.local_ticks,
            uncertain_status=self.uncertain_status, source_pins=self.source_pins)

    def save_bundle(self, path: Path):
        Path(path).write_text(json.dumps(self.to_document(), sort_keys=True,
            allow_nan=False), encoding='utf-8')

    @classmethod
    def load_bundle(cls, path: Path):
        return cls.from_document(json.loads(Path(path).read_text(encoding='utf-8')))

    @classmethod
    def from_document(cls, document):
        if document.get('schema_version') != 'continuous_dma_rx_diagnostic.v1':
            raise ValueError('unsupported continuous RX diagnostic bundle')
        return cls(ScenarioBatchCodec.decode(json.dumps(document['plan']).encode()),
            ScenarioTrace(**document['trace']) if document['trace'] is not None else None,
            tuple(document['cases']), document['identities'], document['execution_ids'],
            ResourceBudget.from_document(document['budget']), document['phase'],
            document['case_index'], document['error'], tuple(document['events']),
            document['local_ticks'], document['uncertain_status'], document['source_pins'])


class ContinuousRxFailure(RuntimeError):
    """Failure with the original source/command prefix and finalized diagnostics."""
    def __init__(self, result):
        self.result = result
        super().__init__(str(result.error))


def _source_pins():
    names = sorted(str(p.relative_to(ROOT))
        for p in (ROOT / 'src/myfuzz').rglob('*.py'))
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}


def _capture(recorder, runner, cases, budget, phase, case_index, error=None, source_pins=None):
    # Preserve issuance-time identities before end_case closes transport peers.
    identities, ids = _identities(runner)
    pending_before = runner._uncertain_transactions()
    trace = None
    cleanup_error = None
    try:
        if not recorder._finished:
            trace = recorder.finish()
        else:
            trace = recorder.trace
    except Exception as exc:
        cleanup_error = dict(type=type(exc).__name__, message=str(exc))
        _close(runner)
    if error is None and (cleanup_error is not None or trace is None or trace.status != 'complete'):
        phase = 'finalize'
        error = dict(type='FinalizationFailure', message=str(cleanup_error or
            (trace.status if trace is not None else 'trace_unavailable')),
            command_count=len(recorder.commands), case_start=runner.event_count)
    drift = source_pins is not None and source_pins != _source_pins()
    if error is None and drift:
        phase = 'finalize'
        error = dict(type='SourceDrift', message='host source changed during execution',
            command_count=len(recorder.commands), case_start=runner.event_count)
    events = tuple(runner.events)
    uncertain = dict(runner_failure=runner.failure_status,
        pending_before_finalize=pending_before,
        pending_after_finalize=runner._uncertain_transactions(),
        source_drift=drift,
        cleanup_error=cleanup_error,
        markers=[e for e in events if e.get('kind') in
            ('budget_exhausted', 'command_failed', 'runtime_failure')
            or e.get('uncertain_transactions') or e.get('cleanup_errors')])
    return ContinuousRxResult(ScenarioBatchPlan(recorder.template, recorder.commands),
        trace, tuple(cases), identities, ids, budget, phase, case_index, error,
        events, dict(runner.local_ticks), uncertain, source_pins or _source_pins())


def _positive(value, name, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f'{name} must be in 1..{maximum}')


def _case_evidence(rows, expected, counter, action_id):
    """Historical joins; frame-to-FIFO origin remains explicitly unknown."""
    frames = [e for e in rows if e.get('kind') == 'uart_frame_validation'
        and e.get('waveform_matched') and e.get('byte') == expected
        and e.get('action_id') == action_id]
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
    starts = [e for e in rows if e.get('kind') == 'source_start'
        and tuple(e.get('source', ())) == ('dma', 'irq')
        and tuple(e.get('target', ())) == ('cpu', 'irq')]
    taken = [e for e in rows if e.get('kind') == 'cpu_irq_taken'
        and tuple(e.get('source', ())) == ('dma', 'irq')
        and tuple(e.get('target', ())) == ('cpu', 'irq')
        and e.get('cpu_tick') == irqs[0].get('local_tick')]
    if len(starts) != 1 or len(taken) != 1 or starts[0]['source_event_id'] != taken[0]['source_event_id']:
        raise RuntimeError('CPU native take is not joined to the DMA bound pulse')
    irq_edges = [e for e in rows if e.get('kind') == 'dma_edge'
        and e.get('native_local_tick') == starts[0]['source_tick']
        and any(e.get('payload', {}).get('observations', {}).get('physical', {}).values())
        and e.get('payload', {}).get('pre_backend', {}).get('mwb_ack') == 1
        and e.get('payload', {}).get('pre_backend', {}).get('mwb_we') == 1
        and e.get('payload', {}).get('pre_backend', {}).get('mwb_err') == 0]
    if len(irq_edges) != 1 or not write['event_id'] < irq_edges[0]['event_id'] < irqs[0]['event_id']:
        raise RuntimeError('DMA completion ACK/native IRQ does not match bound source tick')
    status_reads = [e for e in rows if e.get('kind') == 'mmio_delivery'
        and e.get('device_id') == 'dma' and e.get('address') == DMA_BASE
        and e.get('write') is False and e.get('read_value') == 0
        and cause['event_id'] < e['event_id'] < status['event_id']]
    if len(status_reads) != 1:
        raise RuntimeError('ISR status store lacks native DMA status MMIO delivery')
    status_key = status_reads[0]['source_transaction']
    responses = [e for e in rows if e.get('kind') == 'data_response'
        and e.get('transaction') == status_key and e.get('rdata') == 0]
    status_loads = [e for e in rows if e.get('kind') == 'cpu_retire'
        and e.get('pc_rdata') == ISR + 8 and e.get('mem_addr') == DMA_BASE
        and e.get('mem_rmask') == 15 and e.get('mem_rdata') == 0
        and e.get('rd_addr') == 7 and e.get('rd_wdata') == 0]
    status_stores = [e for e in rows if e.get('kind') == 'cpu_retire'
        and e.get('pc_rdata') == ISR + 12 and e.get('mem_addr') == RESULT + 4
        and e.get('mem_wmask') == 15 and e.get('mem_wdata') == 0
        and e.get('rs2_addr') == 7 and e.get('rs2_rdata') == 0]
    if len(responses) != 1 or len(status_loads) != 1 or len(status_stores) != 1:
        raise RuntimeError('DMA status lacks native CPU response/load/store register flow')
    # CPU memory service commits stores before retirement; do not equate those
    # event orders. Require response/load before the native store retirement.
    if not (responses[0]['event_id'] <= status_loads[0]['event_id'] < status_stores[0]['event_id']):
        raise RuntimeError('native status register flow is out of order')
    return dict(counter=counter, source_byte=expected,
        action_id=action_id, frame_id=frames[0].get('frame_id'),
        dma_irq_edge_event_id=irq_edges[0]['event_id'],
        bound_source_event_id=starts[0]['event_id'], bound_take_event_id=taken[0]['event_id'],
        status_delivery_event_id=status_reads[0]['event_id'],
        status_cpu_load_event_id=status_loads[0]['event_id'],
        status_cpu_store_event_id=status_stores[0]['event_id'],
        fifo_origin='unknown', proof_grade='bounded_historical_chain',
        status_register_flow='native_cpu_rvfi_historical',
        fifo_read_event_id=reads[0]['event_id'], dma_write_event_id=write['event_id'],
        cpu_load_event_id=loads[0]['event_id'], irq_event_id=irqs[0]['event_id'],
        completed_event_id=completed['event_id'])


def _execution_ids(runner):
    return {**{n: getattr(s, '_execution', None) for n, s in runner.sessions.items()},
        'runner': runner.execution_id}


def _identities(runner):
    return ({n: s.identity_document() for n, s in runner.sessions.items()},
        _execution_ids(runner))


def _close(runner):
    # Try all peers even if one end command fails.
    for session in runner.sessions.values():
        try:
            session.end_case()
        except Exception:
            pass


CASE_PREFIX_SCHEMA = 'continuous_dma_case_prefix.v1'


def _command_document(command):
    """Same wire fields as ScenarioBatchCodec, without the genome template."""
    if isinstance(command, BatchSourceEvent):
        return dict(kind='source_event', action_id=command.action_id,
            component=command.component, port=command.port, value=command.value,
            bit_offset=command.bit_offset, width=command.width)
    if isinstance(command, BatchAdvance):
        return dict(kind='advance', schedule=list(command.schedule))
    raise ValueError('unknown batch command')


def _prefix_digest(commands, rows, ticks_before, ticks_after, execution_ids):
    """Fresh-comparable digest of one case command/event/tick prefix."""
    document = dict(schema_version=CASE_PREFIX_SCHEMA,
        commands=[_command_document(command) for command in commands],
        events=_normalize(rows, execution_ids),
        ticks_before=dict(ticks_before), ticks_after=dict(ticks_after))
    return hashlib.sha256(json.dumps(document, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False)
        .encode('utf-8')).hexdigest()


def _fifo_depth_after(rows):
    """Last observed FIFO depth in the case slice, or None without a sample."""
    depth = None
    for event in rows:
        if event.get('kind') == 'uart_tick_observation':
            post = event.get('post')
            if isinstance(post, dict) and type(post.get('probe_uart_fifo_depth')) is int:
                depth = post['probe_uart_fifo_depth']
    return depth


def _case_boundaries(*, commands, rows, command_start, command_end,
        event_start, event_end, ticks_before, ticks_after, execution_ids):
    """Per-case command/event/tick boundaries plus a normalized prefix digest.

    ``event_start``/``event_end`` are zero-based journal indices in the same
    units as ``ScenarioRunner.events_since``; ``command_start``/``command_end``
    index ``ScenarioBatchPlan.commands``.
    """
    return dict(command_start=command_start, command_end=command_end,
        event_start=event_start, event_end=event_end,
        ticks_before=dict(ticks_before), ticks_after=dict(ticks_after),
        prefix_sha256=_prefix_digest(commands[command_start:command_end],
            rows, ticks_before, ticks_after, execution_ids),
        fifo_depth_after=_fifo_depth_after(rows))


class _ContinuousRxBoot:
    """One supplied boot that can execute successive bounded RX cases.

    Public continuous runners keep their existing command stream through this
    object; a search layer reuses it to place decisions between cases without
    rebooting native components. No method starts native RTL by itself.
    """

    def __init__(self, runner: ScenarioRunner, *, budget: ResourceBudget,
                 template: ScenarioGenome, source_pins: dict) -> None:
        if not isinstance(budget, ResourceBudget):
            raise ValueError('ResourceBudget is required')
        if not isinstance(template, ScenarioGenome):
            raise ValueError('ScenarioGenome template is required')
        if not isinstance(source_pins, dict) or not source_pins:
            raise ValueError('host source pins are required')
        self.runner = runner
        self.budget = budget
        self.template = template
        self.source_pins = dict(source_pins)
        self.recorder = ScenarioBatchRecorder(template, runner)
        self.cases: list[dict] = []
        self.phase = 'boot'
        self.case_index = 0
        self.case_start = 0
        self.case_failure: dict | None = None
        self.booted = False

    def boot(self) -> None:
        """Wait for the real CPU UART CTRL request before the first waveform."""
        self.recorder.begin()
        self.booted = True
        router = self.runner.sessions['cpu'].router
        # A genome-owned UART cannot take its first step without an admitted
        # byte. Boot CPU/DMA until the actual CTRL request is queued; the first
        # source admission then starts UART and its idle margin lets that real
        # CTRL transaction finish before the serial waveform starts.
        for _ in range(512):
            self.recorder.advance(('dma', 'cpu'))
            if 'uart' in router.ready_targets:
                return
        raise RuntimeError('CPU UART initialization exceeded boot bound')

    def run_case(self, source_bytes: tuple[int, ...], *, case_index: int,
                 action_prefix: str = 'continuous-rx', max_source_ticks: int = 2048,
                 max_rounds_per_case: int = 4096,
                 expected: dict | None = None) -> dict:
        """Admit exactly one serial byte, then certify the native DMA chain."""
        if not self.booted or self.recorder._finished:
            raise RuntimeError('continuous RX boot is not active')
        values = tuple(source_bytes)
        if len(values) != 1:
            raise ValueError('continuous RX boot executes exactly one serial byte per case')
        source = values[0]
        if type(source) is not int or not 0 <= source <= 255:
            raise ValueError('source bytes must be integers in 0..255')
        _positive(case_index, 'case index', 1 << 20)
        _positive(max_rounds_per_case, 'max_rounds_per_case', 4096)
        _positive(max_source_ticks, 'max_source_ticks', 4096)
        outcome = {'outcome': 'complete'} if expected is None else expected
        if not isinstance(outcome, dict) or outcome.get('outcome') != 'complete':
            raise ValueError('S1 continuous RX boot certifies only a complete chain')
        self.phase, self.case_index = 'source', case_index
        start = self.case_start = self.runner.event_count
        command_start = len(self.recorder.commands)
        ticks_before = dict(self.runner.local_ticks)
        execution_ids = _execution_ids(self.runner)
        action_id = f'{action_prefix}-{case_index}'
        try:
            evidence = self._execute_case(source, case_index, action_id,
                start, command_start, ticks_before, execution_ids,
                max_source_ticks=max_source_ticks,
                max_rounds_per_case=max_rounds_per_case)
        except Exception as exc:
            self.case_failure = self._failure_boundaries(action_id, command_start,
                start, ticks_before, execution_ids)
            raise exc
        return evidence

    def _execute_case(self, source, case_index, action_id, start, command_start,
                      ticks_before, execution_ids, *, max_source_ticks,
                      max_rounds_per_case):
        runner, recorder = self.runner, self.recorder
        recorder.submit_source_event(BatchSourceEvent(action_id,
            'uart', 'uart_rx_byte', source, width=8))
        uart = runner.sessions['uart']
        # During the waveform only UART advances: its native TLUL adapter
        # forbids register access overlapping that waveform.
        for _ in range(max_source_ticks):
            recorder.advance(('uart',))
            ended = any(e.get('kind') == 'uart_source_frame_end'
                and e.get('action_id') == action_id and e.get('waveform_matched')
                for e in uart.source_events)
            if ended and uart.register_access_conflict() is None:
                break
        else:
            raise RuntimeError('native serial frame exceeded source bound')
        self.phase = 'isr'
        poll_cursor = start
        for _ in range(max_rounds_per_case):
            recorder.advance(('dma', 'cpu', 'uart'))
            # A native CPU store is the completion signal, never a host write.
            new_rows = runner.events_since(poll_cursor)
            poll_cursor = runner.event_count
            commits = [e for e in new_rows
                if e.get('kind') == 'memory_write' and e.get('component') == 'cpu'
                and e.get('address') == COMPLETED]
            if commits:
                if len(commits) != 1 or commits[0].get('value') != case_index:
                    raise RuntimeError('CPU completed-case counter is not monotonic')
                self.phase = 'case_check'
                rows = runner.events_since(start)
                evidence = _case_evidence(rows, source, case_index, action_id)
                evidence.update(_case_boundaries(
                    commands=recorder.commands, rows=rows,
                    command_start=command_start,
                    command_end=len(recorder.commands),
                    event_start=start, event_end=runner.event_count,
                    ticks_before=ticks_before,
                    ticks_after=dict(runner.local_ticks),
                    execution_ids=execution_ids))
                return evidence
        raise RuntimeError('CPU ISR completion exceeded per-case bound')

    def _failure_boundaries(self, action_id, command_start, event_start,
                            ticks_before, execution_ids):
        """Retain the attempted boundaries of a failed case, best effort."""
        failure = dict(action_id=action_id, phase=self.phase, complete=False,
            command_start=command_start, command_end=len(self.recorder.commands),
            event_start=event_start, event_end=self.runner.event_count,
            ticks_before=dict(ticks_before),
            ticks_after=dict(self.runner.local_ticks),
            prefix_sha256=None, fifo_depth_after=None)
        try:
            rows = self.runner.events_since(event_start)
            failure['prefix_sha256'] = _prefix_digest(
                self.recorder.commands[command_start:], rows,
                ticks_before, failure['ticks_after'], execution_ids)
            failure['fifo_depth_after'] = _fifo_depth_after(rows)
        except Exception:
            pass
        return failure

    def finish(self, *, phase: str = 'complete', case_index: int | None = None,
               error: dict | None = None) -> ContinuousRxResult:
        """Finalize the supplied runner and capture the continuous diagnostics."""
        return _capture(self.recorder, self.runner, self.cases, self.budget,
            phase, self.case_index if case_index is None else case_index,
            error, self.source_pins)

    def close(self) -> None:
        if not self.recorder._finished:
            _close(self.runner)


@host_source_discovery_scope()
def run_continuous_uart_rx(source_bytes, *, cache_dir: Path,
        max_rounds_per_case=4096, max_source_ticks=2048,
        budget: ResourceBudget | None = None,
        factory: Callable[[], ScenarioRunner] | None = None) -> ContinuousRxResult:
    """Record 1..16 byte cases in one boot, with no intervening resets.

    This is a thin wrapper over one ``_ContinuousRxBoot``: the command stream,
    native events, ticks, per-case evidence and failure diagnostics are
    unchanged, and every case additionally reports its prefix boundaries.
    """
    values = tuple(islice(iter(source_bytes), 17))
    _positive(len(values), 'case count', 16)
    if any(type(v) is not int or not 0 <= v <= 255 for v in values):
        raise ValueError('source bytes must be integers in 0..255')
    _positive(max_rounds_per_case, 'max_rounds_per_case', 4096)
    _positive(max_source_ticks, 'max_source_ticks', 4096)
    source_pins = _source_pins()
    runner = factory() if factory else make_continuous_uart_rx_runner(cache_dir=cache_dir)
    selected_budget = budget or ResourceBudget(max_wall_time_ms=300000)
    runner.set_resource_budget(selected_budget)
    template = ScenarioGenome('continuous-dma-uart-rx', 'IP_TO_CPU',
        'uart-fifo-dma-ram-cpu-isr', ('dma', 'cpu', 'uart'),
        3 * 512 + len(values) * (max_source_ticks + 3 * max_rounds_per_case), ())
    boot = _ContinuousRxBoot(runner, budget=selected_budget, template=template,
        source_pins=source_pins)
    try:
        boot.boot()
        for index, source in enumerate(values, 1):
            boot.cases.append(boot.run_case((source,), case_index=index,
                max_source_ticks=max_source_ticks,
                max_rounds_per_case=max_rounds_per_case))
        result = boot.finish()
        if (result.error is not None or result.trace is None
                or result.trace.status != 'complete' or result.uncertain_status['source_drift']):
            raise ContinuousRxFailure(result)
        return result
    except ContinuousRxFailure:
        raise
    except Exception as exc:
        diagnostic = dict(type=type(exc).__name__, message=str(exc),
            command_count=len(boot.recorder.commands), case_start=boot.case_start,
            max_rounds_per_case=max_rounds_per_case, max_source_ticks=max_source_ticks,
            requested_source_bytes=list(values))
        result = boot.finish(phase=boot.phase, case_index=boot.case_index,
            error=diagnostic)
        raise ContinuousRxFailure(result) from exc
    finally:
        boot.close()


def _normalize(events, execution_ids):
    """Normalize declared execution fields and typed journal ledger references."""
    import re
    if set(execution_ids) != {'cpu', 'dma', 'uart', 'runner'}:
        raise ValueError('execution IDs must identify CPU, DMA, UART and Runner')
    issued = {n: v for n, v in execution_ids.items() if v is not None}
    if (len(set(issued.values())) != len(issued)
            or any(type(v) is not str or re.fullmatch(r'[0-9a-f]{32}', v) is None
                for v in issued.values())):
        raise ValueError('execution IDs must be distinct native UUID hex strings')
    mapping = {v: 'execution:' + n for n, v in issued.items()}
    def visit(value, field=None, *, event_record=False, ledger_reference=False):
        if isinstance(value, dict):
            state_edge = (event_record and value.get('kind') == 'state_dependency'
                and {'event_id', 'producer_event_id', 'edge_kind', 'memory_id',
                     'generation', 'byte_offset', 'version', 'source', 'target'} <= value.keys())
            return {key: visit(item, key,
                ledger_reference=state_edge and key in ('source', 'target'))
                for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [visit(item, field) for item in value]
        if type(value) is str:
            if field in ('execution', 'execution_id'):
                return mapping.get(value, value)
            if ledger_reference or field in ('writer_event_id', 'writer_event_ids',
                    'pending_before_finalize', 'pending_after_finalize',
                    'uncertain_transactions'):
                # Producer stores TransactionKey repr in ledger writer and
                # uncertainty fields. List recursion retains the field context. Match
                # only its leading execution token; retain the entire suffix.
                match = re.fullmatch(r"TransactionKey\(execution_id='([0-9a-f]{32})', (.*)\)", value)
                if match and match[1] in mapping:
                    return "TransactionKey(execution_id='" + mapping[match[1]] + "', " + match[2] + ')'
        return value
    # Only records in the supplied journal root are state-dependency edges.
    # Identically named nested payloads and untyped source strings stay intact.
    if isinstance(events, (tuple, list)):
        return [visit(event, event_record=True) for event in events]
    return visit(events)


def _host_failure_still_present(reference, runner):
    """Re-evaluate host bounds/checks after replaying the exact command prefix."""
    phase = reference.phase
    rows = runner.events_since(reference.error.get('case_start', 0))
    if phase == 'boot':
        return 'uart' not in runner.sessions['cpu'].router.ready_targets
    sources = [c for c in reference.plan.commands if isinstance(c, BatchSourceEvent)]
    if not sources:
        return False
    source = sources[-1]
    if phase == 'source':
        uart = runner.sessions['uart']
        return not (any(e.get('kind') == 'uart_source_frame_end'
            and e.get('action_id') == source.action_id and e.get('waveform_matched')
            for e in uart.source_events) and uart.register_access_conflict() is None)
    if phase == 'isr':
        commits = [e for e in rows if e.get('kind') == 'memory_write'
            and e.get('component') == 'cpu' and e.get('address') == COMPLETED]
        return not commits or len(commits) != 1 or commits[0].get('value') != reference.case_index
    if phase == 'case_check':
        try:
            _case_evidence(rows, source.value, reference.case_index, source.action_id)
        except RuntimeError as exc:
            return type(exc).__name__ == reference.error['type'] and str(exc) == reference.error['message']
    return False


@host_source_discovery_scope()
def replay_continuous_uart_rx(reference: ContinuousRxResult, *, cache_dir: Path,
        budget: ResourceBudget | None = None,
        factory: Callable[[], ScenarioRunner] | None = None) -> ContinuousRxResult:
    """Fresh reconstruction of successful or failed original command prefixes.

    Source/build identities and host source pins must match. Serialized bundles
    are diagnostics supplied by the caller, never source or execution authority.
    Native command exceptions must recur at the same attempted command boundary;
    host bound/check failures must recur under their original predicate.
    """
    return _replay_continuous_uart_rx(reference, cache_dir=cache_dir,
        budget=budget, factory=factory)


def _replay_continuous_uart_rx(reference: ContinuousRxResult, *, cache_dir: Path,
        budget: ResourceBudget | None = None,
        factory: Callable[[], ScenarioRunner] | None = None) -> ContinuousRxResult:
    """Undecorated replay core so one discovery scope covers a whole search."""
    if _source_pins() != reference.source_pins:
        raise ValueError('continuous RX host source pins differ')
    if budget is not None and budget != reference.budget:
        raise ValueError('replay budget must equal the recorded original budget')
    runner = factory() if factory else make_continuous_uart_rx_runner(cache_dir=cache_dir)
    runner.set_resource_budget(reference.budget)
    if reference.trace is not None:
        from myfuzz.scenario.replay import _install_batch_wall_cut
        _install_batch_wall_cut(runner, reference.trace)
    recorder = ScenarioBatchRecorder(reference.plan.template, runner)
    caught = None
    command_count = 0
    starts = []
    end_events = end_ticks = None
    try:
        try:
            recorder.begin()
            identities, execution_ids = _identities(runner)
            if identities != reference.identities:
                raise ValueError('fresh native identity documents differ')
            for name, previous in reference.execution_ids.items():
                if previous is not None and execution_ids[name] == previous:
                    raise ValueError('replay requires fresh native processes and Runner')
            for index, command in enumerate(reference.plan.commands):
                command_count += 1
                if isinstance(command, BatchSourceEvent):
                    # Preserve the attempted case boundary before execution so a
                    # terminal failure still reconstructs the same prefix.
                    starts.append((index, runner.event_count,
                        dict(runner.local_ticks)))
                    recorder.submit_source_event(command)
                elif isinstance(command, BatchAdvance):
                    recorder.advance(command.schedule)
                else:
                    raise ValueError('unknown batch command')
            end_events, end_ticks = runner.event_count, dict(runner.local_ticks)
        except Exception as exc:
            caught = dict(type=type(exc).__name__, message=str(exc), command_count=command_count)
        if caught is not None:
            if (reference.error is None or caught['type'] != reference.error['type']
                    or caught['message'] != reference.error['message']
                    or caught['command_count'] != reference.error['command_count']):
                raise RuntimeError('fresh replay command failure differs from original')
        elif (reference.error is not None and reference.phase != 'finalize'
                and not _host_failure_still_present(reference, runner)):
            raise RuntimeError('original host bound/check failure did not recur')
        actual = _capture(recorder, runner, [], reference.budget,
            reference.phase, reference.case_index, reference.error if caught is None else
            {**reference.error, **caught}, source_pins=reference.source_pins)
        if actual.identities != reference.identities:
            raise RuntimeError('fresh native identity documents differ')
        if (actual.local_ticks != reference.local_ticks
                or _normalize(actual.events, actual.execution_ids)
                != _normalize(reference.events, reference.execution_ids)
                or _normalize(actual.uncertain_status, actual.execution_ids)
                != _normalize(reference.uncertain_status, reference.execution_ids)
                or (actual.trace.status if actual.trace else None)
                != (reference.trace.status if reference.trace else None)):
            raise RuntimeError('fresh replay differs from full finalized original prefix')
        # Recheck all completed cases against the original source records. A
        # terminal failed case is retained as diagnostics, never graded complete.
        sources = [e for e in actual.events if e.get('kind') == 'source_injection']
        original = [c for c in reference.plan.commands if isinstance(c, BatchSourceEvent)]
        cases = []
        for i, expected_case in enumerate(reference.cases):
            event, command = sources[i], original[i]
            if event.get('value') != command.value or event.get('action_id') != command.action_id:
                raise RuntimeError('replay source differs from original record')
            following = starts[i + 1] if i + 1 < len(starts) else None
            rows = list(actual.events[starts[i][1]:(
                following[1] if following else end_events)])
            case = _case_evidence(rows, command.value, i + 1, command.action_id)
            case.update(_case_boundaries(
                commands=reference.plan.commands, rows=rows,
                command_start=starts[i][0],
                command_end=following[0] if following else len(reference.plan.commands),
                event_start=starts[i][1],
                event_end=following[1] if following else end_events,
                ticks_before=starts[i][2],
                ticks_after=following[2] if following else end_ticks,
                execution_ids=actual.execution_ids))
            if case != expected_case:
                raise RuntimeError('replay per-case causal evidence differs')
            cases.append(case)
        return ContinuousRxResult(actual.plan, actual.trace, tuple(cases), actual.identities,
            actual.execution_ids, actual.budget, actual.phase, actual.case_index,
            actual.error, actual.events, actual.local_ticks, actual.uncertain_status,
            actual.source_pins)
    finally:
        if not recorder._finished:
            _close(runner)
