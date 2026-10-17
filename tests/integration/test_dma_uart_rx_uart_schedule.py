"""S1c: the ISR poll round advances UART only when UART has real work.

The fake runner models the scheduling surface the boot object uses: a router
that reports ready queued targets, a UART that can report a live waveform
conflict, a journal, and per-step local ticks. It never starts native RTL, so
these tests prove the recorded command schedule only. The native before/after
throughput and causal evidence come from the opt-in gates in
``test_dma_uart_rx_runtime.py`` and ``test_dma_uart_rx_search_real.py``.

Invariants under test:
- with no queued UART request and no live waveform conflict, a poll round is
  exactly ``('dma', 'cpu')`` (no idle UART tick);
- when UART has a ready request (or a live conflict) the round keeps the real
  UART step, last, so MMIO queued by this round's CPU/DMA step is serviced on
  the following round;
- the before/after command streams keep every real UART service and the same
  CPU/DMA steps; only idle UART ticks disappear.
"""
from types import SimpleNamespace

import pytest

from myfuzz.integration import dma_uart_rx_runtime as runtime
from myfuzz.integration.dma_uart_rx_runtime import _ContinuousRxBoot
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.genome import ScenarioGenome

WAVEFORM_TICKS = 3
POLL_ROUNDS = 6


def _ids(offset=1):
    return {name: f'{offset + index:032x}'
            for index, name in enumerate(('cpu', 'dma', 'uart', 'runner'))}


def _template(max_steps=100000):
    return ScenarioGenome('continuous-dma-uart-rx', 'IP_TO_CPU',
        'uart-fifo-dma-ram-cpu-isr', ('dma', 'cpu', 'uart'), max_steps, ())


def _budget():
    return ResourceBudget(max_wall_time_ms=1000)


class _Router:
    """Only the readiness question the poll schedule is allowed to ask."""

    def __init__(self, runner):
        self.runner = runner

    @property
    def ready_targets(self):
        return ('uart',) if self.runner.queue else ()


class _Session:
    def __init__(self, name, execution):
        self.name, self._execution = name, execution

    def identity_document(self):
        return {'fake_session': self.name}


class _Uart(_Session):
    def __init__(self, execution):
        super().__init__('uart', execution)
        self.source_events = []

    def register_access_conflict(self):
        return None


class _Runner:
    """Minimal runner/recorder surface plus a deterministic UART queue."""

    def __init__(self, ids, *, status_round=0):
        self.ids = dict(ids)
        self.queue = []
        self.status_round = status_round
        self.boot_round = 0
        self.poll_round = 0
        self.poll_phase = False
        self.waveform_ticks = 0
        self.case = 0
        self.byte = None
        self.action_id = None
        self.local_ticks = {'cpu': 0, 'dma': 0, 'uart': 0}
        self.failure_status = None
        self.rows = []
        self.advances = []
        self.sessions = {'cpu': _Session('cpu', ids['cpu']),
                         'dma': _Session('dma', ids['dma']),
                         'uart': _Uart(ids['uart'])}
        self.sessions['cpu'].router = _Router(self)
        self.execution_id = ids['runner']

    # -- runner surface ---------------------------------------------------
    def set_resource_budget(self, budget):
        self.budget = budget

    @property
    def events(self):
        return tuple(self.rows)

    @property
    def event_count(self):
        return len(self.rows)

    def events_since(self, index):
        return tuple(self.rows[index:])

    def _uncertain_transactions(self):
        return ()

    def append(self, record):
        self.rows.append({'event_id': len(self.rows) + 1, **record})
        return self.rows[-1]


class _Recorder:
    """Fake recorder: applies each schedule to the fake runner's state."""

    def __init__(self, template, runner):
        assert isinstance(template, ScenarioGenome)
        self.template, self.runner = template, runner
        self._commands = []
        self._finished = False

    @property
    def commands(self):
        return tuple(self._commands)

    @property
    def trace(self):
        return None

    def begin(self):
        pass

    def submit_source_event(self, event):
        assert isinstance(event, BatchSourceEvent)
        self._commands.append(event)
        self.runner.case += 1
        self.runner.byte = event.value
        self.runner.action_id = event.action_id
        self.runner.waveform_ticks = 0
        self.runner.append({'kind': 'source_injection',
            'action_id': event.action_id, 'component': 'uart',
            'port': event.port, 'value': event.value})

    def advance(self, schedule):
        schedule = tuple(schedule)
        self._commands.append(BatchAdvance(schedule))
        runner = self.runner
        pending = bool(runner.queue)
        uart_services = []
        services = []
        idle_uart = False
        for component in schedule:
            runner.local_ticks[component] += 1
        if schedule == ('uart',):
            # Waveform phase: the first UART tick drains the queued CTRL write,
            # then the real 8N1 frame consumes the remaining ticks.
            if runner.queue:
                uart_services.append(runner.queue.pop(0))
            runner.append({'kind': 'uart_tick_observation',
                'component': 'uart',
                'post': {'probe_uart_fifo_depth': 0}})
            runner.waveform_ticks += 1
            if runner.waveform_ticks == WAVEFORM_TICKS:
                runner.waveform_ticks = 0
                runner.poll_phase = True
                runner.sessions['uart'].source_events.append({
                    'kind': 'uart_source_frame_end',
                    'action_id': runner.action_id, 'waveform_matched': True})
            runner.advances.append(dict(phase='source', schedule=schedule,
                pending_at_start=pending,
                uart_services=tuple(uart_services),
                services=tuple(uart_services), idle_uart=False))
            return tuple({} for _ in schedule)
        if not runner.poll_phase:
            runner.boot_round += 1
            if runner.boot_round == 1:
                runner.queue.append('ctrl_write')
            runner.advances.append(dict(phase='boot', schedule=schedule,
                pending_at_start=pending, uart_services=(), services=(),
                idle_uart=False))
            return tuple({} for _ in schedule)
        # One ISR poll round: the CPU issues the STATUS read, and a DMA master
        # read of UART RDATA advances the UART inside the DMA step.
        round_index = runner.poll_round
        runner.poll_round += 1
        if round_index == runner.status_round:
            runner.queue.append('status_read')
        if round_index == runner.status_round + 2:
            runner.local_ticks['uart'] += 1
            runner.append({'kind': 'uart_rdata_access', 'component': 'uart'})
            services.append('dma_rdata_read')
        if 'uart' in schedule:
            if runner.queue:
                uart_services.append(runner.queue.pop(0))
            else:
                idle_uart = True
            runner.append({'kind': 'uart_tick_observation',
                'component': 'uart',
                'post': {'probe_uart_fifo_depth': 0}})
        if round_index == POLL_ROUNDS - 1:
            runner.append({'kind': 'memory_write', 'component': 'dma',
                'address': runtime.DESTINATION, 'value': runner.byte,
                'transaction': {'channel_id': 'dma-memory',
                                'execution_id': runner.ids['dma']}})
            runner.append({'kind': 'memory_write', 'component': 'cpu',
                'address': runtime.COMPLETED, 'value': runner.case})
        runner.advances.append(dict(phase='poll', round=round_index,
            schedule=schedule, pending_at_start=pending,
            uart_services=tuple(uart_services),
            services=tuple(uart_services) + tuple(services),
            idle_uart=idle_uart))
        return tuple({} for _ in schedule)

    def finish(self):
        self._finished = True
        return SimpleNamespace(status='complete')


def _evidence(rows, expected, counter, action_id):
    return dict(counter=counter, source_byte=expected, action_id=action_id)


@pytest.fixture
def fake_runtime(monkeypatch):
    monkeypatch.setattr(runtime, 'ScenarioBatchRecorder', _Recorder)
    monkeypatch.setattr(runtime, '_case_evidence', _evidence)
    return monkeypatch


def _run(*, status_round=0, ids=None):
    runner = _Runner(ids or _ids(), status_round=status_round)
    runner.set_resource_budget(_budget())
    boot = _ContinuousRxBoot(runner, budget=_budget(), template=_template(),
        source_pins=runtime._source_pins())
    boot.boot()
    boot.cases.append(boot.run_case((0x5a,), case_index=1))
    return runner, boot, boot.finish()


def _poll(runner):
    return [row for row in runner.advances if row['phase'] == 'poll']


def _services(runner):
    return [service for row in runner.advances for service in row['services']]


def test_poll_round_advances_uart_only_when_a_request_is_ready(fake_runtime):
    runner, _boot, _result = _run()
    poll = _poll(runner)
    assert len(poll) == POLL_ROUNDS
    for row in poll:
        assert row['schedule'][:2] == ('dma', 'cpu')
        if row['pending_at_start']:
            assert row['schedule'] == ('dma', 'cpu', 'uart')
        else:
            assert row['schedule'] == ('dma', 'cpu')
    # Exactly the one STATUS read delivery owns a poll UART step; every other
    # poll round is a pure CPU/DMA round with no idle UART tick.
    assert sum(1 for row in poll if 'uart' in row['schedule']) == 1
    assert sum(1 for row in poll if row['idle_uart']) == 0
    assert all(row['uart_services']
               for row in poll if 'uart' in row['schedule'])


def test_thinner_schedule_keeps_every_real_uart_service(fake_runtime):
    runner, _boot, result = _run()
    # The boot CTRL write, the CPU STATUS read and the DMA RDATA read are all
    # still real steps; the fake would not be able to finish the case without
    # them because the STATUS read gates the CPU's DMA programming.
    assert _services(runner) == ['ctrl_write', 'status_read', 'dma_rdata_read']
    assert [case['source_byte'] for case in result.cases] == [0x5a]
    # The waveform phase is untouched: only UART-only source ticks.
    assert sum(1 for row in runner.advances
               if row['phase'] == 'source') == WAVEFORM_TICKS


def test_before_after_only_removes_idle_uart_ticks(fake_runtime):
    new_runner, _boot, new_result = _run()
    # The pre-S1c schedule advanced UART in every poll round. Recreate it to
    # compare the two command streams on the same fake runner.
    fake_runtime.setattr(runtime, '_poll_schedule',
        lambda runner: ('dma', 'cpu', 'uart'), raising=False)
    old_runner, _boot, old_result = _run()
    old_poll, new_poll = _poll(old_runner), _poll(new_runner)
    # CPU/DMA are stepped identically every round; only the trailing UART step
    # is removed, never any component step.
    assert [row['schedule'][:2] for row in old_poll] == [row['schedule'][:2]
        for row in new_poll] == [('dma', 'cpu')] * POLL_ROUNDS
    # Same real services, same order, in both schedules.
    assert _services(old_runner) == _services(new_runner) == [
        'ctrl_write', 'status_read', 'dma_rdata_read']
    old_uart = sum(1 for row in old_poll if 'uart' in row['schedule'])
    new_uart = sum(1 for row in new_poll if 'uart' in row['schedule'])
    old_idle = sum(1 for row in old_poll if row['idle_uart'])
    old_services = sum(len(row['uart_services']) for row in old_poll)
    new_services = sum(len(row['uart_services']) for row in new_poll)
    assert old_uart == POLL_ROUNDS and new_uart == new_services == 1
    assert old_services == new_services
    # The removed UART steps are exactly the before-run's idle ticks; every
    # surviving UART step is a service, and UART is always last.
    assert old_idle == old_uart - old_services
    for row in new_poll:
        assert row['schedule'] == (('dma', 'cpu', 'uart')
            if row['pending_at_start'] else ('dma', 'cpu'))
        assert row['idle_uart'] is False
    # No command is dropped: each round is still one advance command. CPU/DMA
    # local ticks and per-case evidence are unchanged; only UART ticks shrink.
    assert len(old_result.plan.commands) == len(new_result.plan.commands)
    assert old_result.local_ticks['cpu'] == new_result.local_ticks['cpu']
    assert old_result.local_ticks['dma'] == new_result.local_ticks['dma']
    assert old_result.local_ticks['uart'] > new_result.local_ticks['uart']
    assert (old_result.local_ticks['uart'] - new_result.local_ticks['uart']
            == old_idle)
    assert [case['counter'] for case in old_result.cases] == [
        case['counter'] for case in new_result.cases] == [1]
    assert [case['source_byte'] for case in old_result.cases] == [
        case['source_byte'] for case in new_result.cases] == [0x5a]


def test_fifo_depth_after_reads_the_latest_real_probe():
    # S1c removes the idle UART ticks after the DMA pop, so the last tick sample
    # can predate the pop. The saved DMA/CPU UART access captures still carry a
    # real post-pop depth probe; the case evidence must use it instead of the
    # stale pre-pop depth.
    rows = [
        {'kind': 'uart_tick_observation', 'event_id': 1,
         'post': {'probe_uart_fifo_depth': 1}},
        {'kind': 'uart_rdata_access', 'event_id': 2,
         'read_capture': {
             'pre': {'probe_uart_fifo_depth': 1},
             'post': {'probe_uart_fifo_depth': 0}}},
    ]
    assert runtime._fifo_depth_after(rows) == 0
    dma = [{'kind': 'dma_edge', 'event_id': 2,
        'target_delivery': {'target_uart_access': {'read_capture': {
            'pre': {'probe_uart_fifo_depth': 1},
            'post': {'probe_uart_fifo_depth': 0}}}}}]
    assert runtime._fifo_depth_after(dma) == 0
    assert runtime._fifo_depth_after([]) is None
    assert runtime._fifo_depth_after([{'kind': 'uart_tick_observation',
        'post': {'probe_uart_fifo_depth': 3}}]) == 3


def test_schedule_helper_keeps_uart_last_for_ready_or_conflicting_uart():
    def runner(*, ready, conflict):
        uart = SimpleNamespace(register_access_conflict=lambda: (
            None if conflict is None else {'basis': 'fake live waveform'}))
        router = SimpleNamespace(ready_targets=('uart',) if ready else ())
        return SimpleNamespace(sessions={
            'cpu': SimpleNamespace(router=router), 'uart': uart})
    # No queued request and no live waveform: UART would be a pure idle tick.
    assert runtime._poll_schedule(runner(ready=False, conflict=None)) == (
        'dma', 'cpu')
    # A ready queued request (for example this round's STATUS read) is serviced
    # last so the same round's CPU/DMA step still runs first.
    assert runtime._poll_schedule(runner(ready=True, conflict=None)) == (
        'dma', 'cpu', 'uart')
    # A live serial waveform/conflict still needs its own real UART clock even
    # when no register request is queued.
    assert runtime._poll_schedule(runner(ready=False, conflict=True)) == (
        'dma', 'cpu', 'uart')
    assert runtime._poll_schedule(runner(ready=True, conflict=True)) == (
        'dma', 'cpu', 'uart')
