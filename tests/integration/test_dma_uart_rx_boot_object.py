"""The continuous RX runner is one reusable boot object plus a thin wrapper.

The fake runner only implements the runner/recorder surface the boot object
uses. It never starts native RTL and never claims a native case: it proves the
command stream and the per-case prefix boundaries are produced by one shared
code path, so a search layer can inject decisions between cases.
"""
from types import SimpleNamespace

import pytest

from myfuzz.integration import dma_uart_rx_runtime as runtime
from myfuzz.integration.dma_uart_rx_runtime import _ContinuousRxBoot
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.genome import ScenarioGenome

CASE_FIELDS = ('command_start', 'command_end', 'event_start', 'event_end',
               'ticks_before', 'ticks_after', 'prefix_sha256', 'fifo_depth_after')


def _ids(offset=1):
    return {name: f'{offset + index:032x}'
            for index, name in enumerate(('cpu', 'dma', 'uart', 'runner'))}


def _template(max_steps=100000):
    return ScenarioGenome('continuous-dma-uart-rx', 'IP_TO_CPU',
        'uart-fifo-dma-ram-cpu-isr', ('dma', 'cpu', 'uart'), max_steps, ())


class _Router:
    def __init__(self):
        self.ready = False

    @property
    def ready_targets(self):
        return ('uart',) if self.ready else ()


class _Session:
    def __init__(self, name, execution):
        self.name, self._execution = name, execution

    def identity_document(self):
        return {'fake_session': self.name, 'session_execution': self._execution}


class _Uart(_Session):
    def __init__(self, execution, *, fail_frame):
        super().__init__('uart', execution)
        self.source_events = []
        self.fail_frame = fail_frame

    def register_access_conflict(self):
        return None


class _Runner:
    """Minimal journal and identity surface of one ScenarioRunner."""

    def __init__(self, ids, *, fail_frame=False, isr_rounds=2):
        self.ids = dict(ids)
        self.sessions = {
            'cpu': _Session('cpu', ids['cpu']),
            'dma': _Session('dma', ids['dma']),
            'uart': _Uart(ids['uart'], fail_frame=fail_frame)}
        self.sessions['cpu'].router = _Router()
        self.execution_id = ids['runner']
        self.local_ticks = {'cpu': 0, 'dma': 0, 'uart': 0}
        self.failure_status = None
        self.budgets = []
        self.rows = []
        self.isr_rounds = isr_rounds
        self.isr_round = 0
        self.case = 0
        self.byte = None

    # -- runner surface ---------------------------------------------------
    def set_resource_budget(self, budget):
        self.budgets.append(budget)

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

    # -- journal ----------------------------------------------------------
    def append(self, record):
        self.rows.append({'event_id': len(self.rows) + 1, **record})
        return self.rows[-1]


class _Recorder:
    """Fake ScenarioBatchRecorder driving the fake runner deterministically."""

    instances = []

    def __init__(self, template, runner):
        assert isinstance(template, ScenarioGenome)
        self.template, self.runner = template, runner
        self._commands = []
        self._finished = False
        self._begun = False
        self._trace = None
        self._action_id = None
        _Recorder.instances.append(self)

    @property
    def commands(self):
        return tuple(self._commands)

    @property
    def trace(self):
        return self._trace

    def begin(self):
        self._begun = True

    def submit_source_event(self, event):
        assert isinstance(event, BatchSourceEvent)
        self._commands.append(event)
        self._action_id = event.action_id
        self.runner.case += 1
        self.runner.byte = event.value
        self.runner.isr_round = 0
        self.runner.append({'kind': 'source_injection', 'action_id': event.action_id,
            'component': 'uart', 'port': event.port, 'value': event.value,
            'execution_id': self.runner.ids['uart']})

    def advance(self, schedule):
        command = BatchAdvance(tuple(schedule))
        self._commands.append(command)
        for component in schedule:
            self.runner.local_ticks[component] += 1
        runner = self.runner
        if schedule == ('dma', 'cpu'):
            runner.sessions['cpu'].router.ready = True
            runner.append({'kind': 'boot_step', 'component': 'cpu',
                'execution_id': runner.ids['cpu']})
        elif schedule == ('uart',):
            runner.append({'kind': 'uart_tick_observation',
                'execution_id': runner.ids['uart'],
                'post': {'probe_uart_fifo_wvalid': 0,
                         'probe_uart_fifo_depth': 0}})
            if not runner.sessions['uart'].fail_frame:
                runner.sessions['uart'].source_events.append({
                    'kind': 'uart_source_frame_end', 'action_id': self._action_id,
                    'waveform_matched': True})
        else:
            runner.append({'kind': 'isr_step', 'component': 'cpu',
                'execution_id': runner.ids['cpu']})
            runner.isr_round += 1
            if runner.isr_round == runner.isr_rounds:
                runner.append({'kind': 'memory_write', 'component': 'dma',
                    'address': runtime.DESTINATION, 'value': runner.byte,
                    'transaction': {'channel_id': 'dma-memory',
                                    'execution_id': runner.ids['dma']}})
                runner.append({'kind': 'memory_write', 'component': 'cpu',
                    'address': runtime.COMPLETED, 'value': runner.case,
                    'execution_id': runner.ids['cpu']})
        return tuple({} for _ in schedule)

    def finish(self):
        self._finished = True
        self._trace = SimpleNamespace(status='complete')
        return self._trace


def _evidence(rows, expected, counter, action_id):
    return dict(counter=counter, source_byte=expected, action_id=action_id)


@pytest.fixture
def fake_runtime(monkeypatch):
    _Recorder.instances = []
    monkeypatch.setattr(runtime, 'ScenarioBatchRecorder', _Recorder)
    monkeypatch.setattr(runtime, '_case_evidence', _evidence)
    return monkeypatch


def _budget():
    return ResourceBudget(max_wall_time_ms=1000)


def _run_boot(case_bytes, *, ids, fail_frame=False, max_source_ticks=2048):
    """Execute cases through the boot object exactly as the wrapper does."""
    runner = _Runner(ids, fail_frame=fail_frame)
    runner.set_resource_budget(_budget())
    boot = _ContinuousRxBoot(runner, budget=_budget(), template=_template(),
        source_pins=runtime._source_pins())
    boot.boot()
    started = dict(events=runner.event_count,
                   commands=len(_Recorder.instances[-1].commands),
                   ticks=dict(runner.local_ticks))
    for index, value in enumerate(case_bytes, 1):
        boot.cases.append(boot.run_case((value,), case_index=index,
            max_source_ticks=max_source_ticks))
    return boot, boot.finish(), started


def test_continuous_runner_is_a_thin_wrapper_over_the_boot_object(fake_runtime, tmp_path):
    ids = _ids()
    result = runtime.run_continuous_uart_rx((0x5a,), cache_dir=tmp_path,
        factory=lambda: _Runner(ids))
    wrapper = _Recorder.instances[-1]
    boot, direct, _ = _run_boot((0x5a,), ids=_ids(20))
    direct_recorder = _Recorder.instances[-1]
    assert wrapper is not direct_recorder
    assert wrapper.commands == direct_recorder.commands
    assert direct.plan.commands == result.plan.commands
    assert direct.cases == result.cases
    assert [case['source_byte'] for case in result.cases] == [0x5a]


def test_each_case_records_prefix_boundaries_and_a_stable_digest(fake_runtime, tmp_path):
    _boot, result, started = _run_boot((0x5a,), ids=_ids())
    case = result.cases[0]
    assert set(CASE_FIELDS) <= set(case)
    assert case['command_start'] == started['commands']
    assert case['event_start'] == started['events']
    assert case['ticks_before'] == started['ticks']
    assert case['command_end'] == len(result.plan.commands)
    assert case['event_end'] == len(result.events)
    assert all(case['ticks_after'][name] > case['ticks_before'][name]
               for name in ('cpu', 'dma', 'uart'))
    digest = case['prefix_sha256']
    assert isinstance(digest, str) and len(digest) == 64
    assert all(character in '0123456789abcdef' for character in digest)
    assert isinstance(case['fifo_depth_after'], int)


def test_case_boundaries_chain_across_cases(fake_runtime, tmp_path):
    _boot, result, started = _run_boot((0x5a, 0x00), ids=_ids())
    first, second = result.cases
    assert second['command_start'] == first['command_end']
    assert second['event_start'] == first['event_end']
    assert second['ticks_before'] == first['ticks_after']
    assert first['event_start'] == started['events']
    assert first['prefix_sha256'] != second['prefix_sha256']


def test_prefix_digest_follows_the_admitted_byte_not_the_process_identity(fake_runtime, tmp_path):
    _boot, same, _ = _run_boot((0x5a,), ids=_ids())
    _boot, fresh, _ = _run_boot((0x5a,), ids=_ids(40))
    _boot, other, _ = _run_boot((0x00,), ids=_ids())
    assert same.cases[0]['prefix_sha256'] == fresh.cases[0]['prefix_sha256']
    assert same.cases[0]['prefix_sha256'] != other.cases[0]['prefix_sha256']


@pytest.mark.parametrize('case_bytes', [(), (0x5a, 0x00)])
def test_run_case_refuses_anything_but_one_serial_byte(fake_runtime, case_bytes):
    runner = _Runner(_ids())
    runner.set_resource_budget(_budget())
    boot = _ContinuousRxBoot(runner, budget=_budget(), template=_template(),
        source_pins=runtime._source_pins())
    boot.boot()
    recorded = boot.recorder.commands
    with pytest.raises(ValueError, match='exactly one serial byte'):
        boot.run_case(case_bytes, case_index=1)
    assert boot.recorder.commands == recorded


@pytest.mark.parametrize('value', [256, -1, True, '0x5a'])
def test_run_case_refuses_out_of_range_bytes_before_consuming_rtl(fake_runtime, value):
    runner = _Runner(_ids())
    runner.set_resource_budget(_budget())
    boot = _ContinuousRxBoot(runner, budget=_budget(), template=_template(),
        source_pins=runtime._source_pins())
    boot.boot()
    recorded = boot.recorder.commands
    with pytest.raises(ValueError, match='integers in 0..255'):
        boot.run_case((value,), case_index=1)
    assert boot.recorder.commands == recorded


@pytest.mark.parametrize('expected', [{'outcome': 'environment_error'}, {}, {'outcome': None}])
def test_run_case_certifies_only_a_complete_chain_expectation(fake_runtime, expected):
    runner = _Runner(_ids())
    runner.set_resource_budget(_budget())
    boot = _ContinuousRxBoot(runner, budget=_budget(), template=_template(),
        source_pins=runtime._source_pins())
    boot.boot()
    recorded = boot.recorder.commands
    with pytest.raises(ValueError, match='complete chain'):
        boot.run_case((0x5a,), case_index=1, expected=expected)
    assert boot.recorder.commands == recorded


def test_failed_case_keeps_its_attempted_boundaries(fake_runtime):
    runner = _Runner(_ids(), fail_frame=True)
    runner.set_resource_budget(_budget())
    boot = _ContinuousRxBoot(runner, budget=_budget(), template=_template(),
        source_pins=runtime._source_pins())
    boot.boot()
    started = dict(events=runner.event_count,
                   commands=len(boot.recorder.commands), ticks=dict(runner.local_ticks))
    with pytest.raises(RuntimeError, match='native serial frame exceeded source bound'):
        boot.run_case((0x5a,), case_index=1, max_source_ticks=2)
    failure = boot.case_failure
    assert failure is not None and failure['complete'] is False
    assert failure['phase'] == 'source'
    assert failure['command_start'] == started['commands']
    assert failure['event_start'] == started['events']
    assert failure['ticks_before'] == started['ticks']
    assert failure['command_end'] == len(boot.recorder.commands)
    assert failure['event_end'] == runner.event_count
    assert all(failure['ticks_after'][name] >= failure['ticks_before'][name]
               for name in ('cpu', 'dma', 'uart'))


def test_wrapper_failure_diagnostic_keeps_the_attempted_command_boundary(fake_runtime, tmp_path):
    ids = _ids()
    with pytest.raises(runtime.ContinuousRxFailure) as caught:
        runtime.run_continuous_uart_rx((0x5a,), cache_dir=tmp_path,
            factory=lambda: _Runner(ids, fail_frame=True), max_source_ticks=2)
    failed = caught.value.result
    recorder = _Recorder.instances[-1]
    assert failed.phase == 'source' and failed.case_index == 1
    assert failed.error['type'] == 'RuntimeError'
    assert failed.error['message'] == 'native serial frame exceeded source bound'
    assert failed.error['command_count'] == len(recorder.commands)
    assert failed.error['case_start'] == 1
    assert failed.error['requested_source_bytes'] == [0x5a]
    assert failed.cases == ()


def test_boot_refuses_a_sealed_recorder(fake_runtime):
    runner = _Runner(_ids())
    runner.set_resource_budget(_budget())
    boot = _ContinuousRxBoot(runner, budget=_budget(), template=_template(),
        source_pins=runtime._source_pins())
    boot.boot()
    boot.finish()
    with pytest.raises(RuntimeError, match='not active'):
        boot.run_case((0x5a,), case_index=1)
