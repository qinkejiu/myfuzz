"""Execute three-component schedules through the real runner, no native RTL."""
from types import SimpleNamespace
import pytest

from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from tests.scenario.test_runner_continuity import RecordingSession


def runtime_shell():
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    cpu, dma, storage = RecordingSession(), RecordingSession(), RecordingSession()
    cpu.waiting_instruction_address = None
    cpu._request_evidence = {}
    ordinary = cpu.step_local
    def cpu_step(inputs):
        outputs = ordinary(inputs)
        if storage.steps:
            cpu.waiting_instruction_address = 0x11000
            cpu._request_evidence['instr'] = dict(transaction='software-transport-double', acceptance_tick=len(cpu.steps))
        return outputs
    cpu.step_local = cpu_step
    runner = ScenarioRunner(sessions={'cpu': cpu, 'dma': dma, 'peripheral': storage},
        ownership=compile_ownership((), ()), bindings=())
    runner.begin_test('shared-schedule')
    schedules = []
    def advance_initial(order):
        schedules.append(order)
        runner.step_batch(order)
        return SimpleNamespace(violations=(), status='running')
    session = SimpleNamespace(template=SimpleNamespace(schedule_order=tuple(runner.sessions)),
        advance_initial=advance_initial)
    runtime = object.__new__(CompiledF6Runtime)
    runtime.session, runtime.runner, runtime.cpu = session, runner, cpu
    runtime.cpu_id, runtime.dma_id, runtime.rounds_per_case = 'cpu', 'dma', 3
    runtime.contract = dict(cpu=dict(instance_id='cpu'), dma=dict(instance_id='dma'),
        program_contract=dict(slot_base=0x11000))
    runtime._drain_observer_view = lambda: None
    return runtime, storage, schedules


def test_bootstrap_progresses_storage_through_actual_runner_steps():
    runtime, storage, schedules = runtime_shell()
    runtime._bootstrap_to_first_slot()
    assert schedules == [('cpu', 'dma', 'peripheral')]*2
    assert len(storage.steps) == runtime.runner.local_ticks['peripheral'] == 2
    assert runtime._first_fetch['address'] == 0x11000


def test_case_and_tail_advance_all_template_components_without_reset():
    from myfuzz.integration.compiled_f6 import _f6_runtime_case_advances
    runtime, storage, _ = runtime_shell()
    advances = _f6_runtime_case_advances(runtime)
    assert [row.schedule for row in advances] == [('cpu',), ('dma',), ('peripheral',)]*3
    for advance in advances:
        runtime.runner.step_batch(advance.schedule)
    assert len(storage.steps) == runtime.runner.local_ticks['peripheral'] == 3
    assert storage.begins == 1 and storage.ends == 0
