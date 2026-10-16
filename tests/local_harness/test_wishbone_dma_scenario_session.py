"""DMA exposes the same mapping/tick interface used by ScenarioRunner."""
from pathlib import Path

import pytest

from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
from test_wishbone_dma_transport import artifact

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('tick_base', (0, 50))
def test_runner_step_preserves_native_sample_and_actual_irq(artifact, tmp_path, monkeypatch, tick_base):
    session = GeneratedWishboneDmaScenarioSession(artifact, base_dir=ROOT,
        cache_dir=tmp_path, memory=PersistentMemory(initialization_seed=1,
            max_initialized_bytes=16, regions=(MemoryRegion('ram', 0x1000, 16),)))
    session._execution = 'contract'
    session._case_id = 'case'
    session._tick_base = tick_base
    calls = []
    irq_name = session._irq_runtime_name
    idle = dict(mwb_cyc=0, mwb_stb=0, mwb_we=0, mwb_adr=0, mwb_dat_w=0)
    sample = dict(local_tick=1, pre=dict(backend=idle, physical={irq_name: 0}),
        post=dict(backend={'mwb_stb': 0}, physical={irq_name: 1}))

    def command(op, fields):
        calls.append((op, fields))
        return DriverReceipt('result', 'contract', 1, 0, 1, 1,
            payload=dict(pre_backend=idle, samples=[sample],
                observations=sample['post']))

    monkeypatch.setattr(session, 'command', command)
    with pytest.raises(ValueError, match='no external input'):
        session.step_local({'irq': 1})
    assert not calls
    result = session.step_local({})
    assert result['irq'] == 1
    assert session.service is session.memory_service
    assert session.runtime_events[0]['kind'] == 'dma_edge'
    samples = session.drain_tick_samples()
    assert samples[0]['local_tick'] == tick_base + 1
    assert samples[0]['pre']['irq'] == 0 and samples[0]['post']['irq'] == 1
    assert samples[0]['post']['physical'] == {irq_name: 1}
    assert session.drain_tick_samples() == ()
    samples[0]['post']['physical'][irq_name] = 0
    assert session.runtime_events[0]['payload']['samples'][0]['post']['physical'][irq_name] == 1


def test_declared_master_ip_accesses_have_scheduler_tick_bounds(artifact, tmp_path):
    from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.scenario.runner import ScenarioRunner

    class Target:
        max_local_ticks_per_register_access = 37

        def write_register(self, *args, **kwargs):
            raise AssertionError('construction cannot clock the target')

    target = Target()
    window = MasterTargetWindow('uart', 0x50000000, 0x1000, target,
        (0x1c,), range(256))
    session = GeneratedWishboneDmaScenarioSession(artifact, base_dir=ROOT,
        cache_dir=tmp_path, master_targets=(window,),
        memory=PersistentMemory(initialization_seed=1, max_initialized_bytes=16,
            regions=(MemoryRegion('ram', 0x1000, 16),)))
    runner = ScenarioRunner(sessions={'dma': session, 'uart': target},
        ownership=compile_ownership((), ()), bindings=())
    assert runner._step_tick_bounds('dma') == {'dma': 1, 'uart': 33*37}
    from types import SimpleNamespace
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    cpu = SimpleNamespace(router=DataflowRouter((DeviceWindow('dma', 0x40000000, 16, session),)),
        max_mmio_target_accesses_per_step=1)
    immediate = ScenarioRunner(sessions={'cpu': cpu, 'dma': session, 'uart': target},
        ownership=compile_ownership((), ()), bindings=())
    assert immediate._step_tick_bounds('cpu') == {'cpu': 1, 'dma': 32, 'uart': 33*37}
    with pytest.raises(ValueError, match='registered indirect target'):
        ScenarioRunner(sessions={'dma': session, 'uart': Target()},
            ownership=compile_ownership((), ()), bindings=())._step_tick_bounds('dma')
    with pytest.raises(ValueError, match='multiple instance names'):
        ScenarioRunner(sessions={'dma': session, 'alias': session, 'uart': target},
            ownership=compile_ownership((), ()), bindings=())


def test_one_dma_control_target_cannot_have_two_source_routers(artifact, tmp_path):
    from types import SimpleNamespace
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.runner import ScenarioRunner

    dma = GeneratedWishboneDmaScenarioSession(artifact, base_dir=ROOT,
        cache_dir=tmp_path, memory=PersistentMemory(initialization_seed=1,
            max_initialized_bytes=16, regions=(MemoryRegion('ram', 0x1000, 16),)))
    cpus = {name: SimpleNamespace(router=DataflowRouter((
        DeviceWindow('dma', 0x40000000, 16, dma),))) for name in ('cpu_a', 'cpu_b')}
    with pytest.raises(ValueError, match='shared target router'):
        ScenarioRunner(sessions={**cpus, 'dma': dma},
            ownership=compile_ownership((), ()), bindings=())
