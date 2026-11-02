"""Wishbone CPU shares the real host RAM evidence services with other buses."""
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession, _LIMITS
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
from myfuzz.scenario.router import DataflowRouter
from tests.local_harness.test_wishbone_cpu import cpu_artifact

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def artifact():
    return cpu_artifact()


def session(artifact, **flags):
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                              initialization_seed=0, max_initialized_bytes=4096)
    cpu = GeneratedWishboneCpuSession(artifact, base_dir=ROOT, cache_dir=ROOT/'unused',
        memory=memory, router=DataflowRouter(()), **flags)
    cpu._case_id = 'testcase'
    return cpu


def test_real_ram_write_and_read_use_shared_commit_and_read_authorities(artifact):
    cpu = session(artifact, memory_commit_receipts=True, memory_readback_receipts=True)
    cpu.memory.preload(0x100, bytes.fromhex('11223344'))
    cpu.memory_read_authority = MemoryReadAuthority(services={'cpu_wb': cpu.service})
    cpu._serve(instruction=False, write=1, address=0x100, wdata=0xaabbccdd, sel=5)
    commits = cpu.service.drain_commit_events()
    assert len(commits) == 1 and commits[0]['transaction']['channel_id'] == 'data'
    assert commits[0]['commit_document']['byte_enable'] == 5
    cpu._pending = None
    cpu._serve(instruction=False, write=0, address=0x100, wdata=0, sel=0)
    assert cpu._pending[0] == 0x44bb22dd
    assert cpu.memory_read_authority.pending_count == 1
    assert cpu.service.events[-1]['kind'] == 'memory_read'
    assert cpu.service.events[-1]['writer_kinds']


def test_optional_physical_tick_stream_keeps_measured_pre_post(artifact):
    cpu = session(artifact, physical_tick_samples=True)
    physical = {row['runtime_name']:('0'*row['hex_digits'] if row['width'] > 64 else 0)
        for row in artifact.runtime_document['physical_exports']}
    physical[artifact.runtime_document['instruction_identity_observation']] = 0
    backend = {name:0 for name in _LIMITS}
    sample = {'local_tick':1,'pre':{'backend':backend,'physical':physical},
              'post':{'backend':backend,'physical':physical}}
    payload = {'kind':'wishbone_cpu','pre_backend':backend,'samples':[sample],
               'observations':sample['post']}
    def command(*args):
        cpu.local_ticks = 1
        return DriverReceipt('result','a'*32,1,0,1,1,payload)
    with patch.object(cpu, 'command', side_effect=command):
        cpu.step_local({})
    samples = cpu.drain_tick_samples()
    assert len(samples) == 1 and samples[0]['local_tick'] == 1
    assert samples[0]['pre'] == sample['pre'] and samples[0]['post'] == sample['post']
    assert cpu.drain_tick_samples() == []


def test_memory_evidence_identity_is_accepted_and_forged_capacity_is_not(artifact):
    from myfuzz.scenario.contracts import _verify_generated_session
    cpu = session(artifact, memory_commit_receipts=True, memory_readback_receipts=True,
                  physical_tick_samples=True)
    identity = cpu.identity_document()
    assert _verify_generated_session(identity).runtime_document == artifact.runtime_document
    identity['memory_commit_stream']['capacity'] = 999
    with pytest.raises(ValueError):
        _verify_generated_session(identity)


def test_standard_runner_installs_actual_shared_ram_authorities(artifact):
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.scenario.runner import ScenarioRunner
    cpu = session(artifact, memory_commit_receipts=True, memory_readback_receipts=True)
    runner = ScenarioRunner(sessions={'cpu_wb':cpu}, ownership=compile_ownership((),()), bindings=())
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a'*64)
    assert cpu.memory_read_authority is runner._memory_read_authority
    cpu._serve(instruction=False,write=1,address=0x100,wdata=0x12345678,sel=15)
    cpu._pending=None
    cpu._serve(instruction=False,write=0,address=0x100,wdata=0,sel=0)
    assert cpu._pending[0] == 0x12345678
    assert len(cpu.service.drain_commit_events()) == 1
    assert runner._memory_read_authority.pending_count == 1


def test_real_wishbone_cpu_emits_ram_authority_and_physical_samples(artifact):
    """Execute load/store/load on the real CPU; no inferred retirement or IRQ."""
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(prefix='myfuzz-wb-evidence-') as directory:
        cpu = GeneratedWishboneCpuSession(artifact, base_dir=ROOT, cache_dir=Path(directory),
            memory=PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                initialization_seed=0, max_initialized_bytes=4096),
            router=DataflowRouter(()), memory_commit_receipts=True,
            memory_readback_receipts=True, physical_tick_samples=True)
        cpu.memory.preload(0, bytes.fromhex('83200002 23221002 03214002 6f000000'.replace(' ', '')))
        cpu.memory.preload(0x20, bytes.fromhex('78563412'))
        cpu.memory_read_authority = MemoryReadAuthority(services={'cpu_wb':cpu.service})
        observed = []
        cpu.begin_case('real-wb-ram-evidence')
        try:
            for _ in range(200):
                observed.append(cpu.step_local({}))
                assert len(cpu.drain_tick_samples()) == 1
                if cpu.memory_read_authority.pending_count >= 2 and cpu.pending_responses == 0:
                    break
            else:
                pytest.fail('real CPU did not complete two reads and one write')
            assert cpu.memory.read(0x24,4,transaction_id='test').value == 0x12345678
            assert cpu.memory_read_authority.pending_count == 2
            assert len(cpu.service.drain_commit_events()) == 1
            assert any(row['data_req_accepted'] and row['data_write'] for row in observed)
            assert sum(row['data_req_accepted'] and not row['data_write'] for row in observed) == 2
        finally:
            cpu.end_case()
