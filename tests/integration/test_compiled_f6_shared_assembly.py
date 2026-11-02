"""Pre-start assembly tests; no build, launch, or native execution."""
import pytest

from tests.integration.test_compiled_f6_runtime import inputs
from tests.integration.test_compiled_f6_contract import ROOT, f6


def assemble(inputs, tmp_path, **kwargs):
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    compiled, artifacts = inputs
    contract = f6(compiled['compiled'])['execution_contract']
    return build_f6_assembly(contract=contract, artifacts=artifacts,
        ownership=_f6_runner_ownership(compiled['ownership'], cpu_id='cpu', dma_id='dma'),
        base_dir=ROOT, cache_dir=tmp_path, **kwargs)


def test_external_ram_and_dma_service_are_the_actual_assembly_owners(inputs, tmp_path):
    from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.ledger import TransactionLedger
    resource = f6(inputs[0]['compiled'])['execution_contract']['memory']['resource']
    memory = PersistentMemory(regions=(MemoryRegion(resource['resource_id'],
        resource['base'], resource['size']),), initialization_seed=0,
        max_initialized_bytes=resource['size'])
    service = MemoryService(memory, TransactionLedger(), include_writer_kinds=True,
        commit_stream_capacity=256)
    assembly = assemble(inputs, tmp_path, memory=memory, dma_service=service)
    assert assembly.memory is memory
    assert assembly.cpu.memory is memory
    assert assembly.dma.memory_service is service
    assert assembly.runner.sessions == {'cpu': assembly.cpu, 'dma': assembly.dma}
    assert assembly.cpu.router.windows[0].target is assembly.dma
    assert assembly.cpu._process is assembly.dma._process is None
    assert assembly.cpu.memory_commit_receipts_enabled
    assert assembly.cpu.memory_readback_receipts_enabled
    assert assembly.cpu.native_irq_receipts_enabled


def test_existing_cpu_dma_and_runner_are_reused(inputs, tmp_path):
    first = assemble(inputs, tmp_path)
    second = assemble(inputs, tmp_path, memory=first.memory, cpu=first.cpu,
        dma=first.dma, runner=first.runner)
    assert second.cpu is first.cpu
    assert second.dma is first.dma
    assert second.runner is first.runner


@pytest.mark.parametrize('mutation, error', [
    ('foreign_ram', 'memory-owner'), ('started', 'pre-start'),
    ('missing_receipts', 'CPU-capabilities'), ('missing_window', 'control-window'),
    ('foreign_runner', 'runner-sessions'),
])
def test_external_assembly_rejects_mismatched_live_owners(inputs, tmp_path, mutation, error):
    first = assemble(inputs, tmp_path)
    if mutation == 'foreign_ram':
        first.dma.memory_service.memory = object()
    elif mutation == 'started':
        first.cpu._case_id = 'already-started'
    elif mutation == 'missing_receipts':
        first.cpu.memory_readback_receipts_enabled = False
    elif mutation == 'missing_window':
        first.cpu.router.windows = ()
    else:
        first.runner.sessions['cpu'] = object()
    with pytest.raises(ValueError, match=error):
        assemble(inputs, tmp_path, memory=first.memory, cpu=first.cpu,
            dma=first.dma, runner=first.runner)


def test_other_flow_reservation_cannot_overlap_f6_program_or_data(inputs, tmp_path):
    from myfuzz.integration.shared_f6_assembly import MemoryReservation
    p = f6(inputs[0]['compiled'])['execution_contract']['program_contract']
    with pytest.raises(ValueError, match='reservation-overlap'):
        assemble(inputs, tmp_path, reservations=(MemoryReservation('F4', p['source_address'], 4),))


@pytest.mark.parametrize('external', [True, False])
def test_constructor_consumes_external_assembly_before_preparing_native(inputs, tmp_path, monkeypatch, external):
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    assembly = assemble(inputs, tmp_path) if external else None
    prepared = []
    class StopBeforeBuild(Exception):
        pass
    def stop(self):
        prepared.append(self)
        raise StopBeforeBuild
    monkeypatch.setattr(GeneratedCve2Session, 'prepare_local', stop)
    with pytest.raises(StopBeforeBuild):
        CompiledF6Runtime(artifacts=inputs[1], compiled_inputs=inputs[0],
            base_dir=ROOT, cache_dir=tmp_path, shared_assembly=assembly,
            defer_begin=True, max_cases=1)
    assert len(prepared) == 1
    if external:
        assert prepared == [assembly.cpu]
        assert assembly.runner._uart_ram_commit_join is not None


def test_invalid_assembly_object_cannot_reach_prepare(inputs, tmp_path):
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    with pytest.raises(ValueError, match='shared-assembly-type'):
        CompiledF6Runtime(artifacts=inputs[1], compiled_inputs=inputs[0],
            base_dir=ROOT, cache_dir=tmp_path, shared_assembly=object(),
            defer_begin=True, max_cases=1)

