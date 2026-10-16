"""Reduced AXI contract and real generated Vexii CPU/RAM acceptance."""
import copy
import json
import os
from dataclasses import replace
from pathlib import Path
import pytest
from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.local_harness.vexii_axi_fields import SHAPES, STEP_PORTS
from myfuzz.local_harness.vexii_axi_session import GeneratedReducedAxiCpuSession
from myfuzz.local_harness.template_contracts import select_template_contract
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory

ROOT = Path(__file__).resolve().parents[2]
BOOT = 0x80000000
PROGRAM = (0x800000b7, 0x10008093, 0x03500113, 0x0020a023,
           0x0000a183, 0x00118213, 0x0040a223, 0x0000006f)


def artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/cpus/vexiiriscv/component_profile.json', instance_id='cpu',
        reset_assert_ticks=12, reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)


def test_reduced_axi_matches_actual_ports_and_requires_semantic_admission():
    a = artifact()
    assert len(a.plan.facts.ports) == 48
    assert len(a.runtime_document['backend_ports']) == 42
    assert a.runtime_document['kind'] == 'reduced_dual_axi_cpu'
    assert 'STEP_REDUCED_AXI' in a.cpp_text
    for row in a.runtime_document['backend_ports']:
        assert row['role'] in SHAPES[row['channel']]
        assert row['role'] not in ('arlen', 'awlen', 'arburst', 'awburst')
    caps = dict(a.plan.profile.capabilities)
    for endpoint in a.plan.binding.endpoints:
        contract = select_template_contract(endpoint, caps)
        assert contract.contract.template_id == 'cpu.axi4-reduced'
        missing = {k:v for k,v in caps.items() if k != 'single_beat_reduced_axi'}
        with pytest.raises(ValueError):
            select_template_contract(endpoint, missing)
        with pytest.raises(ValueError):
            select_template_contract(endpoint, {**caps, 'bursts':True})
    assert not any(name.startswith('i_aw') for name in STEP_PORTS)


class FaultReadMemory(PersistentMemory):
    """Explicit negative-control environment, not a production session mode."""
    def read(self, address, width_bytes, **kwargs):
        result = super().read(address, width_bytes, **kwargs)
        if address == BOOT+0x100:
            return replace(result, data=bytes(width_bytes))
        return result


def exercise(a, cache, *, fault=False):
    cls = FaultReadMemory if fault else PersistentMemory
    memory = cls(regions=(MemoryRegion('ram', BOOT, 0x100000),),
                 initialization_seed=0, max_initialized_bytes=0x10000)
    memory.preload(BOOT, b''.join(word.to_bytes(4, 'little') for word in PROGRAM))
    cpu = GeneratedReducedAxiCpuSession(a, base_dir=ROOT, cache_dir=cache,
                                       memory=memory, command_timeout_seconds=120)
    samples = []
    try:
        cpu.begin_case('vexii-generated-ram')
        for _ in range(500):
            cpu.step_local({})
            samples.extend(copy.deepcopy(cpu.last_samples))
            if cpu.write_responses == 2:
                break
        else:
            pytest.fail('generated CPU did not finish both actual B responses')
        # Read physical accepted stores and data R responses independently of
        # the service counters and RAM's write ledger.
        pre = [sample['pre']['backend'] for sample in samples]
        aw = [x['d_awaddr'] for x in pre if x['d_awvalid'] and x['d_awready']]
        writes = [(x['d_wdata'], x['d_wstrb'], x['d_wlast']) for x in pre
                  if x['d_wvalid'] and x['d_wready']]
        assert aw == [BOOT+0x100, BOOT+0x104]
        assert writes == [(53,15,1), (1 if fault else 54,15,1)]
        loads = [x for x in pre if x['d_arvalid'] and x['d_arready']]
        responses = [x for x in pre if x['d_rvalid'] and x['d_rready']]
        assert len(loads) == len(responses) == 1
        assert loads[0]['d_araddr'] == BOOT+0x100 and loads[0]['d_arsize'] == 2
        assert responses[0]['d_rdata'] == (0 if fault else 53)
        assert responses[0]['d_rlast'] == 1
        assert sum(x['i_arvalid'] and x['i_arready'] for x in pre) >= 8
        assert cpu.write_beats == cpu.write_responses == 2
        assert PersistentMemory.read(memory, BOOT+0x100, 4, transaction_id='verify0').value == 53
        assert PersistentMemory.read(memory, BOOT+0x104, 4, transaction_id='verify1').value == (1 if fault else 54)
        return dict(identity=cpu.identity_document(), execution=cpu._execution,
                    ticks=cpu.local_ticks, samples=samples, fault_read=fault,
                    stores=writes, data_reads=len(loads), b_responses=cpu.write_responses)
    finally:
        cpu.end_case()


@pytest.mark.skipif(os.environ.get('MYFUZZ_VEXII_REAL') != '1', reason='explicit real RTL gate')
def test_real_generated_cpu_ram_two_fresh_processes_and_load_negative_control(tmp_path):
    a = artifact()
    cache = Path(os.environ.get('MYFUZZ_VEXII_CACHE', str(tmp_path/'cache')))
    first = exercise(a, cache)
    fresh = exercise(a, cache)
    fault = exercise(a, cache, fault=True)
    assert first['execution'] != fresh['execution']
    assert first['identity'] == fresh['identity']
    assert first['samples'] == fresh['samples']
    assert first['stores'] != fault['stores']
    if 'MYFUZZ_VEXII_EVIDENCE' in os.environ:
        directory = Path(os.environ['MYFUZZ_VEXII_EVIDENCE'])
        directory.mkdir(parents=True, exist_ok=True)
        for name, data in [('first',first), ('fresh',fresh), ('fault',fault), ('artifact',a.runtime_document)]:
            (directory/(name+'.json')).write_text(json.dumps(data, indent=2, sort_keys=True)+'\n')


def fake_cpu():
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.ledger import TransactionLedger
    from types import SimpleNamespace
    cpu = object.__new__(GeneratedReducedAxiCpuSession)
    cpu.memory = PersistentMemory(regions=(MemoryRegion('ram', BOOT, 4096),),
        initialization_seed=0, max_initialized_bytes=4096)
    cpu.service = MemoryService(cpu.memory, TransactionLedger())
    cpu._case_id, cpu.source_component, cpu.reset_epoch = 'test', 'renamed-cpu', 0
    cpu.read_beats = cpu.write_beats = cpu.write_responses = 0
    cpu._clear()
    def edge(**outputs):
        def command(operation, fields):
            assert operation == 'STEP_REDUCED_AXI'
            row = {p+'_'+role: 0 for p, shape in SHAPES.items() for role in shape}
            row.update(zip(STEP_PORTS, fields))
            row.update(outputs)
            return SimpleNamespace(status='ok', new_ticks=1, payload={
                'kind':cpu.artifact_kind, 'pre_backend':row,
                'samples':[{'pre':{'backend':row}}], 'observations':{'physical':{}}})
        cpu.command = command
        return cpu.step_local({})
    return cpu, edge


@pytest.mark.parametrize('data_first', [True, False])
def test_independent_aw_w_single_commit_and_response_hold(data_first):
    cpu, edge = fake_cpu()
    aw = dict(d_awvalid=1,d_awaddr=BOOT+0x100,d_awid=1,d_awsize=2)
    w = dict(d_wvalid=1,d_wdata=53,d_wstrb=15,d_wlast=1)
    edge(**(w if data_first else aw))
    assert cpu.write_beats == 0
    cpu.begin_quiesce()
    edge(**(aw if data_first else w))
    assert cpu.write_beats == 1
    pending = cpu._ready_inputs()
    edge()
    assert cpu._ready_inputs() == pending and cpu.write_beats == 1
    assert pending['d_bvalid'] == pending['d_bid'] == 1
    edge(d_bready=1)
    assert cpu.write_responses == 1 and cpu.pending_responses == 0
    assert cpu.memory.read(BOOT+0x100,4,transaction_id='check').value == 53


def test_read_snapshot_holds_until_acceptance():
    cpu, edge = fake_cpu()
    cpu.memory.preload(BOOT+0x100, (53).to_bytes(4,'little'))
    edge(d_arvalid=1,d_araddr=BOOT+0x100,d_arid=1,d_arsize=2)
    pending = cpu._ready_inputs()
    edge()
    assert pending == cpu._ready_inputs()
    assert pending['d_rdata'] == 53 and pending['d_rid'] == pending['d_rlast'] == 1
    edge(d_rready=1)
    assert cpu.read_beats == 1 and cpu.pending_responses == 0


@pytest.mark.parametrize('outputs', [
    dict(d_arvalid=1,d_araddr=BOOT+1,d_arsize=2),
    dict(d_arvalid=1,d_araddr=BOOT,d_arsize=3),
    dict(d_wvalid=1,d_wlast=0),
    dict(d_awvalid=1,d_awaddr=BOOT,d_awsize=0,d_wvalid=1,d_wlast=1,d_wstrb=15),
])
def test_unsupported_transfers_refuse(outputs):
    from myfuzz.scenario.contracts import ProtocolEnvironmentError
    cpu, edge = fake_cpu()
    with pytest.raises(ProtocolEnvironmentError):
        edge(**outputs)
    assert cpu.write_beats == 0
