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
    cpu._execution = 'unit-test-native-execution'
    cpu._case_id, cpu.source_component, cpu.reset_epoch = 'test', 'renamed-cpu', 0
    cpu.read_beats = cpu.write_beats = cpu.write_responses = 0
    cpu._clear()
    edge_tick = 0
    def edge(**outputs):
        nonlocal edge_tick
        edge_tick += 1
        def command(operation, fields):
            assert operation == 'STEP_REDUCED_AXI'
            row = {p+'_'+role: 0 for p, shape in SHAPES.items() for role in shape}
            row.update(zip(STEP_PORTS, fields))
            row.update(outputs)
            return SimpleNamespace(status='ok', new_ticks=1, payload={
                'kind':cpu.artifact_kind, 'pre_backend':row,
                'samples':[{'local_tick':edge_tick, 'pre':{'backend':row},
                            'post':{'backend':copy.deepcopy(row)}}], 'observations':{'physical':{}}})
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


def exercise_mmio(a, cache, *, substitute=False):
    """Actual native CPU → queued router → native GPIO → CPU → RAM."""
    from dataclasses import asdict
    from myfuzz.local_harness import GeneratedPulpGpioSession
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact, GPIO_PROFILE
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    gpio = GeneratedPulpGpioSession(_artifact(GPIO_PROFILE, 'gpio', physical_observations=True),
                                   base_dir=ROOT, cache_dir=cache, command_timeout_seconds=120)
    gpio.configure_ordinary_apb_access_receipts(max_records=8)
    router = DataflowRouter((DeviceWindow('gpio', 0x40000000, 0x1000, gpio),))
    memory = PersistentMemory(regions=(MemoryRegion('ram', BOOT, 0x100000),),
                              initialization_seed=0, max_initialized_bytes=0x10000)
    # GPIO PADOUT=53; read PADOUT; add1; store result in RAM.
    program = (0x400000b7, 0x03500113, 0x0020a623, 0x00c0a183,
               0x00118213, 0x800002b7, 0x1042a223, 0x0000006f)
    memory.preload(BOOT, b''.join(w.to_bytes(4,'little') for w in program))
    cpu = GeneratedReducedAxiCpuSession(a, base_dir=ROOT, cache_dir=cache,
        memory=memory, mmio_router=router, command_timeout_seconds=120)
    samples=[];target_samples=[]; substitutions=[]
    if substitute:
        original = gpio.execute_observed_register_access
        def replaced(key, *, delivery_context):
            result = original(key, delivery_context=delivery_context)
            # Explicit adversarial environment: corrupt target return while its
            # actual native receipt remains unchanged. Router must reject it.
            if not delivery_context['write']:
                substitutions.append(copy.deepcopy(result))
                return {**result, 'rdata':result['rdata'] ^ 1}
            return result
        gpio.execute_observed_register_access = replaced
    try:
        gpio.begin_case('vexii-gpio');cpu.begin_case('vexii-gpio')
        rejected=None
        for _ in range(500):
            cpu.step_local({});samples.extend(copy.deepcopy(cpu.last_samples))
            try:
                for name in router.ready_targets:router.drain_one(name)
            except ValueError as error:
                if not substitute:raise
                rejected=str(error);break
            target_samples.extend(gpio.drain_tick_samples())
            if cpu.write_responses==2:break
        else:pytest.fail('strict 500 CPU tick bound exceeded')
        rows=[s['pre']['backend'] for s in samples]
        aw=[r['d_awaddr'] for r in rows if r['d_awvalid'] and r['d_awready']]
        assert aw[:1]==[0x4000000c]
        assert len(router.acceptances)==2
        keys=[r['source_transaction'] for r in router.acceptances]
        assert all(k.execution_id==cpu._execution and k.source_epoch==cpu.reset_epoch for k in keys)
        assert [k.source_sequence for k in keys]==[1,2]
        if substitute:
            assert rejected=='ordinary APB actual receipt binding mismatch'
            assert substitutions and cpu.write_responses==1
            assert not any(r['d_awaddr']==BOOT+0x104 for r in rows if r['d_awvalid'] and r['d_awready'])
        else:
            assert aw==[0x4000000c, BOOT+0x104]
            assert [r['d_wdata'] for r in rows if r['d_wvalid'] and r['d_wready']]==[53,54]
            assert [r['d_rdata'] for r in rows if r['d_rvalid'] and r['d_rready']]==[53]
            assert memory.read(BOOT+0x104,4,transaction_id='verify').value==54
            assert len(router.deliveries)==2 and not cpu.service.ledger.unresolved_keys
            assert all(r['source_delivery_confirmed'] for r in router.deliveries)
        return dict(identity=cpu.identity_document(), target_identity=gpio.identity_document(),
            execution=cpu._execution, ticks=cpu.local_ticks, samples=samples,
            target_samples=target_samples, acceptances=router.acceptances, deliveries=router.deliveries,
            ledger=[dict(key=asdict(k),status=e.status,payload_digest=e.payload_digest,receipt=e.receipt)
                    for k,e in cpu.service.ledger._entries.items()],
            rejected=rejected, substitutions=substitutions)
    finally:
        cpu.end_case();gpio.end_case()


@pytest.mark.skipif(os.environ.get('MYFUZZ_VEXII_MMIO_REAL')!='1',reason='explicit real CPU/IP gate')
def test_real_generated_vexii_gpio_two_fresh_runs_and_substitution(tmp_path):
    from dataclasses import asdict,is_dataclass
    a=artifact();cache=Path(os.environ.get('MYFUZZ_VEXII_CACHE',str(tmp_path/'cache')))
    first=exercise_mmio(a,cache);fresh=exercise_mmio(a,cache)
    fault=exercise_mmio(a,cache,substitute=True)
    assert first['execution']!=fresh['execution']
    assert first['identity']==fresh['identity'] and first['target_identity']==fresh['target_identity']
    assert first['samples']==fresh['samples']
    assert first['target_samples']==fresh['target_samples']
    if 'MYFUZZ_VEXII_EVIDENCE' in os.environ:
        directory=Path(os.environ['MYFUZZ_VEXII_EVIDENCE']);directory.mkdir(parents=True,exist_ok=True)
        for name,value in [('mmio-first',first),('mmio-fresh',fresh),('mmio-fault',fault),('mmio-artifact',a.runtime_document)]:
            (directory/(name+'.json')).write_text(json.dumps(value,indent=2,sort_keys=True,
                default=lambda x:asdict(x) if is_dataclass(x) else str(x))+'\n')


def test_runtime_observer_uses_actual_receipt_and_preserves_failed_edge():
    cpu, edge = fake_cpu()
    edge(i_arvalid=1, i_araddr=BOOT, i_arsize=2, i_arid=1)
    stream = cpu.runtime_events
    assert stream[-1]['kind'] == 'reduced_axi_accept'
    assert stream[-1]['payload']['arid'] == 1
    assert stream[-2]['raw_sample'] == cpu.last_samples[0]
    from myfuzz.scenario.contracts import ProtocolEnvironmentError
    with pytest.raises(ProtocolEnvironmentError, match='(last|LAST)'):
        edge(d_wvalid=1, d_wlast=0)
    assert cpu.runtime_events is stream
    assert stream[-1]['kind'] == 'reduced_axi_violation'
    assert stream[-2]['raw_sample'] == cpu.last_samples[0]


def test_observer_failure_blocks_later_native_commands():
    from myfuzz.scenario.contracts import ProtocolEnvironmentError
    cpu, edge = fake_cpu()
    with pytest.raises(ProtocolEnvironmentError, match='last'):
        edge(d_wvalid=1, d_wlast=0)
    calls = []
    def forbidden_command(*args):
        calls.append(args)
        raise AssertionError('poisoned observer must block before native edge')
    cpu.command = forbidden_command
    with pytest.raises(ProtocolEnvironmentError, match='scope_not_active'):
        cpu.step_local({})
    assert calls == []
