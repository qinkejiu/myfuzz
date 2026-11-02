"""Registered E20 source contract drives actual receipt parsing, not Ibex fields."""
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch
import pytest
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
from myfuzz.scenario.router import DataflowRouter,DeviceWindow
from tests.local_harness.test_cpu_session import Target,NAMES
ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def artifact():
    from tests.local_harness.test_renderer import real_plan
    from myfuzz.local_harness import render_local_harness,verify_local_source_lock,render_local_runtime
    plan=real_plan('configs/cpus/cv32e20/component_profile.json','cpu')
    return render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)


def cpu(artifact,tmp_path,enabled=True):
    instance=GeneratedCve2Session(artifact,base_dir=ROOT,cache_dir=tmp_path,
        memory=PersistentMemory(regions=(MemoryRegion('ram',0,0x30000),),initialization_seed=0,max_initialized_bytes=0x30000),
        router=DataflowRouter((DeviceWindow('target',0x40000000,4096,Target()),)),native_irq_receipts=enabled)
    instance._case_id='case';instance._execution='a'*32
    return instance


def step(instance,*,taken=1,valid=1,intr=1,serial=3,mutate=None):
    def command(op,values):
        exports=instance._artifact_document['physical_exports']
        names={r['physical_port']:r['runtime_name'] for r in exports}
        pre={r['runtime_name']:('0'*r['hex_digits'] if r['width']>64 else 0) for r in exports}
        pre[instance._irq_runtime_name if instance.native_irq_receipts_enabled else names['irq_external_i']]=values[0]
        pre['probe_irq_taken_pre']=taken;pre['probe_irq_masked_pre']=0
        pre[names['irq_decision_serial']]=serial
        post=deepcopy(pre)
        post.update({names[n]:v for n,v in {'rvfi_valid':valid,'rvfi_intr':intr,'rvfi_order':7,
            'rvfi_insn':0x13,'rvfi_pc_rdata':0x10000,'irq_retirement_serial':serial}.items()})
        backend=dict.fromkeys(NAMES,0)
        backend.update(zip(('i_req_ready','i_rsp_valid','i_rsp_rdata','i_rsp_error','d_req_ready','d_rsp_valid','d_rsp_rdata','d_rsp_error'),values[1:]))
        seq=instance._sequence+1;tick=instance.local_ticks+1
        payload=dict(kind='obi_cpu',pre_backend=backend,observations=dict(backend=backend,physical=post),
            samples=[dict(local_tick=tick,pre=dict(backend=backend,physical=pre),post=dict(backend=backend,physical=post))])
        if mutate:mutate(payload,names)
        reply=DriverReceipt('result',instance._execution,seq,tick-1,tick,1,payload)
        instance._sequence=seq;instance.local_ticks=tick
        return reply
    with patch.object(instance,'command',side_effect=command):return instance.step_local({'irq':1})


def test_registered_E20_native_take_and_retirement_have_own_contract(artifact,tmp_path):
    instance=cpu(artifact,tmp_path)
    step(instance)
    sample=next(e for e in instance.cpu_events if e['kind']=='cpu_external_irq_sample')
    take=next(e for e in instance.cpu_events if e['kind']=='cpu_external_irq_taken')
    retired=next(e for e in instance.cpu_events if e['kind']=='cpu_retire')
    assert sample['observation_contract']['schema_version']=='cv32e20_native_irq_receipts.v1'
    assert set(sample['notification_post'])=={'rvfi_valid','rvfi_intr','rvfi_ext_mip','rvfi_ext_nmi','rvfi_ext_debug_req'}
    assert take['irq_serial_observation']['schema_version']=='cpu_irq_serial_observation.v1'
    assert retired['schema_version']=='cpu_retire.v2'
    assert retired['irq_serial_observation']['retirement']['value']==3
    assert 'ext_irq_valid' not in retired


def test_bare_RVFI_never_gains_native_serial_source_authority(artifact,tmp_path):
    instance=cpu(artifact,tmp_path,False)
    step(instance)
    retired=next(e for e in instance.cpu_events if e['kind']=='cpu_retire')
    assert 'irq_serial_observation' not in retired and 'observation_contract' not in retired
    assert not any(e['kind']=='cpu_external_irq_taken' for e in instance.cpu_events)


def test_incomplete_actual_E20_fields_fail_before_events(artifact,tmp_path):
    instance=cpu(artifact,tmp_path)
    def mutate(payload,names):payload['samples'][0]['post']['physical'].pop(names['rvfi_ext_mip'])
    with pytest.raises(ProtocolEnvironmentError):step(instance,mutate=mutate)
    assert not instance.cpu_events


def test_actual_RVFI_interrupt_notification_does_not_invent_external_take(artifact,tmp_path):
    instance=cpu(artifact,tmp_path)
    step(instance,taken=0,serial=0)
    assert any(e['kind']=='cpu_irq_notification' for e in instance.cpu_events)
    assert not any(e['kind']=='cpu_external_irq_taken' for e in instance.cpu_events)
    retired=next(e for e in instance.cpu_events if e['kind']=='cpu_retire')
    assert retired['irq_serial_observation']['retirement']['value']==0


def test_E20_decision_output_uses_actual_pre_edge_not_cleared_post(artifact,tmp_path):
    instance=cpu(artifact,tmp_path)
    def mutate(payload,names):payload['samples'][0]['post']['physical']['probe_irq_taken_pre']=0
    output=step(instance,mutate=mutate)
    assert output['irq_taken_pre']==1
