"""Declared actual output transport, without an IP-specific IRQ formula."""
import json
from copy import deepcopy
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def spi_artifact():
    from myfuzz.local_harness import load_local_harness_request,plan_local_harness,render_local_harness,render_local_runtime,verify_local_source_lock
    from myfuzz.local_harness.driver_renderer import render_local_driver
    doc=json.loads((ROOT/'configs/scenarios/compiled-f4-obi-apb-spi-ibex/requests/peripheral.json').read_text())
    doc['profile_path']='configs/peripherals/pulp_spi/component_profile.json';doc['instance_id']='spi'
    doc['tuning'].pop('apb_storage_observations')
    plan=plan_local_harness(load_local_harness_request(doc),base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan,render_local_harness(plan),
        verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)


def session(artifact,tmp_path):
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    return GeneratedApb3RegisterSession(artifact,base_dir=ROOT,cache_dir=tmp_path)


def test_real_SPI_observed_vector_uses_generic_output_adapter(spi_artifact,tmp_path):
    from myfuzz.local_harness.declared_irq_output import declared_irq_runtime_mapping
    local=session(spi_artifact,tmp_path)
    assert not local.artifact.plan.profile.interrupts
    mapping=declared_irq_runtime_mapping(local,physical_port='events_o',source_bit_offset=0)
    assert mapping['adapter_id']=='declared-output.v1' and mapping['source_width']==2
    assert mapping['transport_only'] is True and mapping['cause']=='unknown'
    assert mapping['reward_eligible'] is False and local.process is None
    assert declared_irq_runtime_mapping(local,physical_port='events_o',source_bit_offset=1)['raw_bit_offset']==1


@pytest.mark.parametrize('port,bit',[('events_o',2),('events_o',True),('spi_sdi0',0),('invented',0)])
def test_undeclared_input_or_out_of_range_bit_refuses(spi_artifact,tmp_path,port,bit):
    from myfuzz.local_harness.declared_irq_output import declared_irq_runtime_mapping
    with pytest.raises(ValueError):declared_irq_runtime_mapping(session(spi_artifact,tmp_path),physical_port=port,source_bit_offset=bit)


def test_actual_output_projection_mismatch_refuses(spi_artifact,tmp_path):
    from myfuzz.local_harness.declared_irq_output import declared_irq_runtime_mapping
    local=session(spi_artifact,tmp_path);local._outputs['events_o']=('invented',2)
    with pytest.raises(ValueError):declared_irq_runtime_mapping(local,physical_port='events_o',source_bit_offset=0)


def test_actual_SPI_single_source_installs_without_internal_IRQ_contract(spi_artifact,tmp_path):
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
    from myfuzz.scenario.router import DataflowRouter
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup,IrqDeliveryMember
    from myfuzz.scenario.ownership import InputField,InputOwner,compile_ownership
    from myfuzz.scenario.runner import ScenarioRunner
    source=session(spi_artifact,tmp_path)
    cpu=GeneratedCve2Session(_artifact('configs/cpus/ibex_rvfi_local/component_profile.json','cpu'),
        base_dir=ROOT,cache_dir=tmp_path,memory=PersistentMemory(regions=(MemoryRegion('ram',0,0x30000),),
            initialization_seed=0,max_initialized_bytes=0x30000),router=DataflowRouter(()),native_irq_receipts=True)
    group=IrqDeliveryGroup('spi-external','cpu',cpu.irq_input_port,(
        IrqDeliveryMember('spi','events_o',source_bit_offset=0,source_adapter='declared-output.v1'),))
    fields=[InputField('cpu',cpu.irq_input_port,1)];owners=[InputOwner('cpu',cpu.irq_input_port,0,1,'bound',group.owner_ref)]
    for row in spi_artifact.runtime_document['fixed_physical_inputs']:
        port=row['endpoint_id']+'.'+row['role'];fields.append(InputField('spi',port,row['width']))
        owners.append(InputOwner('spi',port,0,row['width'],'fixed','profile_constant'))
    runner=ScenarioRunner(sessions={'spi':source,'cpu':cpu},ownership=compile_ownership(tuple(fields),tuple(owners)),
        bindings=group.member_bindings(),irq_delivery_groups=(group,))
    binding=group.member_bindings()[0]
    assert runner._irq_group_adapters[binding]['transport_only'] is True
    assert runner._irq_pulses[binding].source_level is None
    assert all(local.process is None for local in runner.sessions.values())
    with pytest.raises(ValueError,match='native state unavailable'):runner._irq_group_states[group.group_id].frame(1)
    # A parsed ACCESS receipt may contain a pulse wholly inside its tick span.
    # Feed the original target parser, then the original Runner raw drain;
    # no native process or live acceptance authority is claimed by this test.
    from myfuzz.local_harness.wire import DriverReceipt
    def parsed_access(start,values):
        samples=[]
        for tick,value in enumerate(values,start):
            physical={r['runtime_name']:0 for r in spi_artifact.runtime_document['physical_exports']}
            physical[source._outputs['events_o'][0]]=value
            backend={r['name']:0 for r in spi_artifact.runtime_document['backend_ports']}
            phase=dict(physical=physical,backend=backend)
            samples.append(dict(local_tick=tick,pre=deepcopy(phase),post=deepcopy(phase)))
        reply=DriverReceipt('result','parsed-only',1,start-1,start+len(values)-1,len(values),
            dict(samples=samples,observations=dict(physical=samples[-1]['post']['physical']),rdata=0,error=0))
        final=source._take(reply)
        source.local_ticks=start+len(values)-1;runner.local_ticks['spi']=source.local_ticks
        runner._drain_tick_samples(1)
        return final
    assert parsed_access(1,(0,1,0))['events_o']==0
    pulse=runner._irq_pulses[binding]
    assert pulse.input_at(1)==1
    frame=runner._irq_group_states[group.group_id].frame(1)
    reference=frame['members'][0]['native_source']
    event=runner._event_ref_by_id(reference['event_id'])
    assert event['local_tick']==2 and event['phase']=='pre'
    assert event['outputs']['physical'][source._outputs['events_o'][0]]==1
    # A pulse of the other real vector bit never raises the declared bit.
    pulse.reset(cpu_tick=4);runner.local_ticks['cpu']=4
    runner._irq_group_states[group.group_id].reset()
    parsed_access(4,(0,2,0))
    assert pulse.input_at(5)==0



@pytest.mark.parametrize('name',['_take_impl','step_local_routed','_step_with_inputs'])
def test_native_sampler_delegates_cannot_be_replaced(spi_artifact,tmp_path,name):
    from myfuzz.local_harness.declared_irq_output import declared_irq_runtime_mapping
    local=session(spi_artifact,tmp_path)
    setattr(local,name,lambda *args,**kwargs:None)
    with pytest.raises(ValueError,match='original-native-sampler'):
        declared_irq_runtime_mapping(local,physical_port='events_o',source_bit_offset=0)


def test_target_class_selector_is_one_protocol_registry_not_source_authority(spi_artifact):
    from dataclasses import replace
    from myfuzz.local_harness.declared_irq_output import declared_irq_target_session_type
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.local_harness.wishbone_register_session import GeneratedWishboneRegisterSession
    from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
    # Metadata selection only: real constructors and mapping still admit their
    # entire actual artifact. These altered kinds grant no sampler authority.
    for kind,cls in [('apb3_register_observe',GeneratedApb3RegisterSession),
                     ('wishbone_register_observe',GeneratedWishboneRegisterSession),
                     ('ahb_lite_register_observe',GeneratedAhbLiteRegisterSession)]:
        assert declared_irq_target_session_type(replace(spi_artifact,runtime_document={'kind':kind})) is cls
    with pytest.raises(ValueError):declared_irq_target_session_type(replace(spi_artifact,runtime_document={'kind':'unknown'}))
    with pytest.raises(ValueError):declared_irq_target_session_type(object())
