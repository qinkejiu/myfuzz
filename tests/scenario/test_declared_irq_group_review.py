"""Independent pure review of declared-output transport, not native authority."""
import pytest
from myfuzz.scenario.irq import IrqPulseDelivery
from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup,IrqDeliveryMember,IrqDeliveryGroupState


def test_declared_high_first_sample_and_reset_do_not_invent_edges():
    pulse=IrqPulseDelivery(width_ticks=4,require_observed_baseline=True)
    pulse.observe_source(1,source_tick=1,cpu_tick=0)
    assert pulse.input_at(1)==0 and pulse.events==[]
    pulse.observe_source(0,source_tick=2,cpu_tick=0)
    pulse.observe_source(1,source_tick=3,cpu_tick=0)
    assert pulse.input_at(1)==1
    pulse.reset(cpu_tick=4)
    assert pulse.source_level is None and pulse.input_at(5)==0
    pulse.observe_source(1,source_tick=4,cpu_tick=4)
    assert pulse.input_at(5)==0


def test_same_physical_source_port_cannot_be_counted_as_two_independent_bits():
    with pytest.raises(ValueError,match='invalid host IRQ delivery group'):
        IrqDeliveryGroup('bits','cpu','irq',tuple(IrqDeliveryMember('spi','events_o',
            source_bit_offset=bit,source_adapter='declared-output.v1') for bit in (0,1)))


@pytest.mark.parametrize('names,status',[ (('one',),'unique'),(('one','two'),'joint') ])
def test_single_and_joint_declared_sources_keep_native_sample_requirements(names,status):
    group=IrqDeliveryGroup('declared','cpu','irq',tuple(IrqDeliveryMember(name,'events_o',
        source_adapter='declared-output.v1') for name in names))
    assert IrqDeliveryGroup.from_document(group.document())==group
    pulses={binding:IrqPulseDelivery(width_ticks=4,require_observed_baseline=True) for binding in group.member_bindings()}
    state=IrqDeliveryGroupState(group,pulses)
    with pytest.raises(ValueError,match='native state unavailable'):state.frame(1)
    for index,binding in enumerate(group.member_bindings()):
        for tick,value in ((1,0),(2,1)):
            state.observe(binding,value,dict(event_id=10*index+tick,component=binding.source_component,
                local_tick=tick,phase='post',reset_epoch=0))
            pulses[binding].observe_source(value,source_tick=tick,cpu_tick=0)
    frame=state.frame(1)
    assert frame['attribution_status']==status and frame['value']==1
    assert frame['unique_source']==('one.events_o' if status=='unique' else None)
    assert 'native_take_event_id' not in frame
    state.reset()
    with pytest.raises(ValueError,match='native state unavailable'):state.frame(1)
