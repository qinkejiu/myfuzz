import pytest
from myfuzz.scenario.irq import IrqPulseDelivery
from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup,IrqDeliveryMember


def test_single_declared_source_roundtrip_and_default_documents_unchanged():
    member=IrqDeliveryMember('spi','events_o',source_adapter='declared-output.v1')
    group=IrqDeliveryGroup('external','cpu','irq_external_i',(member,))
    assert IrqDeliveryGroup.from_document(group.document())==group
    legacy=IrqDeliveryGroup('legacy','cpu','irq_external_i',(IrqDeliveryMember('dma','irq'),IrqDeliveryMember('gpio','interrupt')))
    assert all('source_adapter' not in row for row in legacy.document()['members'])


def test_declared_pulse_needs_actual_baseline_and_reset_reestablishes_it():
    pulse=IrqPulseDelivery(width_ticks=4,require_observed_baseline=True)
    assert pulse.source_level is None
    pulse.observe_source(1,source_tick=1,cpu_tick=0)
    assert not pulse.events and pulse.input_at(1)==0
    pulse.observe_source(0,source_tick=2,cpu_tick=0)
    assert not pulse.events
    pulse.observe_source(1,source_tick=3,cpu_tick=0)
    assert pulse.input_at(1)==1
    pulse.reset(cpu_tick=2)
    assert pulse.source_level is None
    count=len(pulse.events);pulse.observe_source(1,source_tick=4,cpu_tick=2)
    assert len(pulse.events)==count and pulse.input_at(3)==0


def test_legacy_pulse_still_maps_its_first_high():
    pulse=IrqPulseDelivery(width_ticks=4)
    pulse.observe_source(1,source_tick=1,cpu_tick=0)
    assert pulse.input_at(1)==1


def test_same_vector_multiple_members_are_explicitly_unsupported():
    with pytest.raises(ValueError):IrqDeliveryGroup('duplicate','cpu','irq_external_i',(
        IrqDeliveryMember('spi','events_o',source_bit_offset=0,source_adapter='declared-output.v1'),
        IrqDeliveryMember('spi','events_o',source_bit_offset=1,source_adapter='declared-output.v1')))
