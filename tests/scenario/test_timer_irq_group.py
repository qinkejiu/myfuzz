"""Vector pulse routing uses the selected bit of the actual raw source sample."""
from types import SimpleNamespace
import pytest

from myfuzz.scenario.irq import IrqPulseDelivery
from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember, IrqDeliveryGroupState
from myfuzz.scenario.runner import ScenarioRunner


def source_runner(raw_value):
    group = IrqDeliveryGroup('timer-or', 'cpu', 'irq', (
        IrqDeliveryMember('timer', 'irq_o', source_bit_offset=3),
        IrqDeliveryMember('gpio', 'interrupt')))
    binding = group.member_bindings()[0]
    pulse = IrqPulseDelivery(width_ticks=4)
    runner = object.__new__(ScenarioRunner)
    runner._irq_group_members = {binding: group}
    runner._irq_group_adapters = {binding: {'runtime_name': 'actual_timer_wire',
        'source_width': 4, 'adapter_id': 'pulp_timer.apb-native-pulses.v1'}}
    runner.sessions = {'timer': SimpleNamespace(reset_epoch=0)}
    runner._events = [dict(event_id=1, kind='local_tick_sample', component='timer',
        local_tick=1, phase='post', reset_epoch=0, outputs={'physical': {'actual_timer_wire': raw_value}})]
    runner._irq_group_states = {group.group_id: IrqDeliveryGroupState(group, {binding: pulse})}
    runner._irq_pulses = {binding: pulse}
    runner._irq_event_offsets = {binding: 0}
    runner._gpio_irq_runtime_ports = {}
    runner._provenance = None
    runner.local_ticks = {'cpu': 0}
    runner.bindings = (binding,)
    runner._status = 'running'
    return runner, group, binding


def test_timer_vector_bit_is_checked_against_exact_native_sample():
    runner, group, binding = source_runner(8)
    runner._route_observed_outputs('timer', {'irq_o': 8}, 1, 1)
    assert runner._irq_group_states[group.group_id].samples[binding]['value'] == 1
    assert runner._irq_pulses[binding].source_level == 1


@pytest.mark.parametrize('raw', [0, 16, -1, True])
def test_vector_decoded_value_cannot_replace_different_or_invalid_raw_sample(raw):
    runner, group, binding = source_runner(raw)
    with pytest.raises(ValueError, match='actual native source'):
        runner._route_observed_outputs('timer', {'irq_o': 8}, 1, 1)
    assert not runner._irq_group_states[group.group_id].samples
