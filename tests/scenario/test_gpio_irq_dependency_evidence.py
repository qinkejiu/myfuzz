"""GPIO IRQ boundaries require measured source, exact CPU input/take and serial."""
from copy import deepcopy
import pytest
from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
from tests.scenario.test_gpio_consumption_versions import probes, tick
from tests.scenario.test_irq_serial_certificates import serial_observation


def trace():
    pin = 3; mask = 1 << pin
    pre = probes(gpioen=mask, inten=mask, inttype=1 << (pin*2), input_clock_enable=1, sync0=mask)
    post = probes(gpioen=mask, inten=mask, inttype=1 << (pin*2), input_clock_enable=1,
        sync1=mask, rise=mask, irq_trigger_mask=mask, native_irq=1)
    raw = tick(1, pre, post, component='device')
    ref = dict(trigger_id='actual-trigger', trigger_event_id=2, observation_event_id=1, sample_event_id=3)
    endpoint = dict(source=['device','interrupt'], target=['core','irq'],
        source_bit_offset=0, target_bit_offset=0, width=1, source_event_id=1, source_trigger=ref)
    scope = dict(component='core', reset_epoch=0, command_sequence=1)
    native = dict(component='core', source_component='core', execution_id='run', reset_epoch=0,
        source_epoch=0, local_tick=1, producer_event_id=6, command_scope=scope,
        receipt_id={'execution':'wire', 'sequence':1}, expected_input=1, actual_pre_input=1,
        actual_post_input=1, irq_taken_pre=1, observation_contract=ibex_irq_receipt_contract(),
        irq_serial_observation=serial_observation(decision=7, retirement=0))
    return [raw,
        dict(event_id=2, kind='gpio_irq_trigger', component='device', reset_epoch=0,
             local_tick=1, observation_event_id=1, phase='post', trigger_id='actual-trigger', mask=mask, status='observed'),
        dict(event_id=3, kind='local_tick_sample', component='device', reset_epoch=0,
             local_tick=1, phase='post', outputs={'interrupt':1}),
        dict(event_id=4, kind='source_start', source_tick=1, cpu_tick=0, **endpoint),
        dict(event_id=5, kind='pulse_start', start_cpu_tick=1, end_cpu_tick_exclusive=5, **endpoint),
        dict(event_id=6, component='core', local_tick=1, inputs={'irq':1}, outputs={'irq_taken_pre':1}),
        dict(native, event_id=7, kind='cpu_external_irq_sample'),
        dict(native, event_id=8, kind='cpu_external_irq_taken', sample_event_id=7,
             sample_ref={'command_scope':scope,'local_tick':1}, take_key=['core',0,1]),
        dict(event_id=9, kind='cpu_irq_input', cpu_step_event_id=6, cpu_tick=1, value=1, **endpoint),
        dict(event_id=10, kind='cpu_irq_taken', cpu_step_event_id=6, cpu_tick=1, **endpoint),
        dict(event_id=11, kind='cpu_retire', component='core', source_component='core',
             execution_id='run', reset_epoch=0, source_epoch=0, producer_event_id=6,
             valid=1, intr=1, order=1, irq_serial_observation=serial_observation(decision=0,
             retirement=7, sampling='post_rising', decision_phase='post'))]


def consumer(**kwargs):
    from myfuzz.scenario.gpio_irq_dependency_evidence import GpioNativeIrqEvidenceConsumer
    return GpioNativeIrqEvidenceConsumer(source_component='device', target_component='core', pin=3,
        source_port='interrupt', target_port='irq', runtime_contract_sha256='a'*64, **kwargs)


def test_exact_live_boundary_layers_do_not_claim_isr_or_reward():
    c = consumer()
    for event in trace(): c.consume(event)
    report = c.report()
    assert report['counts'] == {'irq_delivery':1, 'irq_acceptance':1, 'cpu_retirement_serial':1}
    assert report['isr_mmio'] == 'unknown'
    assert report['reward_eligible'] is False and report['grants_prerequisites'] is False
    assert report['certificates'][-1]['serial_certificate']['decision_serial'] == 7
    report['certificates'][0]['pin'] = 9
    assert c.report()['certificates'][0]['pin'] == 3


def test_registered_cpu_contract_is_explicit_not_inferred_from_sample():
    from myfuzz.local_harness.cv32e20_irq_receipt_contract import cv32e20_irq_receipt_contract
    contract = cv32e20_irq_receipt_contract()
    events = trace()[:8]
    for event in events:
        if 'observation_contract' in event:
            event['observation_contract'] = contract
    old, selected = consumer(), consumer(observation_contract=contract)
    for event in events:
        old.consume(event)
        selected.consume(event)
    assert not old._native
    assert selected._native
    assert selected.report()['reward_eligible'] is False


@pytest.mark.parametrize('fault', ['source_port','pin','sample','input','take','serial','reset'])
def test_mismatched_or_reset_chain_never_becomes_full_consumption(fault):
    events = deepcopy(trace())
    if fault == 'source_port': events[3]['source'][1] = 'guessed-alias'
    elif fault == 'pin': events[1]['mask'] = 1 << 4
    elif fault == 'sample': events[2]['outputs']['interrupt'] = 0
    elif fault == 'input': events[6]['actual_pre_input'] = 0
    elif fault == 'take': events[7]['sample_event_id'] = 999
    elif fault == 'serial': events[-1]['irq_serial_observation']['retirement']['value'] = 8
    else: events[8] = {'event_id':9, 'kind':'reset_barrier'}
    c = consumer()
    for event in events: c.consume(event)
    assert c.report()['counts']['cpu_retirement_serial'] == 0


def test_masked_delivery_does_not_imply_acceptance():
    events = trace()[:9]
    events[5]['outputs']['irq_taken_pre'] = 0
    events[6]['irq_taken_pre'] = 0
    events[7] = {'event_id':8}
    c = consumer()
    for event in events: c.consume(event)
    assert c.report()['counts'] == {'irq_delivery':1, 'irq_acceptance':0, 'cpu_retirement_serial':0}


def test_expiry_and_record_capacity_are_bounded_and_do_not_award_credit():
    c = consumer(max_event_gap=1)
    for event in trace(): c.consume(event)
    assert c.report()['counts']['cpu_retirement_serial'] == 0
    c = consumer(max_records=1)
    for event in trace(): c.consume(event)
    assert c.report()['status'] == 'incomplete'
    assert len(c.report()['certificates']) == 1
    assert c.report()['reward_eligible'] is False


def test_duplicate_or_skipped_journal_identity_is_refused():
    c = consumer()
    c.consume(trace()[0])
    with pytest.raises(ValueError, match='contiguous'):c.consume(trace()[0])


def test_runner_without_actual_configuration_stays_unknown():
    from tests.scenario.test_session_runtime_paths import factory
    runner = factory()
    assert runner.gpio_irq_dependency_evidence_report()['status'] == 'not_configured'
    with pytest.raises(ValueError):
        runner.configure_gpio_irq_dependency_evidence(source_component='a',target_component='b',
            pin=3,runtime_contract_sha256='a'*64)


def test_verified_runtime_port_mapping_routes_interrupt_without_alias_guess():
    from types import SimpleNamespace
    from myfuzz.scenario.runner import ScenarioRunner, Binding
    events = trace()
    runner = object.__new__(ScenarioRunner)
    runner.sessions = {'device': SimpleNamespace(reset_epoch=0)}
    runner._gpio_irq_runtime_ports = {'device': 'interrupt'}
    runner._gpio_irq_trigger_refs = {('device',0,1,'post'): {
        'trigger_id':'actual-trigger','trigger_event_id':2,'observation_event_id':1}}
    runner._events = events[:3]
    binding = Binding('device','interrupt','core','irq',1)
    assert runner._gpio_irq_source_trigger(binding,3,1,'post') == events[3]['source_trigger']
    alias = Binding('device','irq','core','irq',1)
    assert runner._gpio_irq_source_trigger(alias,3,1,'post') is None
