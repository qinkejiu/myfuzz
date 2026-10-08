"""Independent fail-closed receipt review; no RTL build required."""
from copy import deepcopy
import pytest
from tests.scenario.test_runner_source_provenance import configured_runner
from tests.scenario.test_gpio_consumption_versions import tick, probes


def paired():
    scope={'component':'b','reset_epoch':0,'command_sequence':1}
    pre,post=probes(),probes();pre['gpio_in']=post['gpio_in']=1
    sample={**tick(1,pre,post,component='b'),'command_scope':scope}
    marker={'kind':'gpio_input_applied','component':'b','reset_epoch':0,'source_epoch':0,
            'local_tick':1,'command_scope':scope,
            'actual_receipt_ref':{'command_scope':scope,'local_tick':1},
            'actual_input_value':1,'segments':[{'bit_lo':0,'width':1,'value':1,
            'origin':{'kind':'source_admission','action_id':'unknown'}}]}
    return sample,marker


def resources(runner):
    return [e for e in runner.events if e['kind']=='gpio_input_applied_resource']


def test_unpaired_direct_marker_cannot_fabricate_actual_input_resource():
    runner,_,_=configured_runner(gpio_causal=True)
    _,marker=paired()
    # No raw paired receipt exists. An injected event ID must not constitute
    # physical consumption merely because the direct tracker schema is valid.
    marker.update(actual_receipt_event_id=12345,port='gpio_in',bit_lo=0,width=1,
                  value=1,origin={'kind':'source_admission','action_id':'unknown'})
    runner.sessions['b'].gpio_events=[marker]
    runner._append_external_events('b',1)
    assert not resources(runner)


def test_segment_cannot_override_verified_parent_input_value():
    runner,_,_=configured_runner(gpio_causal=True)
    sample,marker=paired()
    marker['segments'][0].update(value=0,actual_input_value=0)
    runner.sessions['b'].gpio_events=[sample,marker]
    runner._append_external_events('b',1)
    assert not resources(runner)


def test_segment_cannot_override_verified_parent_component():
    runner,_,_=configured_runner(gpio_causal=True)
    sample,marker=paired()
    marker['segments'][0]['component']='a'
    runner.sessions['b'].gpio_events=[sample,marker]
    runner._append_external_events('b',1)
    assert not resources(runner)


def test_missing_command_scope_cannot_bind_actual_receipt():
    runner,_,_=configured_runner(gpio_causal=True)
    sample,marker=paired();sample.pop('command_scope');marker.pop('command_scope')
    marker['actual_receipt_ref']['command_scope']=None
    runner.sessions['b'].gpio_events=[sample,marker]
    runner._append_external_events('b',1)
    assert not resources(runner)


def test_legacy_runner_drain_does_not_activate_gpio_tracker():
    runner,_,_=configured_runner()
    sample,marker=paired();runner.sessions['b'].gpio_events=[sample,marker]
    runner._append_external_events('b',1)
    assert runner._gpio_consumption_tracker is None
    assert not resources(runner)
    before=deepcopy(runner.events)
    runner._append_external_events('b',1)
    assert runner.events==before


def test_full_transaction_key_mismatch_cannot_link_retirement_delivery():
    from types import SimpleNamespace
    from tests.scenario.test_retirement_delivery import match,delivery
    runner,_,_=configured_runner(gpio_causal=True)
    m,d=match(),delivery()
    m['cpu_scope']['source_component']='a'
    for value in m['transaction_keys']:value['source_component']='a'
    for value in m['instruction_responses']:value['transaction']['source_component']='a'
    for value in m['data_beats']:
        value['transaction']['source_component']='a'
        value['response']['transaction']['source_component']='a'
    d['source_transaction']['source_component']='a';d['device_id']='b'
    for field in ('target_request','target_response','target_apb_access'):
        d[field]['source_transaction']['source_component']='a'
        d[field]['command_scope']['component']='b'
    # Identical sequence/address/value must not hide a channel mismatch.
    d['target_response']['source_transaction']['channel_id']='instr'
    runner.sessions['a'].router=SimpleNamespace(acceptances=[],deliveries=[d])
    runner.sessions['a'].cpu_events=[{'kind':'cpu_retire'}]
    runner._cpu_retirement_matcher=SimpleNamespace(consume=lambda record:(m,))
    runner._append_external_events('a',9)
    assert not [e for e in runner.events if e['kind']=='cpu_retired_transaction_target_delivery'
                and e.get('status')=='linked_raw']


@pytest.mark.parametrize('fault', ('contract','missing_probe'))
def test_unauthenticated_paired_tick_cannot_admit_input_lineage(fault):
    runner,_,_=configured_runner(gpio_causal=True)
    sample,marker=paired()
    if fault=='contract':sample['observation_contract']={}
    else:sample['pre'].pop('gpio_probe_native_irq')
    runner.sessions['b'].gpio_events=[sample,marker]
    runner._append_external_events('b',1)
    assert not resources(runner),fault


def test_indirect_target_drain_preserves_exact_failure_producer_id():
    runner,_,_=configured_runner(gpio_causal=True)
    runner._status='running'
    runner.sessions['b'].gpio_events=[tick(1,component='b')]
    runner.sessions['a'].cpu_events=[{'kind':'cpu_command_uncertain'}]
    def fail(_):raise RuntimeError('lost source reply after target acted')
    runner.sessions['a'].step_local=fail
    with pytest.raises(RuntimeError):runner._step_once('a')
    failure=next(e for e in runner.events if e['kind']=='harness_failure')
    source=next(e for e in runner.events if e['kind']=='cpu_command_uncertain')
    assert source['producer_event_id']==failure['event_id']
