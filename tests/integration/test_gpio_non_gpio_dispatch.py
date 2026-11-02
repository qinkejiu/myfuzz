"""A registered DMA target is outside GPIO evidence; unknown scopes still fail."""
from copy import deepcopy
import pytest
from tests.integration.test_shared_f5_support_binding import all_six
from tests.integration.test_compiled_f6_contract import ROOT


def test_actual_DMA_route_does_not_poison_GPIO_tracker(all_six,tmp_path):
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    from myfuzz.integration.shared_f6_assembly import shared_irq_ownership,build_f6_assembly
    from myfuzz.scenario.gpio_consumption import is_registered_non_gpio_delivery
    from tests.scenario.test_gpio_consumption_versions import tick
    inputs=all_six.compiled_inputs();artifacts=dict(all_six.artifacts)
    admission=admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    contract=admission['execution_contract']
    ownership=shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],cpu_id='cpu',dma_id='dma'),contract,artifacts,base_dir=ROOT)
    assembly=build_f6_assembly(contract=contract,artifacts=artifacts,request=inputs['request'],ownership=ownership,base_dir=ROOT,cache_dir=tmp_path)
    from myfuzz.scenario.gpio_consumption import GpioConsumptionTracker
    runner=assembly.runner
    # Bare assembly has not installed runtime provenance yet. This factual
    # tracker tests dispatch isolation, not a native credential or a live begin.
    tracker=runner._gpio_consumption_tracker=GpioConsumptionTracker()
    tracker.consume(tick(1,component='peripheral'))
    event=dict(kind='cpu_retired_transaction_target_delivery',component='cpu',status='incomplete',
        proof_scope='retired_instruction_transaction_delivery',
        fullkey=dict(execution_id='e',testcase_id='c',source_component='cpu',source_epoch=0,channel_id='data',source_sequence=1),
        consumer_resource=dict(device_id='dma',address=contract['control']['base']+8,offset=8,
            beat_bytes=4,target_apb_access=None,target_access_id=None))
    assert is_registered_non_gpio_delivery(runner.sessions,event)
    runner._append_retirement_deliveries([event],dict(component='cpu',event_id=1))
    assert tracker._global_barrier is False and tracker._states['peripheral']['degraded'] is False
    assert len(runner.events_since(0))==1  # delivery remains visible in the actual journal
    for mutation in ('unknown','wrong_offset','fake_apb'):
        bad=deepcopy(event)
        if mutation=='unknown':bad['consumer_resource']['device_id']='unknown'
        elif mutation=='wrong_offset':bad['consumer_resource']['offset']=12
        else:bad['consumer_resource']['target_apb_access']={'claimed':'GPIO'}
        assert not is_registered_non_gpio_delivery(runner.sessions,bad)
        runner._append_retirement_deliveries([bad],dict(component='cpu',event_id=1))
        assert tracker._global_barrier is True
    assert all(local.process is None for local in runner.sessions.values())
