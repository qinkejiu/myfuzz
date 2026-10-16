"""Router ordinary receipts, with software targets only."""
from copy import deepcopy
from dataclasses import asdict
import pytest
from myfuzz.scenario.ledger import TransactionKey,TransactionLedger
from myfuzz.scenario.router import DataflowRouter,DeviceWindow

class Target:
    ordinary_apb_access_receipts_enabled=True
    routed_register_access_enabled=False
    def __init__(self):self.calls=[];self.failed=[];self.receipts={}
    def execute_observed_register_access(self,key,*,delivery_context):
        self.calls.append((key,deepcopy(delivery_context)))
        receipt=dict(schema_version='ordinary_apb_target_receipt.v1',access_id='access:1',target_instance=delivery_context['device_id'],endpoint_id='gpio.bus',target_reset_epoch=0,source_transaction=asdict(key),delivery_context=deepcopy(delivery_context),command_scope=dict(component=delivery_context['device_id'],reset_epoch=0,command_sequence=1),driver_receipt=dict(execution_scope='parsed_driver_execution',process_scope=f"local-driver:{delivery_context['device_id']}:0",sequence=1,tick_before=0,tick_after=3,new_ticks=3),sample_ticks=[1,2,3],status='target_observed',rdata=7,error=0,proof_scope='actual_target_command_observation_only',grants_verified=False,grants_storage=False,grants_functional=False)
        self.receipts['access:1']=receipt
        return {'rdata':7,'target_access_id':'access:1','target_access_receipt':deepcopy(receipt)}
    def ordinary_apb_access_receipt(self,access_id):return deepcopy(self.receipts[access_id])
    def ordinary_apb_delivery_failed(self,key,access_id):self.failed.append((key,access_id))
    def write_register(self,*args,**kwargs):raise AssertionError('ordinary bypass')
    def read_register(self,*args,**kwargs):raise AssertionError('ordinary bypass')

def setup():
    target=Target();router=DataflowRouter((DeviceWindow('gpio_a',0x40000000,4096,target),))
    return target,router,TransactionLedger(),TransactionKey('execution','case','cpu',0,'data',1)

def enqueue(router,ledger,key,callback):
    return router.enqueue(ledger,key,address=0x40000004,write=False,wdata=0,be=15,beat_bytes=4,callback=callback)

def test_ordinary_receipt_routes_actual_window_context_and_waits_for_callback():
    target,router,ledger,key=setup()
    def callback(response):assert response==(7,0);assert router.deliveries==[]
    assert enqueue(router,ledger,key,callback)
    assert router.drain_one('gpio_a')
    assert target.calls==[(key,dict(source_transaction=asdict(key),device_id='gpio_a',window_base=0x40000000,window_size=4096,address=0x40000004,offset=4,write=False,value=0,be=15))]
    assert router.deliveries[0]['target_access_id']=='access:1'

def test_callback_failure_terminal_does_not_publish_or_reexecute():
    target,router,ledger,key=setup()
    def fail(response):raise RuntimeError('CPU reply failed')
    enqueue(router,ledger,key,fail)
    with pytest.raises(RuntimeError):router.drain_one('gpio_a')
    assert router.deliveries==[]
    assert target.failed==[(key,'access:1')]
    assert not enqueue(router,ledger,key,lambda response:None)
    assert not router.drain_one('gpio_a')
    assert len(target.calls)==1

def test_default_off_delivery_layout_is_unchanged():
    target,router,ledger,key=setup();target.ordinary_apb_access_receipts_enabled=False
    target.read_register=lambda offset:7
    assert router.transact(ledger,key,address=0x40000004,write=False,wdata=0,be=15,beat_bytes=4)==(7,0)
    assert set(router.deliveries[0])=={'source_transaction','device_id','source_sequence','delivery_order','target_delivery_order','address','beat_bytes','offset','write','byte_enable','write_value','read_value'}
    assert target.calls==[]

def test_causal_branch_has_priority():
    target,router,ledger,key=setup();target.routed_register_access_enabled=True
    target.routed_register_access=lambda *args,**kwargs:{'rdata':9,'target_access_id':'causal'}
    enqueue(router,ledger,key,lambda result:None);router.drain_one('gpio_a')
    assert target.calls==[];assert router.deliveries[0]['target_access_id']=='causal'

def test_duplicate_and_conflicting_full_key_do_not_reexecute():
    target,router,ledger,key=setup()
    enqueue(router,ledger,key,lambda result:None);router.drain_one('gpio_a')
    assert not enqueue(router,ledger,key,lambda result:pytest.fail('duplicate callback'))
    with pytest.raises(ValueError):router.enqueue(ledger,key,address=0x40000008,write=False,wdata=0,be=15,beat_bytes=4,callback=lambda result:None)
    assert len(target.calls)==1;assert len(router.deliveries)==1

def test_equal_value_two_targets_still_bind_unique_actual_windows():
    first,second=Target(),Target()
    router=DataflowRouter((DeviceWindow('gpio_a',0x40000000,4096,first),DeviceWindow('gpio_b',0x40001000,4096,second)))
    ledger=TransactionLedger()
    for sequence,device,address in ((1,'gpio_a',0x40000004),(2,'gpio_b',0x40001004)):
        key=TransactionKey('execution','case','cpu',0,'data',sequence)
        router.enqueue(ledger,key,address=address,write=False,wdata=0,be=15,beat_bytes=4,callback=lambda result:None)
        router.drain_one(device)
    assert [row['target_access_receipt']['target_instance'] for row in router.deliveries]==['gpio_a','gpio_b']
    first.receipts['access:1']['delivery_context']['offset']=88
    assert router.deliveries[0]['target_access_receipt']['delivery_context']['offset']==4

@pytest.mark.parametrize('change',[lambda r:r.pop('target_access_receipt'),lambda r:r.update(rdata=True),lambda r:r.update(extra=1),lambda r:r['target_access_receipt'].update(target_instance='gpio_b'),lambda r:r['target_access_receipt'].update(status='uncertain'),lambda r:r['target_access_receipt'].update(grants_verified=True),lambda r:r['target_access_receipt']['delivery_context'].update(offset=8)])
def test_partial_or_foreign_result_fails_closed_without_publication(change):
    target,router,ledger,key=setup();original=target.execute_observed_register_access
    def malformed(*args,**kwargs):
        result=original(*args,**kwargs);change(result);return result
    target.execute_observed_register_access=malformed
    enqueue(router,ledger,key,lambda result:pytest.fail('invalid callback'))
    with pytest.raises(ValueError):router.drain_one('gpio_a')
    assert router.deliveries==[];assert len(target.calls)==1
    assert not router.drain_one('gpio_a')

def test_terminal_hook_error_preserves_original_callback_failure():
    target,router,ledger,key=setup()
    def fail(response):raise RuntimeError('original CPU callback')
    def terminal(*args):raise ValueError('terminal conflict')
    target.ordinary_apb_delivery_failed=terminal
    enqueue(router,ledger,key,fail)
    with pytest.raises(RuntimeError,match='original CPU callback') as failure:router.drain_one('gpio_a')
    assert isinstance(failure.value.__cause__,ValueError)
    assert router.deliveries==[];assert len(target.calls)==1

def test_sync_observation_is_not_confirmed_cpu_delivery():
    target,router,ledger,key=setup()
    assert router.transact(ledger,key,address=0x40000004,write=False,wdata=0,be=15,beat_bytes=4)==(7,0)
    assert router.deliveries[0]['source_delivery_confirmed'] is False
    target,router,ledger,key=setup();enqueue(router,ledger,key,lambda result:None);router.drain_one('gpio_a')
    assert router.deliveries[0]['source_delivery_confirmed'] is True

def test_registry_agreement_does_not_bypass_closed_receipt_shape():
    target,router,ledger,key=setup();original=target.execute_observed_register_access
    def malformed(*args,**kwargs):
        result=original(*args,**kwargs)
        result['target_access_receipt']['unknown_authority']=True
        target.receipts[result['target_access_id']]=deepcopy(result['target_access_receipt'])
        return result
    target.execute_observed_register_access=malformed
    enqueue(router,ledger,key,lambda result:pytest.fail('invalid callback'))
    with pytest.raises(ValueError):router.drain_one('gpio_a')
    assert router.deliveries==[]

from tests.local_harness.test_ordinary_apb_access_receipts import native_factory,software_transport

def test_actual_native_target_uses_registry_and_parsed_software_receipt(native_factory):
    runner=native_factory();target=runner.sessions['gpio_a']
    target.configure_ordinary_apb_access_receipts();calls=software_transport(target)
    router=runner.sessions['cpu'].router
    window=next(window for window in router.windows if window.target is target)
    ledger=TransactionLedger();key=TransactionKey('execution','case','cpu',0,'data',1)
    router.enqueue(ledger,key,address=window.base+12,write=False,wdata=0,be=15,beat_bytes=4,callback=lambda result:None)
    assert router.drain_one(window.device_id)
    delivery=router.deliveries[-1]
    assert delivery['source_delivery_confirmed'] is True
    assert delivery['target_access_receipt']==target.ordinary_apb_access_receipt(delivery['target_access_id'])
    assert delivery['target_access_receipt']['sample_ticks']==[1,2,3]
    assert len(calls)==1
