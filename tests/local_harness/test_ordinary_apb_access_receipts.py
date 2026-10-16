import copy
import json
import pytest
from myfuzz.local_harness.wire import parse_driver_receipt
from myfuzz.scenario.ledger import TransactionKey


@pytest.fixture(scope='module')
def native_factory(tmp_path_factory):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    return make_ibex_pulp_dual_source_factory(tmp_path_factory.mktemp('ordinary-render'),
        physical_observations=True,memory_commit_receipts=True,
        persistent_memory_runtime_contract_sha256='a'*64)


def context(target='gpio_a', **updates):
    key=TransactionKey('execution','case','cpu',0,'data',1)
    row=dict(source_transaction=key.__dict__ if hasattr(key,'__dict__') else None,
        device_id=target,window_base=0x40001000,window_size=4096,address=0x4000100c,
        offset=12,write=False,value=0,be=15)
    from dataclasses import asdict
    row['source_transaction']=asdict(key);row.update(updates)
    return key,row


def software_transport(session, *, rdata=7, mutate=None):
    """Use the real strict wire parser, then mirror command_impl state publication."""
    session._case_id='software-case';session._execution='0123456789abcdef0123456789abcdef'
    calls=[]
    def command(operation, fields):
        calls.append((operation,fields))
        before=session.local_ticks-session._tick_base; sequence=session._sequence+1
        observed=dict(gpio_out=0,gpio_dir=0,gpio_in_sync=0,gpio_padcfg='0'*32,interrupt=0,
            backend={},physical={row['runtime_name']:0 for row in session.artifact.runtime_document['physical_exports']})
        samples=[]
        for index in range(3):
            state=copy.deepcopy(observed)
            state['backend']=dict(trace_psel=int(index<2),trace_penable=int(index==1),
                trace_pready=1,trace_pslverr=0,trace_paddr=fields[2],trace_pwrite=fields[1],
                trace_pwdata=fields[3],trace_prdata=rdata)
            samples.append(dict(local_tick=before+index+1,pre=state,post=copy.deepcopy(state)))
        payload=dict(schema_version='local_driver_result.v1',kind='apb_gpio',samples=samples,
            observations=observed,pre_backend={},rdata=rdata,error=0)
        encoded=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode().hex()
        receipt=parse_driver_receipt(f'RESULT {session._execution} {sequence:x} {before:x} {before+3:x} {encoded}',
            execution=session._execution,sequence=sequence,current_tick=before,kind='apb_gpio')
        session._sequence=sequence;session.local_ticks=session._tick_base+receipt.tick_after
        return mutate(receipt) if mutate else receipt
    session.command=command
    return calls


def configured(native_factory, *, max_records=256):
    session=native_factory().sessions['gpio_a']
    session.configure_ordinary_apb_access_receipts(max_records=max_records)
    return session


def test_actual_ordinary_access_is_command_bound_detached_and_exact_once(native_factory):
    session=configured(native_factory);calls=software_transport(session)
    key,ctx=context()
    result=session.execute_observed_register_access(key,delivery_context=ctx)
    receipt=result['target_access_receipt']
    assert receipt['status']=='target_observed' and result['rdata']==7
    assert receipt['sample_ticks']==[1,2,3]
    assert not any(receipt[name] for name in ('grants_verified','grants_storage','grants_functional'))
    assert session.execute_observed_register_access(key,delivery_context=ctx)==result
    assert len(calls)==1
    samples=session.drain_tick_samples()
    assert all(s['ordinary_apb_access_ref']['access_id']==result['target_access_id'] for s in samples)
    receipt['sample_ticks'].clear()
    assert session.ordinary_apb_access_receipt(result['target_access_id'])['sample_ticks']==[1,2,3]
    with pytest.raises(ValueError):session.execute_observed_register_access(key,delivery_context={**ctx,'offset':16})
    assert len(calls)==1


def test_closed_context_capacity_and_default_off_refuse_before_command(native_factory):
    session=native_factory().sessions['gpio_a'];calls=software_transport(session)
    key,ctx=context()
    assert not session.ordinary_apb_access_receipts_enabled
    with pytest.raises(ValueError):session.execute_observed_register_access(key,delivery_context=ctx)
    assert calls==[]
    with pytest.raises(ValueError):session.configure_ordinary_apb_access_receipts()
    session=configured(native_factory,max_records=1);calls=software_transport(session)
    for change in ({'be':True},{'device_id':'gpio_b'},{'window_size':8192},{'source_transaction':{}},{'extra':True}):
        with pytest.raises(ValueError):session.execute_observed_register_access(key,delivery_context={**ctx,**change})
    assert calls==[]
    result=session.execute_observed_register_access(key,delivery_context=ctx)
    other=TransactionKey('execution','case','cpu',0,'data',2)
    from dataclasses import asdict
    with pytest.raises(ValueError):session.execute_observed_register_access(other,delivery_context={**ctx,'source_transaction':asdict(other)})
    assert len(calls)==1
    session.ordinary_apb_delivery_failed(key,result['target_access_id'])
    assert session.ordinary_apb_access_receipt(result['target_access_id'])['status']=='target_observed'


@pytest.mark.parametrize('field,value',[('execution','f'*32),('sequence',99),('tick_before',99)])
def test_foreign_parsed_receipt_never_becomes_observed(native_factory,field,value):
    from dataclasses import replace
    session=configured(native_factory)
    calls=software_transport(session,mutate=lambda r:replace(r,**{field:value}))
    key,ctx=context()
    with pytest.raises(ValueError):session.execute_observed_register_access(key,delivery_context=ctx)
    assert len(calls)==1
    with pytest.raises(ValueError):session.execute_observed_register_access(key,delivery_context=ctx)
    assert len(calls)==1


@pytest.mark.parametrize('mutation',['setup','duplicate_ready','rdata','bool_sequence','sample_bool'])
def test_invalid_command_boundary_never_becomes_observed(native_factory,mutation):
    from dataclasses import replace
    session=configured(native_factory)
    def mutate(receipt):
        payload=copy.deepcopy(receipt.payload)
        if mutation=='setup':payload['samples'][0]['pre']['backend']['trace_psel']=0
        elif mutation=='duplicate_ready':payload['samples'][2]['pre']['backend']=copy.deepcopy(payload['samples'][1]['pre']['backend'])
        elif mutation=='rdata':payload['samples'][1]['pre']['backend']['trace_prdata']=999
        elif mutation=='bool_sequence':return replace(receipt,sequence=True)
        else:payload['samples'][0]['local_tick']=True
        return replace(receipt,payload=payload)
    calls=software_transport(session,mutate=mutate)
    key,ctx=context()
    with pytest.raises(ValueError):session.execute_observed_register_access(key,delivery_context=ctx)
    assert len(calls)==1


def test_epoch_and_execution_pin_refuse_stale_live_registry(native_factory):
    session=configured(native_factory);software_transport(session)
    key,ctx=context();result=session.execute_observed_register_access(key,delivery_context=ctx)
    session._execution='f'*32
    with pytest.raises(ValueError):session.ordinary_apb_access_receipt(result['target_access_id'])


def test_native_validator_false_refuses_configuration(native_factory,monkeypatch):
    import myfuzz.local_harness.native_physical_observation as native
    session=native_factory().sessions['gpio_a']
    monkeypatch.setattr(native,'verify_native_physical_observation',lambda _:False)
    with pytest.raises(ValueError):session.configure_ordinary_apb_access_receipts()


def test_read_preserves_source_bus_wdata_without_treating_it_as_write(native_factory):
    session=configured(native_factory);calls=software_transport(session)
    key,ctx=context(value=0xdeadbeef)
    result=session.execute_observed_register_access(key,delivery_context=ctx)
    assert result['rdata']==7
    assert result['target_access_receipt']['delivery_context']['value']==0xdeadbeef
    assert calls==[('ACCESS_GPIO',(0,0,12,0,15))]


def test_configured_capacity_and_mode_identity_are_pinned(native_factory):
    session=native_factory().sessions['gpio_a']
    assert 'ordinary_apb_access_receipts' not in session.identity_document()
    session.configure_ordinary_apb_access_receipts(max_records=1)
    identity=session.identity_document()['ordinary_apb_access_receipts']
    assert identity['max_records']==1
    calls=software_transport(session)
    session._ordinary_apb_receipts.max_records=100
    key,ctx=context()
    with pytest.raises(ValueError):session.execute_observed_register_access(key,delivery_context=ctx)
    assert calls==[]


def test_changed_live_capacity_refuses_before_command(native_factory):
    session=configured(native_factory,max_records=1);calls=software_transport(session)
    session._ordinary_apb_receipts.max_records=100
    key,ctx=context()
    with pytest.raises(ValueError):session.execute_observed_register_access(key,delivery_context=ctx)
    assert calls==[]


def test_sample_digests_are_frozen_from_actual_parsed_command(native_factory):
    import hashlib
    from myfuzz.local_harness.ordinary_apb_access_receipts import _json
    session=configured(native_factory);software_transport(session)
    key,ctx=context();result=session.execute_observed_register_access(key,delivery_context=ctx)
    aid=result['target_access_id'];sample=session._samples[0]
    expected=hashlib.sha256(_json(sample['pre']).encode()).hexdigest()
    assert session.ordinary_apb_sample_digest(aid, sample['local_tick'], 'pre')==expected
    sample['pre']['backend'].clear()
    assert session.ordinary_apb_sample_digest(aid, sample['local_tick'], 'pre')==expected
    with pytest.raises(ValueError):session.ordinary_apb_sample_digest(aid,True,'pre')
    with pytest.raises(ValueError):session.ordinary_apb_sample_digest(aid,1,'unknown')
