"""Pure equation fixtures cannot issue live native versions."""
import pytest


def sample(tick=1,old=9,new=9,address=4,write=0,reset=0,wdata=27):
    pre=dict(storage_value=old,storage_reset=reset,storage_paddr=address,storage_psel=write,storage_penable=write,storage_pwrite=write,storage_pwdata=wdata,storage_prdata=0,storage_pready=1,storage_pslverr=0)
    return dict(local_tick=tick,pre={'storage_probes':pre},post={'storage_probes':dict(pre,storage_value=new)})


def test_first_measured_value_is_not_assumed_zero():
    from myfuzz.scenario.apb_storage_register_version import reduce_storage_samples
    state,writes=reduce_storage_samples([sample()])
    assert state['value']==9 and state['reset_waveform_observed'] is False and not writes


@pytest.mark.parametrize('address',[4,5,6,7,36,0xfe4])
def test_every_alias_write_counts(address):
    from myfuzz.scenario.apb_storage_register_version import reduce_storage_samples
    state,writes=reduce_storage_samples([sample(new=27,address=address,write=1)])
    assert state['value']==27 and writes[0]['raw_address']==address


@pytest.mark.parametrize('mutation',['bool','gap','transition','error','missing','reset'])
def test_bad_raw_transitions_refused(mutation):
    from myfuzz.scenario.apb_storage_register_version import reduce_storage_samples
    row=sample()
    if mutation=='bool':row['pre']['storage_probes']['storage_value']=True
    elif mutation=='gap':row['local_tick']=2
    elif mutation=='transition':row['post']['storage_probes']['storage_value']=1
    elif mutation=='error':row['pre']['storage_probes']['storage_pslverr']=1
    elif mutation=='missing':row['post']['storage_probes'].pop('storage_reset')
    else:row['pre']['storage_probes']['storage_reset']=1
    with pytest.raises(ValueError):reduce_storage_samples([row])


def test_reset_priority_and_contiguous_hold():
    from myfuzz.scenario.apb_storage_register_version import reduce_storage_samples
    first=sample(old=0,new=0,reset=1,write=1)
    state,writes=reduce_storage_samples([first,sample(tick=2,old=0,new=0)])
    assert state['reset_waveform_observed'] is True and not writes


def test_sample_budget_refuses_before_any_live_authority():
    from myfuzz.scenario.apb_storage_register_version import reduce_storage_samples
    with pytest.raises(ValueError):reduce_storage_samples([sample(),sample(tick=2)],max_samples=1)

from tests.local_harness.test_generic_apb_identity import generated
from tests.local_harness.test_native_reset_producer_contract import storage


def test_attachment_cannot_issue_or_consume_native_versions_on_software_fixture(storage):
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    authority=ApbStorageRegisterVersionAuthority(storage)
    with pytest.raises(ValueError):authority.issue(reset_epoch=0)
    with pytest.raises(ValueError):authority.consume({'value':9})


def test_actual_command_callback_cannot_be_called_by_fixture(storage):
    from types import SimpleNamespace
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    authority=ApbStorageRegisterVersionAuthority(storage)
    with pytest.raises(ValueError):authority._actual_command(storage,'STEP_APB3_REG',(),SimpleNamespace())
    with pytest.raises(ValueError):authority.issue(reset_epoch=0)


def test_routed_context_finally_cleared_on_actual_guard_refusal(storage):
    from types import SimpleNamespace
    from dataclasses import asdict
    from myfuzz.scenario.ledger import TransactionKey
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    ApbStorageRegisterVersionAuthority(storage)
    key=TransactionKey('execution','case','cpu',0,'data',1)
    context=dict(source_transaction=asdict(key),device_id='timer',window_base=0x40000000,window_size=4096,address=0x40000004,offset=4,write=True,value=9,be=15)
    storage._process=SimpleNamespace(poll=lambda:None,pid=123)
    try:
        with pytest.raises(ValueError):storage.routed_register_access(key,address=0x40000004,offset=4,write=True,value=9,be=15,delivery_context=context)
        assert storage._storage_active_context is None
    finally:storage._process=None


def test_overriding_frame_and_validate_cannot_create_fixture_authority(storage,monkeypatch):
    from types import SimpleNamespace
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    authority=ApbStorageRegisterVersionAuthority(storage)
    monkeypatch.setattr(authority,'_frame',lambda *a:None)
    monkeypatch.setattr(authority,'_validate',lambda **kw:'fake-build')
    with pytest.raises(ValueError):authority._actual_command(storage,'STEP_APB3_REG',(),SimpleNamespace())
    with pytest.raises(ValueError):authority.issue(reset_epoch=0)


def test_source_constant_ready_cannot_mask_a_writer():
    from myfuzz.scenario.apb_storage_register_version import reduce_storage_samples
    row=sample(write=1)
    row['pre']['storage_probes']['storage_pready']=0
    row['post']['storage_probes']['storage_pready']=0
    with pytest.raises(ValueError):reduce_storage_samples([row])


@pytest.mark.parametrize('mutate',[lambda d:d.update(command_sequence=True),lambda d:d.update(value=10),lambda d:d.update(source_authenticated=True),lambda d:d['source_transaction'].update(source_component=1)])
def test_context_cannot_relabel_actual_command_or_claim_source(mutate):
    from myfuzz.scenario.apb_storage_register_version import validate_routed_context
    from dataclasses import asdict
    from myfuzz.scenario.ledger import TransactionKey
    context=dict(source_transaction=asdict(TransactionKey('e','case','cpu',0,'data',1)),device_id='timer',window_base=0,window_size=4096,address=4,offset=4,write=True,value=9,be=15,execution='native-nonce',reset_epoch=0,command_sequence=1,schema_version='apb_storage_routed_context.v1',source_authenticated=False)
    assert validate_routed_context(context,operation='ACCESS_APB3_REG',fields=(1,4,9,15),sequence=1,execution='native-nonce',epoch=0,window=4096)==context
    mutate(context)
    with pytest.raises(ValueError):validate_routed_context(context,operation='ACCESS_APB3_REG',fields=(1,4,9,15),sequence=1,execution='native-nonce',epoch=0,window=4096)


def test_exhaustive_12bit_source_alias_decode():
    from myfuzz.scenario.apb_storage_register_version import reduce_storage_samples
    writes=0
    for address in range(4096):
        match=(address&0x1c)==4
        state,rows=reduce_storage_samples([sample(address=address,write=1,new=27 if match else 9)])
        assert bool(rows)==match
        writes+=len(rows)
    assert writes==512


def test_mutable_global_width_replacement_cannot_change_live_contract(storage,monkeypatch):
    from myfuzz.scenario import apb_storage_register_version as module
    authority=module.ApbStorageRegisterVersionAuthority(storage)
    monkeypatch.setattr(module,'_WIDTHS',dict(module._WIDTHS,value=64))
    with pytest.raises(ValueError):authority.issue(reset_epoch=0)


@pytest.mark.parametrize('field',['_sequence','local_ticks','_tick_base'])
def test_prior_command_history_cannot_be_hidden_by_fresh_attachment(storage,field):
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    setattr(storage,field,1)
    with pytest.raises(ValueError):ApbStorageRegisterVersionAuthority(storage)


def test_revocation_dispatch_failure_cannot_prevent_abort_teardown(storage,monkeypatch):
    """Mock teardown only; never a measured producer or native issuance."""
    from types import SimpleNamespace
    from myfuzz.local_harness import session
    state={'reaped':False}
    stream=SimpleNamespace(close=lambda:None)
    process=SimpleNamespace(poll=lambda:None,kill=lambda:None,wait=lambda **kw:state.update(reaped=True),stdin=stream,stdout=stream)
    storage._process=process
    monkeypatch.setattr(session,'_STORAGE_VERSION_PIN',())
    try:
        with pytest.raises(ValueError):storage._abort()
        assert storage.process is None and state['reaped']
    finally:storage._process=None


@pytest.mark.parametrize('field',['reset_epoch','_sequence','local_ticks','_tick_base'])
def test_bool_counter_cannot_match_integer_scope(storage,field):
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    authority=ApbStorageRegisterVersionAuthority(storage)
    setattr(storage,field,False)
    with pytest.raises(ValueError,match='authority-drift'):authority._validate()


@pytest.mark.parametrize('change', ['tick','tick_base','sequence','process','execution','epoch'])
def test_scope_guard_rejects_counter_or_process_drift_without_native_fixture(change):
    """Pure scope calculation only; no build eligibility or token issuance."""
    from myfuzz.scenario.apb_storage_register_version import validate_storage_scope
    process=object()
    args=dict(process=process,execution='nonce',epoch=0,tick_base=7,sequence=3,tick=12)
    state=dict(tick=12,sequence=3,value=9,reset_waveform_observed=False)
    scope=(process,'nonce',0,7)
    validate_storage_scope(state,scope,**args)
    args[change]=object() if change=='process' else 'other' if change=='execution' else args[change]+1
    with pytest.raises(ValueError):validate_storage_scope(state,scope,**args)


def test_scope_guard_initial_state_does_not_heal_missing_history():
    from myfuzz.scenario.apb_storage_register_version import validate_storage_scope
    args=dict(process=object(),execution='nonce',epoch=0,tick_base=0,sequence=0,tick=0)
    validate_storage_scope(None,None,allow_initial=True,**args)
    with pytest.raises(ValueError):validate_storage_scope(None,None,**args)
    with pytest.raises(ValueError):validate_storage_scope(None,None,allow_initial=True,**dict(args,tick=1))


def test_all_live_scope_guards_poison_on_failure_source_control():
    """No native-eligible fixture: prove shared guard is inside revoking paths."""
    import ast,inspect,textwrap
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    for name in ('_actual_begin','issue','consume'):
        tree=ast.parse(textwrap.dedent(inspect.getsource(getattr(ApbStorageRegisterVersionAuthority,name))))
        protected=[node for node in ast.walk(tree) if isinstance(node,ast.Try) and any(
            isinstance(call,ast.Call) and isinstance(call.func,ast.Subscript) and isinstance(call.func.value,ast.Name) and call.func.value.id=='_SCOPE_VALIDATOR'
            for part in node.body for call in ast.walk(part))]
        assert len(protected)==1
        assert any(isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute) and call.func.attr=='_revoke'
                   for handler in protected[0].handlers for call in ast.walk(handler))
