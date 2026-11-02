"""Pure equation fixtures cannot issue live native versions."""
import pytest


@pytest.fixture(scope='module', params=(
    ('pulp_timer/component_profile.json', 'timer.bus', 'pulp-apb-timer.ctrl0.source.v1', 'TIMER0_CTRL'),
    ('pulp_spi/local_component_profile.json', 'spi.bus', 'pulp-apb-spi.spicmd.source.v1', 'SPICMD'),
))
def registered_storage_artifact(request):
    """Real generated source/probe artifact; no native process or authority."""
    from pathlib import Path
    from myfuzz.local_harness import (
        load_local_harness_request, plan_local_harness, render_local_harness,
        verify_local_source_lock, render_local_runtime, render_local_driver)
    root = Path(__file__).resolve().parents[2]
    from myfuzz.composition.component_profile import load_component_profile
    profile, endpoint, contract, register = request.param
    component = load_component_profile(root/f'configs/peripherals/{profile}')
    fixed = [dict(endpoint_id=e.endpoint_id, role=f.role, value=0)
             for e in component.endpoints if e.protocol is None
             for f in e.fields if f.direction == 'input']
    harness = load_local_harness_request(dict(schema_version='local_harness.v2',
        profile_path=f'configs/peripherals/{profile}',
        instance_id='peripheral', reset_assert_ticks=2, reset_release_ticks=2,
        max_wait_cycles=16, tuning=dict(fixed_inputs=fixed, endpoint_policies=[dict(
            endpoint_id=endpoint, template_id='target.apb3', template_version='1',
            variant_id='full-word', max_outstanding=1)],
            apb_storage_observations=[dict(endpoint_id=endpoint,
                contract_id=contract, register=register)])))
    plan = plan_local_harness(harness, base_dir=root)
    artifact = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=root), base_dir=root)
    return render_local_driver(artifact, base_dir=root)


def test_registered_decode_drives_every_physical_sample(registered_storage_artifact):
    from myfuzz.scenario.apb_storage_register_version import reduce_storage_samples
    contract = registered_storage_artifact.runtime_document['storage_observation']['source_contract']
    decode = contract['decode']
    writes = 0
    for address in range(1 << decode['address_width']):
        matches = address & decode['mask'] == decode['value']
        state, rows = reduce_storage_samples([sample(address=address, write=1,
            new=27 if matches else 9)], source_contract=contract)
        assert state['value'] == (27 if matches else 9)
        assert bool(rows) == matches
        writes += len(rows)
    assert writes == decode['raw_address_alias_count']


def test_registered_reset_equation_and_read_hold(registered_storage_artifact):
    from myfuzz.scenario.apb_storage_register_version import reduce_storage_samples
    contract = registered_storage_artifact.runtime_document['storage_observation']['source_contract']
    offset = contract['register']['canonical_offset']
    state, writes = reduce_storage_samples([
        sample(old=0, new=0, address=offset, write=1, reset=1),
        sample(tick=2, old=0, new=27, address=offset, write=1),
        sample(tick=3, old=27, new=27, address=offset)], source_contract=contract)
    assert state == dict(tick=3, value=27, reset_waveform_observed=True)
    assert len(writes) == 1 and writes[0]['raw_address'] == offset


@pytest.mark.parametrize('mutation', ('register', 'digest', 'mask', 'decode_value', 'reset'))
def test_reducer_cannot_redefine_registered_source(registered_storage_artifact, mutation):
    from copy import deepcopy
    from myfuzz.scenario.apb_storage_register_version import reduce_storage_samples
    contract = deepcopy(registered_storage_artifact.runtime_document['storage_observation']['source_contract'])
    if mutation == 'register': contract['register']['name'] = 'FORGED'
    elif mutation == 'digest': contract['digest'] = '0' * 64
    elif mutation == 'mask': contract['decode']['mask'] = 0
    elif mutation == 'decode_value': contract['decode']['value'] = 0
    else: contract['register']['reset_value'] = 9
    with pytest.raises(ValueError):
        reduce_storage_samples([sample()], source_contract=contract)


@pytest.mark.parametrize('when', ('attachment', 'lifetime'))
@pytest.mark.parametrize('mutation', ('register', 'digest', 'mask', 'decode_value', 'reset', 'cross_contract'))
def test_authority_revalidates_source_contract(registered_storage_artifact, tmp_path, when, mutation):
    from copy import deepcopy
    from dataclasses import replace
    from pathlib import Path
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    from myfuzz.local_harness.apb_storage_source_contract import select_apb_storage_source_contract
    from myfuzz.composition.component_profile import load_component_profile
    root = Path(__file__).resolve().parents[2]
    artifact = replace(registered_storage_artifact,
        runtime_document=deepcopy(registered_storage_artifact.runtime_document))
    target = GeneratedApb3RegisterSession(artifact, base_dir=root, cache_dir=tmp_path)
    authority = ApbStorageRegisterVersionAuthority(target) if when == 'lifetime' else None
    document = target._artifact_document
    contract = document['storage_observation']['source_contract']
    if mutation == 'register': contract['register']['name'] = 'FORGED'
    elif mutation == 'digest': contract['digest'] = '0' * 64
    elif mutation == 'mask': contract['decode']['mask'] = 0
    elif mutation == 'decode_value': contract['decode']['value'] = 0
    elif mutation == 'reset': contract['register']['reset_value'] = 9
    else:
        other = ('pulp_spi', 'pulp-apb-spi.spicmd.source.v1', 'SPICMD') if contract['register']['name'] == 'TIMER0_CTRL' else ('pulp_timer', 'pulp-apb-timer.ctrl0.source.v1', 'TIMER0_CTRL')
        document['storage_observation']['source_contract'] = select_apb_storage_source_contract(
            load_component_profile(root/f'configs/peripherals/{other[0]}/component_profile.json'),
            base_dir=root, selection=dict(contract_id=other[1], register=other[2]))
    # Mutating both serialized copies must still fail against code-owned facts.
    artifact.runtime_document['storage_observation'] = deepcopy(document['storage_observation'])
    with pytest.raises(ValueError):
        if authority is None: ApbStorageRegisterVersionAuthority(target)
        else: authority.writes()


def test_contract_drift_permanently_revokes_the_authority(registered_storage_artifact, tmp_path):
    from copy import deepcopy
    from dataclasses import replace
    from pathlib import Path
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    artifact = replace(registered_storage_artifact,
        runtime_document=deepcopy(registered_storage_artifact.runtime_document))
    target = GeneratedApb3RegisterSession(artifact,
        base_dir=Path(__file__).resolve().parents[2], cache_dir=tmp_path)
    authority = ApbStorageRegisterVersionAuthority(target)
    saved = deepcopy(target._artifact_document['storage_observation'])
    for document in (artifact.runtime_document, target._artifact_document):
        document['storage_observation']['source_contract']['digest'] = '0' * 64
    with pytest.raises(ValueError): authority.writes()
    for document in (artifact.runtime_document, target._artifact_document):
        document['storage_observation'] = deepcopy(saved)
    with pytest.raises(ValueError, match='incomplete|revoked'): authority.writes()


def test_authority_captures_immutable_registered_facts(registered_storage_artifact, tmp_path):
    from dataclasses import FrozenInstanceError
    from pathlib import Path
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.scenario import apb_storage_register_version as module
    target = GeneratedApb3RegisterSession(registered_storage_artifact,
        base_dir=Path(__file__).resolve().parents[2], cache_dir=tmp_path)
    authority = module.ApbStorageRegisterVersionAuthority(target)
    contract = registered_storage_artifact.runtime_document['storage_observation']['source_contract']
    facts = module._LIVE[authority]['source_facts']
    assert (facts.digest, facts.register, facts.width, facts.reset_value,
            facts.write_mask, facts.decode_mask, facts.decode_value) == (
        contract['digest'], contract['register']['name'], contract['register']['width'],
        contract['register']['reset_value'], contract['register']['write_mask'],
        contract['decode']['mask'], contract['decode']['value'])
    with pytest.raises(FrozenInstanceError): facts.register = 'FORGED'


def test_authority_rereads_source_bytes_during_its_lifetime(
        registered_storage_artifact, tmp_path, monkeypatch):
    from pathlib import Path
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    root = Path(__file__).resolve().parents[2]
    target = GeneratedApb3RegisterSession(registered_storage_artifact,
        base_dir=root, cache_dir=tmp_path)
    authority = ApbStorageRegisterVersionAuthority(target)
    contract = registered_storage_artifact.runtime_document['storage_observation']['source_contract']
    path = root/contract['source']['root']/next(iter(contract['source']['files']))
    original = Path.read_bytes
    # Substitute only the reviewed RTL read; never alter shared source bytes.
    def changed_bytes(self):
        raw = original(self)
        return raw + b'\n// changed source\n' if self == path else raw
    monkeypatch.setattr(Path, 'read_bytes', changed_bytes)
    with pytest.raises(ValueError): authority.writes()


def test_registered_native_write_version_and_single_use(registered_storage_artifact, tmp_path):
    """Actual native process: source descriptions and fabricated receipts cannot pass."""
    from pathlib import Path
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    target = GeneratedApb3RegisterSession(registered_storage_artifact,
        base_dir=Path(__file__).resolve().parents[2], cache_dir=tmp_path/'native-cache')
    authority = ApbStorageRegisterVersionAuthority(target)
    contract = registered_storage_artifact.runtime_document['storage_observation']['source_contract']
    register = contract['register']['name']
    offset = contract['register']['canonical_offset']
    try:
        target.begin_case('registered-storage-native')
        target.step_local({})
        initial = authority.consume(authority.issue(register=register, reset_epoch=0))
        assert initial['value'] == contract['register']['reset_value']
        assert initial['write_count'] == initial['field_version'] == 0
        target.write_register(offset, 0xdecafbad)
        target.write_register(offset + contract['decode']['alias_period_bytes'], 0xdecafbad)
        assert target.read_register(offset) == 0xdecafbad
        token = authority.issue(register=register, reset_epoch=0)
        witness = authority.consume(token)
        assert witness['register'] == register
        assert witness['source_contract_digest'] == contract['digest']
        assert witness['value'] == 0xdecafbad
        assert witness['write_count'] == witness['field_version'] == 2
        assert witness['grants_reset_prerequisite'] is False
        assert [row['raw_address'] for row in authority.writes()] == [
            offset, offset + contract['decode']['alias_period_bytes']]
        with pytest.raises(ValueError, match='token-invalid'): authority.consume(token)
    finally:
        target.end_case()


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


@pytest.mark.parametrize('callback', ['_actual_begin', '_actual_command'])
def test_command_guard_does_not_repeat_unchanged_producer_check(storage, callback):
    """The authority adds no producer check beyond the owner guard it delegates to.

    Counting the pinned producer check itself rather than a literal: the owner
    guard performs its own check and its ``observer.validate()`` re-authenticates
    the sources, so the delegation baseline is measured first.  The authority
    path must consume exactly that baseline before the frame refusal, i.e. it
    must not add an adjacent duplicate check of its own.
    """
    import sys
    from types import SimpleNamespace
    from myfuzz.local_harness.session import (_NATIVE_RESET_CHECK_PRODUCERS,
                                              _NATIVE_RESET_OWNER_GUARD_PIN)
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority

    authority = ApbStorageRegisterVersionAuthority(storage)
    producer_code = _NATIVE_RESET_CHECK_PRODUCERS[0].__code__

    def produce_count(action):
        calls = []
        def profile(frame, event, arg):
            if event == 'call' and frame.f_code is producer_code:
                calls.append(1)
        previous = sys.getprofile()
        try:
            sys.setprofile(profile)
            action()
        finally:
            sys.setprofile(previous)
        return len(calls)

    delegated = produce_count(lambda: _NATIVE_RESET_OWNER_GUARD_PIN[0](storage))
    assert delegated >= 1
    args = (storage, 'STEP_APB3_REG', ())
    if callback == '_actual_command':
        args += (SimpleNamespace(),)

    def refuse():
        with pytest.raises(ValueError, match='actual-producer-frame-required'):
            getattr(authority, callback)(*args)

    assert produce_count(refuse) == delegated


@pytest.mark.parametrize('callback', ['_actual_begin', '_actual_command'])
def test_observerless_guard_still_checks_producer_before_frame_refusal(storage, callback):
    """The owner guard's observer-less fast return must not skip the pin check."""
    import sys
    from types import SimpleNamespace
    from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority

    authority = ApbStorageRegisterVersionAuthority(storage)
    storage._native_reset_observation = None
    code = _NATIVE_RESET_CHECK_PRODUCERS[0].__code__
    calls = []
    def profile(frame, event, arg):
        if event == 'call' and frame.f_code is code:
            calls.append(1)
    previous = sys.getprofile()
    try:
        sys.setprofile(profile)
        with pytest.raises(ValueError, match='actual-producer-frame-required'):
            args = (storage, 'STEP_APB3_REG', ())
            if callback == '_actual_command':
                args += (SimpleNamespace(),)
            getattr(authority, callback)(*args)
    finally:
        sys.setprofile(previous)
    assert len(calls) == 1


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
