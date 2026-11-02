"""Wishbone storage version authority: single-use tokens and routed contexts.

Every fixture here is software-only: a generated Wishbone register artifact and
a fresh (unstarted) session.  Reaching the token path requires injecting a
measured state into the process-local registries, which is a refusal-only
fixture and never a native eligibility claim.
"""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_driver,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.wishbone_register_session import (
    GeneratedWishboneRegisterSession)
from myfuzz.scenario import wishbone_storage_register_version as module
from myfuzz.scenario.wishbone_storage_register_version import (
    HISTORY_SCOPE, WISHBONE_STORAGE_CONTEXT_SCHEMA,
    WishboneStorageRegisterVersionAuthority, validate_routed_context,
    validate_wishbone_storage_scope, wishbone_storage_version_basis)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_uart_storage/component_profile.json'
CONTRACT = 'zipcpu-wbuart.setup.storage.v1'


@pytest.fixture(scope='module')
def generated():
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=PROFILE,
        instance_id='uart_setup', reset_assert_ticks=2,
        reset_release_ticks=2, max_wait_cycles=16, tuning={
            'endpoint_policies': [dict(endpoint_id='uart.bus',
                template_id='target.wishbone', template_version='1',
                variant_id='word-addressed-registered-ack',
                max_outstanding=1)],
            'wishbone_storage_observations': [dict(endpoint_id='uart.bus',
                contract_id=CONTRACT, register='SETUP')],
            'fixed_inputs': [
                dict(endpoint_id='uart.pins', role='rx', value=1),
                dict(endpoint_id='uart.pins', role='cts_n', value=0)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT),
        base_dir=ROOT)


@pytest.fixture
def target(generated, tmp_path):
    return GeneratedWishboneRegisterSession(
        generated, base_dir=ROOT, cache_dir=tmp_path / 'cache')


def context(**overrides):
    value = dict(
        source_transaction=dict(
            execution_id='exec', testcase_id='case', source_component='cpu',
            source_epoch=0, channel_id='data', source_sequence=1),
        device_id='uart_setup', window_base=0x40000000, window_size=16,
        address=0x40000000, offset=0, word_index=0, write=True, value=0x55,
        read_value=0, byte_enable=15, tick=20, execution='exec',
        reset_epoch=0, command_sequence=7,
        schema_version=WISHBONE_STORAGE_CONTEXT_SCHEMA,
        source_authenticated=False)
    value.update(overrides)
    return value


def validate(value, **overrides):
    arguments = dict(operation='ACCESS_WB_REG', fields=(1, 0, 0x55, 15),
                     sequence=7, execution='exec', epoch=0, window=16)
    arguments.update(overrides)
    return validate_routed_context(value, **arguments)


def install_live(authority, *, value=0x55, sequence=8, tick=40,
                 execution='exec', pid=123, build='a' * 64):
    target = authority.target
    target._process = SimpleNamespace(pid=pid, poll=lambda: None)
    target._execution = execution
    target._sequence = sequence
    target.local_ticks = tick
    target._tick_base = 0
    module._LIVE[authority]['state'] = dict(
        tick=tick, value=value, sequence=sequence,
        reset_waveform_observed=False)
    module._LIVE[authority]['scope'] = (
        target.process, execution, target.reset_epoch, target._tick_base)
    module._LIVE[authority]['build_digest'] = build


@pytest.fixture
def live_authority(target):
    authority = WishboneStorageRegisterVersionAuthority(target)
    install_live(authority)
    try:
        yield authority
    finally:
        target._process = None


def test_routed_context_accepts_the_exact_command_and_copies():
    value = context()
    result = validate(value)
    assert result == value
    assert result is not value
    assert result['source_transaction'] is not value['source_transaction']
    read = context(write=False, value=0, read_value=0x55,
                   source_transaction=dict(value['source_transaction'],
                                           source_sequence=2))
    assert validate(read, fields=(0, 0, 0, 15), sequence=7) == read


@pytest.mark.parametrize('mutation', (
    'schema', 'extra_key', 'missing_key', 'transaction', 'transaction_bool',
    'write_type', 'write_value', 'value_bool', 'byte_enable', 'word_index',
    'address', 'offset', 'offset_unaligned', 'window', 'window_base',
    'execution', 'epoch', 'sequence', 'tick', 'read_value_on_write',
    'value_on_read', 'source_authenticated', 'device'))
def test_malformed_or_foreign_context_refused(mutation):
    value = context()
    arguments = {}
    if mutation == 'schema':
        value['schema_version'] = 'apb_storage_routed_context.v1'
    elif mutation == 'extra_key':
        value['caller_readback'] = 0x55
    elif mutation == 'missing_key':
        value.pop('tick')
    elif mutation == 'transaction':
        value['source_transaction'] = {'execution_id': 'exec'}
    elif mutation == 'transaction_bool':
        value['source_transaction']['source_epoch'] = True
    elif mutation == 'write_type':
        value['write'] = 1
    elif mutation == 'write_value':
        value['write'] = False
    elif mutation == 'value_bool':
        value['value'] = True
    elif mutation == 'byte_enable':
        value['byte_enable'] = 3
        arguments['fields'] = (1, 0, 0x55, 3)
    elif mutation == 'word_index':
        value['word_index'] = 1
    elif mutation == 'address':
        value['address'] = 0x40000004
    elif mutation == 'offset':
        value['offset'] = 4
        arguments['fields'] = (1, 4, 0x55, 15)
    elif mutation == 'offset_unaligned':
        value['offset'] = 2
        arguments['fields'] = (1, 2, 0x55, 15)
    elif mutation == 'window':
        value['window_size'] = 32
    elif mutation == 'window_base':
        value['window_base'] = 0xfffffff8
    elif mutation == 'execution':
        value['execution'] = 'other'
    elif mutation == 'epoch':
        value['reset_epoch'] = 1
    elif mutation == 'sequence':
        value['command_sequence'] = 8
    elif mutation == 'tick':
        value['tick'] = -1
    elif mutation == 'read_value_on_write':
        value['read_value'] = 0x55
    elif mutation == 'value_on_read':
        value['write'] = False
        value['read_value'] = 0x55
        arguments['fields'] = (0, 0, 0x55, 15)
    elif mutation == 'source_authenticated':
        value['source_authenticated'] = True
    else:
        value['device_id'] = ''
    with pytest.raises(ValueError):
        validate(value, **arguments)


@pytest.mark.parametrize('arguments', (
    dict(fields=(2, 0, 0x55, 15)), dict(fields=(1, 0, 0x55, 7)),
    dict(fields=(1, 0, 0x56, 15)), dict(fields=(1, 4, 0x55, 15)),
    dict(sequence=8), dict(execution='other'), dict(epoch=1),
    dict(window=32), dict(window=8)))
def test_context_must_match_the_carried_command(arguments):
    with pytest.raises(ValueError):
        validate(context(), **arguments)


def test_access_requires_a_context_and_a_step_carries_none():
    with pytest.raises(ValueError, match='context-required'):
        validate_routed_context(None, operation='ACCESS_WB_REG',
                                fields=(1, 0, 0x55, 15), sequence=7,
                                execution='exec', epoch=0, window=16)
    assert validate_routed_context(
        None, operation='STEP_WB_REG', fields=(), sequence=7,
        execution='exec', epoch=0, window=16) is None
    with pytest.raises(ValueError, match='command-mismatch'):
        validate_routed_context(context(), operation='STEP_WB_REG',
                                fields=(), sequence=7, execution='exec',
                                epoch=0, window=16)


def test_version_basis_and_scope_guard():
    assert wishbone_storage_version_basis('SETUP') == (
        'all_measured_SETUP_word_writes_since_first_command')
    process = object()
    state = dict(tick=12, sequence=3, value=9)
    scope = (process, 'nonce', 0, 7)
    arguments = dict(process=process, execution='nonce', epoch=0,
                     tick_base=7, sequence=3, tick=12)
    validate_wishbone_storage_scope(state, scope, **arguments)
    validate_wishbone_storage_scope(None, None, allow_initial=True,
                                    **dict(arguments, sequence=0, tick=7))
    for change in ('tick', 'tick_base', 'sequence', 'process', 'execution',
                   'epoch'):
        broken = dict(arguments)
        broken[change] = (object() if change == 'process' else
                          'other' if change == 'execution' else
                          broken[change] + 1)
        with pytest.raises(ValueError):
            validate_wishbone_storage_scope(state, scope, **broken)
    with pytest.raises(ValueError):
        validate_wishbone_storage_scope(None, None, **arguments)


def test_authority_is_fresh_exact_and_fails_closed_without_a_native_build(
        generated, tmp_path):
    target = GeneratedWishboneRegisterSession(
        generated, base_dir=ROOT, cache_dir=tmp_path / 'closed')
    authority = WishboneStorageRegisterVersionAuthority(target)
    assert authority.target is target
    assert authority.writes() == []
    with pytest.raises(ValueError, match='actual-native-build-required'):
        authority.issue(register='SETUP', reset_epoch=0)
    # Every failed issuance poisons the issuer, including its token path.
    with pytest.raises(ValueError, match='drift-or-revoked'):
        authority.consume(object())
    fresh = GeneratedWishboneRegisterSession(
        generated, base_dir=ROOT, cache_dir=tmp_path / 'closed-2')
    other = WishboneStorageRegisterVersionAuthority(fresh)
    with pytest.raises(ValueError, match='actual-native-build-required'):
        other.consume(object())


def test_authority_refuses_a_reused_or_foreign_target(generated, tmp_path):
    target = GeneratedWishboneRegisterSession(
        generated, base_dir=ROOT, cache_dir=tmp_path / 'one')
    WishboneStorageRegisterVersionAuthority(target)
    with pytest.raises(ValueError, match='fresh-exact-producer'):
        WishboneStorageRegisterVersionAuthority(target)
    for attribute, value in (('_sequence', 1), ('local_ticks', 1),
                             ('_tick_base', 1), ('reset_epoch', 1),
                             ('_execution', 'exec')):
        other = GeneratedWishboneRegisterSession(
            generated, base_dir=ROOT, cache_dir=tmp_path / (attribute + 'x'))
        setattr(other, attribute, value)
        with pytest.raises(ValueError, match='fresh-exact-producer'):
            WishboneStorageRegisterVersionAuthority(other)
        other._process = SimpleNamespace(pid=1, poll=lambda: None)
        with pytest.raises(ValueError, match='fresh-exact-producer'):
            WishboneStorageRegisterVersionAuthority(other)
        other._process = None
    for forged in (None, object(), SimpleNamespace(), 7):
        with pytest.raises(ValueError):
            WishboneStorageRegisterVersionAuthority(forged)


def test_issue_consumes_exactly_once_and_reports_stable_facts(live_authority):
    authority = live_authority
    token = authority.issue(register='SETUP', reset_epoch=0)
    assert type(token) is object
    witness = authority.consume(token)
    assert set(witness) == module.WITNESS_KEYS
    document = authority.target._artifact_document
    probe = document['storage_observation']
    assert witness['register'] == 'SETUP'
    assert witness['value'] == 0x55
    assert witness['write_count'] == witness['field_version'] == 0
    assert witness['command_sequence'] == 8
    assert witness['reset_epoch'] == 0
    assert witness['probe_digest'] == probe['digest']
    assert witness['artifact_digest'] == document['artifact_digest']
    assert witness['source_contract_digest'] == (
        probe['source_contract']['digest'])
    assert witness['version_basis'] == wishbone_storage_version_basis('SETUP')
    assert witness['history_scope'] == HISTORY_SCOPE
    assert witness['grants_reset_prerequisite'] is False
    assert witness['routed_context_authenticated'] is False
    assert witness['pid'] == 123 and witness['execution'] == 'exec'
    with pytest.raises(ValueError, match='token-invalid'):
        authority.consume(token)
    # The single failure revokes the issuer permanently.
    with pytest.raises(ValueError, match='drift-or-revoked'):
        authority.writes()


def test_token_is_not_transferable_between_authorities(generated, tmp_path):
    first = GeneratedWishboneRegisterSession(
        generated, base_dir=ROOT, cache_dir=tmp_path / 'a')
    second = GeneratedWishboneRegisterSession(
        generated, base_dir=ROOT, cache_dir=tmp_path / 'b')
    a = WishboneStorageRegisterVersionAuthority(first)
    b = WishboneStorageRegisterVersionAuthority(second)
    install_live(a)
    install_live(b, execution='exec', pid=124)
    token = a.issue(register='SETUP', reset_epoch=0)
    with pytest.raises(ValueError, match='token-invalid'):
        b.consume(token)
    # The foreign authority's refusal did not consume the real token.
    witness = a.consume(token)
    assert witness['pid'] == 123
    first._process = None
    second._process = None


def test_token_reuse_after_scope_drift_is_refused(live_authority):
    authority = live_authority
    token = authority.issue(register='SETUP', reset_epoch=0)
    authority.target._sequence = 9
    with pytest.raises(ValueError, match='stale-scope'):
        authority.consume(token)
    authority.target._process = None


def test_source_contract_drift_permanently_revokes(target):
    authority = WishboneStorageRegisterVersionAuthority(target)
    document = target._artifact_document['storage_observation']
    saved = deepcopy(document)
    for source in (target._artifact_document, target.artifact.runtime_document):
        source['storage_observation']['source_contract']['digest'] = '0' * 64
    with pytest.raises(ValueError):
        authority.writes()
    for source in (target._artifact_document, target.artifact.runtime_document):
        source['storage_observation'] = deepcopy(saved)
    with pytest.raises(ValueError, match='incomplete|revoked|drift'):
        authority.writes()


@pytest.mark.parametrize('mutation', (
    'probe_digest', 'probe_port', 'probe_flag', 'probe_schema',
    'source_probe_ports', 'selection', 'artifact_kind'))
def test_probe_or_selection_drift_revokes(generated, tmp_path, mutation):
    artifact = replace(generated, runtime_document=deepcopy(
        generated.runtime_document))
    target = GeneratedWishboneRegisterSession(
        artifact, base_dir=ROOT, cache_dir=tmp_path / 'drift')
    authority = WishboneStorageRegisterVersionAuthority(target)
    for source in (target._artifact_document, artifact.runtime_document):
        probe = source['storage_observation']
        if mutation == 'probe_digest':
            probe['digest'] = '0' * 64
        elif mutation == 'probe_port':
            probe['ports'][0]['width'] = 16
        elif mutation == 'probe_flag':
            probe['version_authority'] = True
        elif mutation == 'probe_schema':
            probe['schema_version'] = 'apb_storage_probe.v1'
        elif mutation == 'source_probe_ports':
            source['storage_probe_ports'] = probe['ports'][:1]
        elif mutation == 'selection':
            probe['selection']['register'] = 'RXREG'
        else:
            source['kind'] = 'apb3_register_observe'
    with pytest.raises(ValueError):
        authority.writes()


def test_authority_without_a_probe_document_refused(generated, tmp_path):
    document = deepcopy(generated.runtime_document)
    document.pop('storage_observation')
    artifact = replace(generated, runtime_document=document)
    target = GeneratedWishboneRegisterSession(
        artifact, base_dir=ROOT, cache_dir=tmp_path / 'missing')
    with pytest.raises(ValueError, match='source-contract-required'):
        WishboneStorageRegisterVersionAuthority(target)


def test_method_or_registry_replacement_cannot_reissue(
        target, generated, tmp_path, monkeypatch):
    authority = WishboneStorageRegisterVersionAuthority(target)
    install_live(authority)
    token = authority.issue(register='SETUP', reset_epoch=0)
    other = GeneratedWishboneRegisterSession(
        generated, base_dir=ROOT, cache_dir=tmp_path / 'second')
    authority2 = WishboneStorageRegisterVersionAuthority(other)
    with monkeypatch.context() as patch:
        patch.setattr(module, 'validate_routed_context', lambda *a, **k: None)
        with pytest.raises(ValueError, match='drift-or-revoked'):
            authority.consume(token)
    with monkeypatch.context() as patch:
        patch.setattr(module, '_LIVE', dict(module._LIVE))
        with pytest.raises(ValueError, match='drift-or-revoked'):
            authority2.writes()
    target._process = None
