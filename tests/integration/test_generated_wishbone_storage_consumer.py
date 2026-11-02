"""Software/synthetic receipt controls for the Wishbone F4 storage consumer.

No native run: the receipt is a caller-supplied event list and the version
token is a refusal-only fixture installed into the process-local registries.
The consumer must still join every element and refuse by name; these controls
can never assert runtime admission.
"""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.integration.generated_wishbone_storage_consumer import (
    CONSUMER_QUALNAME, RECEIPT_ELEMENTS, VERSION_SCHEMA, check_wishbone_storage_observation,
    stable_wishbone_storage_version, wishbone_storage_consumer_support)
from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_driver,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.wishbone_register_session import (
    GeneratedWishboneRegisterSession)
from myfuzz.local_harness.wishbone_storage_probe_contract import ROLES
from myfuzz.scenario import wishbone_storage_register_version as version_module
from myfuzz.scenario.wishbone_storage_register_version import (
    HISTORY_SCOPE, WishboneStorageRegisterVersionAuthority,
    wishbone_storage_version_basis)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_uart_storage/component_profile.json'
CONTRACT = 'zipcpu-wbuart.setup.storage.v1'
VALUE = 0x0055a5a5
BEFORE = 0x00112233
WINDOW = 0x40000000
RESULT = 0x30000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def digest(value):
    return sha256(canonical(value).encode()).hexdigest()


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


def transaction(sequence):
    return dict(execution_id='local-execution', testcase_id='unit',
                source_component='cpu', source_epoch=0, channel_id='data',
                source_sequence=sequence)


def declaration(artifact, value=VALUE):
    return dict(
        schema_version='generated_register_writer.v1',
        candidate=dict(value=value, access=dict(
            source_component='cpu', target_component='uart_setup',
            device_id='uart_setup', source_endpoint='cpu.data',
            register='SETUP', operation='write',
            value_origin='cpu_transaction_wdata',
            register_origin='bound_target_register_commit',
            width_bytes=4, allowed_byte_enables=[15],
            byte_enable_domain='target_word_lanes', access_alignment=4,
            value_mask=0x7fffffff, window_base=WINDOW, window_size=16,
            register_offset=0, word_index=0, address=WINDOW)),
        result_address=RESULT)


def probes(value, *, cyc=0, stb=0, we=0, adr=0, sel=0, dat_w=0, dat_r=0,
           ack=0, stall=0, reset=0):
    return {'storage_value': value, 'storage_reset': reset, 'storage_cyc': cyc,
            'storage_stb': stb, 'storage_we': we, 'storage_adr': adr,
            'storage_sel': sel, 'storage_dat_w': dat_w, 'storage_dat_r': dat_r,
            'storage_ack': ack, 'storage_stall': stall}


def receipt(artifact, declaration, *, value=VALUE, before_value=BEFORE):
    signals = artifact.runtime_document['base_protocol_trace']['signals']
    address = declaration['candidate']['access']['address']
    events = []

    def add(**row):
        row['event_id'] = len(events) + 1
        events.append(row)
        return row

    def sample(tick, phase, producer, observed):
        backend = {signals[role]: observed['storage_' + role]
                   for role in ROLES}
        return add(kind='local_tick_sample', component='uart_setup',
                   local_tick=tick, phase=phase, producer_event_id=producer,
                   reset_epoch=0,
                   observation_schema_version='ip_raw_observation.v1',
                   outputs=dict(backend=backend, storage_probes=observed))

    add(kind='mmio_acceptance', component='cpu', device_id='uart_setup',
        address=address, offset=0, write=True, source_transaction=transaction(1),
        producer_event_id=101)
    add(kind='mmio_delivery', component='cpu', device_id='uart_setup',
        address=address, offset=0, write=True, write_value=value,
        read_value=None, byte_enable=15, source_transaction=transaction(1),
        source_sequence=1, producer_event_id=101)
    sample(20, 'pre', 101, probes(before_value, cyc=1, stb=1, we=1, adr=0,
                                  sel=15, dat_w=value, ack=0, stall=0))
    sample(20, 'post', 101, probes(value, cyc=1, stb=0, we=0, ack=0, stall=0))
    sample(22, 'pre', 101, probes(value, cyc=1, ack=1, stall=0))
    add(kind='mmio_acceptance', component='cpu', device_id='uart_setup',
        address=address, offset=0, write=False,
        source_transaction=transaction(2), producer_event_id=102)
    add(kind='mmio_delivery', component='cpu', device_id='uart_setup',
        address=address, offset=0, write=False, write_value=None,
        read_value=value, byte_enable=15, source_transaction=transaction(2),
        source_sequence=2, producer_event_id=102)
    sample(30, 'pre', 102, probes(value, cyc=1, stb=1, we=0, adr=0, sel=15,
                                  dat_w=0, ack=0, stall=0))
    sample(30, 'post', 102, probes(value, cyc=1, stb=0, we=0, ack=0, stall=0))
    sample(32, 'pre', 102, probes(value, cyc=1, ack=1, stall=0, dat_r=value))
    add(kind='memory_write', component='cpu', address=RESULT, value=value,
        byte_enable=15)
    return SimpleNamespace(events=events, violations=(), status='running',
                           case_id='unit:0')


def context(declaration, *, value=VALUE, tick=20, sequence=7, execution='exec'):
    access = declaration['candidate']['access']
    return dict(source_transaction=transaction(1),
                device_id=access['device_id'],
                window_base=access['window_base'],
                window_size=access['window_size'],
                address=access['address'], offset=access['register_offset'],
                word_index=access['word_index'], write=True, value=value,
                read_value=0, byte_enable=15, tick=tick, execution=execution,
                reset_epoch=0, command_sequence=sequence,
                schema_version='wishbone_storage_routed_context.v1',
                source_authenticated=False)


def commit(artifact, declaration, *, tick=20, sequence=7, execution='exec',
           raw_address=0, mutate=None):
    value = declaration['candidate']['value']
    reference = dict(execution=execution, sequence=sequence, sample_index=0,
                     phase='pre')
    row = dict(tick=tick, raw_address=raw_address, before=BEFORE, after=value,
               sample_index=0, phase='pre', command_sequence=sequence,
               context=context(declaration, value=value, tick=tick,
                               sequence=sequence, execution=execution),
               raw_reference=reference)
    if mutate is not None:
        mutate(row)
    return row


def witness(artifact, *, value, write_count, history, tick, sequence,
            execution='exec', pid=1, build='a' * 64):
    probe = artifact.runtime_document['storage_observation']
    return dict(register='SETUP', value=value, local_tick=tick,
                write_history_sha256=history, field_version=write_count,
                write_count=write_count,
                version_basis=wishbone_storage_version_basis('SETUP'),
                reset_epoch=0, command_sequence=sequence, pid=pid,
                execution=execution, build_identity_sha256=build,
                producer_source_sha256=sha256(
                    Path(version_module.__file__).read_bytes()).hexdigest(),
                artifact_digest=artifact.runtime_document['artifact_digest'],
                source_contract_digest=probe['source_contract']['digest'],
                probe_digest=probe['digest'],
                reset_waveform_observed=False,
                grants_reset_prerequisite=False, history_scope=HISTORY_SCOPE,
                routed_context_authenticated=False)


@pytest.fixture
def setup(generated, tmp_path):
    artifact = replace(generated, runtime_document=deepcopy(
        generated.runtime_document))
    target = GeneratedWishboneRegisterSession(
        artifact, base_dir=ROOT, cache_dir=tmp_path / 'consumer')
    authority = WishboneStorageRegisterVersionAuthority(target)
    target._process = SimpleNamespace(pid=1, poll=lambda: None)
    target._execution = 'exec'
    target._sequence = 8
    target.local_ticks = 40
    target._tick_base = 0
    declared = declaration(artifact)
    write = commit(artifact, declared)
    before = witness(artifact, value=BEFORE, write_count=0,
                     history=digest([]), tick=5, sequence=0)
    final = witness(artifact, value=VALUE, write_count=1,
                    history=digest([write]), tick=40, sequence=8)
    module = version_module
    module._LIVE[authority]['writes'] = [write]
    module._LIVE[authority]['state'] = dict(tick=40, value=VALUE, sequence=8,
                                            reset_waveform_observed=False)
    module._LIVE[authority]['scope'] = (
        target.process, 'exec', 0, 0)
    module._LIVE[authority]['build_digest'] = final['build_identity_sha256']
    token = object()
    module._TOKENS[authority][token] = final
    try:
        yield SimpleNamespace(
            artifact=artifact, target=target, authority=authority,
            declaration=declared, receipt=receipt(artifact, declared),
            before=before, commit=write, witness=final, token=token)
    finally:
        target._process = None


_UNSET = object()


def run(state, *, declaration=None, receipt=None, before=None, token=_UNSET,
        register='SETUP', authority=None, artifact=None):
    return check_wishbone_storage_observation(
        state.declaration if declaration is None else declaration,
        state.receipt if receipt is None else receipt,
        target_artifact=state.artifact if artifact is None else artifact,
        authority=state.authority if authority is None else authority,
        token=state.token if token is _UNSET else token,
        register=register, reset_epoch=0,
        before=state.before if before is None else before, prior_writes=0)


def test_consumer_joins_the_full_wishbone_chain(setup):
    observed, public_commit, after = run(setup)
    assert observed['schema_version'] == (
        'compiled_F4_wishbone_storage_observation.v1')
    assert observed['case_id'] == 'unit:0'
    assert (observed['value'], observed['address'], observed['offset'],
            observed['word_index'], observed['register']) == (
        VALUE, WINDOW, 0, 0, 'SETUP')
    assert observed['runtime_admitted'] is False
    assert [row['write'] for row in observed['joins']] == [True, False]
    assert observed['native_samples']['write']['word_index'] == 0
    assert observed['native_samples']['write']['byte_enable'] == 15
    assert observed['native_samples']['write']['ack_tick'] == 22
    assert observed['native_samples']['read']['ack_tick'] == 32
    assert observed['native_samples']['read']['rdata'] == VALUE
    assert observed['storage_probes']['write']['pre']['storage_sel'] == 15
    assert observed['storage_probes']['write']['post']['storage_cyc'] == 1
    assert observed['storage_probes']['write']['ack']['storage_ack'] == 1
    assert observed['RAM_event'] == 11
    assert observed['token'] == dict(
        schema_version='wishbone_storage_register_version_token.v1',
        consumed=True, single_use=True, opaque=True,
        issuer=('myfuzz.scenario.wishbone_storage_register_version.'
                'WishboneStorageRegisterVersionAuthority'),
        register='SETUP', reset_epoch=0, write_count=1)
    assert public_commit['schema_version'] == 'wishbone_storage_commit.v1'
    assert public_commit['raw_address'] == public_commit['word_index'] == 0
    assert public_commit['before'] == BEFORE
    assert public_commit['after'] == VALUE
    assert public_commit['field_version'] == public_commit['write_count'] == 1
    assert after['schema_version'] == VERSION_SCHEMA
    assert after['probe_digest'] == (
        setup.artifact.runtime_document['storage_observation']['digest'])
    assert after['artifact_digest'] == (
        setup.artifact.runtime_document['artifact_digest'])
    assert after['register'] == 'SETUP'
    assert (after['value'], after['write_count'], after['command_sequence'],
            after['reset_epoch']) == (VALUE, 1, 8, 0)
    for volatile in ('pid', 'execution', 'write_history_sha256',
                     'build_identity_sha256', 'producer_source_sha256'):
        assert volatile not in after
    with pytest.raises(ValueError, match='token-invalid') as error:
        run(setup)
    assert 'wishbone-storage-version-token-invalid' in str(error.value)


def test_stable_version_shape_refuses_extra_fields():
    good = witness(SimpleNamespace(runtime_document=dict(
        storage_observation={'digest': 'd' * 64,
                             'source_contract': {'digest': 'c' * 64}},
        artifact_digest='e' * 64)), value=1, write_count=1, history='f' * 64,
        tick=4, sequence=2)
    stable = stable_wishbone_storage_version(good)
    assert stable['schema_version'] == VERSION_SCHEMA
    with pytest.raises(ValueError, match='witness-shape'):
        stable_wishbone_storage_version(dict(good, caller_value=0))


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('missing_acceptance', 'CPU-acceptance-join'),
    ('missing_write_delivery', 'delivery-count'),
    ('delivery_offset', 'delivery-geometry'),
    ('byte_enable', 'delivery-count'),
    ('sequence', 'sequence-mismatch'),
    ('missing_pre', 'native-transfer-missing'),
    ('missing_post', 'native-post-sample-missing'),
    ('missing_ack', 'missing-ack'),
    ('pre_ack', 'protocol-mismatch'),
    ('post_ack', 'protocol-mismatch'),
    ('stalled_ack', 'protocol-mismatch'),
    ('cyc_not_held', 'protocol-mismatch'),
    ('stalled_accept', 'protocol-mismatch'),
    ('word_index', 'word-index-mismatch'),
    ('sel', 'select-mismatch'),
    ('post_not_idle', 'protocol-mismatch'),
    ('trace_value', 'storage-probe-trace-mismatch'),
    ('native_pwdata', 'native-write-value-mismatch'),
    ('storage_transition', 'storage-transition-mismatch'),
    ('read_prdata', 'native-read-value-mismatch'),
    ('ram', 'readback-RAM-mismatch'),
))
def test_consumer_refuses_tampered_receipt_evidence(setup, mutation, expected):
    events = setup.receipt.events
    signals = setup.artifact.runtime_document['base_protocol_trace']['signals']

    def both(event, name, value):
        event['outputs']['storage_probes'][name] = value
        role = name[len('storage_'):]
        if role in signals:
            event['outputs']['backend'][signals[role]] = value

    if mutation == 'missing_acceptance':
        events[0]['kind'] = 'other_acceptance'
    elif mutation == 'missing_write_delivery':
        events[1]['kind'] = 'other_delivery'
    elif mutation == 'delivery_offset':
        events[1]['offset'] = 4
    elif mutation == 'byte_enable':
        events[1]['byte_enable'] = 3
    elif mutation == 'sequence':
        events[6]['source_transaction']['source_sequence'] = 3
        events[5]['source_transaction']['source_sequence'] = 3
    elif mutation == 'missing_pre':
        events[2]['kind'] = 'other_tick'
    elif mutation == 'missing_post':
        events[3]['kind'] = 'other_tick'
    elif mutation == 'missing_ack':
        events[4]['kind'] = 'other_tick'
    elif mutation == 'pre_ack':
        both(events[2], 'storage_ack', 1)
    elif mutation == 'post_ack':
        both(events[3], 'storage_ack', 1)
    elif mutation == 'stalled_ack':
        both(events[4], 'storage_stall', 1)
    elif mutation == 'cyc_not_held':
        both(events[4], 'storage_cyc', 0)
    elif mutation == 'stalled_accept':
        both(events[2], 'storage_stall', 1)
    elif mutation == 'word_index':
        both(events[2], 'storage_adr', 1)
    elif mutation == 'sel':
        both(events[2], 'storage_sel', 3)
    elif mutation == 'post_not_idle':
        both(events[3], 'storage_stb', 1)
    elif mutation == 'trace_value':
        events[7]['outputs']['storage_probes']['storage_dat_w'] = 1
    elif mutation == 'native_pwdata':
        both(events[2], 'storage_dat_w', VALUE + 1)
    elif mutation == 'storage_transition':
        both(events[3], 'storage_value', BEFORE)
    elif mutation == 'read_prdata':
        both(events[9], 'storage_dat_r', VALUE + 1)
    else:
        events[10]['value'] = VALUE + 1
    with pytest.raises(ValueError, match=expected):
        run(setup)


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('tick', 'commit-tick-mismatch'),
    ('word_index', 'commit-word-index-mismatch'),
    ('epoch', 'commit-context-mismatch'),
    ('context_value', 'commit-context-mismatch'),
    ('context_transaction', 'commit-context-mismatch'),
    ('after', 'commit-value-mismatch'),
    ('before', 'commit-value-mismatch'),
    ('raw_sequence', 'commit-sequence-mismatch'),
    ('missing', 'commit-count'),
))
def test_consumer_refuses_tampered_version_journal(setup, mutation, expected):
    declared = setup.declaration

    def mutate(row):
        if mutation == 'tick':
            row['tick'] = 21
            row['context']['tick'] = 21
        elif mutation == 'word_index':
            row['raw_address'] = 1
        elif mutation == 'epoch':
            row['context']['reset_epoch'] = 1
        elif mutation == 'context_value':
            row['context']['value'] = VALUE + 1
        elif mutation == 'context_transaction':
            row['context']['source_transaction']['source_sequence'] = 9
        elif mutation == 'after':
            row['after'] = VALUE + 1
        elif mutation == 'before':
            row['before'] = 1
        elif mutation == 'raw_sequence':
            row['raw_reference']['sequence'] = 8

    journal = [] if mutation == 'missing' else [
        commit(setup.artifact, declared, mutate=mutate)]
    version_module._LIVE[setup.authority]['writes'] = journal
    with pytest.raises(ValueError, match=expected):
        run(setup)


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('history', 'before-history-mismatch'),
    ('artifact_digest', 'before-witness-mismatch'),
    ('register', 'before-witness-required'),
    ('reset_epoch', 'before-witness-mismatch'),
    ('grants_reset', 'before-witness-required'),
    ('extra_key', 'before-witness-required'),
    ('version_basis', 'before-witness-required'),
))
def test_consumer_refuses_a_serialized_before_witness(setup, mutation,
                                                      expected):
    before = deepcopy(setup.before)
    if mutation == 'history':
        before['write_history_sha256'] = digest([{'forged': True}])
    elif mutation == 'artifact_digest':
        before['artifact_digest'] = 'f' * 64
    elif mutation == 'register':
        before['register'] = 'RXREG'
    elif mutation == 'reset_epoch':
        before['reset_epoch'] = 1
    elif mutation == 'grants_reset':
        before['grants_reset_prerequisite'] = True
    elif mutation == 'version_basis':
        before['version_basis'] = 'caller_basis'
    else:
        before['caller_readback'] = VALUE
    with pytest.raises(ValueError, match=expected):
        run(setup, before=before)


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('offset', 'declaration-geometry'),
    ('word_index', 'declaration-geometry'),
    ('mask', 'declaration-geometry'),
    ('byte_enables', 'declaration-geometry'),
    ('address', 'declaration-geometry'),
    ('register', 'declaration-geometry'),
    ('operation', 'declaration-geometry'),
    ('value', 'declaration-geometry'),
    ('result', 'declaration-required'),
))
def test_consumer_refuses_tampered_declaration(setup, mutation, expected):
    declared = deepcopy(setup.declaration)
    access = declared['candidate']['access']
    if mutation == 'offset':
        access['register_offset'] = 4
        access['address'] = WINDOW + 4
        access['word_index'] = 1
    elif mutation == 'word_index':
        access['word_index'] = 1
    elif mutation == 'mask':
        access['value_mask'] = 0xffff
    elif mutation == 'byte_enables':
        access['allowed_byte_enables'] = [7]
    elif mutation == 'address':
        access['address'] = WINDOW + 4
    elif mutation == 'register':
        access['register'] = 'RXREG'
    elif mutation == 'operation':
        access['operation'] = 'read'
    elif mutation == 'value':
        declared['candidate']['value'] = 0x80000000
    else:
        declared['result_address'] = RESULT + 2
    with pytest.raises(ValueError, match=expected):
        run(setup, declaration=declared)


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('register', 'witness'),
    ('source_digest', 'witness'),
    ('build', 'witness'),
    ('value', 'witness'),
))
def test_consumer_refuses_a_mismatched_token_witness(setup, mutation,
                                                     expected):
    final = deepcopy(setup.witness)
    if mutation == 'register':
        final['register'] = 'RXREG'
    elif mutation == 'source_digest':
        final['source_contract_digest'] = '0' * 64
    elif mutation == 'build':
        final['build_identity_sha256'] = 'b' * 64
    else:
        final['value'] = VALUE + 1
    version_module._TOKENS[setup.authority].clear()
    token = object()
    version_module._TOKENS[setup.authority][token] = final
    with pytest.raises(ValueError, match='token-invalid|witness'):
        check_wishbone_storage_observation(
            setup.declaration, setup.receipt,
            target_artifact=setup.artifact, authority=setup.authority,
            token=token, register='SETUP', reset_epoch=0,
            before=setup.before, prior_writes=0)


def test_consumer_requires_an_opaque_token_and_exact_authority(setup):
    for forged in (None, 'opaque', b'token', 7, dict(setup.witness),
                   SimpleNamespace(witness=setup.witness)):
        with pytest.raises(ValueError, match='token-required'):
            run(setup, token=forged)
    with pytest.raises(ValueError, match='authority-required'):
        run(setup, authority=SimpleNamespace(target=setup.target))
    with pytest.raises(ValueError, match='artifact-required'):
        run(setup, artifact=object())
    with pytest.raises(ValueError, match='contract-mismatch'):
        run(setup, register='RXREG')


@pytest.mark.parametrize('mutation', (
    'schema', 'flag', 'probe_digest', 'probe_port', 'trace_protocol',
    'trace_role', 'artifact_kind', 'selection', 'missing_probe'))
def test_consumer_refuses_a_tampered_probe_document(setup, mutation):
    document = deepcopy(setup.artifact.runtime_document)
    if mutation == 'missing_probe':
        document.pop('storage_observation')
    elif mutation == 'artifact_kind':
        document['kind'] = 'apb3_register_observe'
    elif mutation == 'trace_protocol':
        document['base_protocol_trace']['protocol'] = 'apb3'
    elif mutation == 'trace_role':
        document['base_protocol_trace']['signals']['err'] = 'trace_err'
    elif mutation == 'schema':
        document['storage_observation']['schema_version'] = (
            'apb_storage_probe.v1')
    elif mutation == 'flag':
        document['storage_observation']['native_verified'] = True
    elif mutation == 'probe_digest':
        document['storage_observation']['digest'] = '0' * 64
    elif mutation == 'probe_port':
        document['storage_observation']['ports'][0]['width'] = 16
    else:
        document['storage_observation']['selection']['register'] = 'RXREG'
    # Mutate the artifact the live authority is bound to, in place.
    setup.artifact.runtime_document.clear()
    setup.artifact.runtime_document.update(document)
    with pytest.raises(ValueError):
        run(setup)


def test_consumer_rejects_an_apb_declaration_shape(setup):
    declared = deepcopy(setup.declaration)
    declared['candidate']['access'].pop('word_index')
    with pytest.raises(ValueError, match='declaration-geometry'):
        run(setup, declaration=declared)


def binding_document(setup):
    probe = setup.artifact.runtime_document['storage_observation']
    consumer = Path(
        'src/myfuzz/integration/generated_wishbone_storage_consumer.py')
    issuer = Path('src/myfuzz/scenario/wishbone_storage_register_version.py')
    return dict(
        row='generic_wishbone_storage_abi', target_component='uart_setup',
        endpoint_id='uart.bus', protocol=['wishbone', 'classic'],
        template=dict(template_id='target.wishbone', template_version='1',
                      variant_id='word-addressed-registered-ack'),
        target_artifact_kind='wishbone_register_observe',
        target_artifact_digest=setup.artifact.runtime_document['artifact_digest'],
        register=dict(name='SETUP', address=WINDOW, word_index=0),
        bound_input=dict(kind='ip_register_commit', component='uart_setup',
                         endpoint_id='uart.bus',
                         input_id='uart_setup.uart.bus.register.SETUP.value'),
        probe=dict(digest=probe['digest'],
                   source_contract_digest=probe['source_contract']['digest']),
        producer=dict(
            commit_consumer=CONSUMER_QUALNAME,
            commit_consumer_source_sha256=sha256(
                (ROOT / consumer).read_bytes()).hexdigest(),
            issuer_class=('myfuzz.scenario.wishbone_storage_register_version.'
                          'WishboneStorageRegisterVersionAuthority'),
            issuer_source_sha256=sha256((ROOT / issuer).read_bytes()).hexdigest(),
            version_issuance=('WishboneStorageRegisterVersionAuthority.'
                              'issue/consume/writes'),
            live_token_scope='actual_initial_samples_required_not_claimed',
            grants_reset_prerequisite=False),
        prerequisite=dict(allowed_kinds=['ip_register_version'],
                          expected=dict(kind='ip_register_version', subject=dict(
                              component='uart_setup', register='SETUP',
                              reset_epoch=0))))


def support(document, setup):
    return wishbone_storage_consumer_support(
        binding=SimpleNamespace(document=lambda: document),
        artifacts={'uart_setup': setup.artifact})


def test_support_reports_all_four_joins_and_refuses_each_absence(setup):
    document = binding_document(setup)
    report = support(document, setup)
    assert report['schema_version'] == (
        'compiled_F4_wishbone_storage_consumer_support.v1')
    assert report['complete'] is True
    assert report['disposition'] == 'supported_requires_actual_native_wishbone'
    assert report['runtime_admitted'] is False
    assert tuple(report['elements']) == RECEIPT_ELEMENTS
    assert all(row['present'] for row in report['elements'].values())
    assert report['elements']['native_wishbone_pre_sample']['basis'] == (
        'native Wishbone pre/ACK storage_probes with word-index ADR[1:0], '
        'registered ACK, CYC held, stall=0 and reset levels')
    for mutation, element in (
            ('consumer', 'cpu_acceptance'),
            ('bound', 'router_delivery'),
            ('artifact', 'native_wishbone_pre_sample'),
            ('issuer', 'version_token'),
            ('protocol', 'router_delivery'),
            ('template', 'router_delivery')):
        forged = deepcopy(document)
        artifacts = {'uart_setup': setup.artifact}
        if mutation == 'consumer':
            forged['producer']['commit_consumer'] = 'other.consumer'
        elif mutation == 'bound':
            forged['bound_input']['kind'] = 'dynamic'
        elif mutation == 'issuer':
            forged['producer']['issuer_class'] = 'other.UnknownIssuer'
        elif mutation == 'protocol':
            forged['protocol'] = ['apb', '3']
        elif mutation == 'template':
            forged['template']['variant_id'] = 'half-word'
        else:
            runtime = deepcopy(setup.artifact.runtime_document)
            runtime.pop('storage_probe_ports')
            artifacts['uart_setup'] = replace(
                setup.artifact, runtime_document=runtime)
        report = wishbone_storage_consumer_support(
            binding=SimpleNamespace(document=lambda value=forged: value),
            artifacts=artifacts)
        assert report['complete'] is False, mutation
        assert report['disposition'] == 'unsupported'
        assert report['elements'][element]['present'] is False, mutation
        assert any(row['element'] == element for row in report['refusals'])


@pytest.mark.parametrize('forged', (
    None, {}, {'row': 'generic_apb_storage_abi'}))
def test_support_requires_the_wishbone_row(setup, forged):
    with pytest.raises(ValueError):
        wishbone_storage_consumer_support(
            binding=SimpleNamespace(document=lambda: forged),
            artifacts={'uart_setup': setup.artifact})
    with pytest.raises(ValueError):
        wishbone_storage_consumer_support(
            binding=object(), artifacts={'uart_setup': setup.artifact})


def test_support_row_only_document_is_incomplete_not_supported(setup):
    report = wishbone_storage_consumer_support(
        binding=SimpleNamespace(document=lambda: {
            'row': 'generic_wishbone_storage_abi'}),
        artifacts={'uart_setup': setup.artifact})
    assert report['complete'] is False
    assert report['disposition'] == 'unsupported'
    assert {row['element'] for row in report['refusals']} == set(RECEIPT_ELEMENTS)
