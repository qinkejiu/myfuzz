"""Software-only G8.1 Wishbone storage producer row and writer declaration.

These controls exercise the closed third producer row
(``generic_wishbone_storage_abi``), the four receipt elements of that row's
in-row consumer, and the Wishbone writer projection/masked-full-word policy on
real D2/D3 source documents.  No native process, RTL, reset or campaign is
started: selection and declaration are not runtime admission, a version token,
a hierarchy/native proof or a G8.1 PASS.
"""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[2]
WB_CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-wb-uart-setup'
SPI_CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p'
WB_PROFILE = 'configs/peripherals/zipcpu_uart_storage/component_profile.json'
CONTRACT = 'zipcpu-wbuart.setup.storage.v1'
REGISTER = 'SETUP'
RESULT_ADDRESS = 0x2fffc
VALUE = 0x0055a5a5


def _document(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _generate(config, output):
    """The source-only D2/D3 path used by the SPI real-source test."""
    from myfuzz.local_harness.auto_harness_test import (
        build_path_compile_request, load_composition)
    from myfuzz.local_harness.generated_artifact_admission import (
        load_generated_artifacts)
    from myfuzz.local_harness.harness_set import generate_harness_set, load_compose
    from myfuzz.scenario.compiled_paths import (
        compile_paths, load_path_compile_request)
    from myfuzz.scenario.ownership import compile_ownership

    generated = Path(output) / 'generated'
    compose = load_compose(config / 'compose.json', base_dir=ROOT)
    generate_harness_set(compose, base_dir=ROOT, compose_base=config,
                         output_root=generated)
    composition = load_composition(config / 'compose.json', base_dir=ROOT)
    document, sidecars = build_path_compile_request(composition,
        wiring_path=generated / 'wiring_contract.json',
        ip_capabilities=[config / 'test_capability.json'])
    request = load_path_compile_request(document, base_dir=ROOT)
    compiled = compile_paths(request)
    artifacts = load_generated_artifacts(generated_root=generated, base_dir=ROOT)
    inputs = dict(request=request, compiled=compiled,
                  ownership=compile_ownership((), ()),
                  physical_port_map={})
    return generated, sidecars, artifacts, inputs


@pytest.fixture(scope='module')
def wishbone_generated(tmp_path_factory):
    return _generate(WB_CONFIG, tmp_path_factory.mktemp('compiled-f4-wb'))


@pytest.fixture(scope='module')
def spi_generated(tmp_path_factory):
    return _generate(SPI_CONFIG, tmp_path_factory.mktemp('compiled-f4-spi-row'))


@pytest.fixture(scope='module')
def full_word_generated(tmp_path_factory):
    """Synthetic full-mask D3 capability: projection control, never the row.

    The reviewed ``SETUP`` row stores only bits [30:0].  This copy raises just
    the D3 capability mask so the existing ``declare_writer`` path can run and
    its bytes can be compared with the Wishbone builder; the producer row still
    refuses it because the registered contract mask stays ``0x7fffffff``.
    """
    config = tmp_path_factory.mktemp('wb-full-word-config')
    shutil.copytree(WB_CONFIG, config, dirs_exist_ok=True)
    capability = config / 'test_capability.json'
    document = _document(capability)
    assert document['register_semantics'][0]['register'] == REGISTER
    document['register_semantics'][0]['write_mask'] = 0xffffffff
    capability.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
    return _generate(config, tmp_path_factory.mktemp('compiled-f4-wb-full'))


def _f4_path(compiled):
    paths = [path for path in compiled['paths']
             if path['flow_id'] == 'F4' and path['status'] == 'executable']
    assert len(paths) == 1
    return paths[0]


def _stream(path):
    rows = [source for source in path['sources']
            if source['kind'] == 'cpu_mmio_stream']
    assert len(rows) == 1
    return rows[0]


def _sync_source_mirror(path, source_id):
    """Keep the D3 constraint mirror equal to a doctored source declaration."""
    source = next(row for row in path['sources']
                  if row['source_id'] == source_id)
    mirror = next(row for row in path['constraints']['source_constraints']
                  if row['source_id'] == source_id)
    for key in tuple(mirror):
        mirror[key] = deepcopy(source.get(key))
    return source, mirror


def _select(generated, artifacts=None, compiled_inputs=None):
    from myfuzz.integration.compiled_storage_producer import select_storage_producer
    _generated, _sidecars, loaded, inputs = generated
    return select_storage_producer(
        artifacts=artifacts if artifacts is not None else loaded,
        compiled_inputs=compiled_inputs if compiled_inputs is not None else inputs,
        base_dir=ROOT)


# --- The third row: real Wishbone D2/D3 documents --------------------------

def test_wishbone_d2_d3_selects_the_third_row(wishbone_generated):
    generated, sidecars, artifacts, inputs = wishbone_generated
    assert sidecars == [{
        'instance_id': 'peripheral',
        'profile': WB_PROFILE,
        'test_capability':
            'configs/scenarios/compiled-f4-obi-wb-uart-setup/test_capability.json',
        'source': 'declared-option'}]
    assert (generated / 'harness_set.json').is_file()
    assert artifacts['peripheral'].runtime_document['kind'] == (
        'wishbone_register_observe')
    path = _f4_path(inputs['compiled'])
    access = _stream(path)['register_access']
    assert {key: access[key] for key in (
        'register', 'register_offset', 'address', 'window_base',
        'window_size', 'width_bytes', 'operation', 'allowed_byte_enables',
        'value_mask')} == {
            'register': REGISTER, 'register_offset': 0, 'address': 0x60000000,
            'window_base': 0x60000000, 'window_size': 16, 'width_bytes': 4,
            'operation': 'write', 'allowed_byte_enables': [15],
            'value_mask': 0x7fffffff}
    observation = artifacts['peripheral'].runtime_document['storage_observation']
    assert observation['hierarchy_verified'] is False
    assert observation['native_verified'] is False
    assert observation['selection'] == {
        'endpoint_id': 'uart.bus', 'contract_id': CONTRACT,
        'register': REGISTER}

    from myfuzz.integration.compiled_storage_producer import (
        ROWS, ROW_GENERIC_APB_STORAGE, ROW_GENERIC_WISHBONE_STORAGE,
        ROW_GPIO_CAUSAL)
    assert ROWS == (ROW_GPIO_CAUSAL, ROW_GENERIC_APB_STORAGE,
                    ROW_GENERIC_WISHBONE_STORAGE)
    assert ROW_GENERIC_WISHBONE_STORAGE == 'generic_wishbone_storage_abi'

    binding = _select(wishbone_generated)
    assert binding.row == ROW_GENERIC_WISHBONE_STORAGE
    document = binding.document()
    assert binding.target_component == 'peripheral'
    assert document['target_component'] == 'peripheral'
    assert document['endpoint_id'] == 'uart.bus'
    assert document['target_artifact_kind'] == 'wishbone_register_observe'
    assert document['target_artifact_digest'] == (
        artifacts['peripheral'].runtime_document['artifact_digest'])
    assert document['protocol'] == ['wishbone', 'classic']
    assert document['template'] == {
        'template_id': 'target.wishbone', 'template_version': '1',
        'variant_id': 'word-addressed-registered-ack'}
    assert document['executor_template'] == (
        artifacts['peripheral'].runtime_document['selected_template']['contract'])
    register = document['register']
    assert (register['name'], register['word_index'], register['offset'],
            register['width']) == (REGISTER, 0, 0, 32)
    assert (register['write_mask'], register['read_mask']) == (
        0x7fffffff, 0x7fffffff)
    assert register['address'] == 0x60000000
    assert register['window_base'] == 0x60000000
    assert register['window_size'] == 16
    assert document['decode']['address_units'] == 'word'
    assert document['decode']['address_width'] == 2
    assert document['decode']['canonical_word_index'] == 0
    assert document['decode']['window_bytes'] == 16
    assert document['decode']['mask'] == 0x3
    assert document['decode']['value'] == 0
    assert document['decode']['alias_period_bytes'] == 16
    assert document['source']['closure_kind'] == (
        'registered_reviewed_source_contract')
    assert document['source']['contract_id'] == CONTRACT
    assert document['source']['contract_digest'] == (
        observation['source_contract']['digest'])
    assert document['source']['root'] == 'third_party/soc-zipcpu-wbuart'
    assert document['source']['revision'] == (
        'git:f43a6b83c3a70fb2ac0696a45c5545b233fb860b')
    assert document['source']['top_module'] == 'wbuart'
    assert document['source']['source_closure'] == (
        observation['source_contract']['source']['files'])
    probe = document['probe']
    assert probe['digest'] == observation['digest']
    assert probe['source_contract_digest'] == (
        observation['source_contract']['digest'])
    assert probe['hierarchy_verified'] is False
    assert probe['native_verified'] is False
    assert probe['reset_authority'] is False
    assert probe['version_authority'] is False
    assert probe['source_authority'] is False
    assert 'hierarchy_evidence' not in probe
    producer = document['producer']
    assert producer['commit_consumer'] == (
        'myfuzz.integration.generated_wishbone_storage_consumer.'
        'check_wishbone_storage_observation')
    assert producer['commit_consumer_source_sha256'] == sha256(
        (ROOT / 'src/myfuzz/integration/generated_wishbone_storage_consumer.py'
         ).read_bytes()).hexdigest()
    assert producer['issuer_class'] == (
        'myfuzz.scenario.wishbone_storage_register_version.'
        'WishboneStorageRegisterVersionAuthority')
    assert producer['issuer_source_sha256'] == sha256(
        (ROOT / 'src/myfuzz/scenario/wishbone_storage_register_version.py'
         ).read_bytes()).hexdigest()
    assert producer['version_issuance'] == (
        'WishboneStorageRegisterVersionAuthority.issue/consume/writes')
    assert producer['live_token_scope'] == (
        'actual_initial_samples_required_not_claimed')
    assert producer['grants_reset_prerequisite'] is False
    assert producer['write_declaration'] == (
        'myfuzz.integration.wishbone_register_writer.declare_wishbone_writer')
    assert producer['write_declaration_source_sha256'] == sha256(
        (ROOT / 'src/myfuzz/integration/wishbone_register_writer.py'
         ).read_bytes()).hexdigest()
    producer_body = {key: value for key, value in producer.items()
                     if key != 'producer_digest'}
    assert producer['producer_digest'] == sha256(json.dumps(
        producer_body, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    assert document['bound_input'] == {
        'input_id': 'peripheral.uart.bus.register.SETUP.value',
        'kind': 'ip_register_commit', 'component': 'peripheral',
        'endpoint_id': 'uart.bus'}
    assert document['prerequisite'] == {
        'allowed_kinds': ['ip_register_version'],
        'expected': {'kind': 'ip_register_version', 'subject': {
            'component': 'peripheral', 'register': REGISTER,
            'reset_epoch': 0}}}
    assert document['candidate']['source_id'] == _stream(path)['source_id']
    assert document['candidate']['external_pin_sources'] == []
    assert document['candidate']['byte_length'] == 4
    assert document['candidate']['bit_length'] == 32
    assert document['live_authority'] == 'not_claimed'
    assert document['runtime_commit_join'] == (
        'generic_wishbone_storage_commit_consumer')
    assert binding.digest == sha256(binding.document_json.encode()).hexdigest()


def test_wishbone_consumer_support_lists_all_four_receipt_elements(
        wishbone_generated):
    from myfuzz.integration.generated_wishbone_storage_consumer import (
        RECEIPT_ELEMENTS, wishbone_storage_consumer_support)
    artifacts, inputs = wishbone_generated[2], wishbone_generated[3]
    binding = _select(wishbone_generated)
    support = wishbone_storage_consumer_support(
        binding=binding, artifacts=artifacts)
    assert support['complete'] is True
    assert support['disposition'] == 'supported_requires_actual_native_wishbone'
    assert support['runtime_admitted'] is False
    assert support['row'] == 'generic_wishbone_storage_abi'
    assert tuple(support['receipt_elements']) == RECEIPT_ELEMENTS == (
        'cpu_acceptance', 'router_delivery', 'native_wishbone_pre_sample',
        'version_token')
    assert tuple(support['elements']) == RECEIPT_ELEMENTS
    assert all(row['present'] for row in support['elements'].values())
    assert support['refusals'] == []
    assert support['elements']['native_wishbone_pre_sample']['basis'] == (
        'native Wishbone pre/ACK storage_probes with word-index ADR[1:0], '
        'registered ACK, CYC held, stall=0 and reset levels')


def test_wishbone_row_builds_exact_session_and_authority(
        wishbone_generated, tmp_path):
    from myfuzz.integration.compiled_storage_producer import (
        AdmittedStorageProducerBinding, build_storage_producer,
        validate_storage_producer_binding)
    from myfuzz.local_harness.wishbone_register_session import (
        GeneratedWishboneRegisterSession)
    from myfuzz.scenario.wishbone_storage_register_version import (
        WishboneStorageRegisterVersionAuthority)
    artifacts, inputs = wishbone_generated[2], wishbone_generated[3]
    binding = _select(wishbone_generated)
    assert validate_storage_producer_binding(
        binding, artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT) is binding
    target, authority = build_storage_producer(binding,
        artifact=artifacts['peripheral'], base_dir=ROOT,
        cache_dir=tmp_path / 'wb-cache', max_cases=3)
    assert type(target) is GeneratedWishboneRegisterSession
    assert type(authority) is WishboneStorageRegisterVersionAuthority
    assert target.setup_writes == () and target.probe_offsets == ()
    assert target.process is None
    assert authority.target is target
    forged = AdmittedStorageProducerBinding.build({
        **binding.document(), 'producer': {
            **binding.document()['producer'],
            'commit_consumer': 'pending_D2_wishbone_commit_join'}})
    with pytest.raises(ValueError,
                       match='producer-receipt-join-incomplete'):
        build_storage_producer(forged, artifact=artifacts['peripheral'],
            base_dir=ROOT, cache_dir=tmp_path / 'wb-cache-2', max_cases=3)


@pytest.mark.parametrize('mutation', (
    'hierarchy_verified', 'native_verified', 'probe_digest', 'probe_port_width',
    'runtime_port_width', 'runtime_sv', 'trace_protocol', 'missing_probe'))
def test_tampered_wishbone_probe_document_refused(wishbone_generated, mutation):
    artifacts, inputs = wishbone_generated[2], wishbone_generated[3]
    artifact = artifacts['peripheral']
    document = deepcopy(artifact.runtime_document)
    runtime_sv = artifact.runtime_sv
    if mutation in ('hierarchy_verified', 'native_verified'):
        document['storage_observation'][mutation] = True
    elif mutation == 'probe_digest':
        document['storage_observation']['digest'] = '0' * 64
    elif mutation == 'probe_port_width':
        document['storage_observation']['ports'][2]['width'] = 32
    elif mutation == 'runtime_port_width':
        row = next(row for row in document['runtime_ports']
                   if row['name'] == 'storage_value')
        row['width'] = 16
    elif mutation == 'runtime_sv':
        runtime_sv = runtime_sv.replace(
            'assign storage_value =', 'assign storage_value_bad =', 1)
    elif mutation == 'trace_protocol':
        document['base_protocol_trace']['protocol'] = 'apb3'
    else:
        document.pop('storage_observation')
    forged = replace(artifact, runtime_document=document, runtime_sv=runtime_sv)
    with pytest.raises(ValueError, match='compiled-F4-producer'):
        _select(wishbone_generated,
                artifacts={**artifacts, 'peripheral': forged})


@pytest.mark.parametrize('mutation', ('variant', 'max_outstanding'))
def test_wrong_wishbone_template_policy_refused(wishbone_generated, mutation):
    from myfuzz.local_harness.tuning import load_local_harness_tuning
    artifacts, inputs = wishbone_generated[2], wishbone_generated[3]
    artifact = artifacts['peripheral']
    tuning = deepcopy(artifact.plan.request.tuning.document())
    if mutation == 'variant':
        tuning['endpoint_policies'][0]['variant_id'] = (
            'addressless-select-ignored')
    else:
        tuning['endpoint_policies'][0]['max_outstanding'] = 2
    forged_plan = replace(artifact.plan,
        request=replace(artifact.plan.request,
                        tuning=load_local_harness_tuning(tuning)))
    with pytest.raises(ValueError,
                       match='compiled-F4-producer-template-unsupported'):
        _select(wishbone_generated,
                artifacts={**artifacts,
                           'peripheral': replace(artifact, plan=forged_plan)})


def test_wrong_wishbone_register_in_source_contract_refused(wishbone_generated):
    artifacts = wishbone_generated[2]
    artifact = artifacts['peripheral']
    document = deepcopy(artifact.runtime_document)
    document['storage_observation']['source_contract']['register']['name'] = (
        'TXREG')
    with pytest.raises(ValueError, match='compiled-F4-producer'):
        _select(wishbone_generated, artifacts={
            **artifacts,
            'peripheral': replace(artifact, runtime_document=document)})


@pytest.mark.parametrize('mutation', ('register', 'offset'))
def test_wrong_declared_register_or_word_index_refused(
        wishbone_generated, mutation):
    inputs = wishbone_generated[3]
    compiled = deepcopy(inputs['compiled'])
    path = _f4_path(compiled)
    stream = _stream(path)
    access = stream['register_access']
    if mutation == 'register':
        access['register'] = 'TXREG'
        stream['register'] = 'TXREG'
    else:
        access['register_offset'] = 4
        access['address'] = access['window_base'] + 4
        stream['range'] = [access['address']] * 2
    _sync_source_mirror(path, stream['source_id'])
    with pytest.raises(ValueError,
                       match='compiled-F4-producer-register-mismatch'):
        _select(wishbone_generated,
                compiled_inputs={**inputs, 'compiled': compiled})


def test_unknown_artifact_kind_still_refused(wishbone_generated):
    artifacts, inputs = wishbone_generated[2], wishbone_generated[3]
    artifact = artifacts['peripheral']
    document = deepcopy(artifact.runtime_document)
    document['kind'] = 'native_memory_observe'
    with pytest.raises(ValueError, match='compiled-F4-producer-unsupported'):
        _select(wishbone_generated, artifacts={
            **artifacts,
            'peripheral': replace(artifact, runtime_document=document)})


def test_apb_row_unchanged_and_never_replaced_by_a_wishbone_artifact(
        spi_generated, wishbone_generated):
    spi_artifacts, spi_inputs = spi_generated[2], spi_generated[3]
    wb_artifacts, wb_inputs = wishbone_generated[2], wishbone_generated[3]
    binding = _select(spi_generated)
    assert binding.row == 'generic_apb_storage_abi'
    document = binding.document()
    assert document['target_artifact_kind'] == 'apb3_register_observe'
    assert document['register']['name'] == 'SPICMD'
    assert document['protocol'] == ['apb', '3']
    # A Wishbone artifact can never fill the APB path ...
    with pytest.raises(ValueError, match='compiled-F4-producer'):
        _select(spi_generated, artifacts={
            **spi_artifacts, 'peripheral': wb_artifacts['peripheral']})
    # ... and an APB artifact can never fill the Wishbone path.
    with pytest.raises(ValueError, match='compiled-F4-producer'):
        _select(wishbone_generated, artifacts={
            **wb_artifacts, 'peripheral': spi_artifacts['peripheral']})


# --- Closed pins for the new row -------------------------------------------

_NEW_DEPENDENCIES = (
    'GeneratedWishboneRegisterSession',
    'WishboneStorageRegisterVersionAuthority',
    'check_wishbone_storage_observation',
    'wishbone_storage_consumer_support',
    'declare_wishbone_writer',
    'wishbone_storage_probe_selection',
    'verified_wishbone_storage_observation',
    'validate_wishbone_storage_source_contract',
    'wishbone_setup_matches',
    'wishbone_word_index',
)


def test_new_row_dependencies_are_pinned(wishbone_generated):
    from myfuzz.integration import compiled_storage_producer as module
    for name in _NEW_DEPENDENCIES:
        assert name in module._DEPENDENCIES
        assert name in module._PINNED
        assert name in module._ORIGINS


@pytest.mark.parametrize('name', _NEW_DEPENDENCIES)
def test_replaced_new_row_dependency_is_a_drift_refusal(
        wishbone_generated, monkeypatch, name):
    from myfuzz.integration import compiled_storage_producer as module
    original = getattr(module, name)
    if isinstance(original, type):
        class Replacement(original):
            pass
        monkeypatch.setattr(module, name, Replacement)
    else:
        monkeypatch.setattr(module, name,
                            lambda *args, **kwargs: original(*args, **kwargs))
    artifacts, inputs = wishbone_generated[2], wishbone_generated[3]
    with pytest.raises(ValueError,
                       match='compiled-F4-producer-selection-drift'):
        module.select_storage_producer(
            artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)


# --- Writer declaration: masked full-word policy and word-index projection --

def _writer_inputs(generated):
    inputs = generated[3]
    stream = _stream(_f4_path(inputs['compiled']))
    return inputs['request'], inputs['compiled'], stream['source_id']


def test_real_setup_row_declares_the_masked_full_word_policy(
        wishbone_generated):
    from myfuzz.integration.generated_register_writer import declare_writer
    from myfuzz.integration.wishbone_register_writer import (
        declare_wishbone_writer)
    request, compiled, source_id = _writer_inputs(wishbone_generated)
    with pytest.raises(ValueError,
                       match='register-candidate-masked-merge-policy-undeclared'):
        declare_writer(request, compiled, source_id=source_id, value=VALUE,
                       result_address=RESULT_ADDRESS)
    declaration = declare_wishbone_writer(request, compiled,
        source_id=source_id, value=VALUE, result_address=RESULT_ADDRESS)
    assert declaration['schema_version'] == 'generated_register_writer.v1'
    source_access = _stream(_f4_path(compiled))['register_access']
    access = declaration['candidate']['access']
    assert set(access) - set(source_access) == {'word_index'}
    assert set(source_access) - set(access) == set()
    assert access['word_index'] == 0
    assert access['value_mask'] == 0x7fffffff
    assert access['register'] == REGISTER
    assert access['register_offset'] == 0
    assert declaration['candidate']['value'] == VALUE
    assert declaration['candidate']['source_id'] == source_id
    assert declaration['candidate']['byte_enable'] == 15
    assert declaration['candidate']['validated'] is True
    assert declaration['candidate']['runtime_admitted'] is False
    assert declaration['result_address'] == RESULT_ADDRESS
    assert declaration['runtime_admitted'] is False
    assert declaration['scope'] == 'directed_CPU_writer_and_readback_only'
    assert declaration['unsupported_flows'] == ['F1', 'F2', 'F3']
    assert declaration['refusals'] == [
        'ip-register-version-prerequisite-not-authenticated',
        'compiled-chain-certificate-checker-not-installed']
    policy = declaration['write_policy']
    assert policy == {
        'schema_version': 'register_write_policy.v1',
        'kind': 'declared_masked_full_word_write',
        'value_mask': 0x7fffffff, 'stored_bits': 0x7fffffff,
        'not_claimed': ['bits outside value_mask are not written',
                        'WBUART SETUP bit 31 always reads 0']}
    assert declaration['write_policy_digest'] == sha256(json.dumps(
        policy, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    code = bytes.fromhex(declaration['code_hex'])
    assert len(code) == 48
    assert sha256(code).hexdigest() == declaration['code_sha256']
    assert declaration['compiled_sha256'] == sha256(
        json.dumps(compiled, sort_keys=True).encode()).hexdigest()
    with pytest.raises(ValueError,
                       match='wishbone-writer-candidate-reserved-value-bits'):
        declare_wishbone_writer(request, compiled, source_id=source_id,
            value=0x80000000, result_address=RESULT_ADDRESS)
    tampered = deepcopy(compiled)
    _stream(_f4_path(tampered))['register_access']['address'] += 8
    with pytest.raises(ValueError, match='compiled-document-mismatch'):
        declare_wishbone_writer(request, tampered, source_id=source_id,
            value=VALUE, result_address=RESULT_ADDRESS)


def test_wrong_writer_source_id_refused(
        wishbone_generated, spi_generated):
    from myfuzz.integration.wishbone_register_writer import (
        declare_wishbone_writer)
    request, compiled, _source_id = _writer_inputs(wishbone_generated)
    with pytest.raises(ValueError, match='generated-writer-F4-source-missing'):
        declare_wishbone_writer(request, compiled,
            source_id='peripheral.RXREG.value.mmio', value=VALUE,
            result_address=RESULT_ADDRESS)
    spi_request, spi_compiled, spi_source_id = _writer_inputs(spi_generated)
    with pytest.raises(ValueError, match='wishbone-writer-target-unsupported'):
        declare_wishbone_writer(spi_request, spi_compiled,
            source_id=spi_source_id, value=VALUE,
            result_address=RESULT_ADDRESS)


def test_masked_candidate_validator_refuses_named_violations(
        wishbone_generated):
    from myfuzz.integration.wishbone_register_writer import (
        validate_wishbone_masked_candidate)
    request, compiled, source_id = _writer_inputs(wishbone_generated)
    access = _stream(_f4_path(compiled))['register_access']
    candidate = validate_wishbone_masked_candidate(request, compiled,
        source_id=source_id, source_component=access['source_component'],
        source_endpoint=access['source_endpoint'],
        target_component=access['target_component'], address=access['address'],
        write=True, value=VALUE, byte_enable=15)
    assert candidate['access']['word_index'] == 0
    assert candidate['write_policy']['value_mask'] == 0x7fffffff
    assert candidate['write_policy_digest'] == sha256(json.dumps(
        candidate['write_policy'], sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    base = dict(source_id=source_id,
                source_component=access['source_component'],
                source_endpoint=access['source_endpoint'],
                target_component=access['target_component'],
                address=access['address'], write=True, value=VALUE,
                byte_enable=15)
    for override, code in (
            ({'write': False},
             'wishbone-writer-candidate-operation-mismatch'),
            ({'byte_enable': 7},
             'wishbone-writer-candidate-partial-access'),
            ({'target_component': 'other'},
             'wishbone-writer-candidate-target-mismatch'),
            ({'address': access['address'] + 4},
             'wishbone-writer-candidate-address-mismatch'),
            ({'value': 0x80000000},
             'wishbone-writer-candidate-reserved-value-bits'),
            ({'source_id': 'peripheral.RXREG.value.mmio'},
             'wishbone-writer-candidate-source-undeclared-or-ambiguous')):
        with pytest.raises(ValueError, match=code):
            validate_wishbone_masked_candidate(
                request, compiled, **{**base, **override})


def test_write_policy_requires_every_field_and_its_digest(wishbone_generated):
    from myfuzz.integration.wishbone_register_writer import (
        _require_policy, declare_wishbone_writer)
    request, compiled, source_id = _writer_inputs(wishbone_generated)
    declaration = declare_wishbone_writer(request, compiled,
        source_id=source_id, value=VALUE, result_address=RESULT_ADDRESS)
    good = {key: declaration[key]
            for key in ('write_policy', 'write_policy_digest')}
    assert _require_policy(good) == declaration['write_policy']
    for key in sorted(good['write_policy']):
        broken = deepcopy(good)
        broken['write_policy'].pop(key)
        with pytest.raises(ValueError, match='wishbone-writer-policy-invalid'):
            _require_policy(broken)
    forged = deepcopy(good)
    forged['write_policy_digest'] = '0' * 64
    with pytest.raises(ValueError, match='wishbone-writer-policy-invalid'):
        _require_policy(forged)


def test_word_index_projection_refuses_wrong_register_or_contract(
        wishbone_generated):
    from myfuzz.integration.wishbone_register_writer import _project_access
    artifacts, inputs = wishbone_generated[2], wishbone_generated[3]
    contract = artifacts['peripheral'].runtime_document[
        'storage_observation']['source_contract']
    access = _stream(_f4_path(inputs['compiled']))['register_access']
    assert _project_access(access, contract)['word_index'] == 0
    for mutation in ('register', 'offset', 'window'):
        changed = deepcopy(access)
        if mutation == 'register':
            changed['register'] = 'TXREG'
        elif mutation == 'offset':
            changed['register_offset'] = 4
        else:
            changed['window_size'] = 8
        with pytest.raises(ValueError,
                           match='wishbone-writer-register-mismatch'):
            _project_access(changed, contract)
    forged = deepcopy(contract)
    forged['register']['name'] = 'TXREG'
    with pytest.raises(ValueError,
                       match='wishbone-writer-contract-mismatch'):
        _project_access(access, forged)


def test_writer_dependency_drift_refused(wishbone_generated, monkeypatch):
    from myfuzz.integration import wishbone_register_writer as module
    request, compiled, source_id = _writer_inputs(wishbone_generated)
    original = module.wishbone_word_index
    monkeypatch.setattr(module, 'wishbone_word_index',
                        lambda value: original(value))
    with pytest.raises(ValueError,
                       match='wishbone-writer-declaration-drift'):
        module.declare_wishbone_writer(request, compiled,
            source_id=source_id, value=VALUE,
            result_address=RESULT_ADDRESS)


def test_synthetic_full_word_projection_matches_declare_writer_bytes(
        wishbone_generated, full_word_generated):
    from myfuzz.integration.generated_register_writer import declare_writer
    from myfuzz.integration.wishbone_register_writer import (
        declare_wishbone_writer)
    full_request, full_compiled, full_source = _writer_inputs(
        full_word_generated)
    full_access = _stream(_f4_path(full_compiled))['register_access']
    assert full_access['value_mask'] == 0xffffffff
    delegate = declare_writer(full_request, full_compiled,
        source_id=full_source, value=VALUE, result_address=RESULT_ADDRESS)
    projected = declare_wishbone_writer(full_request, full_compiled,
        source_id=full_source, value=VALUE, result_address=RESULT_ADDRESS)
    assert projected['code_hex'] == delegate['code_hex']
    assert projected['code_sha256'] == delegate['code_sha256']
    assert set(projected['candidate']['access']) - set(
        delegate['candidate']['access']) == {'word_index'}
    assert set(delegate['candidate']['access']) - set(
        projected['candidate']['access']) == set()
    assert projected['candidate']['access']['word_index'] == 0
    assert projected['candidate']['access']['value_mask'] == 0xffffffff
    assert projected['candidate']['value'] == delegate['candidate']['value']
    for key in ('result_address', 'compiled_sha256', 'scope', 'refusals',
                'unsupported_flows', 'runtime_admitted'):
        assert projected[key] == delegate[key]
    assert 'write_policy' not in projected
    assert 'write_policy_digest' not in projected

    # The masked real row generates the identical instruction stream for the
    # same address/value/result address: only the declaration policy differs.
    real_request, real_compiled, real_source = _writer_inputs(wishbone_generated)
    masked = declare_wishbone_writer(real_request, real_compiled,
        source_id=real_source, value=VALUE, result_address=RESULT_ADDRESS)
    assert masked['code_hex'] == delegate['code_hex']
    assert masked['code_sha256'] == delegate['code_sha256']
    assert 'write_policy' in masked
    assert 'write_policy' not in delegate

    # The synthetic full-mask capability can never select the reviewed row.
    with pytest.raises(ValueError,
                       match='compiled-F4-producer-register-mismatch'):
        _select(full_word_generated)
