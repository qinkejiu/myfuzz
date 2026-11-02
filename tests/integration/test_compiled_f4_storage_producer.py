"""Closed compiled F4 storage producer selection and generic APB consumer.

The registered timer target is selected only from its reviewed source contract,
declaration and generated observation contract.  The generic row consumes the
actual CPU acceptance, Router delivery, native APB pre/post sample and opaque
single-use C version token.  Selection and the pure controls are not a live
token, certificate or native eligibility claim.
"""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2]
TIMER_CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-apb-timer'
GPIO_CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-apb'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))



def timer_loaded(directory):
    """Generate the declared timer target from source; no frontend/model/native."""
    from myfuzz.local_harness.auto_harness_test import (build_path_compile_request,
                                                        load_composition)
    from myfuzz.local_harness.generated_artifact_admission import load_generated_artifacts
    from myfuzz.local_harness.harness_set import generate_harness_set, load_compose
    from myfuzz.scenario.compiled_paths import compile_paths, load_path_compile_request
    from myfuzz.scenario.ownership import compile_ownership
    generated = Path(directory) / 'generated'
    compose = load_compose(TIMER_CONFIG / 'compose.json', base_dir=ROOT)
    generate_harness_set(compose, base_dir=ROOT, compose_base=TIMER_CONFIG, output_root=generated)
    composition = load_composition(TIMER_CONFIG / 'compose.json', base_dir=ROOT)
    document, _ = build_path_compile_request(composition,
        wiring_path=generated / 'wiring_contract.json',
        ip_capabilities=[TIMER_CONFIG / 'test_capability.json'])
    request = load_path_compile_request(document, base_dir=ROOT)
    compiled = compile_paths(request)
    artifacts = load_generated_artifacts(generated_root=generated, base_dir=ROOT)
    ownership = compile_ownership((), ())
    return artifacts, dict(request=request, compiled=compiled, ownership=ownership,
        physical_port_map={})


@pytest.fixture(scope='module')
def timer_generated(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp('timer-f4-producer'))


@pytest.fixture(scope='module')
def gpio_generated(tmp_path_factory):
    from tests.integration import test_compiled_f4 as fixture
    original = fixture.CONFIG
    try:
        fixture.CONFIG = GPIO_CONFIG
        return fixture.loaded(tmp_path_factory.mktemp('gpio-f4-producer'))
    finally:
        fixture.CONFIG = original


def selector():
    from myfuzz.integration import compiled_storage_producer as module
    return module


def f4_path(compiled):
    return next(p for p in compiled['paths'] if p['flow_id'] == 'F4' and p['status'] == 'executable')


def sync_mirror(path, source_id):
    """Keep the D3 constraint mirror equal to a doctored source declaration."""
    sources = path['sources']; mirrors = path['constraints']['source_constraints']
    source = next(s for s in sources if s['source_id'] == source_id)
    mirror = next(m for m in mirrors if m['source_id'] == source_id)
    for key in tuple(mirror):
        mirror[key] = deepcopy(source.get(key))
    return source, mirror


def doctored(inputs, mutate):
    compiled = deepcopy(inputs['compiled'])
    mutate(f4_path(compiled))
    return {**inputs, 'compiled': compiled}


# --- RED boundary: the current hard GPIO/GPIOEN restriction ------------------

def test_registered_generic_timer_is_admitted_by_closed_producer_selection(timer_generated):
    from myfuzz.integration.compiled_f4 import admit_f4
    artifacts, inputs = timer_generated
    with patch('subprocess.Popen', side_effect=AssertionError('pure source admission')):
        path = admit_f4(artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
        binding = selector().select_storage_producer(
            artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    assert path['flow_id'] == 'F4'
    assert binding.row == selector().ROW_GENERIC_APB_STORAGE
    document = binding.document()
    assert document['target_component'] == 'peripheral'
    assert document['target_artifact_kind'] == 'apb3_register_observe'
    assert document['endpoint_id'] == 'timer.bus'
    assert document['protocol'] == ['apb', '3']
    assert document['template'] == {'template_id': 'target.apb3',
        'template_version': '1', 'variant_id': 'full-word'}
    register = document['register']
    assert (register['name'], register['offset'], register['width']) == ('TIMER0_CTRL', 4, 32)
    assert register['write_mask'] == register['read_mask'] == 0xffffffff
    assert register['address'] == 0x40001004 and register['window_size'] == 4096
    assert document['decode']['mask'] == 0x1c and document['decode']['value'] == 4
    assert document['decode']['alias_period_bytes'] == 32
    assert document['source']['contract_id'] == 'pulp-apb-timer.ctrl0.source.v1'
    assert document['source']['source_closure'] == {
        'src/apb_timer.sv': '22dce4e3ff8328bdd6e1621c20e2877e7f44cfecccc07203d09e994632cc1778',
        'src/timer.sv': 'd352fc4476da83658d361e8f500b5a73f857f0a11e9436ab47d5bf0ba0bc7fce'}
    artifact = artifacts['peripheral']
    observation = artifact.runtime_document['storage_observation']
    assert observation['hierarchy_verified'] is True
    assert observation['native_verified'] is True
    assert observation['hierarchy_evidence']['reference'] == \
        'docs/reports/evidence/verilog-probe-pulp-apb-timer/proof.json'
    assert document['probe']['digest'] == observation['digest']
    assert document['probe']['source_contract_digest'] == \
        observation['source_contract']['digest']
    assert document['probe']['hierarchy_verified'] is True
    assert document['probe']['native_verified'] is True
    assert document['probe']['hierarchy_evidence']['binding_digest'] == \
        observation['hierarchy_evidence']['binding_digest']
    assert document['probe']['reset_authority'] is False
    assert document['probe']['version_authority'] is False
    assert document['probe']['source_authority'] is False
    producer = document['producer']
    assert producer['session_class'] == \
        'myfuzz.local_harness.apb3_register_session.GeneratedApb3RegisterSession'
    assert producer['issuer_class'] == \
        'myfuzz.scenario.apb_storage_register_version.ApbStorageRegisterVersionAuthority'
    assert producer['session_construction'] == {'setup_writes': [], 'probe_offsets': [],
        'dynamic_inputs': [], 'bound_inputs': []}
    assert producer['grants_reset_prerequisite'] is False
    assert producer['live_token_scope'] == 'actual_initial_samples_required_not_claimed'
    assert document['prerequisite'] == {'allowed_kinds': ['ip_register_version'],
        'expected': {'kind': 'ip_register_version',
                     'subject': {'component': 'peripheral', 'register': 'TIMER0_CTRL',
                                 'reset_epoch': 0}}}
    assert document['candidate']['byte_length'] == 4
    assert document['candidate']['external_pin_sources'] == []
    assert document['live_authority'] == 'not_claimed'
    assert binding.digest == sha256(binding.document_json.encode()).hexdigest()


def test_gpio_causal_row_preserves_existing_producer(timer_generated, gpio_generated):
    from myfuzz.integration.compiled_f4 import admit_f4
    artifacts, inputs = gpio_generated
    timer_artifacts, timer_inputs = timer_generated
    with patch('subprocess.Popen', side_effect=AssertionError('pure admission')):
        path = admit_f4(artifacts=artifacts, compiled_inputs=inputs)
        binding = selector().select_storage_producer(artifacts=artifacts, compiled_inputs=inputs)
    document = binding.document()
    assert binding.row == selector().ROW_GPIO_CAUSAL
    assert document['register']['name'] == 'GPIOEN'
    assert document['register']['offset'] == 4
    assert document['producer']['session_class'] == \
        'myfuzz.local_harness.gpio_session.GeneratedPulpGpioSession'
    assert document['producer']['issuer_class'] == \
        'myfuzz.scenario.gpio_register_version.GpioRegisterVersionAuthority'
    assert document['producer']['commit_consumer'] == \
        'myfuzz.integration.generated_register_writer.check_writer_observation'
    assert document['producer']['grants_reset_prerequisite'] is False
    assert document['prerequisite']['expected']['subject']['register'] == 'GPIOEN'
    with pytest.raises(ValueError):
        selector().select_storage_producer(artifacts=artifacts, compiled_inputs=timer_inputs)
    with pytest.raises(ValueError):
        selector().select_storage_producer(artifacts=timer_artifacts, compiled_inputs=inputs)


def test_generic_producer_is_supported_only_with_complete_in_row_receipts(
        timer_generated, monkeypatch, tmp_path):
    """Generic enters supported only with the in-row consumer + four receipts.

    The report is source/code identity only: runtime admission still requires
    the actual native startup and the opaque single-use version token.
    """
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    from myfuzz.integration.generated_storage_consumer import RECEIPT_ELEMENTS
    from myfuzz.integration.generated_storage_consumer import storage_consumer_support
    from myfuzz.integration.compiled_storage_producer import (
        build_storage_producer, select_storage_producer)
    from myfuzz.local_harness.compiled_execution_projection import assess_compiled_f4_support
    artifacts, inputs = timer_generated
    report = assess_compiled_f4_support(artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT)
    assert report['execution_supported'] == 1
    assert report['status'] == 'supported_requires_actual_startup'
    assert report['runtime_admitted'] is False
    assert report['producer_binding']['row'] == 'generic_apb_storage_abi'
    assert report['producer_binding']['producer']['commit_consumer'] == \
        'myfuzz.integration.generated_storage_consumer.check_storage_observation'
    elements = report['receipt_elements']
    assert elements['complete'] is True
    assert tuple(elements['elements']) == RECEIPT_ELEMENTS
    assert all(row['present'] for row in elements['elements'].values())
    binding = select_storage_producer(artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT)
    target, authority = build_storage_producer(binding,
        artifact=artifacts['peripheral'], base_dir=ROOT,
        cache_dir=tmp_path / 'cache', max_cases=2)
    assert type(target).__name__ == 'GeneratedApb3RegisterSession'
    assert type(authority).__name__ == 'ApbStorageRegisterVersionAuthority'
    # The old hard refusal is gone, but a missing receipt join still refuses.
    monkeypatch.setattr(
        'myfuzz.local_harness.compiled_execution_projection.'
        '_storage_consumer_support',
        lambda **kwargs: dict(elements, complete=False,
            disposition='unsupported',
            refusals=[dict(code='compiled-F4-storage-receipt-join-incomplete',
                           element='version_token')]))
    refused = assess_compiled_f4_support(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    assert refused['execution_supported'] == 0
    assert refused['status'] == 'unsupported'
    assert refused['reason'] == \
        'compiled-F4-generic-receipt-join-incomplete:version_token'
    with patch('subprocess.Popen', side_effect=AssertionError('no native process')):
        try:
            CompiledF4Runtime(artifacts=artifacts, compiled_inputs=inputs,
                base_dir=ROOT, cache_dir=tmp_path / 'cache-2', run_id='timer-i3')
        except ValueError as error:
            assert 'generic-commit-consumer-unsupported' not in str(error)
        except AssertionError:
            pass


def test_generic_support_requires_each_of_the_four_receipt_joins(timer_generated,
                                                                 tmp_path):
    from myfuzz.integration.compiled_storage_producer import (
        AdmittedStorageProducerBinding, build_storage_producer,
        select_storage_producer)
    from myfuzz.integration.generated_storage_consumer import (
        RECEIPT_ELEMENTS, storage_consumer_support)
    artifacts, inputs = timer_generated
    binding = select_storage_producer(artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT)
    baseline = storage_consumer_support(binding=binding, artifacts=artifacts)
    assert baseline['complete'] is True
    document = binding.document()
    expected_missing = {
        'consumer': 'cpu_acceptance',
        'bound': 'router_delivery',
        'artifact': 'native_apb_pre_sample',
        'issuer': 'version_token',
    }
    for mutation, element in expected_missing.items():
        forged = deepcopy(document)
        forged_artifacts = dict(artifacts)
        if mutation == 'consumer':
            forged['producer']['commit_consumer'] = \
                'pending_D2_generic_commit_join'
        elif mutation == 'bound':
            forged['bound_input']['kind'] = 'dynamic'
        elif mutation == 'issuer':
            forged['producer']['issuer_class'] = 'other.UnknownIssuer'
        else:
            runtime = deepcopy(artifacts['peripheral'].runtime_document)
            runtime.pop('storage_probe_ports')
            forged_artifacts['peripheral'] = replace(
                artifacts['peripheral'], runtime_document=runtime)
        tampered = storage_consumer_support(
            binding=AdmittedStorageProducerBinding.build(forged),
            artifacts=forged_artifacts)
        assert tampered['complete'] is False, mutation
        assert tampered['disposition'] == 'unsupported'
        assert tampered['elements'][element]['present'] is False, mutation
        assert any(row['element'] == element for row in tampered['refusals'])
    # Construction also refuses an incomplete row before any native startup.
    forged = AdmittedStorageProducerBinding.build({
        **document, 'producer': {
            **document['producer'],
            'commit_consumer': 'pending_D2_generic_commit_join'}})
    with patch('subprocess.Popen', side_effect=AssertionError('no native process')):
        with pytest.raises(ValueError, match='producer-receipt-join-incomplete'):
            build_storage_producer(forged, artifact=artifacts['peripheral'],
                base_dir=ROOT, cache_dir=tmp_path / 'cache', max_cases=2)
    assert tuple(baseline['receipt_elements']) == RECEIPT_ELEMENTS



# --- Negative controls: nothing but exact trusted declarations selects ------

def test_unknown_protocol_or_template_variant_refused(timer_generated):
    artifacts, inputs = timer_generated
    artifact = artifacts['peripheral']
    document = deepcopy(artifact.runtime_document)
    document['kind'] = 'wishbone_register_observe'
    forged = replace(artifact, runtime_document=document)
    with pytest.raises(ValueError, match='compiled-F4-producer'):
        selector().select_storage_producer(artifacts={**artifacts, 'peripheral': forged},
            compiled_inputs=inputs, base_dir=ROOT)
    from myfuzz.local_harness.tuning import load_local_harness_tuning
    tuning = artifact.plan.request.tuning.document()
    tuning['endpoint_policies'][0]['variant_id'] = 'half-word'
    forged_plan = replace(artifact.plan, request=replace(artifact.plan.request,
        tuning=load_local_harness_tuning(tuning)))
    with pytest.raises(ValueError, match='compiled-F4-producer-template-unsupported'):
        selector().select_storage_producer(
            artifacts={**artifacts, 'peripheral': replace(artifact, plan=forged_plan)},
            compiled_inputs=inputs, base_dir=ROOT)


def test_cross_protocol_target_and_component_rename_refused(timer_generated, gpio_generated):
    timer_artifacts, timer_inputs = timer_generated
    gpio_artifacts, gpio_inputs = gpio_generated
    from myfuzz.integration.compiled_f4 import admit_f4
    # A pinned GPIO artifact cannot fill the timer declaration slot.
    with pytest.raises(ValueError, match='compiled-runtime-input-refused'):
        admit_f4(artifacts={**timer_artifacts, 'peripheral': gpio_artifacts['peripheral']},
                 compiled_inputs=timer_inputs, base_dir=ROOT)
    # Renaming the target component identity never re-selects a producer.
    renamed = dict(timer_artifacts)
    renamed['renamed.peripheral'] = renamed.pop('peripheral')
    with pytest.raises(ValueError, match='compiled-F4-producer'):
        selector().select_storage_producer(artifacts=renamed, compiled_inputs=timer_inputs,
            base_dir=ROOT)


@pytest.mark.parametrize('mutation', ('offset', 'width', 'mask', 'register', 'address'))
def test_wrong_register_offset_width_mask_or_address_refused(timer_generated, mutation):
    artifacts, inputs = timer_generated
    def mutate(path):
        source, mirror = sync_mirror(path, 'peripheral.TIMER0_CTRL.value.mmio')
        access = source['register_access']
        if mutation == 'offset':
            access['register_offset'] = 8; access['address'] += 4
            source['range'] = [access['address']] * 2
        elif mutation == 'width':
            source['width'] = 16; access['width_bytes'] = 2
        elif mutation == 'mask':
            source['mask'] = 0xffff; access['value_mask'] = 0xffff
        elif mutation == 'register':
            source['register'] = 'TIMER1_CTRL'; access['register'] = 'TIMER1_CTRL'
        else:
            access['address'] += 4; source['range'] = [access['address']] * 2
        sync_mirror(path, source['source_id'])
    doctored_inputs = doctored(inputs, mutate)
    with pytest.raises(ValueError, match='compiled-F4-producer'):
        selector().select_storage_producer(artifacts=artifacts, compiled_inputs=doctored_inputs,
            base_dir=ROOT)


@pytest.mark.parametrize('mutation', ('outer_digest', 'contract_digest', 'contract',
                                      'probe_digest', 'missing_observation',
                                      'verification_flag_mismatch',
                                      'verification_evidence_missing',
                                      'verification_evidence_digest',
                                      'verification_evidence_runtime'))
def test_missing_or_tampered_source_probe_identity_refused(timer_generated, mutation):
    artifacts, inputs = timer_generated
    artifact = artifacts['peripheral']
    document = deepcopy(artifact.runtime_document)
    observation = document.get('storage_observation')
    if mutation == 'missing_observation':
        document.pop('storage_observation')
    elif mutation == 'outer_digest':
        observation['digest'] = '0' * 64
    elif mutation == 'probe_digest':
        observation['ports'][0]['expression'] = '1\'b0'
    elif mutation == 'contract_digest':
        observation['source_contract']['digest'] = '0' * 64
    elif mutation == 'verification_flag_mismatch':
        observation['native_verified'] = False
    elif mutation == 'verification_evidence_missing':
        observation.pop('hierarchy_evidence')
    elif mutation == 'verification_evidence_digest':
        observation['hierarchy_evidence']['proof_digest'] = '0' * 64
    elif mutation == 'verification_evidence_runtime':
        observation['hierarchy_evidence']['runtime_sv_sha256'] = '0' * 64
    else:
        observation['source_contract']['register']['name'] = 'TIMER1_CTRL'
    with pytest.raises(ValueError, match='compiled-F4-producer'):
        selector().select_storage_producer(
            artifacts={**artifacts, 'peripheral': replace(artifact, runtime_document=document)},
            compiled_inputs=inputs, base_dir=ROOT)


def test_registered_contract_requires_trusted_source_directory(timer_generated):
    artifacts, inputs = timer_generated
    with pytest.raises(ValueError, match='compiled-F4-producer-source-inputs-required'):
        selector().select_storage_producer(artifacts=artifacts, compiled_inputs=inputs)


@pytest.mark.parametrize('name', ('GeneratedApb3RegisterSession',
                                 'ApbStorageRegisterVersionAuthority',
                                 'check_writer_observation', 'verify_apb_register_trace',
                                 'validate_apb_storage_source_contract'))
def test_caller_supplied_producer_factory_or_method_refused(timer_generated, monkeypatch, name):
    artifacts, inputs = timer_generated
    module = selector()
    original = getattr(module, name)
    if isinstance(original, type):
        class Replacement(original):
            pass
        monkeypatch.setattr(module, name, Replacement)
    else:
        monkeypatch.setattr(module, name, lambda *a, **kw: original(*a, **kw))
    with pytest.raises(ValueError, match='compiled-F4-producer-selection-drift'):
        module.select_storage_producer(artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)


def test_caller_metadata_is_not_a_binding(timer_generated):
    artifacts, inputs = timer_generated
    module = selector()
    binding = module.select_storage_producer(artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT)
    with pytest.raises(TypeError):
        module.select_storage_producer(artifacts=artifacts, compiled_inputs=inputs,
            base_dir=ROOT, producer_factory=object())
    with pytest.raises(ValueError, match='compiled-F4-producer-binding-required'):
        module.validate_storage_producer_binding(binding.document(), artifacts=artifacts,
            compiled_inputs=inputs, base_dir=ROOT)


@pytest.mark.parametrize('mutation', ('tampered', 'stale', 'foreign', 'component'))
def test_stale_foreign_or_tampered_binding_refused(timer_generated, gpio_generated, mutation):
    module = selector()
    artifacts, inputs = timer_generated
    gpio_artifacts, gpio_inputs = gpio_generated
    binding = module.select_storage_producer(artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT)
    assert module.validate_storage_producer_binding(binding, artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT) is binding
    if mutation == 'tampered':
        with pytest.raises(ValueError, match='compiled-F4-producer-binding-required'):
            replace(binding, document_json=binding.document_json.replace(
                '"TIMER0_CTRL"', '"TIMER1_CTRL"'))
    elif mutation == 'stale':
        gpio = module.select_storage_producer(artifacts=gpio_artifacts,
            compiled_inputs=gpio_inputs)
        with pytest.raises(ValueError, match='compiled-F4-producer-binding-mismatch'):
            module.validate_storage_producer_binding(gpio, artifacts=artifacts,
                compiled_inputs=inputs, base_dir=ROOT)
    elif mutation == 'foreign':
        other_inputs = dict(inputs)
        other_inputs['compiled'] = deepcopy(inputs['compiled'])
        renames = {'peripheral': 'other.peripheral'}
        for path in other_inputs['compiled']['paths']:
            for key in ('sources', 'bound_inputs', 'prerequisites', 'endpoints'):
                for row in path.get(key, []):
                    for field in ('component', 'target_component', 'source_component',
                                  'instance_id', 'target_instance'):
                        if row.get(field) in renames:
                            row[field] = renames[row[field]]
        with pytest.raises(ValueError, match='compiled-F4-producer'):
            module.select_storage_producer(artifacts=artifacts,
                compiled_inputs=other_inputs, base_dir=ROOT)
    else:
        forged = module.AdmittedStorageProducerBinding.build(
            {**binding.document(), 'target_component': 'renamed'})
        with pytest.raises(ValueError, match='compiled-F4-producer-binding-mismatch'):
            module.validate_storage_producer_binding(forged, artifacts=artifacts,
                compiled_inputs=inputs, base_dir=ROOT)


# --- Binding identity reaches checker, prefix, stability and fresh replay ----

def test_binding_enters_checker_and_prefix_identity(timer_generated):
    from myfuzz.integration.compiled_f4 import (
        CompiledF4Runtime, derive_f4_execution_binding)
    artifacts, inputs = timer_generated
    binding = selector().select_storage_producer(artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT)
    from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout
    path = f4_path(inputs['compiled'])
    layout = compile_candidate_layout(path)
    execution_binding = derive_f4_execution_binding(
        artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    runtime = SimpleNamespace(path=path, compiled_digest='compiled', layout=layout,
        error_policy={'mode': 'native_error_role'}, producer_binding=binding,
        execution_binding=execution_binding)
    configuration = CompiledF4Runtime.online_identity_configuration(runtime)
    assert configuration['producer_binding'] == binding.document()
    assert configuration['execution_binding'] == execution_binding.document()
    assert configuration['execution_binding_sha256'] == execution_binding.digest
    trace = SimpleNamespace(status='complete', events=(), local_ticks={},
        semantic_sha256='semantic', manifest_sha256='manifest')
    finished = SimpleNamespace(finished=False, _stable=lambda **kw: None,
        session=SimpleNamespace(finish=lambda: trace,
            encode_plan=lambda: '{}'),
        execution_audit=lambda: {'exits': {}},
        _native_processes={}, _process_identities={}, compiled_digest='compiled',
        closure={}, artifacts={}, rounds=1, max_cases=1, records=[], layout=layout,
        error_policy={'mode': 'native_error_role'}, run_id='unit',
        producer_binding=binding, execution_binding=execution_binding,
        row=binding.row, feedback=lambda: {}, _mixed_flows=False)
    prefix = CompiledF4Runtime.finish(finished)
    assert prefix['schema_version'] == 'compiled_F4_prefix.v2'
    assert prefix['producer_binding'] == binding.document()
    assert prefix['execution_binding'] == execution_binding.document()
    assert prefix['execution_binding_sha256'] == execution_binding.digest


def test_stability_rebuilds_binding_and_refuses_drift(timer_generated):
    from myfuzz.integration import compiled_f4
    artifacts, inputs = timer_generated
    module = selector()
    binding = module.select_storage_producer(artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT)
    foreign = module.AdmittedStorageProducerBinding.build(
        {**binding.document(), 'target_component': 'renamed'})
    runtime = SimpleNamespace(finished=False, _caller_inputs=inputs,
        _caller_artifacts=artifacts, inputs=inputs, artifacts=artifacts,
        _input_digest='same', cpu_id='processor', image={'component': 'processor'},
        stream=next(s for s in f4_path(inputs['compiled'])['sources']
                    if s['kind'] == 'cpu_mmio_stream'),
        error_policy={'mode': 'native_error_role'}, path=f4_path(inputs['compiled']),
        layout=object(), base_dir=ROOT, closure={}, compiled_digest='compiled',
        producer_binding=binding)
    with patch.multiple('myfuzz.integration.compiled_f4',
            _input_identity=lambda *a: 'same',
            _cpu_error_policy=lambda *a: {'mode': 'native_error_role'},
            compile_candidate_layout=lambda path: runtime.layout,
            _admit_f4=lambda **kw: (runtime.path, foreign),
            _closure=lambda base: {},
            _digest=lambda value: 'compiled',
            _difference=lambda left, right: None,
            compile_paths=lambda request: inputs['compiled']):
        with pytest.raises(ValueError, match='producer-binding-changed'):
            compiled_f4.CompiledF4Runtime._stable(runtime)


def test_stability_rebuilds_execution_binding_and_refuses_drift(timer_generated):
    from myfuzz.integration import compiled_f4
    from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout
    artifacts, inputs = timer_generated
    producer = selector().select_storage_producer(
        artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    execution = compiled_f4.derive_f4_execution_binding(
        artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    path = f4_path(inputs['compiled'])
    image = next(source for source in path['sources']
                 if source['kind'] == 'instruction_image')
    stream = next(source for source in path['sources']
                  if source['kind'] == 'cpu_mmio_stream')
    layout = compile_candidate_layout(path)
    error_policy = compiled_f4._cpu_error_policy(
        artifacts['processor'], image, stream)
    runtime = SimpleNamespace(finished=False, _caller_inputs=inputs,
        _caller_artifacts=artifacts, inputs=inputs, artifacts=artifacts,
        _input_digest='same', cpu_id='processor', image=image, stream=stream,
        error_policy=error_policy, traces={}, path=path, layout=layout, base_dir=ROOT,
        closure={}, compiled_digest=compiled_f4.compiled_document_sha256(
            inputs['compiled']), producer_binding=producer,
        execution_binding=execution, _validated_built_receipts=lambda: None)
    changed_body = execution.document()
    changed_body.pop('binding_sha256')
    changed_body['selected_path_sha256'] = '0' * 64

    with patch.multiple('myfuzz.integration.compiled_f4',
            _input_identity=lambda *a: 'same',
            _cpu_error_policy=lambda *a: error_policy,
            compile_candidate_layout=lambda current: layout,
            _admit_f4=lambda **kw: (path, producer),
            _closure=lambda base: {},
            _execution_binding_document=lambda **kw: changed_body,
            _difference=lambda left, right: None,
            compile_paths=lambda request: inputs['compiled']):
        with pytest.raises(ValueError, match='execution-binding-changed'):
            compiled_f4.CompiledF4Runtime._stable(runtime)


def test_closed_rows_construct_exact_session_and_issuer(timer_generated, gpio_generated, tmp_path):
    """Fixture-level construction only: no process, no bitstream, no token."""
    from myfuzz.integration.compiled_storage_producer import build_storage_producer
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    module = selector()
    artifacts, inputs = timer_generated
    binding = module.select_storage_producer(artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT)
    target, authority = build_storage_producer(binding,
        artifact=artifacts['peripheral'], base_dir=ROOT,
        cache_dir=tmp_path / 'apb-cache', max_cases=4)
    assert type(target) is GeneratedApb3RegisterSession
    assert target.setup_writes == () and target.probe_offsets == ()
    assert type(authority) is ApbStorageRegisterVersionAuthority
    assert authority.target is target
    gpio_artifacts, gpio_inputs = gpio_generated
    gpio_binding = module.select_storage_producer(artifacts=gpio_artifacts,
        compiled_inputs=gpio_inputs)
    gpio_target, gpio_authority = build_storage_producer(gpio_binding,
        artifact=gpio_artifacts['peripheral'], base_dir=ROOT,
        cache_dir=tmp_path / 'gpio-cache', max_cases=4)
    assert type(gpio_target) is GeneratedPulpGpioSession
    assert type(gpio_authority) is GpioRegisterVersionAuthority
    assert gpio_authority.target is gpio_target
    with pytest.raises(ValueError, match='compiled-F4-producer-artifact-binding-mismatch'):
        build_storage_producer(binding, artifact=gpio_artifacts['peripheral'],
            base_dir=ROOT, cache_dir=tmp_path / 'other', max_cases=4)


# --- Generic APB storage consumer: actual event/journal joins, no native token --

_DECLARATIONS = {}


def timer_declaration(timer_generated, value):
    artifacts, inputs = timer_generated
    path = f4_path(inputs['compiled'])
    stream = next(s for s in path['sources'] if s['kind'] == 'cpu_mmio_stream')
    image = next(s for s in path['sources'] if s['kind'] == 'instruction_image')
    key = (id(inputs['compiled']), value)
    if key not in _DECLARATIONS:
        from myfuzz.integration.generated_register_writer import declare_writer
        _DECLARATIONS[key] = declare_writer(inputs['request'],
            inputs['compiled'], source_id=stream['source_id'], value=value,
            result_address=image['range'][1] - 3)
    return _DECLARATIONS[key]


def _transaction(sequence):
    return dict(execution_id='local-execution', testcase_id='unit',
                source_component='processor', source_epoch=0,
                channel_id='data', source_sequence=sequence)


def _probes(value, *, pwrite, pwdata=0, prdata=0, paddr=4, psel=1,
            penable=1):
    return dict(storage_value=value, storage_reset=0, storage_paddr=paddr,
                storage_psel=psel, storage_penable=penable,
                storage_pwrite=pwrite,
                storage_pwdata=pwdata, storage_prdata=prdata,
                storage_pready=1, storage_pslverr=0)


def _backend(target_artifact, *, pwrite, pwdata=0, prdata=0, paddr=4,
             psel=1, penable=1):
    signals = target_artifact.runtime_document['base_protocol_trace']['signals']
    return {signals['psel']: psel, signals['penable']: penable,
            signals['pready']: 1,
            signals['pslverr']: 0, signals['pwrite']: pwrite,
            signals['paddr']: paddr, signals['pwdata']: pwdata,
            signals['prdata']: prdata}


def timer_receipt(target_artifact, declaration, *, before_value=0):
    value = declaration['candidate']['value']
    access = declaration['candidate']['access']
    events = []

    def add(**row):
        row['event_id'] = len(events) + 1
        events.append(row)
        return row

    def sample(tick, phase, producer, probes, backend):
        return add(kind='local_tick_sample', component='peripheral',
            local_tick=tick, phase=phase, producer_event_id=producer,
            reset_epoch=0, observation_schema_version='ip_raw_observation.v1',
            outputs=dict(backend=backend, storage_probes=probes))

    add(kind='mmio_acceptance', component='processor',
        device_id='peripheral', address=access['address'],
        offset=access['register_offset'], write=True,
        source_transaction=_transaction(1), producer_event_id=101)
    add(kind='mmio_delivery', component='processor', device_id='peripheral',
        address=access['address'], offset=access['register_offset'],
        write=True, write_value=value, read_value=None, byte_enable=15,
        source_transaction=_transaction(1), source_sequence=1,
        producer_event_id=101)
    sample(20, 'pre', 101, _probes(before_value, pwrite=1, pwdata=value),
           _backend(target_artifact, pwrite=1, pwdata=value))
    sample(20, 'post', 101,
           _probes(value, pwrite=0, paddr=0, psel=0, penable=0),
           _backend(target_artifact, pwrite=0, paddr=0, psel=0, penable=0))
    add(kind='mmio_acceptance', component='processor',
        device_id='peripheral', address=access['address'],
        offset=access['register_offset'], write=False,
        source_transaction=_transaction(2), producer_event_id=102)
    add(kind='mmio_delivery', component='processor', device_id='peripheral',
        address=access['address'], offset=access['register_offset'],
        write=False, write_value=None, read_value=value, byte_enable=15,
        source_transaction=_transaction(2), source_sequence=2,
        producer_event_id=102)
    sample(30, 'pre', 102, _probes(value, pwrite=0, prdata=value),
           _backend(target_artifact, pwrite=0, prdata=value))
    sample(30, 'post', 102,
           _probes(value, pwrite=0, paddr=0, psel=0, penable=0),
           _backend(target_artifact, pwrite=0, paddr=0, psel=0, penable=0))
    add(kind='memory_write', component='processor',
        address=declaration['result_address'], value=value, byte_enable=15)
    return SimpleNamespace(events=events, violations=(), status='running',
                           case_id='unit:0')


def timer_commit(target_artifact, declaration, *, before_value=0, tick=20,
                 command_sequence=7, execution='', context_reset_epoch=0,
                 raw_sequence=None, mutate=None):
    value = declaration['candidate']['value']
    access = declaration['candidate']['access']
    context = dict(source_transaction=_transaction(1),
        device_id='peripheral', window_base=access['window_base'],
        window_size=access['window_size'], address=access['address'],
        offset=access['register_offset'], write=True, value=value, be=15,
        execution=execution, reset_epoch=context_reset_epoch,
        command_sequence=command_sequence,
        schema_version='apb_storage_routed_context.v1',
        source_authenticated=False)
    commit = dict(tick=tick, raw_address=4, before=before_value, after=value,
        sample_index=0, phase='pre', command_sequence=command_sequence,
        context=context,
        raw_reference=dict(execution=execution,
            sequence=command_sequence if raw_sequence is None else raw_sequence,
            sample_index=0, phase='pre'))
    if mutate is not None:
        mutate(commit)
    return commit


def version_witness(target_artifact, *, value=0, write_count=0, history=None,
                    execution='', pid=1):
    from myfuzz.integration.generated_storage_consumer import (
        HISTORY_SCOPE, VERSION_BASIS)
    observation = target_artifact.runtime_document['storage_observation']
    if history is None:
        history = sha256(canonical([]).encode()).hexdigest()
    return dict(register='TIMER0_CTRL', value=value,
        local_tick=10 + write_count, write_history_sha256=history,
        field_version=write_count, write_count=write_count,
        version_basis=VERSION_BASIS, reset_epoch=0,
        command_sequence=write_count, pid=pid, execution=execution,
        build_identity_sha256='a' * 64, producer_source_sha256='b' * 64,
        artifact_digest=target_artifact.runtime_document['artifact_digest'],
        source_contract_digest=observation['source_contract']['digest'],
        probe_digest=observation['digest'], reset_waveform_observed=False,
        grants_reset_prerequisite=False, history_scope=HISTORY_SCOPE,
        routed_context_authenticated=False)


def generic_authority(timer_generated, tmp_path):
    from myfuzz.integration.compiled_storage_producer import (
        build_storage_producer, select_storage_producer)
    artifacts, inputs = timer_generated
    binding = select_storage_producer(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    target, authority = build_storage_producer(binding,
        artifact=artifacts['peripheral'], base_dir=ROOT,
        cache_dir=Path(tmp_path) / 'consumer-cache', max_cases=4)
    return artifacts, inputs, binding, target, authority


def install_writes(authority, writes):
    from myfuzz.scenario import apb_storage_register_version as module
    module._LIVE[authority]['writes'] = deepcopy(writes)


from tests.scenario.test_apb_storage_register_version import registered_storage_artifact


def registered_consumer(artifact, timer_generated, tmp_path, *, alias=False):
    """Pure receipt controls; reaching consume must still refuse native eligibility."""
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    target = GeneratedApb3RegisterSession(artifact, base_dir=ROOT, cache_dir=tmp_path)
    authority = ApbStorageRegisterVersionAuthority(target)
    contract = artifact.runtime_document['storage_observation']['source_contract']
    register = contract['register']['name']
    offset = contract['register']['canonical_offset']
    if alias: offset += contract['decode']['alias_period_bytes']
    declaration = deepcopy(timer_declaration(timer_generated, 0x55))
    access = declaration['candidate']['access']
    access.update(register=register, register_offset=offset,
                  address=access['window_base'] + offset)
    receipt = timer_receipt(artifact, declaration)
    signals = artifact.runtime_document['base_protocol_trace']['signals']
    for event in receipt.events:
        if (event['kind'] == 'local_tick_sample'
                and event['phase'] == 'pre'):
            event['outputs']['backend'][signals['paddr']] = offset
            event['outputs']['storage_probes']['storage_paddr'] = offset
    commit = timer_commit(artifact, declaration)
    commit['raw_address'] = offset
    before = version_witness(artifact)
    before.update(register=register,
        version_basis=f'all_measured_{register.rsplit("_", 1)[-1]}_alias_writes_since_first_command')
    install_writes(authority, [commit])
    args = dict(target_artifact=artifact, authority=authority, token=object(),
        register=register, reset_epoch=0, before=before, prior_writes=0)
    return declaration, receipt, args


@pytest.mark.parametrize('alias', (False, True))
def test_registered_consumer_joins_canonical_or_exact_declared_alias(
        registered_storage_artifact, timer_generated, tmp_path, alias):
    from myfuzz.integration.generated_storage_consumer import check_storage_observation
    declaration, receipt, args = registered_consumer(registered_storage_artifact,
        timer_generated, tmp_path, alias=alias)
    with pytest.raises(ValueError, match='storage-version-actual-native-build-required'):
        check_storage_observation(declaration, receipt, **args)


def test_generic_producer_uses_registered_decode(registered_storage_artifact,
        timer_generated, tmp_path):
    """Exercise shared producer projection without requiring Task 4 config."""
    from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout
    artifact = registered_storage_artifact
    declaration, _, _ = registered_consumer(artifact, timer_generated, tmp_path)
    artifacts, inputs = timer_generated
    path = deepcopy(f4_path(inputs['compiled']))
    endpoint = artifact.plan.binding.endpoints[0].endpoint_id
    contract = artifact.runtime_document['storage_observation']['source_contract']
    path['bound_inputs'][0].update(endpoint_id=endpoint,
        input_id=f'peripheral.{endpoint}.register.{contract["register"]["name"]}.value')
    result = selector()._generic_apb_document(
        artifacts={**artifacts, 'peripheral': artifact}, compiled_inputs=inputs,
        path=path, image=next(s for s in path['sources'] if s['kind'] == 'instruction_image'),
        stream=next(s for s in path['sources'] if s['kind'] == 'cpu_mmio_stream'),
        access=declaration['candidate']['access'], layout=compile_candidate_layout(path),
        target_endpoint=endpoint, base_dir=ROOT)
    for key in ('mask', 'value', 'alias_period_bytes', 'raw_address_alias_count',
                'aligned_word_alias_count'):
        assert result['decode'][key] == contract['decode'][key]
    assert result['register']['name'] == contract['register']['name']
    assert result['source']['contract_digest'] == contract['digest']
    from myfuzz.integration.generated_storage_consumer import storage_consumer_support
    result['binding_sha256'] = sha256(canonical(result).encode()).hexdigest()
    support = storage_consumer_support(
        binding=selector().AdmittedStorageProducerBinding(canonical(result)),
        artifacts={'peripheral': artifact})
    assert support['complete'] is True and support['runtime_admitted'] is False
    high = contract['decode']['mask'].bit_length() - 1
    assert support['elements']['native_apb_pre_sample']['basis'] == (
        f'native APB pre/post storage_probes with PADDR[{high}:2] alias and reset levels')


@pytest.mark.parametrize(('missing', 'expected'), (
    ('cpu_acceptance', 'compiled-F4-storage-CPU-acceptance-join'),
    ('router_delivery', 'compiled-F4-storage-delivery-count'),
    ('native_apb_pre_sample', 'compiled-F4-storage-native-transfer-missing'),
    ('version_token', 'compiled-F4-storage-token-required'),
))
def test_registered_consumer_requires_each_receipt_join(
        registered_storage_artifact, timer_generated, tmp_path, missing, expected):
    from myfuzz.integration.generated_storage_consumer import check_storage_observation
    declaration, receipt, args = registered_consumer(registered_storage_artifact,
        timer_generated, tmp_path)
    if missing == 'cpu_acceptance': receipt.events[0]['kind'] = 'missing'
    elif missing == 'router_delivery': receipt.events[1]['kind'] = 'missing'
    elif missing == 'native_apb_pre_sample': receipt.events[2]['kind'] = 'missing'
    else: args['token'] = None
    with pytest.raises(ValueError, match=expected):
        check_storage_observation(declaration, receipt, **args)


@pytest.mark.parametrize(('where', 'expected'), (
    ('backend', 'compiled-F4-storage-native-transfer-missing'),
    ('probe', 'compiled-F4-storage-storage-probe-trace-mismatch'),
    ('backend_and_probe', 'compiled-F4-storage-native-transfer-missing'),
    ('commit', 'compiled-F4-storage-commit-alias-mismatch'),
    ('post_backend', 'compiled-F4-storage-storage-probe-trace-mismatch'),
    ('post_probe', 'compiled-F4-storage-storage-probe-trace-mismatch'),
))
def test_registered_consumer_rejects_a_different_valid_alias(
        registered_storage_artifact, timer_generated, tmp_path, where, expected):
    from myfuzz.integration.generated_storage_consumer import check_storage_observation
    from myfuzz.scenario import apb_storage_register_version as module
    declaration, receipt, args = registered_consumer(registered_storage_artifact,
        timer_generated, tmp_path)
    contract = registered_storage_artifact.runtime_document['storage_observation']['source_contract']
    alias = contract['register']['canonical_offset'] + contract['decode']['alias_period_bytes']
    signals = registered_storage_artifact.runtime_document['base_protocol_trace']['signals']
    if where in ('backend', 'backend_and_probe'):
        receipt.events[2]['outputs']['backend'][signals['paddr']] = alias
    if where in ('probe', 'backend_and_probe'):
        receipt.events[2]['outputs']['storage_probes']['storage_paddr'] = alias
    if where == 'commit':
        module._LIVE[args['authority']]['writes'][0]['raw_address'] = alias
    if where == 'post_backend':
        receipt.events[3]['outputs']['backend'][signals['paddr']] = alias
    if where == 'post_probe':
        receipt.events[3]['outputs']['storage_probes']['storage_paddr'] = alias
    with pytest.raises(ValueError, match=expected):
        check_storage_observation(declaration, receipt, **args)


def test_registered_consumer_treats_post_idle_address_as_dont_care(
        registered_storage_artifact, timer_generated, tmp_path):
    from myfuzz.integration.generated_storage_consumer import check_storage_observation
    declaration, receipt, args = registered_consumer(registered_storage_artifact,
        timer_generated, tmp_path)
    signals = registered_storage_artifact.runtime_document['base_protocol_trace']['signals']
    alias = (registered_storage_artifact.runtime_document['storage_observation']
             ['source_contract']['register']['canonical_offset']
             + registered_storage_artifact.runtime_document['storage_observation']
             ['source_contract']['decode']['alias_period_bytes'])
    receipt.events[3]['outputs']['backend'][signals['paddr']] = alias
    receipt.events[3]['outputs']['storage_probes']['storage_paddr'] = alias
    with pytest.raises(ValueError, match='storage-version-actual-native-build-required'):
        check_storage_observation(declaration, receipt, **args)


def test_registered_consumer_requires_post_sample_to_be_idle(
        registered_storage_artifact, timer_generated, tmp_path):
    from myfuzz.integration.generated_storage_consumer import check_storage_observation
    declaration, receipt, args = registered_consumer(registered_storage_artifact,
        timer_generated, tmp_path)
    signals = registered_storage_artifact.runtime_document['base_protocol_trace']['signals']
    receipt.events[3]['outputs']['backend'][signals['psel']] = 1
    receipt.events[3]['outputs']['storage_probes']['storage_psel'] = 1
    with pytest.raises(ValueError, match='compiled-F4-storage-native-post-not-idle'):
        check_storage_observation(declaration, receipt, **args)


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('event_order', 'compiled-F4-storage-native-post-sample-mismatch'),
    ('schema', 'compiled-F4-storage-native-post-sample-mismatch'),
    ('storage_value', 'compiled-F4-storage-storage-transition-mismatch'),
))
def test_registered_consumer_binds_post_order_schema_and_storage_value(
        registered_storage_artifact, timer_generated, tmp_path,
        mutation, expected):
    from myfuzz.integration.generated_storage_consumer import check_storage_observation
    declaration, receipt, args = registered_consumer(registered_storage_artifact,
        timer_generated, tmp_path)
    post = receipt.events[3]
    if mutation == 'event_order':
        post['event_id'] = receipt.events[2]['event_id']
    elif mutation == 'schema':
        post['observation_schema_version'] = 'ip_raw_observation.v2'
    else:
        post['outputs']['storage_probes']['storage_value'] = 0x54
    with pytest.raises(ValueError, match=expected):
        check_storage_observation(declaration, receipt, **args)


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('register', 'compiled-F4-storage-witness-mismatch'),
    ('digest', 'compiled-F4-storage-witness-source-mismatch'),
))
def test_registered_consumer_refuses_a_cross_contract_token_witness(
        registered_storage_artifact, timer_generated, tmp_path, mutation, expected):
    """Refusal-only fake witness; cannot assert any native token authority."""
    from myfuzz.integration.generated_storage_consumer import check_storage_observation
    from myfuzz.scenario import apb_storage_register_version as version_module
    declaration, receipt, args = registered_consumer(registered_storage_artifact,
        timer_generated, tmp_path)
    authority = args['authority']
    journal = version_module._LIVE[authority]['writes']
    witness = dict(args['before'], value=0x55, local_tick=40, command_sequence=8,
        write_count=1, field_version=1,
        write_history_sha256=sha256(canonical(journal).encode()).hexdigest(),
        producer_source_sha256=sha256(Path(version_module.__file__).read_bytes()).hexdigest())
    if mutation == 'register':
        witness['register'] = 'SPICMD' if args['register'] == 'TIMER0_CTRL' else 'TIMER0_CTRL'
    else: witness['source_contract_digest'] = '0' * 64
    target = authority.target
    target._process = SimpleNamespace(pid=1, poll=lambda: None)
    target.local_ticks = 40
    target._sequence = 8
    try:
        with patch.object(authority, 'writes', return_value=journal), \
             patch.object(authority, 'consume', return_value=witness):
            with pytest.raises(ValueError, match=expected):
                check_storage_observation(declaration, receipt, **args)
    finally:
        target._process = None


@pytest.mark.parametrize(('where', 'expected'), (
    ('argument', 'compiled-F4-storage-observation-contract-mismatch'),
    ('declaration', 'compiled-F4-storage-declaration-geometry'),
    ('before', 'compiled-F4-storage-before-witness-required'),
    ('before_digest', 'compiled-F4-storage-before-witness-mismatch'),
))
def test_registered_consumer_rejects_cross_register_or_digest(
        registered_storage_artifact, timer_generated, tmp_path, where, expected):
    from myfuzz.integration.generated_storage_consumer import check_storage_observation
    declaration, receipt, args = registered_consumer(registered_storage_artifact,
        timer_generated, tmp_path)
    other = 'SPICMD' if args['register'] == 'TIMER0_CTRL' else 'TIMER0_CTRL'
    if where == 'argument': args['register'] = other
    elif where == 'declaration': declaration['candidate']['access']['register'] = other
    elif where == 'before': args['before']['register'] = other
    else: args['before']['source_contract_digest'] = '0' * 64
    with pytest.raises(ValueError, match=expected):
        check_storage_observation(declaration, receipt, **args)


def consume_storage(timer_generated, tmp_path, *, value=0x55, receipt=None,
                    before=None, token=None, journal=None):
    from myfuzz.integration.generated_storage_consumer import (
        check_storage_observation)
    artifacts, inputs, binding, target, authority = generic_authority(
        timer_generated, tmp_path)
    artifact = artifacts['peripheral']
    declaration = timer_declaration(timer_generated, value)
    receipt = receipt if receipt is not None else timer_receipt(
        artifact, declaration)
    before = before if before is not None else version_witness(artifact)
    journal = journal if journal is not None else [timer_commit(
        artifact, declaration)]
    install_writes(authority, journal)
    return check_storage_observation(declaration, receipt,
        target_artifact=artifact, authority=authority,
        token=object() if token is None else token,
        register='TIMER0_CTRL', reset_epoch=0, before=before,
        prior_writes=0)


def test_storage_consumer_checks_the_whole_chain_before_the_native_token(
        timer_generated, tmp_path):
    artifacts, inputs, binding, target, authority = generic_authority(
        timer_generated, tmp_path)
    artifact = artifacts['peripheral']
    declaration = timer_declaration(timer_generated, 0x55)
    install_writes(authority, [timer_commit(artifact, declaration)])
    with pytest.raises(ValueError,
                       match='storage-version-actual-native-build-required'):
        from myfuzz.integration.generated_storage_consumer import (
            check_storage_observation)
        check_storage_observation(declaration,
            timer_receipt(artifact, declaration), target_artifact=artifact,
            authority=authority, token=object(), register='TIMER0_CTRL',
            reset_epoch=0, before=version_witness(artifact), prior_writes=0)


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('write_value', 'compiled-F4-storage-delivery-count'),
    ('delivery_offset', 'compiled-F4-storage-delivery-geometry'),
    ('delivery_device', 'compiled-F4-storage-delivery-count'),
    ('byte_enable', 'compiled-F4-storage-delivery-count'),
    ('sequence', 'compiled-F4-storage-sequence-mismatch'),
    ('missing_acceptance', 'compiled-F4-storage-CPU-acceptance-join'),
    ('missing_pre', 'compiled-F4-storage-native-transfer-missing'),
    ('probe_paddr', 'compiled-F4-storage-storage-probe-trace-mismatch'),
    ('native_pwdata', 'compiled-F4-storage-native-write-value-mismatch'),
    ('storage_transition', 'compiled-F4-storage-storage-transition-mismatch'),
    ('read_prdata', 'compiled-F4-storage-native-read-value-mismatch'),
    ('ram', 'compiled-F4-storage-readback-RAM-mismatch'),
))
def test_storage_consumer_refuses_tampered_delivery_or_native_sample(
        timer_generated, tmp_path, mutation, expected):
    artifacts, inputs, binding, target, authority = generic_authority(
        timer_generated, tmp_path)
    artifact = artifacts['peripheral']
    declaration = timer_declaration(timer_generated, 0x55)
    value = declaration['candidate']['value']
    receipt = timer_receipt(artifact, declaration)
    events = receipt.events
    if mutation == 'write_value':
        events[1]['write_value'] = value + 1
    elif mutation == 'delivery_offset':
        events[1]['offset'] = 8
    elif mutation == 'delivery_device':
        events[1]['device_id'] = 'other'
        events[5]['device_id'] = 'other'
    elif mutation == 'byte_enable':
        events[1]['byte_enable'] = 3
    elif mutation == 'sequence':
        events[4]['source_transaction']['source_sequence'] = 3
        events[5]['source_transaction']['source_sequence'] = 3
    elif mutation == 'missing_acceptance':
        events[0]['kind'] = 'other_acceptance'
    elif mutation == 'missing_pre':
        events[2]['kind'] = 'other_tick'
    elif mutation == 'probe_paddr':
        events[2]['outputs']['storage_probes']['storage_paddr'] = 0
    elif mutation == 'native_pwdata':
        events[2]['outputs']['storage_probes']['storage_pwdata'] = value + 1
        signals = artifact.runtime_document['base_protocol_trace']['signals']
        events[2]['outputs']['backend'][signals['pwdata']] = value + 1
    elif mutation == 'storage_transition':
        events[2]['outputs']['storage_probes']['storage_value'] = 1
    elif mutation == 'read_prdata':
        events[6]['outputs']['storage_probes']['storage_prdata'] = value + 1
        signals = artifact.runtime_document['base_protocol_trace']['signals']
        events[6]['outputs']['backend'][signals['prdata']] = value + 1
    elif mutation == 'ram':
        events[8]['value'] = value + 1
    install_writes(authority, [timer_commit(artifact, declaration)])
    with pytest.raises(ValueError, match=expected):
        from myfuzz.integration.generated_storage_consumer import (
            check_storage_observation)
        check_storage_observation(declaration, receipt,
            target_artifact=artifact, authority=authority, token=object(),
            register='TIMER0_CTRL', reset_epoch=0,
            before=version_witness(artifact), prior_writes=0)


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('tick', 'compiled-F4-storage-commit-tick-mismatch'),
    ('epoch', 'compiled-F4-storage-commit-epoch-mismatch'),
    ('raw_sequence', 'compiled-F4-storage-commit-sequence-mismatch'),
    ('context_value', 'compiled-F4-storage-commit-context-mismatch'),
    ('context_transaction', 'compiled-F4-storage-commit-context-mismatch'),
    ('after', 'compiled-F4-storage-commit-value-mismatch'),
    ('before', 'compiled-F4-storage-commit-value-mismatch'),
    ('raw_address', 'compiled-F4-storage-commit-alias-mismatch'),
    ('missing', 'compiled-F4-storage-commit-count'),
))
def test_storage_consumer_refuses_tampered_c_version_journal(
        timer_generated, tmp_path, mutation, expected):
    artifacts, inputs, binding, target, authority = generic_authority(
        timer_generated, tmp_path)
    artifact = artifacts['peripheral']
    declaration = timer_declaration(timer_generated, 0x55)
    value = declaration['candidate']['value']

    def mutate(commit):
        if mutation == 'tick':
            commit['tick'] = 21
        elif mutation == 'epoch':
            commit['context']['reset_epoch'] = 1
        elif mutation == 'raw_sequence':
            commit['raw_reference']['sequence'] = 8
        elif mutation == 'context_value':
            commit['context']['value'] = value + 1
        elif mutation == 'context_transaction':
            commit['context']['source_transaction']['source_sequence'] = 9
        elif mutation == 'after':
            commit['after'] = value + 1
        elif mutation == 'before':
            commit['before'] = 1
        elif mutation == 'raw_address':
            commit['raw_address'] = 8

    journal = [] if mutation == 'missing' else [timer_commit(
        artifact, declaration, mutate=mutate)]
    before = version_witness(artifact, write_count=0)
    if mutation == 'missing':
        before['local_tick'] = 10
    install_writes(authority, journal)
    with pytest.raises(ValueError, match=expected):
        from myfuzz.integration.generated_storage_consumer import (
            check_storage_observation)
        check_storage_observation(declaration,
            timer_receipt(artifact, declaration), target_artifact=artifact,
            authority=authority, token=object(), register='TIMER0_CTRL',
            reset_epoch=0, before=before, prior_writes=0)


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('history', 'compiled-F4-storage-before-history-mismatch'),
    ('artifact_digest', 'compiled-F4-storage-before-witness-mismatch'),
    ('register', 'compiled-F4-storage-before-witness-required'),
    ('reset_epoch', 'compiled-F4-storage-before-witness-mismatch'),
    ('grants_reset', 'compiled-F4-storage-before-witness-required'),
    ('extra_key', 'compiled-F4-storage-before-witness-required'),
))
def test_storage_consumer_refuses_a_caller_serialized_before_witness(
        timer_generated, tmp_path, mutation, expected):
    artifacts, inputs, binding, target, authority = generic_authority(
        timer_generated, tmp_path)
    artifact = artifacts['peripheral']
    declaration = timer_declaration(timer_generated, 0x55)
    before = version_witness(artifact)
    if mutation == 'history':
        before['write_history_sha256'] = sha256(
            canonical([{'forged': True}]).encode()).hexdigest()
    elif mutation == 'artifact_digest':
        before['artifact_digest'] = 'f' * 64
    elif mutation == 'register':
        before['register'] = 'TIMER1_CTRL'
    elif mutation == 'reset_epoch':
        before['reset_epoch'] = 1
    elif mutation == 'grants_reset':
        before['grants_reset_prerequisite'] = True
    elif mutation == 'extra_key':
        before['caller_readback'] = 0x55
    install_writes(authority, [timer_commit(artifact, declaration)])
    with pytest.raises(ValueError, match=expected):
        from myfuzz.integration.generated_storage_consumer import (
            check_storage_observation)
        check_storage_observation(declaration,
            timer_receipt(artifact, declaration), target_artifact=artifact,
            authority=authority, token=object(), register='TIMER0_CTRL',
            reset_epoch=0, before=before, prior_writes=0)


@pytest.mark.parametrize(('mutation', 'expected'), (
    ('offset_alias', 'compiled-F4-storage-declaration-geometry'),
    ('value_mask', 'compiled-F4-storage-declaration-geometry'),
    ('byte_enables', 'compiled-F4-storage-declaration-geometry'),
    ('address', 'compiled-F4-storage-declaration-geometry'),
    ('result_address', 'compiled-F4-storage-declaration-required'),
    ('operation', 'compiled-F4-storage-declaration-geometry'),
))
def test_storage_consumer_refuses_tampered_declaration_geometry(
        timer_generated, tmp_path, mutation, expected):
    artifacts, inputs, binding, target, authority = generic_authority(
        timer_generated, tmp_path)
    artifact = artifacts['peripheral']
    declaration = deepcopy(timer_declaration(timer_generated, 0x55))
    access = declaration['candidate']['access']
    if mutation == 'offset_alias':
        access['register_offset'] = 8
        access['address'] += 4
    elif mutation == 'value_mask':
        access['value_mask'] = 0xffff
    elif mutation == 'byte_enables':
        access['allowed_byte_enables'] = [7]
    elif mutation == 'address':
        access['address'] += 4
    elif mutation == 'result_address':
        declaration['result_address'] += 2
    elif mutation == 'operation':
        access['operation'] = 'read'
    install_writes(authority, [timer_commit(artifact, declaration)])
    with pytest.raises(ValueError, match=expected):
        from myfuzz.integration.generated_storage_consumer import (
            check_storage_observation)
        check_storage_observation(declaration,
            timer_receipt(artifact, declaration), target_artifact=artifact,
            authority=authority, token=object(), register='TIMER0_CTRL',
            reset_epoch=0, before=version_witness(artifact), prior_writes=0)


def test_storage_consumer_requires_an_opaque_authority_and_live_token(
        timer_generated, tmp_path):
    from myfuzz.integration.generated_storage_consumer import (
        check_storage_observation, stable_storage_version)
    artifacts, inputs, binding, target, authority = generic_authority(
        timer_generated, tmp_path)
    artifact = artifacts['peripheral']
    declaration = timer_declaration(timer_generated, 0x55)
    install_writes(authority, [timer_commit(artifact, declaration)])
    receipt = timer_receipt(artifact, declaration)
    before = version_witness(artifact)
    # Serialized witness/readback is never a token or an authority.
    for forged_token in (dict(before), SimpleNamespace(witness=before),
                         'opaque', b'token', 7, None):
        with pytest.raises(ValueError,
                           match='compiled-F4-storage-token-required'):
            check_storage_observation(declaration, receipt,
                target_artifact=artifact, authority=authority,
                token=forged_token, register='TIMER0_CTRL', reset_epoch=0,
                before=before, prior_writes=0)
    with pytest.raises(ValueError,
                       match='compiled-F4-storage-authority-required'):
        check_storage_observation(declaration, receipt,
            target_artifact=artifact,
            authority=SimpleNamespace(target=target, writes=lambda: [None],
                                      consume=lambda token: dict(before)),
            token=object(), register='TIMER0_CTRL', reset_epoch=0,
            before=before, prior_writes=0)
    # A forged opaque token still fails closed at actual native eligibility.
    with pytest.raises(ValueError,
                       match='storage-version-actual-native-build-required'):
        check_storage_observation(declaration, receipt,
            target_artifact=artifact, authority=authority, token=object(),
            register='TIMER0_CTRL', reset_epoch=0, before=before,
            prior_writes=0)


def test_storage_consumer_refuses_changed_build_identity_in_same_process(
        timer_generated, tmp_path):
    from myfuzz.integration.generated_storage_consumer import (
        check_storage_observation)
    from myfuzz.scenario import apb_storage_register_version as version_module
    artifacts, inputs, binding, target, authority = generic_authority(
        timer_generated, tmp_path)
    artifact = artifacts['peripheral']
    declaration = timer_declaration(timer_generated, 0x55)
    receipt = timer_receipt(artifact, declaration)
    journal = [timer_commit(artifact, declaration)]
    before = version_witness(artifact)
    witness = version_witness(artifact, value=0x55, write_count=1,
        history=sha256(canonical(journal).encode()).hexdigest())
    witness.update(local_tick=40, command_sequence=8,
                   build_identity_sha256='c' * 64,
                   producer_source_sha256=sha256(
                       Path(version_module.__file__).read_bytes()).hexdigest())
    target._process = SimpleNamespace(pid=1, poll=lambda: None)
    target.local_ticks = 40
    target._sequence = 8
    with patch.object(authority, 'writes', return_value=journal), \
         patch.object(authority, 'consume', return_value=witness):
        with pytest.raises(ValueError,
                           match='compiled-F4-storage-witness-build-identity-mismatch'):
            check_storage_observation(declaration, receipt,
                target_artifact=artifact, authority=authority, token=object(),
                register='TIMER0_CTRL', reset_epoch=0, before=before,
                prior_writes=0)
def test_stable_storage_version_keeps_only_process_independent_fields():
    from myfuzz.integration.generated_storage_consumer import (
        STABLE_VERSION_KEYS, stable_storage_version)
    witness = dict(register='TIMER0_CTRL', value=0x55, local_tick=40,
        write_history_sha256='c' * 64, field_version=1, write_count=1,
        version_basis='all_measured_CTRL_alias_writes_since_first_command',
        reset_epoch=0, command_sequence=12, pid=4242,
        execution='driver-nonce', build_identity_sha256='a' * 64,
        producer_source_sha256='b' * 64, artifact_digest='d' * 64,
        source_contract_digest='e' * 64, probe_digest='f' * 64,
        reset_waveform_observed=False, grants_reset_prerequisite=False,
        history_scope=('complete_commands_since_first_measured_state_'
                       'not_unobserved_startup'),
        routed_context_authenticated=False)
    stable = stable_storage_version(witness)
    assert stable['schema_version'] == 'apb_storage_register_version.v1'
    for key in ('pid', 'execution', 'write_history_sha256',
                'build_identity_sha256', 'producer_source_sha256'):
        assert key not in stable
    for key in STABLE_VERSION_KEYS:
        assert key in stable
    tampered = dict(witness, caller_value=0)
    with pytest.raises(ValueError, match='compiled-F4-storage-witness-shape'):
        stable_storage_version(tampered)


def test_storage_consumer_accepts_an_actual_tuple_receipt_without_relaxing(
        timer_generated, tmp_path):
    """OnlineCaseReceipt.events is a tuple in real runs; content checks stay."""
    from myfuzz.integration.generated_storage_consumer import (
        check_storage_observation)
    artifacts, inputs, binding, target, authority = generic_authority(
        timer_generated, tmp_path / 'first')
    artifact = artifacts['peripheral']
    declaration = timer_declaration(timer_generated, 0x55)
    receipt = timer_receipt(artifact, declaration)
    receipt.events = tuple(receipt.events)
    install_writes(authority, [timer_commit(artifact, declaration)])
    with pytest.raises(ValueError,
                       match='storage-version-actual-native-build-required'):
        check_storage_observation(declaration, receipt,
            target_artifact=artifact, authority=authority, token=object(),
            register='TIMER0_CTRL', reset_epoch=0,
            before=version_witness(artifact), prior_writes=0)
    # A tuple receipt is not a content bypass: a missing native pre sample
    # still refuses by name.
    artifacts, inputs, binding, target, tampered_authority = generic_authority(
        timer_generated, tmp_path / 'second')
    tampered = timer_receipt(artifact, declaration)
    events = list(tampered.events)
    events[2]['kind'] = 'other_tick'
    tampered.events = tuple(events)
    install_writes(tampered_authority, [timer_commit(artifact, declaration)])
    with pytest.raises(ValueError,
                       match='compiled-F4-storage-native-transfer-missing'):
        check_storage_observation(declaration, tampered,
            target_artifact=artifact, authority=tampered_authority,
            token=object(), register='TIMER0_CTRL', reset_epoch=0,
            before=version_witness(artifact), prior_writes=0)
    # A non-dict member is still refused as an invalid receipt, not accepted.
    broken = timer_receipt(artifact, declaration)
    broken.events = (dict(broken.events[0]), 'not-an-event')
    with pytest.raises(ValueError, match='compiled-F4-storage-receipt-required'):
        check_storage_observation(declaration, broken,
            target_artifact=artifact, authority=tampered_authority,
            token=object(), register='TIMER0_CTRL', reset_epoch=0,
            before=version_witness(artifact), prior_writes=0)


# --- Fresh-prefix semantic identity: only the process receipt nonce is local --

def process_local_events(execution):
    return [
        dict(event_id=1, kind='mmio_delivery', value=85,
             target_access_id=f'apb-storage:{execution}:13'),
        dict(event_id=2, kind='local_tick_sample', value=85,
             outputs=dict(nested=[dict(
                 target_access_id=f'apb-storage:{execution}:17')])),
    ]


def test_normalized_semantic_hash_ignores_only_the_process_execution_nonce():
    from myfuzz.integration.compiled_f4 import normalized_semantic_sha256
    ticks = {'processor': 12, 'peripheral': 23}
    first = process_local_events('a' * 32)
    second = process_local_events('b' * 32)
    before = deepcopy(first)
    assert normalized_semantic_sha256('complete', first, ticks) == \
        normalized_semantic_sha256('complete', second, ticks)
    # The real events are untouched: only the verification hash is normalized.
    assert first == before
    assert first[0]['target_access_id'] == 'apb-storage:' + 'a' * 32 + ':13'
    assert first[1]['outputs']['nested'][0]['target_access_id'] == \
        'apb-storage:' + 'a' * 32 + ':17'
    # The sequence suffix, every other field, ticks and status still matter.
    suffix = process_local_events('a' * 32)
    suffix[0]['target_access_id'] = 'apb-storage:' + 'a' * 32 + ':14'
    assert normalized_semantic_sha256('complete', suffix, ticks) != \
        normalized_semantic_sha256('complete', first, ticks)
    changed = process_local_events('a' * 32)
    changed[0]['value'] = 86
    assert normalized_semantic_sha256('complete', changed, ticks) != \
        normalized_semantic_sha256('complete', first, ticks)
    assert normalized_semantic_sha256('complete', first,
        {'peripheral': 23, 'processor': 12}) == \
        normalized_semantic_sha256('complete', first, ticks)
    assert normalized_semantic_sha256('running', first, ticks) != \
        normalized_semantic_sha256('complete', first, ticks)
    with pytest.raises(ValueError, match='compiled-F4-semantic-hash-input'):
        normalized_semantic_sha256('complete', (first[0], 'not-an-event'), ticks)


def test_generic_finish_normalizes_hash_but_keeps_real_records(timer_generated):
    from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout
    from myfuzz.integration.compiled_f4 import (
        CompiledF4Runtime, normalized_semantic_sha256)
    artifacts, inputs = timer_generated
    binding = selector().select_storage_producer(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    from myfuzz.integration.compiled_f4 import derive_f4_execution_binding
    execution_binding = derive_f4_execution_binding(
        artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    layout = compile_candidate_layout(f4_path(inputs['compiled']))
    records = [dict(certificate=dict(joins=[dict(delivery_event=1)],
                                     commit=dict(tick=15)))]
    ticks = {'processor': 12, 'peripheral': 23}

    def prefix(row, events, raw):
        trace = SimpleNamespace(genome_sha256='genome', status='complete',
            events=tuple(events), local_ticks=dict(ticks),
            semantic_sha256=raw, manifest_sha256='manifest')
        runtime = SimpleNamespace(finished=False, trace=trace,
            _stable=lambda **kwargs: None,
            session=SimpleNamespace(finish=lambda: trace,
                                    encode_plan=lambda: '{}'),
            execution_audit=lambda: {'exits': {}},
            _native_processes={}, _process_identities={},
            compiled_digest='compiled', closure={}, artifacts={}, rounds=1,
            max_cases=1, records=deepcopy(records), layout=layout,
            error_policy={'mode': 'native_error_role'}, run_id='unit',
            producer_binding=binding, execution_binding=execution_binding,
            feedback=lambda: {}, row=row, _mixed_flows=False)
        return CompiledF4Runtime.finish(runtime)

    first = prefix('generic_apb_storage_abi',
                   process_local_events('a' * 32), 'raw-primary')
    second = prefix('generic_apb_storage_abi',
                    process_local_events('b' * 32), 'raw-fresh')
    expected = normalized_semantic_sha256('complete',
        process_local_events('a' * 32), ticks)
    assert first['semantic_hash'] == second['semantic_hash'] == expected
    assert first['semantic_hash'] != 'raw-primary'
    assert second['semantic_hash'] != 'raw-fresh'
    # Records/certificates are passed through untouched and join by real fields.
    assert first['records'] == records and second['records'] == records
    assert 'target_access_id' not in (
        first['records'][0]['certificate']['joins'][0])
    gpio = prefix('gpio_causal_abi', process_local_events('a' * 32),
                  'raw-gpio')
    assert gpio['semantic_hash'] == 'raw-gpio'


def test_consumer_keeps_real_process_local_access_ids_untouched(
        timer_generated, tmp_path):
    from myfuzz.integration.generated_storage_consumer import (
        check_storage_observation)
    artifacts, inputs, binding, target, authority = generic_authority(
        timer_generated, tmp_path)
    artifact = artifacts['peripheral']
    declaration = timer_declaration(timer_generated, 0x55)
    receipt = timer_receipt(artifact, declaration)
    execution = 'a' * 32
    receipt.events[1]['target_access_id'] = f'apb-storage:{execution}:13'
    receipt.events[5]['target_access_id'] = f'apb-storage:{execution}:17'
    install_writes(authority, [timer_commit(artifact, declaration)])
    with pytest.raises(ValueError,
                       match='storage-version-actual-native-build-required'):
        check_storage_observation(declaration, receipt,
            target_artifact=artifact, authority=authority, token=object(),
            register='TIMER0_CTRL', reset_epoch=0,
            before=version_witness(artifact), prior_writes=0)
    assert receipt.events[1]['target_access_id'] == \
        f'apb-storage:{execution}:13'
    assert receipt.events[5]['target_access_id'] == \
        f'apb-storage:{execution}:17'
