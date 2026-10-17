"""Closed compiled F4 storage producer selection; pure source controls only.

The registered timer target is selected only from its reviewed source contract,
declaration and generated observation contract. Selection is not a live token,
certificate or native eligibility claim, and the generic commit/raw join is D2.
"""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2]
TIMER_CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-apb-timer'
GPIO_CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-apb'


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
    assert document['probe']['digest'] == artifact.runtime_document['storage_observation']['digest']
    assert document['probe']['source_contract_digest'] == \
        artifact.runtime_document['storage_observation']['source_contract']['digest']
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


def test_generic_producer_is_not_reported_as_executable(timer_generated, tmp_path):
    """D1 selection is real, but the generic commit/raw join is D2: fail closed."""
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    from myfuzz.local_harness.compiled_execution_projection import assess_compiled_f4_support
    artifacts, inputs = timer_generated
    with patch('subprocess.Popen', side_effect=AssertionError('no native process')):
        with pytest.raises(ValueError, match='compiled-F4-generic-commit-consumer-unsupported'):
            CompiledF4Runtime(artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT,
                cache_dir=tmp_path / 'cache', run_id='timer-d1')
        report = assess_compiled_f4_support(artifacts=artifacts, compiled_inputs=inputs,
            base_dir=ROOT)
    assert report['execution_supported'] == 0
    assert report['runtime_admitted'] is False
    assert report['reason'] == 'compiled-F4-generic-commit-consumer-unsupported'
    assert report['producer_binding']['row'] == 'generic_apb_storage_abi'


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
                                      'probe_digest', 'missing_observation'))
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
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    artifacts, inputs = timer_generated
    binding = selector().select_storage_producer(artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT)
    from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout
    path = f4_path(inputs['compiled'])
    layout = compile_candidate_layout(path)
    runtime = SimpleNamespace(path=path, compiled_digest='compiled', layout=layout,
        error_policy={'mode': 'native_error_role'}, producer_binding=binding)
    configuration = CompiledF4Runtime.online_identity_configuration(runtime)
    assert configuration['producer_binding'] == binding.document()
    finished = SimpleNamespace(finished=False, _stable=lambda **kw: None,
        session=SimpleNamespace(finish=lambda: SimpleNamespace(semantic_sha256='semantic'),
            encode_plan=lambda: '{}'),
        execution_audit=lambda: {'exits': {}},
        _native_processes={}, _process_identities={}, compiled_digest='compiled',
        closure={}, artifacts={}, rounds=1, max_cases=1, records=[], layout=layout,
        error_policy={'mode': 'native_error_role'}, run_id='unit',
        producer_binding=binding, feedback=lambda: {})
    prefix = CompiledF4Runtime.finish(finished)
    assert prefix['producer_binding'] == binding.document()


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
