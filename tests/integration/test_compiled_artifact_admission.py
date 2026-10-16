"""D3 admission binds regenerated artifacts to compiler inputs, not runtime claims."""
import copy
import json
from pathlib import Path

import pytest

from myfuzz.local_harness.compiled_artifact_admission import admit_compiled_artifacts
from myfuzz.local_harness.generated_artifact_admission import load_generated_artifacts
from myfuzz.local_harness.harness_set import generate_harness_set, load_compose
from myfuzz.scenario.compiled_paths import compile_paths, load_path_compile_request
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from tests.integration.test_p7b_to_p7c_chain import ROOT, ROM, RAM, compose_document


@pytest.fixture(scope='module', params=['ibex_obi_local', 'cv32e40p'])
def loaded(request, tmp_path_factory):
    directory = tmp_path_factory.mktemp('compiled-admission')
    compose_path = compose_document(directory, memory=[ROM, RAM])
    cpu_request = directory / 'requests/cpu.json'
    document = json.loads(cpu_request.read_text())
    document['profile_path'] = f'configs/cpus/{request.param}/component_profile.json'
    cpu_request.write_text(json.dumps(document))
    generated = directory / 'generated'
    generate_harness_set(load_compose(compose_path, base_dir=ROOT), base_dir=ROOT,
                         compose_base=directory, output_root=generated)
    artifacts = load_generated_artifacts(generated_root=generated, base_dir=ROOT)
    document = dict(schema_version='path_compile_request.v1', cpu=dict(instance_id='cpu',
        profile=f'configs/cpus/{request.param}/component_profile.json',
        data_endpoint='processor.data', instruction_endpoint='processor.instruction'),
        devices=[dict(instance_id='gpio', device_id='gpio',
            profile='configs/peripherals/pulp_gpio/component_profile.json',
            test_capability='configs/peripherals/pulp_gpio/test_capability.json')],
        wiring={'source': str(generated / 'wiring_contract.json')})
    compile_request = load_path_compile_request(document, base_dir=ROOT)
    compiled = compile_paths(compile_request)
    return artifacts, compile_request, compiled, document


def admit(loaded, **changes):
    artifacts, request, compiled, _ = loaded
    options = dict(artifacts=artifacts, request=request, compiled=compiled,
                   ownership=compile_ownership((), ()), physical_port_map={})
    options.update(changes)
    return admit_compiled_artifacts(**options)


def test_supported_protocol_and_second_cpu_are_compatible_without_execution_claim(loaded):
    result = admit(loaded)
    assert result['status'] == 'compatible'
    assert result['refusals'] == []
    assert result['scope'] == 'compiled_artifact_consistency'
    assert result['runtime_enforcement'] == 'not_admitted'
    assert result['artifact_digests']


@pytest.mark.parametrize('field', ['sources', 'constraints', 'seed', 'assertions', 'bound_inputs',
                                 'prerequisites', 'runtime_path_identity'])
def test_any_modified_execution_semantic_is_refused(loaded, field):
    compiled = copy.deepcopy(loaded[2])
    compiled['paths'][0][field] = {'invented': True}
    result = admit(loaded, compiled=compiled)
    assert result['status'] == 'refused'
    assert result['refusals'][0]['code'] == 'compiled-document-mismatch'
    assert field in result['refusals'][0]['pointer']


def test_similarly_named_cpu_profile_cannot_borrow_loaded_cpu(loaded):
    document = copy.deepcopy(loaded[3])
    document['cpu']['profile'] = 'configs/cpus/cv32e20/component_profile.json'
    request = load_path_compile_request(document, base_dir=ROOT)
    result = admit(loaded, request=request, compiled=compile_paths(request))
    assert result['status'] == 'refused'
    assert any(r['code'] == 'artifact-profile-mismatch' for r in result['refusals'])


def test_uncompiled_physical_source_is_refused_instead_of_silently_added(loaded):
    ownership = compile_ownership((InputField('gpio', 'gpio_in', 32),),
        (InputOwner('gpio', 'gpio_in', 0, 32, 'source', 'invented-pins'),))
    result = admit(loaded, ownership=ownership,
                   physical_port_map={('gpio', 'gpio_in'): 'gpio_in'})
    assert result['status'] == 'refused'
    assert any(r['code'] == 'ownership-source-uncompiled' for r in result['refusals'])


def test_output_cannot_be_declared_an_input(loaded):
    ownership = compile_ownership((InputField('gpio', 'out', 32),),
        (InputOwner('gpio', 'out', 0, 32, 'fixed', 'zero'),))
    result = admit(loaded, ownership=ownership,
                   physical_port_map={('gpio', 'out'): 'gpio_out'})
    assert result['status'] == 'refused'
    assert any(r['code'] == 'ownership-input-not-physical' for r in result['refusals'])


def test_compiled_external_source_has_exact_physical_ownership(loaded):
    document = copy.deepcopy(loaded[3])
    document['environment_links'] = [dict(link_id='pins', component_instance='gpio',
                                          endpoint_id='gpio.pins', width=32)]
    request = load_path_compile_request(document, base_dir=ROOT)
    compiled = compile_paths(request)
    sources = [s for p in compiled['paths'] if p['status'] == 'executable'
               for s in p['sources'] if s['kind'] == 'external_pin']
    assert sources, 'positive case must actually admit a physical source'
    source = sources[0]
    ownership = compile_ownership((InputField('gpio', 'pins', 32),),
        (InputOwner('gpio', 'pins', 0, 32, 'source', source['source_id']),))
    result = admit(loaded, request=request, compiled=compiled, ownership=ownership,
                   physical_port_map={('gpio', 'pins'): 'gpio_in'})
    assert result['status'] == 'compatible', result['refusals']
    missing = admit(loaded, request=request, compiled=compiled)
    assert missing['status'] == 'refused'
    assert any(r['code'] == 'compiled-physical-source-unowned' for r in missing['refusals'])


def test_bound_input_is_explicitly_refused_until_producer_wiring_is_admitted(loaded):
    ownership = compile_ownership((InputField('gpio', 'pins', 32),),
        (InputOwner('gpio', 'pins', 0, 32, 'bound', 'peer.output'),))
    result = admit(loaded, ownership=ownership,
                   physical_port_map={('gpio', 'pins'): 'gpio_in'})
    assert result['status'] == 'refused'
    assert any(r['code'] == 'ownership-bound-producer-not-admitted' for r in result['refusals'])


def test_reserved_mask_bit_change_names_exact_constraint_pointer(loaded):
    compiled = copy.deepcopy(loaded[2])
    compiled['paths'][0]['constraints']['source_constraints'][0]['mask'] ^= 1
    result = admit(loaded, compiled=compiled)
    assert result['status'] == 'refused'
    assert result['refusals'][0]['pointer'] == '/paths/0/constraints/source_constraints/0/mask'


def test_incomplete_instance_map_cannot_borrow_another_harness(loaded):
    result = admit(loaded, artifacts={'cpu': loaded[0]['cpu']})
    assert result['status'] == 'refused'
    assert result['refusals'][0]['code'] == 'artifact-instance-set-mismatch'
