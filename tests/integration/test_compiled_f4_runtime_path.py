"""Pure same-call D3 admission, never native execution."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from unittest.mock import patch

import pytest

from tests.integration.test_compiled_f4_storage_producer import timer_loaded, f4_path


@pytest.fixture(scope='module')
def generated(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp('runtime-path-admission'))[1]


def admit(inputs, **changes):
    from myfuzz.integration.compiled_f4_runtime_path import admit_compiled_f4_runtime_path
    return admit_compiled_f4_runtime_path(request=changes.get('request', inputs['request']),
        compiled=changes.get('compiled', inputs['compiled']), path=changes.get('path'))


def test_real_d3_selected_path_preserves_graph_and_detaches_document(generated):
    with patch('subprocess.Popen', side_effect=AssertionError('native forbidden')):
        binding = admit(generated)
    row = f4_path(generated['compiled'])
    doc = binding.document()
    assert binding.logical_path_id == row['path_id']
    assert binding.runtime_path_id == row['runtime_path_identity']['path_id']
    assert binding.logical_path_id != binding.runtime_path_id
    assert binding.prepared.document()['graph'] == generated['compiled']['runtime_dependency_graph']
    assert binding.prepared.path_ids == (binding.runtime_path_id,)
    assert binding.instruction_binding.source_id == row['runtime_path_identity']['source_ids'][0]
    image = next(s for s in row['sources'] if s['kind'] == 'instruction_image')
    assert binding.instruction_binding.logical_source_id == image['source_id']
    assert binding.instruction_binding.base == image['range'][0]
    assert binding.instruction_binding.size == image['range'][1] - image['range'][0] + 1
    assert doc['candidate_layout']['digest']
    assert doc['compiled_document_sha256'] and doc['selected_path_sha256']
    from myfuzz.scenario.compiled_paths import compiled_document_sha256
    assert doc['compiled_document_sha256'] == compiled_document_sha256(generated['compiled'])
    assert doc['binding_sha256'] == binding.digest
    doc['path_mapping']['runtime_path_id'] = 'tampered'
    assert binding.document()['path_mapping']['runtime_path_id'] == binding.runtime_path_id
    binding.validate_cached_identity()
    with pytest.raises(FrozenInstanceError):
        binding.logical_path_id = 'tampered'


@pytest.mark.parametrize('mutation', ('graph', 'contract', 'path', 'source', 'range', 'layout', 'edge_order', 'duplicate', 'external_pin'))
def test_changed_d3_is_refused_before_native(generated, mutation):
    compiled = deepcopy(generated['compiled'])
    row = f4_path(compiled)
    if mutation == 'graph':
        compiled['runtime_dependency_graph']['sources'][0]['component'] = 'other'
    elif mutation == 'contract':
        compiled['runtime_path_contract']['graph_sha256'] = '0' * 64
    elif mutation == 'path':
        row['runtime_path_identity']['path_id'] = '0' * 64
    elif mutation == 'source':
        row['runtime_path_identity']['source_ids'] = ['wrong-source']
    elif mutation == 'range':
        next(s for s in row['sources'] if s['kind'] == 'instruction_image')['range'][1] += 4
    elif mutation == 'layout':
        row['constraints']['layout_hash'] = '0' * 64
    elif mutation == 'edge_order':
        row['runtime_path_identity']['edges'].reverse()
    elif mutation == 'duplicate':
        compiled['paths'].append(deepcopy(row))
    else:
        row['sources'].append({'kind': 'external_pin', 'source_id': 'pin'})
    with patch('subprocess.Popen', side_effect=AssertionError('native forbidden')):
        with pytest.raises(ValueError, match='compiled-F4-runtime-path'):
            admit(generated, compiled=compiled)


def test_selected_row_argument_must_match_exact_admitted_row(generated):
    row = deepcopy(f4_path(generated['compiled']))
    row['target']['node'] = 'wrong'
    with pytest.raises(ValueError, match='compiled-F4-runtime-path'):
        admit(generated, path=row)


def test_changed_typed_resource_requires_recompilation(generated):
    request = generated['request']
    resources = tuple(replace(resource, base=resource.base + 4)
                      if resource.base is not None else resource
                      for resource in request.wiring.resources)
    request = replace(request, wiring=replace(request.wiring, resources=resources))
    with pytest.raises(ValueError):
        admit(generated, request=request)


def test_prepared_cache_tampering_is_detected(generated):
    binding = admit(generated)
    binding.prepared.graph.sources.clear()
    with pytest.raises(ValueError):
        binding.validate_cached_identity()


@pytest.mark.parametrize('field,value', (('write', False), ('execute', False), ('initialization_policy', 'zero')))
def test_recompiled_resource_must_still_admit_exact_image_permissions(generated, field, value):
    from myfuzz.scenario.compiled_paths import compile_paths
    request = generated['request']
    resources = tuple(replace(resource, **{field: value}) for resource in request.wiring.resources)
    request = replace(request, wiring=replace(request.wiring, resources=resources))
    try:
        compiled = compile_paths(request)
    except ValueError:
        return  # The typed compiler may refuse an invalid policy before D3 exists.
    with patch('subprocess.Popen', side_effect=AssertionError('native forbidden')):
        with pytest.raises(ValueError, match='compiled-F4-runtime-path'):
            admit(generated, request=request, compiled=compiled)


def test_binding_cache_replacement_is_refused(generated):
    binding = admit(generated)
    modified = replace(binding, instruction_binding=replace(binding.instruction_binding, base=0))
    with pytest.raises(ValueError, match='source-cache-drift'):
        modified.validate_cached_identity()


def test_genuine_compiler_external_pin_is_unmapped_and_refused(tmp_path):
    from tests.integration.test_compiled_f4 import loaded
    # This document is produced by the real compiler, so rejection must happen
    # after same-call document equality rather than via edited-D3 detection.
    inputs = loaded(tmp_path)[1]
    assert any(source['kind'] == 'external_pin'
               for source in f4_path(inputs['compiled'])['sources'])
    with patch('subprocess.Popen', side_effect=AssertionError('native forbidden')):
        with pytest.raises(ValueError, match='compiled-F4-runtime-path-unmapped-source'):
            admit(inputs)
