"""Generation-only DMA endpoint evidence; no Runner or native execution."""
import copy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.renderer import _sha
from myfuzz.local_harness.wishbone_dma_fields import DMA_MASTER_SHAPE
from myfuzz.local_harness.dma_artifact_endpoint_links import (
    render_dma_linked_runtime, parse_dma_artifact_endpoint_links,
    validate_dma_artifact_endpoint_links)

ROOT = Path(__file__).resolve().parents[2]
PROVIDER = 'wishbone-dma-single-master.v1'


@pytest.fixture(scope='module')
def generated():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/peripherals/zipcpu_wbdmac/component_profile.json',
        instance_id='dma', reset_assert_ticks=8, reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    structural = render_local_harness(plan)
    verification = verify_local_source_lock(plan.profile, base_dir=ROOT)
    top = render_local_runtime(plan, structural, verification, base_dir=ROOT)
    legacy = render_local_driver(top, base_dir=ROOT)
    before = copy.deepcopy(legacy.runtime_document)
    linked = render_dma_linked_runtime(plan, structural, verification,
                                     base_dir=ROOT, provider_id=PROVIDER)
    return plan, structural, verification, top, legacy, before, linked


def rehash(document):
    document['identity_sha256'] = _sha({k: v for k, v in document.items() if k != 'identity_sha256'})
    return document


def test_legacy_artifact_bytes_unchanged_without_link_opt_in(generated):
    *_, legacy, before, linked = generated
    assert linked.artifact.runtime_document == before == legacy.runtime_document
    assert linked.artifact.runtime_sv == legacy.runtime_sv
    assert linked.artifact.cpp_text == legacy.cpp_text
    assert 'endpoint_links' not in legacy.runtime_document
    wrapper = linked.document()
    assert set(wrapper) == {'schema_version', 'runtime_artifact', 'endpoint_links', 'identity_sha256'}
    assert wrapper['schema_version'] == 'dma_linked_runtime_artifact.v1'
    assert wrapper['runtime_artifact'] == before
    assert wrapper['identity_sha256'] == _sha({k:v for k,v in wrapper.items() if k != 'identity_sha256'})


def test_final_driver_artifact_has_complete_master_role_link(generated):
    plan, structural, _, _, _, _, linked = generated
    document = linked.endpoint_links_document()
    assert document['runtime_artifact_sha256'] == _sha(linked.artifact.runtime_document)
    link, = document['links']
    master, = [e for e in plan.binding.endpoints if e.function == 'memory_master']
    assert link['endpoint_id'] == master.endpoint_id == 'dma.memory'
    assert link['function'] == 'memory_master'
    assert link['protocol_side'] == 'master'
    assert link['backend_channel'] == 'mwb'
    assert [r['role'] for r in link['roles']] == sorted(DMA_MASTER_SHAPE)
    for row in link['roles']:
        field, = [f for f in master.fields if f.role == row['role']]
        assert row == dict(role=field.role, direction=field.direction, width=field.width,
            physical_port=field.port, member_path=list(field.member_path), raw_lo=field.raw_lo,
            raw_hi=field.raw_hi, port_width=field.port_width, backend_port='mwb_' + field.role)
    assert len(link['template_binding']) == 6
    parsed = parse_dma_artifact_endpoint_links(document)
    assert parsed.document() == document
    assert parsed.identity_sha256 == document['identity_sha256']
    parsed.document()['links'].clear()
    assert parsed.document() == document
    with pytest.raises((FrozenInstanceError, AttributeError)):
        parsed.identity_sha256 = 'x'
    validate_dma_artifact_endpoint_links(document, linked.artifact)


@pytest.mark.parametrize('mutation', ['provider', 'role', 'template', 'backend', 'unknown', 'bool_width', 'range', 'order'])
def test_unknown_provider_missing_role_or_wrong_template_refuses(generated, mutation):
    document = generated[-1].endpoint_links_document()
    link = document['links'][0]
    if mutation == 'provider': document['provider_id'] = 'unknown.v1'
    elif mutation == 'role': link['roles'].pop()
    elif mutation == 'template': link['template_binding']['template_id'] = 'target.wishbone-pipelined'
    elif mutation == 'backend': link['roles'][0]['backend_port'] = 'swb_ack'
    elif mutation == 'unknown': link['roles'][0]['extra'] = True
    elif mutation == 'bool_width': link['roles'][0]['width'] = True
    elif mutation == 'range': link['roles'][0]['raw_hi'] = 900
    elif mutation == 'order': link['roles'].reverse()
    with pytest.raises(ValueError) as error:
        parse_dma_artifact_endpoint_links(rehash(document))
    assert error.value.code.startswith('dma-binding-')
    assert error.value.pointer.startswith('/endpoint_links')


def test_unknown_issuer_refuses_before_generation(generated):
    plan, structural, verification, *_ = generated
    with pytest.raises(ValueError):
        render_dma_linked_runtime(plan, structural, verification, base_dir=ROOT, provider_id='unknown.v1')


def test_runtime_stage_digest_cannot_replace_final_driver_digest(generated):
    _, _, _, top, _, _, linked = generated
    document = linked.endpoint_links_document()
    assert _sha(top.runtime_document) != document['runtime_artifact_sha256']
    document['runtime_artifact_sha256'] = _sha(top.runtime_document)
    with pytest.raises(ValueError):
        validate_dma_artifact_endpoint_links(rehash(document), linked.artifact)
    for attribute in ('runtime_sv', 'cpp_text'):
        with pytest.raises(ValueError):
            validate_dma_artifact_endpoint_links(linked.endpoint_links_document(),
                replace(linked.artifact, **{attribute: getattr(linked.artifact, attribute) + '\n'}))


@pytest.mark.parametrize('mutation', ['selection', 'profile', 'physical', 'member', 'artifact_hash', 'cpp_hash', 'identity'])
def test_rehashed_link_facts_must_match_actual_artifact(generated, mutation):
    linked = generated[-1]
    document = linked.endpoint_links_document()
    link = document['links'][0]
    if mutation == 'selection': link['template_binding']['selection_sha256'] = '0' * 64
    elif mutation == 'profile': link['template_binding']['profile_endpoint_sha256'] = '0' * 64
    elif mutation == 'physical': link['roles'][0]['physical_port'] = 'another_port'
    elif mutation == 'member': link['roles'][0]['member_path'] = ['another_member']
    elif mutation == 'artifact_hash': document['runtime_artifact_sha256'] = '0' * 64
    elif mutation == 'cpp_hash': document['cpp_sha256'] = '0' * 64
    elif mutation == 'identity': document['identity_sha256'] = '0' * 64
    if mutation != 'identity': rehash(document)
    with pytest.raises(ValueError):
        validate_dma_artifact_endpoint_links(document, linked.artifact)


def test_old_artifact_ids_cannot_substitute_for_generation_facts(generated, monkeypatch):
    from myfuzz.local_harness import runtime_renderer
    plan, structural, verification, top, *_ = generated
    def old_render(*args, **kwargs):
        return top  # deliberately does not collect assignment facts
    monkeypatch.setattr(runtime_renderer, 'render_local_runtime', old_render)
    with pytest.raises(ValueError, match='generation assignment facts required'):
        render_dma_linked_runtime(plan, structural, verification, base_dir=ROOT, provider_id=PROVIDER)


@pytest.mark.parametrize('mutation', ['template', 'role', 'abi', 'backend', 'second_master'])
def test_final_artifact_shape_mutations_refuse(generated, mutation):
    linked = generated[-1]
    artifact = copy.deepcopy(linked.artifact)
    document = artifact.runtime_document
    if mutation == 'template':
        document['selected_template']['executor']['protocol_templates'][1]['contract']['template_id'] = 'unknown'
    elif mutation == 'role':
        master, = [e for e in artifact.plan.binding.endpoints if e.function == 'memory_master']
        binding = replace(artifact.plan.binding, endpoints=tuple(
            replace(e, fields=e.fields[:-1]) if e is master else e for e in artifact.plan.binding.endpoints))
        artifact = replace(artifact, plan=replace(artifact.plan, binding=binding))
        document['plan'] = artifact.plan.document()
    elif mutation == 'abi': document['structural_abi']['ports'][0]['width'] += 1
    elif mutation == 'backend':
        row, = [r for r in document['backend_ports'] if r['name'] == 'mwb_ack']
        row['name'] = 'different_ack'
    elif mutation == 'second_master':
        master, = [e for e in artifact.plan.binding.endpoints if e.function == 'memory_master']
        binding = replace(artifact.plan.binding, endpoints=(*artifact.plan.binding.endpoints,
            replace(master, endpoint_id='second.master')))
        artifact = replace(artifact, plan=replace(artifact.plan, binding=binding))
        document['plan'] = artifact.plan.document()
    document['artifact_digest'] = _sha({k:v for k,v in document.items() if k != 'artifact_digest'})
    with pytest.raises(ValueError):
        validate_dma_artifact_endpoint_links(linked.endpoint_links_document(), artifact)


def test_malformed_artifact_refuses_with_caller_pointer(generated):
    linked = generated[-1]
    artifact = copy.deepcopy(linked.artifact)
    artifact.runtime_document['selected_template'] = []
    artifact.runtime_document['artifact_digest'] = _sha({
        k:v for k,v in artifact.runtime_document.items() if k != 'artifact_digest'})
    with pytest.raises(ValueError) as error:
        validate_dma_artifact_endpoint_links(linked.endpoint_links_document(), artifact,
                                             pointer='/saved/dma/endpoint_links')
    assert error.value.pointer.startswith('/saved/dma/endpoint_links')
