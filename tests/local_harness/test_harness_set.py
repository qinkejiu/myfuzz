"""P7-B: one composition-level entry point generates a whole harness set.

The plan's P7-B deliverable replaces "one request, one harness" with "a set of
trusted profiles -> several independent harnesses plus a declared wiring
contract".  Two properties matter more than the generation itself, and these
tests pin them:

* a component whose protocol shape matches no registered template is refused
  **by name**, and no harness is produced for the whole set - the "old
  component" negative the plan requires is about never falling back to a
  similarly named template;
* an accepted set only ever claims the ``generated`` tier.  Exchanging
  transactions is a separate claim, so the document must say what it does
  *not* claim.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from myfuzz.local_harness.harness_set import (GENERATED_TIER,
                                              HarnessSetRefused,
                                              generate_harness_set,
                                              load_compose)

ROOT = Path(__file__).resolve().parents[2]

CPU_PROFILE = 'configs/cpus/ibex_obi_local/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/pulp_gpio/component_profile.json'

CPU_REQUEST = {
    'schema_version': 'local_harness.v1', 'profile_path': CPU_PROFILE,
    'instance_id': 'cpu', 'reset_assert_ticks': 2, 'reset_release_ticks': 2,
    'max_wait_cycles': 16}
GPIO_REQUEST = {
    'schema_version': 'local_harness.v1', 'profile_path': GPIO_PROFILE,
    'instance_id': 'gpio', 'reset_assert_ticks': 2, 'reset_release_ticks': 2,
    'max_wait_cycles': 16}
DMA_REQUEST = {
    'schema_version': 'local_harness.v1',
    'profile_path': 'configs/peripherals/zipcpu_wbdmac/component_profile.json',
    'instance_id': 'mover', 'reset_assert_ticks': 8,
    'reset_release_ticks': 8, 'max_wait_cycles': 16}


def write(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
    return path


def compose_document(tmp_path: Path, *, cpu_endpoint='processor.data',
                     device_endpoint='gpio.bus', device_request=None,
                     cpu_request=None):
    """A compose document plus the requests it names, under one directory."""
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    write(tmp_path / 'requests/cpu.json', cpu_request or CPU_REQUEST)
    write(tmp_path / 'requests/gpio.json', device_request or GPIO_REQUEST)
    document = {
        'schema_version': 'harness_compose.v1',
        'cpu': {'instance_id': 'cpu', 'request': 'requests/cpu.json',
                'data_endpoint': cpu_endpoint},
        'devices': [{'device_id': 'gpio', 'instance_id': 'gpio',
                     'request': 'requests/gpio.json',
                     'bus_endpoint': device_endpoint,
                     'base': 0x40000000, 'size': 0x1000}],
    }
    return write(tmp_path / 'compose.json', document)


def dma_compose_document(tmp_path: Path, *, names=('cpu', 'sink', 'mover')):
    cpu_name, output_name, mover_name = names
    write(tmp_path / 'requests/cpu.json', {**CPU_REQUEST, 'instance_id': cpu_name})
    write(tmp_path / 'requests/gpio.json', {**GPIO_REQUEST,
                                           'instance_id': output_name})
    write(tmp_path / 'requests/dma.json', {**DMA_REQUEST,
                                          'instance_id': mover_name})
    route = {
        'route_id': 'copy.destination', 'initiator_instance': mover_name,
        'initiator_endpoint_id': 'dma.memory',
        'target': {'kind': 'peripheral', 'component_instance': output_name,
                   'device_id': 'output.window', 'endpoint_id': 'gpio.bus'},
        'base': 0x40000000, 'size': 0x1000, 'operation': 'write',
        'permissions': ['write'], 'byte_enable': 15,
        'readable_offsets': [], 'writable_offsets': [12],
        'accepted_write_values': {'kind': 'range', 'start': 0,
                                  'stop': 256, 'step': 1},
    }
    document = {
        'schema_version': 'harness_compose.v2',
        'cpu': {'instance_id': cpu_name, 'request': 'requests/cpu.json',
                'data_endpoint': 'processor.data'},
        'devices': [
            {'device_id': 'output.window', 'instance_id': output_name,
             'request': 'requests/gpio.json', 'bus_endpoint': 'gpio.bus',
             'base': 0x40000000, 'size': 0x1000},
            {'device_id': 'mover.control', 'instance_id': mover_name,
             'request': 'requests/dma.json', 'bus_endpoint': 'dma.control',
             'base': 0x40001000, 'size': 16,
             'template': {'template_id': 'target.wishbone-pipelined',
                          'template_version': '1',
                          'variant_id': 'dma-full-word-no-select'}},
        ],
        'dma_master_routes': {'schema_version': 'dma_master_route_intent.v1',
                              'routes': [route]},
        'dma_master_route_bindings': [{
            'route_id': 'copy.destination',
            'initiator_template': {
                'template_id': 'master.wishbone-pipelined',
                'template_version': '1',
                'variant_id': 'dma-full-word-no-select',
            },
            'target_template': {
                'template_id': 'target.apb3',
                'template_version': '1',
                'variant_id': 'full-word',
            },
        }],
    }
    return write(tmp_path / 'compose.json', document)


def test_v1_output_bytes_remain_the_existing_serialization(tmp_path):
    compose = load_compose(compose_document(tmp_path), base_dir=ROOT)
    output = tmp_path / 'out'
    generated = generate_harness_set(compose, base_dir=ROOT,
                                     compose_base=tmp_path, output_root=output)
    expected = (json.dumps(generated, sort_keys=True, indent=2,
                           ensure_ascii=False, allow_nan=False) + '\n').encode()
    assert (output / 'harness_set.json').read_bytes() == expected
    assert (output / 'wiring_contract.json').read_bytes() == (
        json.dumps(generated['wiring'], sort_keys=True, indent=2,
                   ensure_ascii=False, allow_nan=False) + '\n').encode()
    assert 'dma_master_routes' not in generated['wiring']
    assert hashlib.sha256((output / 'wiring_contract.json').read_bytes()).hexdigest() == (
        '37c1c3861d84a3cd688afc9c84e6e3d0a06a8826f66c46de9d1922c27238d51e')


def test_v2_route_survives_generation_with_static_endpoint_fingerprints(tmp_path):
    source = dma_compose_document(tmp_path)
    compose = load_compose(source, base_dir=ROOT)
    output = tmp_path / 'out'
    generated = generate_harness_set(compose, base_dir=ROOT,
                                     compose_base=tmp_path, output_root=output)
    wiring = generated['wiring']
    assert generated['schema_version'] == 'harness_set.v2'
    assert wiring['schema_version'] == 'wiring_contract.v2'
    assert wiring['dma_master_routes']['schema_version'] == 'dma_master_route_intent.v1'
    assert len(wiring['dma_master_routes_sha256']) == 64
    route, = wiring['dma_master_routes']['routes']
    assert route['initiator_instance'] == 'mover'
    assert route['target']['component_instance'] == 'sink'
    assert 'endpoint_identity_sha256' not in route
    assert 'target_identity_sha256' not in route
    binding, = wiring['dma_master_route_bindings']
    assert binding['route_id'] == route['route_id']
    assert len(binding['initiator']['profile_endpoint_sha256']) == 64
    assert len(binding['target']['profile_endpoint_sha256']) == 64
    assert binding['initiator']['template_id'] == 'master.wishbone-pipelined'
    assert json.loads((output / 'wiring_contract.json').read_text()) == wiring


@pytest.mark.parametrize('names', [
    ('cpu_renamed', 'sink_renamed', 'engine_renamed'),
    ('processor', 'device_2', 'device_1'),
])
def test_v2_route_uses_declared_endpoint_ids_with_renamed_instances(tmp_path, names):
    compose = load_compose(dma_compose_document(tmp_path, names=names),
                           base_dir=ROOT)
    generated = generate_harness_set(compose, base_dir=ROOT,
                                     compose_base=tmp_path,
                                     output_root=tmp_path / 'out')
    route, = generated['wiring']['dma_master_routes']['routes']
    assert route['initiator_instance'] == names[2]
    assert route['target']['component_instance'] == names[1]


@pytest.mark.parametrize('change, code', [
    (lambda r: r.update(initiator_endpoint_id='dma.control'), 'dma-route-initiator-not-master'),
    (lambda r: r.update(initiator_instance='unknown'), 'dma-route-initiator-undeclared'),
    (lambda r: r['target'].update(endpoint_id='gpio.pins'), 'dma-route-target-not-slave'),
    (lambda r: r['target'].update(device_id='wrong'), 'dma-route-target-window-undeclared'),
    (lambda r: r.update(base=0x40002000), 'dma-route-aperture-outside-target'),
])
def test_v2_route_refusal_precedes_output_creation(tmp_path, change, code):
    source = dma_compose_document(tmp_path)
    document = json.loads(source.read_text())
    change(document['dma_master_routes']['routes'][0])
    compose = load_compose(write(source, document), base_dir=ROOT)
    output = tmp_path / 'out'
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT,
                             compose_base=tmp_path, output_root=output)
    assert raised.value.code == code
    assert not output.exists()
    assert not list(tmp_path.glob('.out.*'))


def test_v2_requires_nonempty_routes_and_v1_refuses_routes(tmp_path):
    source = dma_compose_document(tmp_path)
    document = json.loads(source.read_text())
    document['dma_master_routes']['routes'] = []
    with pytest.raises(HarnessSetRefused):
        load_compose(write(source, document), base_dir=ROOT)
    document['schema_version'] = 'harness_compose.v1'
    with pytest.raises(HarnessSetRefused) as raised:
        load_compose(write(source, document), base_dir=ROOT)
    assert raised.value.code == 'compose-field-unknown'


@pytest.mark.parametrize('change', [
    lambda d: d['dma_master_route_bindings'].clear(),
    lambda d: d['dma_master_route_bindings'][0]['initiator_template'].pop('variant_id'),
    lambda d: d['dma_master_route_bindings'][0].update(unexpected=True),
])
def test_v2_requires_closed_one_to_one_route_bindings(tmp_path, change):
    source = dma_compose_document(tmp_path)
    document = json.loads(source.read_text())
    change(document)
    with pytest.raises(HarnessSetRefused):
        load_compose(write(source, document), base_dir=ROOT)
    assert not (tmp_path / 'out').exists()


def test_v2_route_offset_must_match_declared_target_register(tmp_path):
    source = dma_compose_document(tmp_path)
    document = json.loads(source.read_text())
    document['dma_master_routes']['routes'][0]['writable_offsets'] = [0x100]
    compose = load_compose(write(source, document), base_dir=ROOT)
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path,
                             output_root=tmp_path / 'out')
    assert raised.value.code == 'dma-route-target-register-undeclared'
    assert not (tmp_path / 'out').exists()


def test_v2_route_template_mismatch_refuses_before_output(tmp_path):
    source = dma_compose_document(tmp_path)
    document = json.loads(source.read_text())
    document['dma_master_route_bindings'][0]['initiator_template']['variant_id'] = 'wrong'
    compose = load_compose(write(source, document), base_dir=ROOT)
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path,
                             output_root=tmp_path / 'out')
    assert raised.value.code == 'dma-route-template-not-admitted'
    assert not (tmp_path / 'out').exists()


def test_v2_memory_route_uses_resource_and_owner_fingerprints(tmp_path):
    source = dma_compose_document(tmp_path)
    document = json.loads(source.read_text())
    document['memory'] = [{
        'resource_id': 'ram', 'component_instance': 'cpu',
        'base': 0x80000000, 'size': 0x1000,
        'read': True, 'write': True, 'execute': False,
    }]
    route = document['dma_master_routes']['routes'][0]
    route.update(target={'kind': 'persistent_memory',
                         'component_instance': 'cpu', 'resource_id': 'ram'},
                 base=0x80000000, writable_offsets=[],
                 accepted_write_values={'kind': 'values', 'values': []})
    del document['dma_master_route_bindings'][0]['target_template']
    compose = load_compose(write(source, document), base_dir=ROOT)
    generated = generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path,
                                     output_root=tmp_path / 'out')
    binding, = generated['wiring']['dma_master_route_bindings']
    assert binding['target']['kind'] == 'persistent_memory'
    assert binding['target']['owner_profile_fingerprint'].startswith('sha256:')
    assert len(binding['target']['resource_sha256']) == 64
    assert 'profile_endpoint_sha256' not in binding['target']


def test_v2_memory_route_refuses_permission_not_declared_by_resource(tmp_path):
    source = dma_compose_document(tmp_path)
    document = json.loads(source.read_text())
    document['memory'] = [{
        'resource_id': 'ram', 'component_instance': 'cpu',
        'base': 0x80000000, 'size': 0x1000,
        'read': True, 'write': False, 'execute': False,
    }]
    route = document['dma_master_routes']['routes'][0]
    route.update(target={'kind': 'persistent_memory',
                         'component_instance': 'cpu', 'resource_id': 'ram'},
                 base=0x80000000, writable_offsets=[],
                 accepted_write_values={'kind': 'values', 'values': []})
    del document['dma_master_route_bindings'][0]['target_template']
    compose = load_compose(write(source, document), base_dir=ROOT)
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path,
                             output_root=tmp_path / 'out')
    assert raised.value.code == 'dma-route-target-permission-unsupported'
    assert not (tmp_path / 'out').exists()


def test_the_declared_roles_must_be_named_not_inferred(tmp_path):
    """A compose document is a closed declaration; guessing roles is refused."""
    document = json.loads(compose_document(tmp_path).read_text(encoding='utf-8'))
    document['cpu'].pop('data_endpoint')
    broken = write(tmp_path / 'broken.json', document)
    with pytest.raises(HarnessSetRefused) as raised:
        load_compose(broken, base_dir=ROOT)
    assert raised.value.code == 'compose-field-missing'
    assert raised.value.pointer == '/cpu'


def test_a_set_is_generated_with_both_harnesses_and_a_wiring_contract(tmp_path):
    compose = load_compose(compose_document(tmp_path), base_dir=ROOT)
    output = tmp_path / 'out'
    document = generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path, output_root=output)

    assert document['schema_version'] == 'harness_set.v1'
    assert document['tier'] == GENERATED_TIER
    # A generated set must not read as an accepted one.
    assert 'cross_component_accepted' in document['not_claimed']
    roles = {row['instance_id']: row['role'] for row in document['components']}
    assert roles == {'cpu': 'cpu', 'gpio': 'device'}
    for row in document['components']:
        directory = output / row['harness']
        assert (directory / 'runtime.sv').is_file()
        assert (directory / 'artifact.json').is_file()
        assert row['artifact_digest']
        assert row['kind']

    wiring = json.loads((output / 'wiring_contract.json').read_text(encoding='utf-8'))
    assert wiring['schema_version'] == 'wiring_contract.v1'
    assert wiring['delivery'] == 'transaction_level_explicit'
    # The contract must not imply an interconnect that was never generated.
    assert wiring['global_interconnect'] is False
    assert wiring['cycle_accurate'] is False
    assert wiring['cpu']['endpoint_id'] == 'processor.data'
    window, = wiring['windows']
    assert window['target_instance'] == 'gpio'
    assert (window['base'], window['size']) == (0x40000000, 0x1000)
    assert window['endpoint_id'] == 'gpio.bus'


def test_every_admitted_endpoint_names_its_registered_template(tmp_path):
    compose = load_compose(compose_document(tmp_path), base_dir=ROOT)
    document = generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path,
                                    output_root=tmp_path / 'out')
    templates = {row['instance_id']: row['template']
                 for row in document['components']}
    assert templates['cpu']['template_id'].startswith('cpu.')
    assert templates['cpu']['protocol'] == ['obi', '1']
    assert templates['gpio']['template_id'].startswith('target.')
    assert templates['gpio']['protocol'] == ['apb', '3']
    for row in templates.values():
        assert row['identity_sha256']


def test_an_unadmitted_protocol_shape_refuses_the_whole_set(tmp_path):
    """No harness may be produced when any declared shape is unadmitted."""
    document = json.loads(compose_document(tmp_path).read_text(encoding='utf-8'))
    # Declare the device's interrupt endpoint as its bus endpoint: an
    # interrupt source is not a bus, so no target template can match it.
    document['devices'][0]['bus_endpoint'] = 'gpio.pins'
    compose = load_compose(write(tmp_path / 'compose.json', document),
                           base_dir=ROOT)
    output = tmp_path / 'out'
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path, output_root=output)
    assert raised.value.code == 'protocol-shape-not-admitted'
    assert not output.exists(), 'a refused set must not leave a partial output'


def test_an_undeclared_endpoint_is_refused_by_name(tmp_path):
    document = json.loads(compose_document(tmp_path).read_text(encoding='utf-8'))
    document['cpu']['data_endpoint'] = 'processor.not_a_real_endpoint'
    compose = load_compose(write(tmp_path / 'compose.json', document),
                           base_dir=ROOT)
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path,
                             output_root=tmp_path / 'out')
    assert raised.value.code == 'component-endpoint-undeclared'
    assert raised.value.detail['endpoint_id'] == 'processor.not_a_real_endpoint'


def test_an_instance_id_that_disagrees_with_its_request_is_refused(tmp_path):
    """The declaration names the instance; the request must agree with it."""
    document = json.loads(compose_document(tmp_path).read_text(encoding='utf-8'))
    document['devices'][0]['instance_id'] = 'not_gpio'
    compose = load_compose(write(tmp_path / 'compose.json', document),
                           base_dir=ROOT)
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path,
                             output_root=tmp_path / 'out')
    assert raised.value.code == 'component-instance-id-mismatch'


def test_a_missing_request_file_is_refused_before_any_generation(tmp_path):
    document = json.loads(compose_document(tmp_path).read_text(encoding='utf-8'))
    document['devices'][0]['request'] = 'requests/absent.json'
    compose = load_compose(write(tmp_path / 'compose.json', document),
                           base_dir=ROOT)
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path,
                             output_root=tmp_path / 'out')
    assert raised.value.code == 'component-request-missing'


def test_a_component_render_refusal_is_named(tmp_path, monkeypatch):
    """A plan/render/verify failure is a named refusal, not a bare traceback.

    ``generate_component`` used to call ``plan_local_harness``/``render_*``
    directly, so a renderer's ``ValueError`` escaped unwrapped.  A caller above it
    could then only report ``auto-harness-failed`` (or, before the fail-closed
    driver fix, a ``complete`` run next to the traceback).  The refused instance
    must be named, and the whole set must stay ungenerated.
    """
    from myfuzz.local_harness import harness_set

    def refuse_render(*args, **kwargs):
        raise ValueError('synthetic-render-defect')

    monkeypatch.setattr(harness_set, 'render_local_runtime', refuse_render)
    compose = load_compose(compose_document(tmp_path), base_dir=ROOT)
    output = tmp_path / 'out'
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path,
                             output_root=output)
    assert raised.value.code == 'component-render-refused'
    assert raised.value.pointer == '/cpu/request'
    assert raised.value.detail['instance_id'] == 'cpu'
    assert 'synthetic-render-defect' in raised.value.detail['error']
    assert not output.exists(), 'a refused render must not leave a partial set'


def test_an_existing_output_is_never_overwritten(tmp_path):
    compose = load_compose(compose_document(tmp_path), base_dir=ROOT)
    output = tmp_path / 'out'
    output.mkdir()
    (output / 'keep').write_text('do not overwrite', encoding='utf-8')
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path, output_root=output)
    assert raised.value.code == 'harness-set-output-exists'
    assert (output / 'keep').read_text(encoding='utf-8') == 'do not overwrite'


def test_a_refused_declaration_review_blocks_generation(tmp_path):
    """P7-A's verdict is an input to generation, not a separate report."""
    compose = load_compose(compose_document(tmp_path), base_dir=ROOT)
    review = {'schema_version': 'declaration_review.v1', 'generated': False,
              'status': 'refused', 'refused': ['gpio'],
              'admitted': [], 'components': [
                  {'component_id': 'gpio', 'status': 'missing', 'rows': []}]}
    with pytest.raises(HarnessSetRefused) as raised:
        generate_harness_set(compose, base_dir=ROOT, compose_base=tmp_path,
                             output_root=tmp_path / 'out', review=review)
    assert raised.value.code == 'declaration-review-refused'


def test_the_cli_exit_code_is_the_verdict(tmp_path):
    """A refused set must be visible to a caller that only reads the exit code."""
    import subprocess
    import sys

    compose = compose_document(tmp_path, device_endpoint='gpio.pins')
    script = ROOT / 'scripts/generate_local_harness_set.py'
    refused = subprocess.run(
        [sys.executable, str(script), '--compose', str(compose),
         '--output', str(tmp_path / 'out'), '--skip-review', '--base-dir', str(ROOT)],
        capture_output=True, text=True, cwd=ROOT)
    assert refused.returncode != 0, refused.stdout
    assert '"status": "refused"' in refused.stdout
    assert not (tmp_path / 'out').exists()

    good = compose_document(tmp_path / 'good')
    accepted = subprocess.run(
        [sys.executable, str(script), '--compose', str(good),
         '--output', str(tmp_path / 'good-out'), '--skip-review',
         '--base-dir', str(ROOT)],
        capture_output=True, text=True, cwd=ROOT)
    assert accepted.returncode == 0, accepted.stdout
    assert '"status": "generated"' in accepted.stdout


def test_the_cli_reviews_profiles_against_the_repository_not_the_compose_dir(tmp_path):
    """The review resolves profiles from the repository, requests from the compose dir.

    Conflating the two made every profile look unreadable, and the earlier CLI
    tests all passed `--skip-review`, so nothing caught it.
    """
    import subprocess
    import sys

    compose = compose_document(tmp_path)
    script = ROOT / 'scripts/generate_local_harness_set.py'
    output = tmp_path / 'reviewed'
    result = subprocess.run(
        [sys.executable, str(script), '--compose', str(compose),
         '--output', str(output), '--base-dir', str(ROOT)],
        capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0, result.stdout + result.stderr
    review = json.loads((output / 'declaration_review.json').read_text(encoding='utf-8'))
    assert review['status'] == 'ok', review['refused']
    assert set(review['admitted']) == {'ibex_obi_local', 'pulp_gpio'}
    # Every reviewed component must be a real component id, not a file name: a
    # profile resolved from the wrong directory reported 'component_profile'.
    assert all(row['component_id'] != 'component_profile'
               for row in review['components'])
    document = json.loads((output / 'harness_set.json').read_text(encoding='utf-8'))
    assert document['tier'] == 'generated'
