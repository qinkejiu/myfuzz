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
