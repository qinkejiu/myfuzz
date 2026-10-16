"""Persisted P7 artifacts are checked against trusted reconstruction, never loaded as code."""
import json
from types import SimpleNamespace

import pytest

from myfuzz.local_harness import generated_artifact_admission as admission


def _write(path, value):
    path.write_bytes(admission._json_bytes(value))


@pytest.fixture
def generated(tmp_path, monkeypatch):
    root = tmp_path / 'generated'
    root.mkdir()
    component = root / 'core'
    component.mkdir()
    request = dict(schema_version='local_harness.v1', profile_path='configs/cpus/example/component_profile.json',
                   instance_id='core', reset_assert_ticks=3, reset_release_ticks=5, max_wait_cycles=12)
    artifact = SimpleNamespace(plan=SimpleNamespace(request=SimpleNamespace(instance_id='core')),
        structural=SimpleNamespace(wrapper_sv='wrapper', abi_document={'ports': []}),
        runtime_sv='runtime', cpp_text='driver', source_verification={'verified': True},
        runtime_document={'kind': 'obi_cpu', 'artifact_digest': 'trusted-digest'})
    _write(component / 'request.json', request)
    for name, data in admission._artifact_files(artifact).items():
        (component / name).write_bytes(data)
    document = dict(schema_version='harness_set.v1', components=[dict(instance_id='core',
        harness='core', kind='obi_cpu', artifact_digest='trusted-digest')])
    _write(root / 'harness_set.json', document)
    calls = []
    def reconstruct(document, *, base_dir):
        calls.append((document, base_dir))
        return artifact
    monkeypatch.setattr(admission, '_reconstruct', reconstruct)
    return root, artifact, calls, document


def test_same_protocol_artifact_is_returned_with_exact_nondefault_request(generated, tmp_path):
    root, artifact, calls, _ = generated
    result = admission.load_generated_artifacts(generated_root=root, base_dir=tmp_path)
    assert result == {'core': artifact}
    assert result['core'] is artifact
    assert calls[0][0]['reset_assert_ticks'] == 3
    assert calls[0][0]['reset_release_ticks'] == 5


@pytest.mark.parametrize('name', ['wrapper.sv', 'runtime.sv', 'driver.cpp', 'abi.json',
                                 'artifact.json', 'source_verification.json'])
def test_any_changed_generated_bytes_are_refused(generated, tmp_path, name):
    root, _, _, _ = generated
    (root / 'core' / name).write_bytes(b'changed')
    with pytest.raises(admission.GeneratedArtifactRefused, match='generated-artifact-bytes-mismatch'):
        admission.load_generated_artifacts(generated_root=root, base_dir=tmp_path)


def test_similar_name_never_substitutes_a_different_protocol_artifact(generated, tmp_path):
    root, _, _, document = generated
    document['components'][0]['kind'] = 'wishbone_cpu'
    _write(root / 'harness_set.json', document)
    with pytest.raises(admission.GeneratedArtifactRefused, match='generated-artifact-kind-mismatch'):
        admission.load_generated_artifacts(generated_root=root, base_dir=tmp_path)


@pytest.mark.parametrize('harness', ['../outside', '/tmp/outside', 'core/../core'])
def test_harness_path_cannot_escape_or_alias(generated, tmp_path, harness):
    root, _, _, document = generated
    document['components'][0]['harness'] = harness
    _write(root / 'harness_set.json', document)
    with pytest.raises(admission.GeneratedArtifactRefused, match='generated-artifact-directory-invalid'):
        admission.load_generated_artifacts(generated_root=root, base_dir=tmp_path)


def test_symlink_and_missing_request_do_not_fall_back_to_original_compose(generated, tmp_path):
    root, _, _, _ = generated
    request = root / 'core' / 'request.json'
    original = tmp_path / 'request-original.json'
    request.rename(original)
    with pytest.raises(admission.GeneratedArtifactRefused, match='generated-artifact-file-invalid'):
        admission.load_generated_artifacts(generated_root=root, base_dir=tmp_path)
    request.symlink_to(original)
    with pytest.raises(admission.GeneratedArtifactRefused, match='generated-artifact-file-invalid'):
        admission.load_generated_artifacts(generated_root=root, base_dir=tmp_path)


def test_request_instance_and_duplicate_rows_are_refused(generated, tmp_path):
    root, _, _, document = generated
    request = json.loads((root / 'core' / 'request.json').read_text())
    request['instance_id'] = 'other'
    _write(root / 'core' / 'request.json', request)
    with pytest.raises(admission.GeneratedArtifactRefused, match='generated-artifact-instance-mismatch'):
        admission.load_generated_artifacts(generated_root=root, base_dir=tmp_path)
    request['instance_id'] = 'core'
    _write(root / 'core' / 'request.json', request)
    document['components'] *= 2
    _write(root / 'harness_set.json', document)
    with pytest.raises(admission.GeneratedArtifactRefused, match='generated-artifact-instance-duplicate'):
        admission.load_generated_artifacts(generated_root=root, base_dir=tmp_path)


def test_generation_persists_request_and_loader_uses_relocated_copy(generated, tmp_path, monkeypatch):
    import shutil
    from myfuzz.local_harness import harness_set
    root, artifact, calls, document = generated
    request_path = root / 'core' / 'request.json'
    request_document = json.loads(request_path.read_text())
    request = SimpleNamespace(instance_id='core')
    plan = SimpleNamespace(profile=object())
    monkeypatch.setattr(harness_set, 'load_local_harness_request', lambda value: request)
    monkeypatch.setattr(harness_set, 'plan_local_harness', lambda value, **kw: plan)
    monkeypatch.setattr(harness_set, 'verify_local_source_lock', lambda value, **kw: artifact.source_verification)
    monkeypatch.setattr(harness_set, 'render_local_harness', lambda value: artifact.structural)
    monkeypatch.setattr(harness_set, 'render_local_runtime', lambda *args, **kw: artifact)
    monkeypatch.setattr(harness_set, 'render_local_driver', lambda value, **kw: artifact)
    output = tmp_path / 'new-generated'
    output.mkdir()
    harness_set.generate_component(request_path, base_dir=tmp_path, output=output / 'core')
    assert json.loads((output / 'core' / 'request.json').read_text()) == request_document
    _write(output / 'harness_set.json', document)
    relocated = tmp_path / 'relocated'
    shutil.copytree(output, relocated)
    shutil.rmtree(root)
    shutil.rmtree(output)
    assert admission.load_generated_artifacts(generated_root=relocated, base_dir=tmp_path) == {'core': artifact}
    assert calls[-1][0] == request_document


def test_changed_source_refusal_is_not_downgraded_to_persisted_artifact(generated, tmp_path, monkeypatch):
    root, _, _, _ = generated
    def refuse(*args, **kwargs):
        raise ValueError('source-lock-changed')
    monkeypatch.setattr(admission, '_reconstruct', refuse)
    with pytest.raises(admission.GeneratedArtifactRefused, match='generated-artifact-reconstruction-refused') as error:
        admission.load_generated_artifacts(generated_root=root, base_dir=tmp_path)
    assert error.value.detail == 'source-lock-changed'


def test_trusted_reconstruction_uses_copied_request_through_source_gate(monkeypatch, tmp_path):
    request_document = {'nondefault-request': True}
    request, profile, structural, verified, runtime, driver = [object() for _ in range(6)]
    plan = SimpleNamespace(profile=profile)
    calls = []
    def step(name, result):
        def call(*args, **kwargs):
            calls.append((name, args, kwargs))
            return result
        return call
    for name, result in [('load_local_harness_request', request), ('plan_local_harness', plan),
                         ('verify_local_source_lock', verified), ('render_local_harness', structural),
                         ('render_local_runtime', runtime), ('render_local_driver', driver)]:
        monkeypatch.setattr(admission, name, step(name, result))
    assert admission._reconstruct(request_document, base_dir=tmp_path) is driver
    assert calls == [
        ('load_local_harness_request', (request_document,), {}),
        ('plan_local_harness', (request,), {'base_dir': tmp_path}),
        ('verify_local_source_lock', (profile,), {'base_dir': tmp_path}),
        ('render_local_harness', (plan,), {}),
        ('render_local_runtime', (plan, structural, verified), {'base_dir': tmp_path}),
        ('render_local_driver', (runtime,), {'base_dir': tmp_path})]


def test_digest_mismatch_is_refused_even_with_matching_protocol(generated, tmp_path):
    root, _, _, document = generated
    document['components'][0]['artifact_digest'] = 'sibling-digest'
    _write(root / 'harness_set.json', document)
    with pytest.raises(admission.GeneratedArtifactRefused, match='generated-artifact-digest-mismatch'):
        admission.load_generated_artifacts(generated_root=root, base_dir=tmp_path)


def test_real_supported_set_loads_from_generated_bytes_without_building_rtl(tmp_path):
    from unittest.mock import patch
    from myfuzz.local_harness.harness_set import generate_harness_set, load_compose
    from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
    from tests.local_harness.test_harness_set import ROOT, compose_document
    compose = load_compose(compose_document(tmp_path), base_dir=ROOT)
    output = tmp_path / 'out'
    # No build cache: this exercise plans/renders/verifies source only. Neither
    # the generator nor loader may compile or launch a runtime in this slice.
    with patch('myfuzz.local_harness.harness_set.build_local_harness',
               side_effect=AssertionError('no runtime build')):
        document = generate_harness_set(compose, base_dir=ROOT,
            compose_base=tmp_path, output_root=output)
        artifacts = admission.load_generated_artifacts(generated_root=output, base_dir=ROOT)
    assert set(artifacts) == {'cpu', 'gpio'}
    for row in document['components']:
        artifact = artifacts[row['instance_id']]
        assert isinstance(artifact, LocalRuntimeArtifact)
        assert artifact.runtime_document['artifact_digest'] == row['artifact_digest']
        assert artifact.plan.request.reset_assert_ticks == 2
        assert artifact.plan.request.reset_release_ticks == 2
