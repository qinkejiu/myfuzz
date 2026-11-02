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

def test_f6_loader_has_explicit_default_closed_flow_opt_in():
    import inspect
    assert inspect.signature(admission.load_generated_artifacts).parameters['flow'].default is None

from tests.integration.test_compiled_f6_entry import driver_declarations

@pytest.fixture(scope='module')
def f6_generated(tmp_path_factory,driver_declarations):
    from tests.integration.test_compiled_f6_contract import ROOT,_saved_source_facts
    from myfuzz.local_harness.harness_set import load_compose,generate_harness_set
    from myfuzz.local_harness.dma_artifact_endpoint_links import PROVIDER_ID
    root=tmp_path_factory.mktemp('f6-issued')/'generated'
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr('myfuzz.local_harness.plan.elaborate_profile',_saved_source_facts)
        patch.setattr('myfuzz.local_harness.runtime_renderer.elaborate_profile',_saved_source_facts)
        composition=load_compose(driver_declarations['compose'],base_dir=ROOT)
        generate_harness_set(composition,base_dir=ROOT,compose_base=driver_declarations['compose'].parent,
            output_root=root,dma_endpoint_provider=PROVIDER_ID)
    return root

@pytest.mark.parametrize('change',[None,'missing','format','wrong_provider','identity','artifact','request','source_evidence'])
def test_f6_reconstructs_issued_provider_and_rejects_sidecar_or_artifact_drift(f6_generated,tmp_path,monkeypatch,change):
    import shutil
    from tests.integration.test_compiled_f6_contract import ROOT,_saved_source_facts
    monkeypatch.setattr('myfuzz.local_harness.plan.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr('myfuzz.local_harness.runtime_renderer.elaborate_profile',_saved_source_facts)
    root=tmp_path/'generated';shutil.copytree(f6_generated,root)
    sidecar=root/'dma/dma_endpoint_links.v1.json'
    if change=='missing':sidecar.unlink()
    elif change=='format':sidecar.write_bytes(sidecar.read_bytes()+b' ')
    elif change=='wrong_provider':
        row=json.loads(sidecar.read_bytes());row['provider_id']='unregistered';_write(sidecar,row)
    elif change=='identity':
        manifest=json.loads((root/'harness_set.json').read_bytes());manifest['components'][1]['dma_endpoint_links']['identity_sha256']='0'*64
        _write(root/'harness_set.json',manifest)
    elif change=='artifact':(root/'dma/driver.cpp').write_bytes(b'changed')
    elif change=='request':
        request=json.loads((root/'dma/request.json').read_bytes());request['reset_assert_ticks']+=1;_write(root/'dma/request.json',request)
    elif change=='source_evidence':(root/'dma/source_verification.json').write_bytes(b'{}')
    if change:
        with pytest.raises(ValueError):admission.load_generated_artifacts(generated_root=root,base_dir=ROOT,flow='F6')
    else:
        loaded=admission.load_generated_artifacts(generated_root=root,base_dir=ROOT,flow='F6')
        credentials=admission.validated_f6_provider_credentials(loaded)
        assert set(credentials)=={'dma'}
        assert credentials['dma']==json.loads(sidecar.read_bytes())
        with pytest.raises(ValueError,match='same-call-provider'):
            admission.validated_f6_provider_credentials(dict(loaded))
        sidecar.write_bytes(sidecar.read_bytes()+b' ')
        with pytest.raises(ValueError,match='loaded-bytes-changed'):
            admission.validated_f6_provider_credentials(loaded)
        admission.release_f6_provider_credentials(loaded)
    with pytest.raises(admission.GeneratedArtifactRefused,match='route-intent-unsupported'):
        admission.load_generated_artifacts(generated_root=root,base_dir=ROOT)

@pytest.mark.parametrize('refusal',['slot_budget','provider_bytes'])
def test_f6_directed_entry_releases_same_call_provider_on_pre_runtime_refusal(
        f6_generated,tmp_path,monkeypatch,refusal):
    import shutil
    from tests.integration.test_compiled_f6_contract import ROOT,_saved_source_facts
    from myfuzz.integration.compiled_execution_files import _run_f6_file_route
    monkeypatch.setattr('myfuzz.local_harness.plan.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr('myfuzz.local_harness.runtime_renderer.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr('myfuzz.integration.compiled_f6.CompiledF6Runtime',lambda **kw:pytest.fail('native constructor reached'))
    generated=tmp_path/'generated';shutil.copytree(f6_generated,generated)
    artifacts=admission.load_generated_artifacts(generated_root=generated,base_dir=ROOT,flow='F6')
    assert admission.validated_f6_provider_credentials(artifacts)
    if refusal=='provider_bytes':
        sidecar=generated/'dma/dma_endpoint_links.v1.json';sidecar.write_bytes(sidecar.read_bytes()+b' ')
    with pytest.raises(ValueError):
        _run_f6_file_route(output=tmp_path/'out',marker=tmp_path/'out/.incomplete',report={},
            artifacts=artifacts,inputs={},base=ROOT,cache_dir=tmp_path,run_id='refused',rounds=4096,
            max_cases=17 if refusal=='slot_budget' else 1,replay_count=1,records=[],
            lock_path=tmp_path/'lock',check_sources=lambda:None)
    with pytest.raises(admission.GeneratedArtifactRefused,match='same-call-provider-required'):
        admission.validated_f6_provider_credentials(artifacts)

@pytest.mark.parametrize('refusal',['max_tests','rounds','cache','support','provider_bytes'])
def test_f6_public_wrapper_releases_provider_when_support_refuses_before_runtime(f6_generated,tmp_path,monkeypatch,refusal):
    import shutil
    from tests.integration.test_compiled_f6_contract import ROOT,_saved_source_facts
    from myfuzz.integration.compiled_f6_rfuzz import run_compiled_f6_rfuzz_session
    monkeypatch.setattr('myfuzz.local_harness.plan.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr('myfuzz.local_harness.runtime_renderer.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr('myfuzz.integration.compiled_f6_rfuzz_session.CompiledF6Runtime',lambda **kw:pytest.fail('native constructor reached'))
    root=tmp_path/'generated';shutil.copytree(f6_generated,root)
    artifacts=admission.load_generated_artifacts(generated_root=root,base_dir=ROOT,flow='F6')
    assert admission.validated_f6_provider_credentials(artifacts)
    if refusal=='provider_bytes':
        sidecar=root/'dma/dma_endpoint_links.v1.json';sidecar.write_bytes(sidecar.read_bytes()+b' ')
    with pytest.raises(ValueError):
        run_compiled_f6_rfuzz_session(artifacts=artifacts,compiled_inputs={},base_dir=ROOT,
            cache_dir=tmp_path/'absent' if refusal=='cache' else tmp_path,
            run_id='refused',session_dir=tmp_path/'session',output_dir=tmp_path/'output',client_binary=tmp_path/'client',
            budget_seconds=1,max_tests=0 if refusal=='max_tests' else 1,search_seed=1,max_runs_per_batch=1,
            rounds_per_case=0 if refusal=='rounds' else 4096)
    with pytest.raises(admission.GeneratedArtifactRefused,match='same-call-provider-required'):
        admission.validated_f6_provider_credentials(artifacts)

@pytest.mark.parametrize('entry',['prepare_ownership','file_support','file_layout'])
def test_f6_file_preparation_and_outer_refusal_release_loaded_provider(
        driver_declarations,tmp_path,monkeypatch,entry):
    from tests.integration.test_compiled_f6_contract import ROOT,_saved_source_facts
    from myfuzz.integration import compiled_execution_files as files
    monkeypatch.setattr('myfuzz.local_harness.plan.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr('myfuzz.local_harness.runtime_renderer.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr('myfuzz.integration.compiled_f6.CompiledF6Runtime',lambda **kw:pytest.fail('native constructor reached'))
    seen={};loader=files.load_generated_artifacts
    def capture(**kwargs):
        loaded=loader(**kwargs);seen['artifacts']=loaded;return loaded
    monkeypatch.setattr(files,'load_generated_artifacts',capture)
    additions={'deliveries':json.loads(driver_declarations['f6_deliveries'].read_text())}
    if entry!='file_support':additions['f6_execution']=json.loads(driver_declarations['f6_execution'].read_text())
    supplement=dict(schema_version='compiled_execution_file_supplement.v1',request_supplements=additions,
        ownership=dict(fields=[{'component_id':'dma','port':'invalid','width':0}] if entry=='prepare_ownership' else [],owners=[]),
        physical_port_map=[])
    path=tmp_path/'supplement.json';path.write_text(json.dumps(supplement))
    args=dict(base_dir=ROOT,compose_path=driver_declarations['compose'],
        capability_paths=driver_declarations['ip_capabilities'],supplement_path=path)
    if entry=='prepare_ownership':
        with pytest.raises(ValueError):files.prepare_compiled_execution_files(**args,generated_dir=tmp_path/'generated',flow='F6')
    else:
        records=tmp_path/'records.json';records.write_text('["0000000000000000"]' if entry=='file_layout' else '["0108400000020000"]')
        with pytest.raises(ValueError,match='compiled-F6-layout-duplicate-word' if entry=='file_layout' else 'compiled-files-runtime-support-refused'):
            files.run_compiled_execution_files(**args,records_path=records,output_dir=tmp_path/'output',
                cache_dir=tmp_path,executor='compiled_f6_cpu_dma',rounds_per_case=4096,max_cases=1,replay_count=1,
                heavy_lock=tmp_path/'lock')
    assert 'artifacts' in seen
    with pytest.raises(admission.GeneratedArtifactRefused,match='same-call-provider-required'):
        admission.validated_f6_provider_credentials(seen['artifacts'])
