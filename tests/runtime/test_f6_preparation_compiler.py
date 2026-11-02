"""F6 static preparation reuses source-backed D2/D3 without native effects."""

from pathlib import Path

import pytest

from myfuzz.local_harness.generated_artifact_admission import (
    validated_f6_provider_credentials,
)
from myfuzz.integration.compiled_f6_rfuzz_session import assess_compiled_f6_support
from myfuzz.runtime.contracts import GenericRuntimeRefused
from myfuzz.runtime.preparation import create_preparation
from tests.integration.test_compiled_f6_contract import _saved_source_facts


ROOT = Path(__file__).resolve().parents[2]
INPUTS = ROOT / ".superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram"


@pytest.fixture
def f6_preparation(tmp_path, monkeypatch):
    # Reuse pinned elaboration facts; no native process or runtime is started.
    monkeypatch.setattr("myfuzz.local_harness.plan.elaborate_profile", _saved_source_facts)
    monkeypatch.setattr("myfuzz.local_harness.runtime_renderer.elaborate_profile", _saved_source_facts)
    context = create_preparation(
        base_dir=ROOT, compose_path=INPUTS / "base.compose.json",
        capability_paths=(INPUTS / "base.test_capability.json",),
        supplement_path=INPUTS / "base.supplement.json",
        generated_dir=tmp_path / "generated", flow_ids=("F6",))
    yield context
    context.close()


def test_f6_static_admission_retains_same_call_provider_until_close(f6_preparation):
    context = f6_preparation
    assert context.flow_support("F6")["execution_supported"] == 1
    assert context.flow_support("F6")["runtime_admitted"] is False
    owned = context._f6_provider_artifacts
    assert set(validated_f6_provider_credentials(owned)) == {"dma"}
    assert all(owned[name] is context.artifact(name) for name in owned)
    support = assess_compiled_f6_support(
        artifacts=owned, compiled_inputs=context.compiled_inputs(), base_dir=ROOT)
    assert support["execution_supported"] == 1
    assert support["runtime_admitted"] is False
    context.assert_current()
    context.close()
    with pytest.raises(ValueError):
        validated_f6_provider_credentials(owned)


def test_f6_artifact_replacement_is_rejected(f6_preparation):
    owned = f6_preparation._f6_provider_artifacts
    original = owned["dma"]
    owned["dma"] = owned["cpu"]
    try:
        with pytest.raises(GenericRuntimeRefused):
            f6_preparation.assert_current()
    finally:
        owned["dma"] = original


def test_f6_preparation_failure_releases_provider_credentials(tmp_path, monkeypatch):
    from myfuzz.local_harness import generated_artifact_admission as admission
    from myfuzz.runtime import preparation

    monkeypatch.setattr("myfuzz.local_harness.plan.elaborate_profile", _saved_source_facts)
    monkeypatch.setattr("myfuzz.local_harness.runtime_renderer.elaborate_profile", _saved_source_facts)
    released = []
    release = admission.release_f6_provider_credentials

    def record_release(artifacts):
        assert set(validated_f6_provider_credentials(artifacts)) == {"dma"}
        released.append(artifacts)
        release(artifacts)

    def fail_pinning(*args):
        raise RuntimeError("pinning-failed")

    monkeypatch.setattr(admission, "release_f6_provider_credentials", record_release)
    monkeypatch.setattr(preparation, "_generated_pins", fail_pinning)
    with pytest.raises(RuntimeError, match="pinning-failed"):
        create_preparation(
            base_dir=ROOT, compose_path=INPUTS / "base.compose.json",
            capability_paths=(INPUTS / "base.test_capability.json",),
            supplement_path=INPUTS / "base.supplement.json",
            generated_dir=tmp_path / "generated", flow_ids=("F6",))
    assert len(released) == 1
    with pytest.raises(ValueError):
        validated_f6_provider_credentials(released[0])


def test_f6_preparation_identity_depends_on_wiring_content_not_output_directory(tmp_path, monkeypatch):
    import json
    from myfuzz.scenario.compiled_paths import compiled_document_sha256
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path

    monkeypatch.setattr('myfuzz.local_harness.plan.elaborate_profile', _saved_source_facts)
    monkeypatch.setattr('myfuzz.local_harness.runtime_renderer.elaborate_profile', _saved_source_facts)
    contexts = []
    try:
        for mode in ('original', 'fresh'):
            (tmp_path / mode).mkdir()
            contexts.append(create_preparation(
                base_dir=ROOT, compose_path=INPUTS / 'base.compose.json',
                capability_paths=(INPUTS / 'base.test_capability.json',),
                supplement_path=INPUTS / 'base.supplement.json',
                generated_dir=tmp_path / mode / 'generated', flow_ids=('F6',)))
        original, fresh = contexts
        assert original.compiled_inputs()['request'].document == fresh.compiled_inputs()['request'].document
        assert compiled_document_sha256(original.compiled_inputs()['compiled']) == compiled_document_sha256(fresh.compiled_inputs()['compiled'])
        assert original.input_digests == fresh.input_digests
        admissions = [admit_compiled_f6_runtime_path(artifacts=context._f6_provider_artifacts,
            compiled_inputs=context.compiled_inputs(), base_dir=ROOT) for context in contexts]
        assert admissions[0] == admissions[1]
        for name in original.artifacts:
            assert original.artifact(name) is not fresh.artifact(name)
        for context in contexts:
            wiring_path = context.generated_dir / 'wiring_contract.json'
            assert context.compiled_inputs()['request'].document['wiring'] == json.loads(wiring_path.read_text())
            context.assert_current()
            wiring_path.write_text(wiring_path.read_text() + '\n')
            with pytest.raises(GenericRuntimeRefused):
                context.assert_current()
    finally:
        for context in contexts:
            context.close()
