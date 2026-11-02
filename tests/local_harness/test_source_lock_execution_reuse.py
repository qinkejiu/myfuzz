from dataclasses import replace
import pytest
from myfuzz.local_harness import source_lock
from myfuzz.local_harness.execution_validation import execution_validation_scope, ExecutionValidationError
from myfuzz.composition.component_profile import load_component_profile
from tests.composition.soc_generation_fixture import EXAMPLE, ROOT


def test_scope_reuses_isolated_result_and_rechecks(monkeypatch, tmp_path):
    profile = load_component_profile(EXAMPLE / 'profiles/novacore.json')
    calls = []
    def verify(profile, *, base_dir, allow_source_only):
        calls.append((profile.profile_fingerprint, base_dir, allow_source_only))
        return {'items': ['verified']}
    monkeypatch.setattr(source_lock, '_verify_local_source_lock', verify)
    with execution_validation_scope():
        first = source_lock.verify_local_source_lock(profile, base_dir=ROOT)
        first['items'].append('mutated')
        assert source_lock.verify_local_source_lock(profile, base_dir=ROOT) == {'items': ['verified']}
        source_lock.verify_local_source_lock(profile, base_dir=tmp_path)
        source_lock.verify_local_source_lock(profile, base_dir=ROOT, allow_source_only=True)
        source_lock.verify_local_source_lock(replace(profile, component_id='other'), base_dir=ROOT)
        assert len(calls) == 4
    assert len(calls) == 8


def test_strict_exit_detects_changed_validation(monkeypatch):
    profile = load_component_profile(EXAMPLE / 'profiles/novacore.json')
    state = ['old']
    monkeypatch.setattr(source_lock, '_verify_local_source_lock', lambda *a, **k: {'source': state[0]})
    with pytest.raises(ExecutionValidationError):
        with execution_validation_scope():
            source_lock.verify_local_source_lock(profile, base_dir=ROOT)
            state[0] = 'new'
