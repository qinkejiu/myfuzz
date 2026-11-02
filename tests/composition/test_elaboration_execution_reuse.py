"""Profile preparation is reused only inside its explicit execution boundary."""
from dataclasses import replace

import pytest

from myfuzz.composition import component_profile as cp
from myfuzz.local_harness.execution_validation import (
    ExecutionValidationError, execution_validation_scope,
)
from .soc_generation_fixture import EXAMPLE, ROOT


@pytest.fixture
def prepared(monkeypatch):
    profile = cp.load_component_profile(EXAMPLE / 'profiles/novacore.json')
    calls = []
    def direct(profile, **kwargs):
        calls.append((profile.profile_fingerprint, kwargs))
        return cp.PhysicalFacts(profile.source.top_module, (), 'source', 'revision')
    monkeypatch.setattr(cp, '_direct_elaboration', direct)
    return profile, calls


def test_identical_profiles_reuse_frontend_and_revalidate_at_exit(prepared):
    profile, calls = prepared
    with execution_validation_scope():
        first = cp.elaborate_profile(profile, base_dir=ROOT, mode='direct')
        for _ in range(5):
            assert cp.elaborate_profile(profile, base_dir=ROOT, mode='direct') == first
        assert len(calls) == 1
    assert len(calls) == 2
    with execution_validation_scope():
        cp.elaborate_profile(profile, base_dir=ROOT, mode='direct')
    assert len(calls) == 4
    cp.elaborate_profile(profile, base_dir=ROOT, mode='direct')
    cp.elaborate_profile(profile, base_dir=ROOT, mode='direct')
    assert len(calls) == 6


def test_roots_ports_parameters_and_mutable_contracts_do_not_share(prepared, tmp_path):
    profile, calls = prepared
    def run(item=profile, **kwargs):
        return cp.elaborate_profile(item, base_dir=kwargs.pop('base_dir', ROOT),
                                    mode='direct', **kwargs)
    with execution_validation_scope(revalidate=False):
        run()
        run(base_dir=tmp_path)
        run(selected_top_ports=('clk_i',))
        run(replace(profile, source=replace(profile.source, elaboration=replace(profile.source.elaboration, parameters=(('WIDTH', '9'),)))))
        profile.capabilities['reuse_test'] = True
        run()
        profile.source_document['reuse_metadata'] = 'changed'
        run()
        run()
        assert len(calls) == 6


def test_auto_mode_respects_scope_choice(prepared, monkeypatch):
    profile, calls = prepared
    monkeypatch.setattr(cp, 'supervisor_available', lambda: (False, 'test'))
    with execution_validation_scope(revalidate=False):
        with cp.elaboration_mode_scope('direct'):
            cp.elaborate_profile(profile, base_dir=ROOT)
            cp.elaborate_profile(profile, base_dir=ROOT)
        with cp.elaboration_mode_scope('supervised'):
            with pytest.raises(cp.ComponentProfileError, match='supervisor-unavailable'):
                cp.elaborate_profile(profile, base_dir=ROOT)
        assert len(calls) == 1


def test_exit_frontend_drift_is_rejected(prepared, monkeypatch):
    profile, calls = prepared
    with pytest.raises(ExecutionValidationError):
        with execution_validation_scope():
            cp.elaborate_profile(profile, base_dir=ROOT, mode='direct')
            monkeypatch.setattr(cp, '_direct_elaboration', lambda *a, **k:
                                cp.PhysicalFacts('changed', (), 'changed', 'revision'))
