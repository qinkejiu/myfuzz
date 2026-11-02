from types import SimpleNamespace
import pytest
from myfuzz.composition import component_profile as cp


def test_explicit_scope_pins_auto_despite_capability_flip(monkeypatch, tmp_path):
    monkeypatch.setattr(cp, 'supervisor_available', lambda: (True, ''))
    calls = []
    monkeypatch.setattr(cp, '_direct_elaboration', lambda *args, **kwargs: calls.append('direct') or 'facts')
    profile = SimpleNamespace(source_document=None, profile_fingerprint='fixture')
    with cp.elaboration_mode_scope('direct'):
        assert cp.elaborate_profile(profile, base_dir=tmp_path) == 'facts'
    assert calls == ['direct']


def test_supervised_scope_refuses_unavailable_and_resets(monkeypatch, tmp_path):
    monkeypatch.setattr(cp, 'supervisor_available', lambda: (False, 'fixture-no-process-group'))
    profile = SimpleNamespace(profile_fingerprint='fixture', component_id='fixture')
    with cp.elaboration_mode_scope('supervised'):
        with pytest.raises(cp.ComponentProfileError, match='supervisor-unavailable'):
            cp.elaborate_profile(profile, base_dir=tmp_path)
    with pytest.raises(cp.ComponentProfileError, match='invalid-elaboration-mode'):
        with cp.elaboration_mode_scope('invalid'):
            pass


def test_capability_flip_changes_unpinned_facts_but_scope_preserves_all(monkeypatch, tmp_path):
    direct = cp.PhysicalFacts(top_module='dut', ports=('port-fixture',), content_hash='source-hash',
                              revision='revision', modules=(), files=('dut.sv',))
    snapshot = SimpleNamespace(elaborated_top_module='dut', elaborated_ports=direct.ports,
        content_hash='frontend-manifest-hash', revision='revision', modules=('dut',),
        files=('dut.sv',), effective_include_roots=())
    profile = SimpleNamespace(profile_fingerprint='fixture', component_id='fixture', source_document=None,
                              source=SimpleNamespace(top_module='dut', elaboration=None))
    monkeypatch.setattr(cp, '_direct_elaboration', lambda *args, **kwargs: direct)
    monkeypatch.setattr(cp, 'SourceCrawler', lambda: SimpleNamespace(crawl=lambda *args, **kwargs: snapshot))
    monkeypatch.setattr(cp, 'supervisor_available', lambda: (False, 'fixture'))
    original = cp.elaborate_profile(profile, base_dir=tmp_path)
    monkeypatch.setattr(cp, 'supervisor_available', lambda: (True, ''))
    unpinned = cp.elaborate_profile(profile, base_dir=tmp_path)
    assert original.modules != unpinned.modules
    assert original.content_hash != unpinned.content_hash
    with cp.elaboration_mode_scope('direct'):
        fresh = cp.elaborate_profile(profile, base_dir=tmp_path)
    assert fresh == original
    assert cp.elaborate_profile(profile, base_dir=tmp_path) == unpinned
