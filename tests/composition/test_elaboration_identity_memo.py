"""One frontend walk per observed elaboration identity, never per caller.

The elaboration is the most expensive preparation a run performs and planning,
the runtime admission, the builder and the exit re-authentication all ask for
the *same* facts.  These tests pin the identity: the same profile, revision,
base directory and source closure elaborate once; a changed source byte, a
different closure, a different selection or a different frontend mode do not
reuse that result.
"""
import json
import os
import shutil

import pytest

from myfuzz.composition import component_profile as cp
from myfuzz.local_harness import execution_validation as ev

ROOT = __import__('pathlib').Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / 'examples/soc_generation'


@pytest.fixture(autouse=True)
def fresh_memos():
    saved = {
        'results': dict(ev._IDENTITY_RESULTS),
        'digests': dict(ev._DIGESTS),
        'closures': dict(cp._CLOSURE_DECLARATIONS),
        'listings': dict(cp._INCLUDE_LISTINGS),
        'sources': dict(cp._PROFILE_SOURCES),
    }
    ev._IDENTITY_RESULTS.clear()
    ev._DIGESTS.clear()
    cp._CLOSURE_DECLARATIONS.clear()
    cp._INCLUDE_LISTINGS.clear()
    yield
    ev._IDENTITY_RESULTS.clear()
    ev._DIGESTS.clear()
    cp._CLOSURE_DECLARATIONS.clear()
    cp._INCLUDE_LISTINGS.clear()
    cp._PROFILE_SOURCES.update(saved['sources'])


def _copied_example(tmp_path):
    root = tmp_path / 'checkout'
    shutil.copytree(EXAMPLE, root / 'examples/soc_generation')
    return root


def _profile(root, name='novauart'):
    document = json.loads((root / 'examples/soc_generation/profiles' / f'{name}.json').read_text())
    return cp.load_component_profile(document)


def _counting(monkeypatch):
    calls = []

    def fake(profile, *, base_dir, selected_top_ports, mode):
        calls.append((profile.component_id, str(base_dir), selected_top_ports, mode))
        return cp.PhysicalFacts(top_module='novauart', ports=(), content_hash='sha256:facts',
                                revision=profile.source.revision)

    monkeypatch.setattr(cp, '_elaborate_profile', fake)
    return calls


def test_same_identity_elaborates_once(tmp_path, monkeypatch):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    calls = _counting(monkeypatch)
    for _ in range(4):
        facts = cp.elaborate_profile(profile, base_dir=root, mode='direct')
        assert facts.content_hash == 'sha256:facts'
    assert len(calls) == 1


def test_exit_reauthentication_does_not_elaborate_again(tmp_path, monkeypatch):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    calls = _counting(monkeypatch)
    with ev.execution_validation_scope() as state:
        cp.elaborate_profile(profile, base_dir=root, mode='direct')
        cp.elaborate_profile(profile, base_dir=root, mode='direct')
        assert len(calls) == 1
    assert state == {'status': 'verified', 'matches': True}
    assert len(calls) == 1


def test_changed_source_byte_elaborates_again(tmp_path, monkeypatch):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    calls = _counting(monkeypatch)
    source = root / 'examples/soc_generation/rtl/novauart.sv'
    cp.elaborate_profile(profile, base_dir=root, mode='direct')
    original = source.read_bytes()
    stamp = source.stat()
    # Same size, restored mtime: only the content identity can see this.
    source.write_bytes(original.replace(b'u8', b'u9', 1) if b'u8' in original
                       else original[:-1] + bytes([original[-1] ^ 1]))
    os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert source.stat().st_size == stamp.st_size
    cp.elaborate_profile(profile, base_dir=root, mode='direct')
    assert len(calls) == 2


def test_different_selection_or_mode_does_not_reuse(tmp_path, monkeypatch):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    calls = _counting(monkeypatch)
    cp.elaborate_profile(profile, base_dir=root, mode='direct')
    cp.elaborate_profile(profile, base_dir=root, mode='direct',
                         selected_top_ports=('clk', 'rst_n'))
    cp.elaborate_profile(profile, base_dir=root, mode='supervised')
    # Four frontend paths produce different evidence fields, so each identity
    # is its own result: another base directory is a fourth one.
    cp.elaborate_profile(profile, base_dir=root, mode='direct')
    assert len(calls) == 3
    assert [row[2] for row in calls] == [None, ('clk', 'rst_n'), None]
    assert [row[3] for row in calls] == ['direct', 'direct', 'supervised']


def test_identity_is_content_shaped_not_call_ordered(tmp_path):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    first = cp.elaboration_input_identity(profile, base_dir=root)
    second = cp.elaboration_input_identity(profile, base_dir=root)
    assert first == second
    # A second, independently loaded profile of the same bytes is the same
    # identity: nothing here is keyed by object identity.
    assert cp.elaboration_input_identity(_profile(root), base_dir=root) == first
    # The profile file participates, so an edited profile is a new identity.
    path = root / 'examples/soc_generation/profiles/novauart.json'
    document = json.loads(path.read_text())
    document['description'] = document.get('description', '') + ' edited'
    path.write_text(json.dumps(document, indent=2) + '\n')
    assert cp.elaboration_input_identity(_profile(root), base_dir=root) != first


def test_stored_port_evidence_participates_in_the_identity(tmp_path):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    base = cp.elaboration_input_identity(profile, base_dir=root)
    source_root = root / 'examples/soc_generation/rtl'
    manifest = source_root / 'source_manifest.json'
    manifest.write_text(json.dumps({'revision': profile.source.revision,
                                    'physical_ports': 'ports.json'}) + '\n')
    with_manifest = cp.elaboration_input_identity(profile, base_dir=root)
    assert with_manifest != base
    (source_root / 'ports.json').write_text('{"ports": []}\n')
    with_evidence = cp.elaboration_input_identity(profile, base_dir=root)
    assert with_evidence != with_manifest
    (source_root / 'ports.json').write_text('{"ports": [1]}\n')
    assert cp.elaboration_input_identity(profile, base_dir=root) != with_evidence


def test_include_root_bytes_participate_in_the_identity(tmp_path):
    root = _copied_example(tmp_path)
    profile = _profile(root, 'novacore')
    document = json.loads((root / 'examples/soc_generation/profiles/novacore.json').read_text())
    document['source']['include_roots'] = ['.']
    profile = cp.load_component_profile(document)
    base = cp.source_closure_identity(profile, base_dir=root)
    assert base is not None
    (root / 'examples/soc_generation/rtl/extra_pkg.svh').write_text('package extra; endpackage\n')
    assert cp.source_closure_identity(profile, base_dir=root) != base


def test_an_unobservable_closure_is_never_reused(tmp_path):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    (root / 'examples/soc_generation/rtl/novauart.sv').unlink()
    assert cp.elaboration_input_identity(profile, base_dir=root) is None
