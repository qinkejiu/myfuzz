"""The builder's gates are accepted once per observed input content.

The source lock and the build cache are re-read by the builder, by the session
that launches the harness and by the exit re-authentication.  Each is keyed by
the content it actually reads, so the same bytes authenticate once and any
changed byte authenticates again.
"""
import json
import os
import shutil

import pytest

from myfuzz.composition import component_profile as cp
from myfuzz.local_harness import build
from myfuzz.local_harness import execution_validation as ev

ROOT = __import__('pathlib').Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / 'examples/soc_generation'


@pytest.fixture(autouse=True)
def fresh_memos():
    saved = {'results': dict(ev._IDENTITY_RESULTS), 'digests': dict(ev._DIGESTS),
             'closures': dict(cp._CLOSURE_DECLARATIONS),
             'listings': dict(cp._INCLUDE_LISTINGS),
             'build_rows': dict(build._BUILD_ROWS),
             'lock_rows': dict(build._LOCK_ROWS)}
    ev._IDENTITY_RESULTS.clear()
    ev._DIGESTS.clear()
    cp._CLOSURE_DECLARATIONS.clear()
    cp._INCLUDE_LISTINGS.clear()
    build._BUILD_ROWS.clear()
    build._LOCK_ROWS.clear()
    yield
    ev._IDENTITY_RESULTS.clear()
    ev._DIGESTS.clear()
    cp._CLOSURE_DECLARATIONS.clear()
    cp._INCLUDE_LISTINGS.clear()
    build._BUILD_ROWS.clear()
    build._BUILD_ROWS.update(saved['build_rows'])
    build._LOCK_ROWS.clear()
    build._LOCK_ROWS.update(saved['lock_rows'])


def _copied_example(tmp_path):
    root = tmp_path / 'checkout'
    shutil.copytree(EXAMPLE, root / 'examples/soc_generation')
    return root


def _profile(root):
    document = json.loads((root / 'examples/soc_generation/profiles/novauart.json').read_text())
    return cp.load_component_profile(document)


def _counting(monkeypatch):
    calls = []

    def fake(profile, *, base_dir, allow_source_only=False):
        calls.append((profile.component_id, str(base_dir), allow_source_only))
        return {'schema_version': 'local_source_lock_verification.v1',
                'source_status': 'source_verified', 'closure_sha256': 'sha256:fixture'}

    monkeypatch.setattr(build, 'verify_local_source_lock', fake)
    return calls


def test_same_profile_bytes_verify_once(tmp_path, monkeypatch):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    calls = _counting(monkeypatch)
    path = root / 'examples/soc_generation/profiles/novauart.json'
    first = build.verified_source_lock(profile, base_dir=root, profile_path=path)
    for _ in range(3):
        assert build.verified_source_lock(profile, base_dir=root,
                                          profile_path=path) == first
    assert len(calls) == 1


def test_exit_does_not_verify_unchanged_bytes_again(tmp_path, monkeypatch):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    calls = _counting(monkeypatch)
    path = root / 'examples/soc_generation/profiles/novauart.json'
    with ev.execution_validation_scope() as state:
        build.verified_source_lock(profile, base_dir=root, profile_path=path)
    assert state['status'] == 'verified'
    assert len(calls) == 1


def test_changed_source_byte_verifies_again(tmp_path, monkeypatch):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    calls = _counting(monkeypatch)
    path = root / 'examples/soc_generation/profiles/novauart.json'
    source = root / 'examples/soc_generation/rtl/novauart.sv'
    build.verified_source_lock(profile, base_dir=root, profile_path=path)
    original = source.read_bytes()
    stamp = source.stat()
    source.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    build.verified_source_lock(profile, base_dir=root, profile_path=path)
    assert len(calls) == 2


def test_changed_profile_file_verifies_again(tmp_path, monkeypatch):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    calls = _counting(monkeypatch)
    path = root / 'examples/soc_generation/profiles/novauart.json'
    build.verified_source_lock(profile, base_dir=root, profile_path=path)
    document = json.loads(path.read_text())
    document['description'] = document.get('description', '') + ' edited'
    path.write_text(json.dumps(document, indent=2) + '\n')
    # The protocol object is unchanged: only re-reading the file sees this.
    build.verified_source_lock(profile, base_dir=root, profile_path=path)
    assert len(calls) == 2


def test_source_only_scope_is_part_of_the_identity(tmp_path, monkeypatch):
    root = _copied_example(tmp_path)
    profile = _profile(root)
    calls = _counting(monkeypatch)
    path = root / 'examples/soc_generation/profiles/novauart.json'
    build.verified_source_lock(profile, base_dir=root, profile_path=path)
    build.verified_source_lock(profile, base_dir=root, profile_path=path,
                              allow_source_only=True)
    assert len(calls) == 2
    assert calls[0][2] is False and calls[1][2] is True


def test_kernel_registered_identity_covers_a_raw_gate_key(tmp_path, monkeypatch):
    """A raw ``local-source-lock`` key gets the same observation, not a re-run."""
    root = _copied_example(tmp_path)
    profile = _profile(root)
    path = root / 'examples/soc_generation/profiles/novauart.json'
    cp.remember_profile_source(profile, path)
    calls = _counting(monkeypatch)
    key = ('local-source-lock', profile.profile_fingerprint, str(root), False)
    with ev.execution_validation_scope() as state:
        accepted = ev.static_validation(key, lambda: build.verify_local_source_lock(
            profile, base_dir=root))
        assert accepted['schema_version'] == 'local_source_lock_verification.v1'
    assert state['status'] == 'verified'
    assert len(calls) == 1
    assert ev.key_identity(key) is not None


def test_build_cache_identity_sees_a_same_size_restored_mtime_edit(tmp_path):
    import hashlib
    directory = tmp_path / 'digest'
    directory.mkdir()
    binary = directory / 'harness'
    binary.write_bytes(b'executable')
    binary.chmod(0o700)
    inputs = directory / 'inputs'
    inputs.mkdir()
    source = inputs / 'source.sv'
    source.write_bytes(b'original')
    identity = {'build_digest': directory.name,
                'inputs': [{'path': 'source.sv',
                            'sha256': hashlib.sha256(b'original').hexdigest()}]}
    (directory / 'manifest.json').write_text(json.dumps({
        'identity': identity,
        'binary_sha256': hashlib.sha256(b'executable').hexdigest()}))
    calls = []
    original = build._validate_cache_current

    def counted(directory_path, current):
        calls.append(1)
        return original(directory_path, current)

    build._validate_cache_current = counted
    try:
        with pytest.raises(ev.ExecutionValidationError):
            with ev.execution_validation_scope():
                assert build._validate_cache(directory, identity) == binary
                stamp = source.stat()
                source.write_bytes(b'modified')
                os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
                assert build._validate_cache(directory, identity) == binary
    finally:
        build._validate_cache_current = original
    # Body once, then the exit boundary re-read the changed cache bytes and
    # refused the accepted result.
    assert len(calls) == 2
