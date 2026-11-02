"""Boundary validation does not infer trust from filesystem timestamps."""
import os
import pytest
from myfuzz.local_harness.execution_validation import (
    execution_validation_scope, execution_validation_active, static_validation, ExecutionValidationError,
)


def test_static_work_is_bounded_and_cold_scope_is_strict():
    calls = []
    def validate():
        calls.append(1)
        return {'identity': 'original'}
    assert execution_validation_active() is False
    with execution_validation_scope():
        assert execution_validation_active() is True
        for _ in range(20):
            assert static_validation('same', validate) == {'identity': 'original'}
        assert len(calls) == 1
    assert len(calls) == 2
    assert execution_validation_active() is False
    static_validation('same', validate)
    static_validation('same', validate)
    assert len(calls) == 4


@pytest.mark.parametrize('kind', ['source', 'tool', 'cache'])
def test_same_size_restored_mtime_drift_is_rejected(tmp_path, kind):
    path = tmp_path / kind
    path.write_bytes(b'original')
    stamp = path.stat()
    with pytest.raises(ExecutionValidationError):
        with execution_validation_scope():
            assert static_validation(kind, path.read_bytes) == b'original'
            path.write_bytes(b'modified')
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            assert static_validation(kind, path.read_bytes) == b'original'


def test_exception_preserved_and_context_restored(tmp_path):
    path = tmp_path / 'source'
    path.write_bytes(b'a')
    primary = RuntimeError('operation failed')
    with pytest.raises(RuntimeError) as caught:
        with execution_validation_scope():
            static_validation(path, path.read_bytes)
            path.write_bytes(b'b')
            raise primary
    assert caught.value is primary
    assert any('execution validation' in note for note in primary.__notes__)
    assert static_validation(path, path.read_bytes) == b'b'


def test_nested_scopes_are_isolated():
    calls = []
    def validate():
        calls.append(1)
        return 'same'
    with execution_validation_scope():
        static_validation('key', validate)
        with execution_validation_scope():
            static_validation('key', validate)
        static_validation('key', validate)
    assert len(calls) == 4


# This fixture launches only a tiny Python wire worker, never an RTL executable.
from tests.local_harness.test_native_reset_observation import mechanical_local
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory


def test_real_commands_keep_source_work_constant(mechanical_local, monkeypatch):
    from pathlib import Path
    local = mechanical_local
    local.configure_native_reset_observation()
    paths = set(local._native_reset_observation._sources)
    original = Path.read_bytes
    calls = []
    def counted(path):
        if str(path) in paths:
            calls.append(str(path))
        return original(path)
    monkeypatch.setattr(Path, 'read_bytes', counted)
    with execution_validation_scope():
        local.begin_case('scoped')
        before = len(calls)
        for _ in range(8):
            local.command('STEP_GPIO', (0,))
        assert len(calls) == before
        local.end_case()
    assert len(calls) == 2 * len(paths)


@pytest.mark.parametrize('mode', ['binary', 'producer'])
def test_dynamic_drift_is_immediate(mechanical_local, monkeypatch, mode):
    from myfuzz.local_harness.session import GeneratedLocalSession
    local = mechanical_local
    local.configure_native_reset_observation()
    with execution_validation_scope():
        local.begin_case('scoped')
        if mode == 'binary':
            raw = local._binary.read_bytes()
            local._binary.write_bytes(raw + b'\n# changed\n')
        else:
            original = GeneratedLocalSession._expected_ready
            monkeypatch.setattr(GeneratedLocalSession, '_expected_ready', lambda self: None)
        try:
            with pytest.raises(ValueError, match='drift'):
                local.command('STEP_GPIO', (0,))
        finally:
            if mode == 'binary':
                local._binary.write_bytes(raw)
            else:
                monkeypatch.setattr(GeneratedLocalSession, '_expected_ready', original)
            local.end_case()


def test_actual_cache_validation_is_bounded_and_exit_reads_bytes(tmp_path):
    import hashlib
    import json
    from myfuzz.local_harness.build import _validate_cache
    binary = tmp_path / 'harness'
    binary.write_bytes(b'executable')
    binary.chmod(0o700)
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    source = inputs / 'source.sv'
    source.write_bytes(b'original')
    identity = {'build_digest': tmp_path.name, 'inputs': [{'path': 'source.sv', 'sha256': hashlib.sha256(b'original').hexdigest()}]}
    (tmp_path / 'manifest.json').write_text(json.dumps({
        'identity': identity, 'binary_sha256': hashlib.sha256(b'executable').hexdigest()}))
    stamp = source.stat()
    with pytest.raises(ExecutionValidationError):
        with execution_validation_scope():
            assert _validate_cache(tmp_path, identity) == binary
            source.write_bytes(b'modified')
            os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            for _ in range(8):
                assert _validate_cache(tmp_path, identity) == binary
    with pytest.raises(RuntimeError, match='cache-integrity'):
        _validate_cache(tmp_path, identity)


def test_build_identity_static_work_and_artifact_mutation(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from myfuzz.local_harness import build
    artifact = SimpleNamespace(document={'value': 1})
    calls = []
    def prepare(current, base):
        calls.append(1)
        return {'document': dict(current.document)}, {}
    monkeypatch.setattr(build, '_prepare', prepare)
    with pytest.raises(ExecutionValidationError):
        with execution_validation_scope():
            for _ in range(8):
                assert build.local_build_identity(artifact, base_dir=tmp_path) == {'document': {'value': 1}}
            assert len(calls) == 1
            artifact.document['value'] = 2
            with pytest.raises(RuntimeError, match='artifact-drift'):
                build.local_build_identity(artifact, base_dir=tmp_path)
    assert len(calls) == 2


def test_staging_cache_is_not_registered_for_exit(tmp_path):
    import hashlib
    import json
    from myfuzz.local_harness.build import _validate_cache
    stage = tmp_path / '.staging'
    stage.mkdir()
    final = tmp_path / 'digest'
    binary = stage / 'harness'
    binary.write_bytes(b'fake executable')
    binary.chmod(0o700)
    identity = {'build_digest': 'digest', 'inputs': []}
    (stage / 'manifest.json').write_text(json.dumps({
        'identity': identity,
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}))
    with execution_validation_scope():
        assert _validate_cache(stage, identity) == binary
        stage.rename(final)
        assert _validate_cache(final, identity) == final / 'harness'


@pytest.mark.parametrize('location', ['base_dir', 'cache_dir'])
def test_owner_locations_cannot_change_within_scope(mechanical_local, tmp_path, location):
    from myfuzz.local_harness.session import _native_reset_check_producers
    local = mechanical_local
    original = getattr(local, location)
    with execution_validation_scope():
        _native_reset_check_producers(local)
        setattr(local, location, tmp_path / 'different')
        try:
            with pytest.raises(ValueError, match='root or cache drift'):
                _native_reset_check_producers(local)
        finally:
            setattr(local, location, original)


def test_observer_exit_source_failure_remains_incomplete_after_restore(mechanical_local, tmp_path):
    import hashlib
    local = mechanical_local
    local.configure_native_reset_observation()
    source = tmp_path / 'extra-source.py'
    source.write_bytes(b'original')
    stamp = source.stat()
    local._native_reset_observation._sources[str(source)] = hashlib.sha256(b'original').hexdigest()
    with pytest.raises(ExecutionValidationError):
        with execution_validation_scope():
            local.begin_case('scoped')
            local.command('STEP_GPIO', (0,))
            local.end_case()
            source.write_bytes(b'modified')
            os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    source.write_bytes(b'original')
    assert local.native_reset_observation_snapshot()['status'] == 'incomplete'


@pytest.mark.parametrize('kind', ['source', 'tool'])
def test_build_identity_exit_reauthenticates_bytes(monkeypatch, tmp_path, kind):
    import hashlib
    from types import SimpleNamespace
    from myfuzz.local_harness import build
    artifact = SimpleNamespace(document={'fixed': True})
    path = tmp_path / kind
    path.write_bytes(b'original')
    stamp = path.stat()
    calls = []
    def prepare(current, root):
        calls.append(1)
        return {kind: hashlib.sha256(path.read_bytes()).hexdigest()}, {}
    monkeypatch.setattr(build, '_prepare', prepare)
    with pytest.raises(ExecutionValidationError):
        with execution_validation_scope():
            initial = build.local_build_identity(artifact, base_dir=tmp_path)
            path.write_bytes(b'modified')
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            for _ in range(8):
                assert build.local_build_identity(artifact, base_dir=tmp_path) == initial
            assert len(calls) == 1
    assert len(calls) == 2


def test_business_failure_preserves_verified_static_boundary():
    primary = RuntimeError('DUT mismatch')
    state = None
    with pytest.raises(RuntimeError) as caught:
        with execution_validation_scope() as state:
            pending = dict(state) if state is not None else None
            static_validation('source', lambda: b'fixed source')
            raise primary
    assert caught.value is primary
    assert pending == {'status': 'pending', 'matches': None}
    assert state == {'status': 'verified', 'matches': True}
    assert not hasattr(primary, '__notes__')
    assert execution_validation_active() is False


@pytest.mark.parametrize('business_failure', [False, True])
def test_static_failure_records_failed_boundary_and_preserves_primary(business_failure):
    identity = [b'original']
    primary = RuntimeError('DUT mismatch')
    state = None
    expected_error = RuntimeError if business_failure else ExecutionValidationError
    with pytest.raises(expected_error) as caught:
        with execution_validation_scope() as state:
            static_validation('source', lambda: identity[0])
            identity[0] = b'modified'
            if business_failure:
                raise primary
    assert state == {'status': 'failed', 'matches': False}
    if business_failure:
        assert caught.value is primary
        assert any('execution validation failed' in note for note in primary.__notes__)
    else:
        assert isinstance(caught.value, ExecutionValidationError)
    assert execution_validation_active() is False


def test_trusted_scope_checks_each_static_dependency_once():
    calls = []
    def validate():
        calls.append(1)
        return 'identity'
    with execution_validation_scope(revalidate=False) as state:
        for _ in range(20):
            assert static_validation('source', validate) == 'identity'
    assert calls == [1]
    assert state['status'] == 'verified'
    assert not execution_validation_active()


def test_static_comparison_preserves_snapshot_without_returning_it():
    from myfuzz.local_harness.execution_validation import static_validation_matches
    current = {'nested': [1]}
    calls = []
    def validate():
        calls.append(1)
        return current
    with execution_validation_scope():
        assert static_validation_matches('artifact', validate, current)
        assert static_validation_matches('artifact', validate, current)
        assert len(calls) == 1
        current['nested'].append(2)
        assert not static_validation_matches('artifact', validate, current)
        current['nested'].pop()
    assert len(calls) == 2


def test_build_identity_repeated_checks_do_not_copy_artifact(monkeypatch, tmp_path):
    from myfuzz.local_harness import build
    class Artifact:
        copies = 0
        def __init__(self, value):
            self.value = value
        def __deepcopy__(self, memo):
            type(self).copies += 1
            return type(self)(self.value)
        def __eq__(self, other):
            return isinstance(other, Artifact) and self.value == other.value
    artifact = Artifact(1)
    monkeypatch.setattr(build, '_prepare', lambda current, base: ({'value': current.value}, {}))
    with execution_validation_scope(revalidate=False):
        for _ in range(20):
            assert build.local_build_identity(artifact, base_dir=tmp_path) == {'value': 1}
        assert Artifact.copies == 2
        artifact.value = 2
        with pytest.raises(build.LocalHarnessBuildError, match='artifact-drift'):
            build.local_build_identity(artifact, base_dir=tmp_path)


def test_producer_code_is_revalidated_at_strict_exit(monkeypatch):
    from myfuzz.local_harness import session
    with pytest.raises(ExecutionValidationError):
        with execution_validation_scope():
            static_validation(('native-reset-producer-code',), session._validate_producer_static)
            monkeypatch.setattr(session, '_OPERATIONS', {})


def test_producer_static_checks_reused_but_instance_shadow_rejected(mechanical_local, monkeypatch):
    from myfuzz.local_harness import session
    local = mechanical_local
    original = session._validate_producer_static
    calls = []
    def counted():
        calls.append(1)
        return original()
    monkeypatch.setattr(session, '_validate_producer_static', counted)
    with execution_validation_scope():
        session._native_reset_check_producers(local)
        session._native_reset_check_producers(local)
        assert len(calls) == 1
        name = next(iter(session._NATIVE_RESET_SESSION_FUNCTIONS))
        monkeypatch.setattr(local, name, lambda *args: None)
        with pytest.raises(ValueError, match='drift'):
            session._native_reset_check_producers(local)
        monkeypatch.delattr(local, name)
    assert len(calls) == 2
