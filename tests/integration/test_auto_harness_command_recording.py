import json
from types import SimpleNamespace

import pytest

from scripts.auto_harness_test import save_command_recordings


def _identity(component, nonce, pid):
    return dict(component=component, execution_nonce=nonce, pid=pid,
                build_digest='b' * 64, binary_sha256='c' * 64,
                artifact_digest='d' * 64)


def test_recordings_join_original_and_fresh_by_execution_nonce(tmp_path):
    original = _identity('peripheral', 'a' * 32, 1)
    fresh = _identity('peripheral', 'f' * 32, 2)
    join = {phase: {'execution_audit': {'identities': {'peripheral': identity}}}
            for phase, identity in (('original', original), ('fresh', fresh))}
    (tmp_path / 'compiled_f4_build_join.v1.json').write_text(json.dumps(join))
    rows = [dict(component='peripheral', identity=identity, complete=True,
                 records=[{'command': label}])
            for identity, label in ((fresh, 'fresh'), (original, 'original'))]
    save_command_recordings(tmp_path, SimpleNamespace(export_sessions=lambda: rows))
    actual = json.loads((tmp_path / 'local_commands.json').read_text())
    replay = json.loads((tmp_path / 'fresh_local_commands.json').read_text())
    assert actual['sessions']['peripheral']['records'][0]['command'] == 'original'
    assert replay['sessions']['peripheral']['records'][0]['command'] == 'fresh'


def test_recordings_refuse_missing_audited_session(tmp_path):
    identity = _identity('peripheral', 'a' * 32, 1)
    join = {phase: {'execution_audit': {'identities': {'peripheral': identity}}}
            for phase in ('original', 'fresh')}
    (tmp_path / 'compiled_f4_build_join.v1.json').write_text(json.dumps(join))
    with pytest.raises(ValueError, match='recorded trace'):
        save_command_recordings(tmp_path, SimpleNamespace(export_sessions=lambda: []))


def test_incomplete_capture_is_preserved_for_coverage_refusal(tmp_path):
    original = _identity('peripheral', 'a' * 32, 1)
    fresh = _identity('peripheral', 'f' * 32, 2)
    join = {phase: {'execution_audit': {'identities': {'peripheral': identity}}}
            for phase, identity in (('original', original), ('fresh', fresh))}
    (tmp_path / 'compiled_f4_build_join.v1.json').write_text(json.dumps(join))
    rows = [dict(component='peripheral', identity=identity, complete=False, records=[])
            for identity in (original, fresh)]
    save_command_recordings(tmp_path, SimpleNamespace(export_sessions=lambda: rows))
    result = json.loads((tmp_path / 'local_commands.json').read_text())
    assert result['sessions']['peripheral']['complete'] is False
