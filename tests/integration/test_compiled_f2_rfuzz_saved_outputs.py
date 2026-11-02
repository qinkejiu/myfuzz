"""Same-call byte integrity controls; fixtures grant no native authority."""
from copy import deepcopy
import json
from unittest.mock import patch
import pytest

NAMES = (
    'compiled_f2_prefix.json', 'compiled_f2_replay.json',
    'compiled_f2_fresh_prefix.json', 'compiled_f2_fresh_events.json',
    'compiled_f2_fresh_execution_audit.json', 'compiled_f2_fresh_verification.json',
    'compiled_f2_build_join.v1.json', 'compiled_f2_receipt_join.v1.json',
    'compiled_assertion_results.v1.json', 'compiled_assertion_evidence.v1.json',
)


def saved_f2_outcome(tmp_path):
    from myfuzz.integration.compiled_f2_saved_outputs import write_pinned_json
    outcome = dict(plan={'records': []}, replay=dict(matches=True,
        first_difference=None, verification_scope='full',
        actual_prefix={'records': []}, actual_events=[{'raw': 1}],
        execution_audit={'closed': True}), verification=dict(matches=True,
        first_difference=None, verification_scope='full'), build_join={'status': 'complete'},
        join={'flow': 'F2'}, assertion_material={'assertions': {'results': []},
        'assertion_evidence': {'cases': []}}, saved_output_hashes={},
        transport_files={}, harness_set={}, manifest={})
    from myfuzz.integration.compiled_f2_saved_outputs import expected_f2_documents
    docs = expected_f2_documents(outcome)
    for name, doc in docs.items():
        write_pinned_json(tmp_path / name, doc, outcome['saved_output_hashes'])
    from hashlib import sha256
    session = tmp_path / 'session'
    session.mkdir()
    for name in ('seed.bin', 'receipts.jsonl', 'online_session_manifest.json', 'online_plan.json', 'online_final_trace.json'):
        path = session / name
        path.write_bytes(b'{}')
        outcome['transport_files'][str(path)] = sha256(path.read_bytes()).hexdigest()
    return outcome, deepcopy(docs)


@pytest.mark.parametrize('name', NAMES)
@pytest.mark.parametrize('change', ('semantic', 'format'))
def test_saved_substitution_refuses_before_build_material_join(tmp_path, name, change):
    from myfuzz.integration.compiled_f2_saved_outputs import verify_saved_compiled_f2_build_outputs
    outcome, docs = saved_f2_outcome(tmp_path)
    value = docs[name]
    if change == 'semantic':
        value = value + [{'changed': True}] if isinstance(value, list) else dict(value, changed=True)
    (tmp_path / name).write_text(json.dumps(value, indent=4) + '\n')
    with patch('myfuzz.integration.compiled_f2_build_join.verify_compiled_f2_build_material') as check:
        with pytest.raises(ValueError, match='mismatch|bytes-changed'):
            verify_saved_compiled_f2_build_outputs(tmp_path, outcome=outcome,
                harness_set={}, manifest={})
        check.assert_not_called()


def test_clean_documents_reach_actual_build_material_verifier(tmp_path):
    from myfuzz.integration.compiled_f2_saved_outputs import verify_saved_compiled_f2_build_outputs
    outcome, docs = saved_f2_outcome(tmp_path)
    with patch('myfuzz.integration.compiled_f2_build_join.verify_compiled_f2_build_material') as check:
        hashes = verify_saved_compiled_f2_build_outputs(tmp_path, outcome=outcome,
            harness_set={}, manifest={})
        assert set(hashes) == set(docs) | set(outcome['transport_files'])
        check.assert_called_once_with(outcome['build_join'], harness_set={}, manifest={},
            prefix=outcome['plan'], replay=docs['compiled_f2_replay.json'])


@pytest.mark.parametrize('key', ('actual_prefix', 'actual_events', 'execution_audit'))
def test_missing_fresh_material_refuses(tmp_path, key):
    from myfuzz.integration.compiled_f2_saved_outputs import verify_saved_compiled_f2_build_outputs
    outcome, _ = saved_f2_outcome(tmp_path)
    del outcome['replay'][key]
    with pytest.raises(ValueError, match='fresh-material-required'):
        verify_saved_compiled_f2_build_outputs(tmp_path, outcome=outcome,
            harness_set={}, manifest={})


def test_atomic_writer_never_rebases_an_existing_initial_pin(tmp_path):
    from myfuzz.integration.compiled_f2_saved_outputs import write_pinned_json
    pins = {}
    path = tmp_path / 'document.json'
    write_pinned_json(path, {'original': True}, pins)
    before = path.read_bytes(), dict(pins)
    with pytest.raises(ValueError, match='already-pinned'):
        write_pinned_json(path, {'substituted': True}, pins)
    assert (path.read_bytes(), pins) == before


def test_transport_bytes_checked_before_material_join(tmp_path):
    from hashlib import sha256
    from myfuzz.integration.compiled_f2_saved_outputs import verify_saved_compiled_f2_build_outputs
    outcome, _ = saved_f2_outcome(tmp_path)
    receipts = tmp_path / 'session' / 'receipts.jsonl'
    receipts.write_bytes(b'original\n')
    outcome['transport_files'][str(receipts)] = sha256(receipts.read_bytes()).hexdigest()
    receipts.write_bytes(b'substituted\n')
    with patch('myfuzz.integration.compiled_f2_build_join.verify_compiled_f2_build_material') as check:
        with pytest.raises(ValueError, match='transport-bytes-changed'):
            verify_saved_compiled_f2_build_outputs(tmp_path, outcome=outcome,
                harness_set={}, manifest={})
        check.assert_not_called()


def test_fresh_exports_continue_after_one_export_fails(tmp_path, monkeypatch):
    import myfuzz.integration.compiled_f2_saved_outputs as mod
    outcome, _ = saved_f2_outcome(tmp_path)
    attempted = []
    primary = OSError('raw export unavailable')
    def write(path, value, pins):
        attempted.append(path.name)
        if path.name == 'compiled_f2_fresh_events.json':
            raise primary
        if path.name == 'compiled_f2_fresh_prefix.json':
            raise OSError('prefix export unavailable')
    monkeypatch.setattr(mod, 'write_pinned_json', write)
    with pytest.raises(OSError) as caught:
        mod.save_f2_replay_outputs(tmp_path, outcome['replay'], {})
    assert caught.value is primary
    assert attempted == ['compiled_f2_fresh_events.json', 'compiled_f2_fresh_prefix.json',
        'compiled_f2_fresh_execution_audit.json', 'compiled_f2_replay.json']
    assert any('prefix export unavailable' in note for note in primary.__notes__)


def test_atomic_writer_cleanup_preserves_original_error(tmp_path, monkeypatch):
    import myfuzz.integration.compiled_f2_saved_outputs as mod
    primary, secondary = OSError('replace failed'), OSError('cleanup failed')
    def replace(*args):
        raise primary
    def unlink(*args):
        raise secondary
    monkeypatch.setattr(mod.os, 'replace', replace)
    monkeypatch.setattr(mod.os, 'unlink', unlink)
    with pytest.raises(OSError) as caught:
        mod.write_pinned_json(tmp_path / 'output.json', {}, {})
    assert caught.value is primary
    assert any('cleanup failed' in note for note in primary.__notes__)


def test_success_cannot_omit_transport_pins(tmp_path):
    from myfuzz.integration.compiled_f2_saved_outputs import verify_saved_compiled_f2_build_outputs
    outcome, _ = saved_f2_outcome(tmp_path)
    outcome.pop('transport_files')
    with patch('myfuzz.integration.compiled_f2_build_join.verify_compiled_f2_build_material'):
        with pytest.raises(ValueError, match='transport.*required'):
            verify_saved_compiled_f2_build_outputs(tmp_path, outcome=outcome,
                harness_set={}, manifest={})
