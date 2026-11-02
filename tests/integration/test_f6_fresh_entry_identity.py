"""The saved F6 replay entry identifies the code-owned caller route."""

import pytest

from myfuzz.integration.compiled_f6_rfuzz_session import f6_fresh_verification


def _materials():
    plan = {'completed': True, 'semantic_hash': 'original', 'records': [{}]}
    replay = {'matches': True, 'first_difference': None, 'verification_scope': 'full',
              'actual_prefix': {'semantic_hash': 'fresh'}, 'actual_events': [{}],
              'execution_audit': {'closed': True}}
    return replay, plan


def test_rfuzz_default_entry_is_unchanged():
    replay, plan = _materials()
    result = f6_fresh_verification(replay, plan)
    assert result['replay_entry'] == (
        'myfuzz.integration.compiled_f6_rfuzz:run_compiled_f6_rfuzz_session')


def test_directed_file_entry_names_the_real_route():
    replay, plan = _materials()
    result = f6_fresh_verification(replay, plan, route='directed_file')
    assert result['replay_entry'] == (
        'myfuzz.integration.compiled_execution_files:run_compiled_execution_files')
    assert result['matches'] is True and result['verification_scope'] == 'full'


def test_directed_file_route_selects_its_registered_entry(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from myfuzz.integration import compiled_execution_files as files, compiled_f6, compiled_f6_rfuzz_session as session
    from myfuzz.local_harness import generated_artifact_admission as admission

    class Runtime:
        finished = True
        execution_binding = {}
        def __init__(self, **kwargs): pass
        def submit(self, raw): pass
        def finish(self): return {'completed': True}
        def replay(self, plan, *, audit_sink): return {}
        def execution_audit(self): return {}

    seen = []
    def verification(replay, plan, *, route):
        seen.append(route)
        raise RuntimeError('verification-reached')

    monkeypatch.setattr(compiled_f6, 'CompiledF6Runtime', Runtime)
    monkeypatch.setattr(session, 'f6_fresh_verification', verification)
    monkeypatch.setattr(admission, 'validated_f6_provider_credentials',
                        lambda *args, **kwargs: {'file_pins': {}})
    monkeypatch.setattr(files, '_worker_lock', lambda path: nullcontext())
    from myfuzz.integration import compiled_f6_saved_outputs
    monkeypatch.setattr(compiled_f6_saved_outputs, 'write_pinned_json', lambda *args: None)
    with pytest.raises(RuntimeError, match='verification-reached'):
        files._run_f6_file_route_owned(output=tmp_path, marker=tmp_path / '.incomplete',
            report={}, artifacts={}, inputs={}, base=tmp_path, cache_dir=tmp_path,
            run_id='test', rounds=1, max_cases=1, replay_count=1,
            records=['0000000000000000'], lock_path=tmp_path / 'lock', check_sources=lambda: None)
    assert seen == ['directed_file']


@pytest.mark.parametrize('route', [None, True, '', 'rfuzz:other',
                                   'myfuzz.integration.compiled_f6:CompiledF6Runtime.replay'])
def test_unregistered_or_caller_selected_entry_is_rejected(route):
    replay, plan = _materials()
    with pytest.raises(ValueError, match='compiled-F6-replay-entry-unsupported'):
        f6_fresh_verification(replay, plan, route=route)


def test_zero_replay_file_route_keeps_original_and_omits_fresh_artifacts(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from myfuzz.integration import compiled_execution_files as files, compiled_f6, compiled_f6_saved_outputs as saved
    from myfuzz.local_harness import generated_artifact_admission as admission
    from myfuzz.scenario import f6_assertion_evidence, capability_report
    from myfuzz.integration import compiled_f6_layout
    calls = []
    raw = bytes(8)
    plan = {'completed': True, 'records': [{'case_id':'case','raw8_hex':raw.hex(), 'words':[], 'prefix_hex':'00'}],
        'original_build': {'real':'build'}, 'original_execution_audit': {'closed': True}}
    class Runtime:
        finished = True
        execution_binding = {}
        path = {'path_id':'path','sources':[]}
        program = SimpleNamespace(prefix=lambda *a, **kw: b'\x00')
        def __init__(self, **kwargs): pass
        def submit(self, raw): calls.append('submit')
        def finish(self): calls.append('finish'); return plan
        def replay(self, *a, **kw): pytest.fail('search must not replay')
        def execution_audit(self): return {'closed':True}
    monkeypatch.setattr(compiled_f6, 'CompiledF6Runtime', Runtime)
    monkeypatch.setattr(admission, 'validated_f6_provider_credentials', lambda *a, **kw: {'file_pins':{}})
    monkeypatch.setattr(files, '_worker_lock', lambda p: nullcontext())
    documents = {}
    monkeypatch.setattr(saved, 'write_pinned_json', lambda path, doc, pins: documents.update({path.name:doc}))
    monkeypatch.setattr(saved, 'verify_pins', lambda *a: None)
    monkeypatch.setattr(f6_assertion_evidence, 'build_f6_assertion_material', lambda runtime: {
        'assertions':{'cases':[{'case_id':'case'}]},'assertion_evidence':{'cases':[]}})
    monkeypatch.setattr(compiled_f6_layout, 'compile_f6_candidate_layout', lambda path: SimpleNamespace(
        decode=lambda raw: SimpleNamespace(raw=raw, words=[])))
    monkeypatch.setattr(capability_report, 'build_capability_report', lambda *a, **kw: {})
    monkeypatch.setattr(files, '_read', lambda p: {})
    marker=tmp_path/'.incomplete'; marker.touch()
    result=files._run_f6_file_route_owned(output=tmp_path, marker=marker, report={}, artifacts={},
        inputs={'compiled':{}}, base=tmp_path, cache_dir=tmp_path, run_id='test', rounds=1,
        max_cases=1, replay_count=0, records=[raw.hex()], lock_path=tmp_path/'lock', check_sources=lambda:None)
    assert calls == ['submit','finish']
    assert result['fresh_verification'] is None and result['replay_matches'] is None
    assert result['verification']['within_invocation']['status'] == 'not-requested'
    assert documents['compiled_f6_prefix.json'] is plan
    assert not any('fresh' in name or 'build_join' in name for name in documents)
