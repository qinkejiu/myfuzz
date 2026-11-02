"""The CLI must validate the saved documents whose byte digests it publishes."""
from copy import deepcopy
from hashlib import sha256
import json
from unittest.mock import patch
from types import SimpleNamespace

import pytest


def saved_outcome(tmp_path):
    outcome={'build_join':{'status':'complete'},'plan':{'path':'selected'},
        'replay':{'matches':True,'actual_prefix':{'path':'fresh'},
            'actual_events':[{'event_id':1,'native':'raw'}],
            'execution_audit':{'closed':True}},'verification':{'matches':True}}
    docs={'compiled_f4_build_join.v1.json':deepcopy(outcome['build_join']),
        'compiled_f4_prefix.json':deepcopy(outcome['plan']),
        'compiled_f4_replay.json':{'matches':True,'actual_event_count':1,
            'execution_audit':{'closed':True}},
        'compiled_f4_fresh_prefix.json':deepcopy(outcome['replay']['actual_prefix']),
        'compiled_f4_fresh_events.json':deepcopy(outcome['replay']['actual_events']),
        'compiled_f4_fresh_execution_audit.json':deepcopy(outcome['replay']['execution_audit']),
        'compiled_f4_fresh_verification.json':deepcopy(outcome['verification'])}
    for name,doc in docs.items():(tmp_path/name).write_text(json.dumps(doc)+'\n')
    outcome['saved_output_hashes']={name:sha256((tmp_path/name).read_bytes()).hexdigest()
        for name in docs}
    return outcome,docs


@pytest.mark.parametrize('changed',['none','join','prefix','replay','fresh_prefix',
    'fresh_events','fresh_audit','verification'])
def test_saved_outputs_match_same_call_before_material_verification(tmp_path,changed):
    from myfuzz.integration.compiled_rfuzz import verify_saved_compiled_f4_build_outputs
    outcome,docs=saved_outcome(tmp_path)
    if changed!='none':
        name={'join':'compiled_f4_build_join.v1.json','prefix':'compiled_f4_prefix.json',
            'replay':'compiled_f4_replay.json','fresh_prefix':'compiled_f4_fresh_prefix.json',
            'fresh_events':'compiled_f4_fresh_events.json',
            'fresh_audit':'compiled_f4_fresh_execution_audit.json',
            'verification':'compiled_f4_fresh_verification.json'}[changed]
        replacement=([{'substituted':True}] if changed=='fresh_events'
            else dict(docs[name],substituted=True))
        (tmp_path/name).write_text(json.dumps(replacement)+'\n')
    with patch('myfuzz.integration.compiled_f4_build_join.verify_compiled_f4_build_material') as check:
        if changed=='none':
            hashes=verify_saved_compiled_f4_build_outputs(tmp_path,outcome=outcome,harness_set={},manifest={})
            assert set(hashes)==set(docs)
            assert hashes['compiled_f4_build_join.v1.json']==sha256((tmp_path/'compiled_f4_build_join.v1.json').read_bytes()).hexdigest()
            check.assert_called_once()
        else:
            with pytest.raises(ValueError,match='saved.*build|saved.*output'):
                verify_saved_compiled_f4_build_outputs(tmp_path,outcome=outcome,harness_set={},manifest={})
            check.assert_not_called()


@pytest.mark.parametrize('name',['compiled_f4_fresh_prefix.json',
    'compiled_f4_fresh_events.json','compiled_f4_fresh_execution_audit.json',
    'compiled_f4_fresh_verification.json'])
def test_later_format_only_change_rejects_initial_byte_pin(tmp_path,name):
    from myfuzz.integration.compiled_rfuzz import verify_saved_compiled_f4_build_outputs
    outcome,docs=saved_outcome(tmp_path)
    (tmp_path/name).write_text(json.dumps(docs[name],indent=4)+'\n')
    with patch('myfuzz.integration.compiled_f4_build_join.verify_compiled_f4_build_material') as check:
        with pytest.raises(ValueError,match='saved.*output'):
            verify_saved_compiled_f4_build_outputs(tmp_path,outcome=outcome,harness_set={},manifest={})
        check.assert_not_called()


@pytest.mark.parametrize('key',['actual_prefix','actual_events','execution_audit'])
def test_successful_saved_verification_requires_fresh_material(tmp_path,key):
    from myfuzz.integration.compiled_rfuzz import verify_saved_compiled_f4_build_outputs
    outcome,_=saved_outcome(tmp_path);del outcome['replay'][key]
    with patch('myfuzz.integration.compiled_f4_build_join.verify_compiled_f4_build_material') as check:
        with pytest.raises(ValueError,match='fresh.*required|saved.*output'):
            verify_saved_compiled_f4_build_outputs(tmp_path,outcome=outcome,harness_set={},manifest={})
        check.assert_not_called()


def run_saved_session(tmp_path,monkeypatch,*,replay_error=None):
    """Exercise the real orchestration callback; no native/runtime authority."""
    from myfuzz.integration import compiled_rfuzz as mod
    output=tmp_path/'output';output.mkdir();cache=tmp_path/'cache';cache.mkdir()
    plan={'records':[],'semantic_hash':'same'}
    envelope={'matches':True,'actual_semantic_hash':'same',
        'actual_prefix':deepcopy(plan),'actual_events':[{'event_id':1,'raw':True}],
        'execution_audit':{'closed':True,'identities':{}},
        'original_build':{},'fresh_build':{}}
    if replay_error:
        envelope={'error_type':type(replay_error).__name__,'error':str(replay_error),
            'actual_events':[{'event_id':1,'partial':True}],
            'execution_audit':{'closed':True}}
    class SoftwareRuntime:
        finished=False
        execution_binding=SimpleNamespace(document=lambda:{'path_id':'selected','runtime_path_id':'runtime'})
        def __init__(self,**kwargs):pass
        def finish(self):self.finished=True;return deepcopy(plan)
        def build_audit_snapshot(self):return {}
        def replay(self,plan,*,audit_sink):
            audit_sink(deepcopy(envelope))
            if replay_error:raise replay_error
            return deepcopy(envelope)
    monkeypatch.setattr(mod,'CompiledF4Runtime',SoftwareRuntime)
    monkeypatch.setattr(mod,'build_compiled_rfuzz_executor',lambda *args,**kw:object())
    monkeypatch.setattr(mod,'compiled_document_sha256',lambda doc:'a'*64)
    monkeypatch.setattr(mod,'join_compiled_receipts',lambda *args:{'status':'ok'})
    monkeypatch.setattr('myfuzz.integration.scenario_rfuzz_live.run_scenario_rfuzz_live',
        lambda **kw:SimpleNamespace(client_returncode=0))
    monkeypatch.setattr('myfuzz.integration.compiled_f4_build_join.build_compiled_f4_build_join',
        lambda **kw:{'status':'refused' if kw.get('error') else 'complete'})
    monkeypatch.setattr('myfuzz.integration.compiled_f4_build_join.verify_compiled_f4_build_join',lambda *args,**kw:None)
    kwargs=dict(artifacts={},compiled_inputs={'compiled':{}},base_dir=tmp_path,
        cache_dir=cache,run_id='software',session_dir=tmp_path/'session',output_dir=output,
        client_binary=tmp_path/'no-client',budget_seconds=1,max_tests=1,search_seed=1,max_runs_per_batch=1)
    return mod,output,envelope,kwargs


def test_real_save_callback_retains_raw_events_and_returns_initial_pins(tmp_path,monkeypatch):
    mod,output,envelope,kwargs=run_saved_session(tmp_path,monkeypatch)
    outcome=mod.run_compiled_f4_rfuzz_session(**kwargs)
    assert json.loads((output/'compiled_f4_fresh_events.json').read_text())==envelope['actual_events']
    with patch('myfuzz.integration.compiled_f4_build_join.verify_compiled_f4_build_material'):
        hashes=mod.verify_saved_compiled_f4_build_outputs(output,outcome=outcome,harness_set={},manifest={})
    assert hashes==outcome['saved_output_hashes']


def test_client_failure_is_reported_before_replay_or_receipt_join(tmp_path, monkeypatch):
    mod, output, _, kwargs = run_saved_session(tmp_path, monkeypatch)
    monkeypatch.setattr('myfuzz.integration.scenario_rfuzz_live.run_scenario_rfuzz_live',
                        lambda **kw: SimpleNamespace(client_returncode=1))
    monkeypatch.setattr(mod, 'join_compiled_receipts',
                        lambda *a: pytest.fail('receipt join should not run'))
    with pytest.raises(ValueError, match='compiled-F4-rfuzz-client-exit:1'):
        mod.run_compiled_f4_rfuzz_session(**kwargs)
    assert not (output / 'compiled_f4_fresh_prefix.json').exists()


def test_failed_replay_preserves_primary_and_available_partial_raw(tmp_path,monkeypatch):
    primary=ValueError('primary native replay failure')
    mod,output,envelope,kwargs=run_saved_session(tmp_path,monkeypatch,replay_error=primary)
    with pytest.raises(ValueError) as caught:mod.run_compiled_f4_rfuzz_session(**kwargs)
    assert caught.value is primary
    assert json.loads((output/'compiled_f4_fresh_events.json').read_text())==envelope['actual_events']
    assert json.loads((output/'compiled_f4_fresh_execution_audit.json').read_text())==envelope['execution_audit']
    assert not (output/'compiled_f4_fresh_prefix.json').exists()


def test_raw_and_audit_survive_another_replay_output_write_failure(tmp_path,monkeypatch):
    mod,output,envelope,kwargs=run_saved_session(tmp_path,monkeypatch)
    original=mod._write_json
    def write(path,value):
        if path.name=='compiled_f4_fresh_prefix.json':raise OSError('prefix export failed')
        return original(path,value)
    monkeypatch.setattr(mod,'_write_json',write)
    with pytest.raises(OSError,match='prefix export failed'):
        mod.run_compiled_f4_rfuzz_session(**kwargs)
    assert json.loads((output/'compiled_f4_fresh_events.json').read_text())==envelope['actual_events']
    assert json.loads((output/'compiled_f4_fresh_execution_audit.json').read_text())==envelope['execution_audit']
    assert (output/'compiled_f4_replay.json').exists()


@pytest.mark.parametrize('kind',['semantic','format'])
def test_initial_writer_rejects_changed_bytes_instead_of_rebaselining(tmp_path,monkeypatch,kind):
    mod,output,envelope,kwargs=run_saved_session(tmp_path,monkeypatch)
    original=mod._write_json
    def write(path,value):
        result=original(path,value)
        if path.name=='compiled_f4_fresh_events.json':
            altered=[{'substituted':True}] if kind=='semantic' else value
            path.write_text(json.dumps(altered,indent=4)+'\n')
        return result
    monkeypatch.setattr(mod,'_write_json',write)
    with pytest.raises(ValueError,match='saved.*output'):
        mod.run_compiled_f4_rfuzz_session(**kwargs)


def test_saved_verification_requires_initial_same_call_byte_pins(tmp_path):
    from myfuzz.integration.compiled_rfuzz import verify_saved_compiled_f4_build_outputs
    outcome,_=saved_outcome(tmp_path);del outcome['saved_output_hashes']['compiled_f4_fresh_events.json']
    with patch('myfuzz.integration.compiled_f4_build_join.verify_compiled_f4_build_material') as check:
        with pytest.raises(ValueError,match='saved.*output'):
            verify_saved_compiled_f4_build_outputs(tmp_path,outcome=outcome,harness_set={},manifest={})
        check.assert_not_called()


@pytest.mark.parametrize('key',['actual_events','actual_prefix','execution_audit'])
def test_run_cannot_return_success_with_missing_fresh_material(tmp_path,monkeypatch,key):
    mod,output,envelope,kwargs=run_saved_session(tmp_path,monkeypatch)
    del envelope[key]
    with pytest.raises(ValueError,match='fresh.*required|saved.*output'):
        mod.run_compiled_f4_rfuzz_session(**kwargs)
