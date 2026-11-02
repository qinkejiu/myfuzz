"""Initial byte commitments remain authoritative after coherent JSON changes."""
import json
from hashlib import sha256
import pytest

def test_first_writer_pins_formatting_and_refuses_repin(tmp_path):
    from myfuzz.integration.compiled_f6_saved_outputs import write_pinned_json, verify_pins
    pins={}; path=tmp_path/'typed.json'
    write_pinned_json(path,{'a':1},pins)
    first=dict(pins);verify_pins(tmp_path,pins)
    path.write_text('{"a":1}')
    with pytest.raises(ValueError,match='bytes-changed'): verify_pins(tmp_path,pins)
    assert pins==first
    with pytest.raises(ValueError,match='already-pinned'):write_pinned_json(path,{'a':2},pins)

def test_failed_outcome_never_enters_success_verifier(tmp_path):
    from myfuzz.integration.compiled_f6_saved_outputs import verify_saved_compiled_f6_build_outputs
    with pytest.raises(ValueError,match='success-required'):
        verify_saved_compiled_f6_build_outputs(tmp_path,outcome={'plan':{'completed':False}},harness_set={},manifest={})

def test_transport_first_writer_never_rebases_bytes():
    from myfuzz.integration.scenario_rfuzz_live import _commit_f6_bytes
    context={}
    _commit_f6_bytes(context,'typed.json',b'{"a":1}\n')
    with pytest.raises(ValueError,match='first-writer'):
        _commit_f6_bytes(context,'typed.json',b'{"a":1} ')
    assert context['f6_initial_bytes']['typed.json']==sha256(b'{"a":1}\n').hexdigest()

from copy import deepcopy
from types import SimpleNamespace
from tests.integration.test_compiled_f6_build_join import admitted

@pytest.fixture
def saved_outcome(admitted,tmp_path):
    from myfuzz.integration.compiled_f6_build_join import build_compiled_f6_build_join
    from myfuzz.integration.compiled_f6_saved_outputs import expected_f6_documents,write_pinned_json
    from myfuzz.scenario.f6_assertion_evidence import build_f6_assertion_material
    binding=deepcopy(admitted['execution_binding'])
    class RuntimeScope:
        def __init__(self,**values):self.__dict__.update(values)
    scope=RuntimeScope(compiled_document_sha256=binding['compiled_document_sha256'],
        binding_sha256=binding['binding_sha256'],execution_binding_sha256=binding['binding_sha256'],
        path=binding['runtime_path_admission']['logical_path'],run_id=binding['run_id'],admitted_attempts=())
    material=build_f6_assertion_material(scope)
    material['assertion_evidence']=dict(execution_binding=binding,path_id=binding['path_id'],run_id=binding['run_id'],
        cases=material['assertion_evidence']['cases'])
    artifacts=admitted['artifacts'];digests={c:a.runtime_document['artifact_digest'] for c,a in artifacts.items()}
    plan=dict(completed=True,scope='full',records=[],execution_binding=binding,original_build=admitted['original'],artifact_digests=digests)
    replay=dict(matches=True,first_difference=None,verification_scope='full',actual_prefix=deepcopy(plan),actual_events=[],
        execution_audit=admitted['fresh']['execution_audit'],fresh_build=admitted['fresh'])
    manifest={'source_backed_fixture':True}
    runtime=SimpleNamespace(artifacts=artifacts,execution_binding=binding,session=SimpleNamespace(manifest_document=manifest))
    outcome=dict(plan=plan,replay=replay,verification=dict(matches=True,first_difference=None,verification_scope='full'),
        build_join=build_compiled_f6_build_join(**admitted),join={},assertion_material=material,saved_output_hashes={},runtime=runtime)
    for name,value in expected_f6_documents(outcome).items():write_pinned_json(tmp_path/name,value,outcome['saved_output_hashes'])
    session=tmp_path/'session';session.mkdir()
    for name in ('seed.bin','receipts.jsonl','online_session_manifest.json','online_plan.json','online_final_trace.json'):
        (session/name).write_bytes(b'{}')
    outcome['transport_files']={str(p):sha256(p.read_bytes()).hexdigest() for p in session.iterdir()}
    harness={'components':[{'instance_id':c,'artifact_digest':d} for c,d in digests.items()]}
    return outcome,harness,manifest

def test_source_backed_saved_join_validates_actual_build_snapshots(tmp_path,saved_outcome):
    from myfuzz.integration.compiled_f6_saved_outputs import verify_saved_compiled_f6_build_outputs
    outcome,harness,manifest=saved_outcome
    hashes=verify_saved_compiled_f6_build_outputs(tmp_path,outcome=outcome,harness_set=harness,manifest=manifest)
    assert len(hashes)==15

@pytest.mark.parametrize('name',['compiled_f6_prefix.json','compiled_f6_replay.json','compiled_f6_fresh_prefix.json',
    'compiled_f6_fresh_events.json','compiled_f6_fresh_execution_audit.json','compiled_f6_fresh_verification.json',
    'compiled_f6_build_join.v1.json','compiled_f6_receipt_join.v1.json',
    'compiled_assertion_results.v1.json','compiled_assertion_evidence.v1.json'])
def test_late_formatting_never_rebases_initial_pins(tmp_path,saved_outcome,name):
    from myfuzz.integration.compiled_f6_saved_outputs import verify_saved_compiled_f6_build_outputs
    outcome,harness,manifest=saved_outcome
    path=tmp_path/name;path.write_bytes(path.read_bytes()+b' ')
    with pytest.raises(ValueError,match='bytes-changed'):
        verify_saved_compiled_f6_build_outputs(tmp_path,outcome=outcome,harness_set=harness,manifest=manifest)

def test_expected_error_uses_independent_failed_prefix_verifier(tmp_path,saved_outcome):
    from myfuzz.integration.compiled_f6_saved_outputs import (expected_f6_failed_prefix_documents,
        verify_saved_compiled_f6_failed_prefix_outputs,verify_saved_compiled_f6_build_outputs,write_pinned_json)
    outcome,harness,manifest=saved_outcome
    outcome['plan'].update(completed=False,scope='failed_prefix_full',status='expected_error')
    outcome['replay']['actual_prefix'].update(completed=False,scope='failed_prefix_full',status='expected_error')
    outcome['replay']['verification_scope']='failed_prefix_full'
    outcome['verification']['verification_scope']='failed_prefix_full'
    outcome['saved_output_hashes']={}
    target=tmp_path/'failed'
    for name,value in expected_f6_failed_prefix_documents(outcome).items():
        write_pinned_json(target/name,value,outcome['saved_output_hashes'])
    with pytest.raises(ValueError,match='success-required'):
        verify_saved_compiled_f6_build_outputs(target,outcome=outcome,harness_set=harness,manifest=manifest)
    hashes=verify_saved_compiled_f6_failed_prefix_outputs(target,outcome=outcome,harness_set=harness,manifest=manifest)
    assert 'compiled_f6_fresh_verification.json' in hashes


def test_stream_writer_preserves_legacy_bytes_without_whole_document_render(tmp_path, monkeypatch):
    import hashlib
    import json
    from myfuzz.integration import compiled_f6_saved_outputs as saved
    value = {'unicode': '中文\n☃', 'nested': [{'n': n, 'v': [None, True, -0.0]} for n in range(50)]}
    expected = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    def forbidden(*args, **kwargs):
        raise AssertionError('whole-document JSON render')
    monkeypatch.setattr(saved.json, 'dumps', forbidden)
    pins = {}
    path = saved.write_pinned_json(tmp_path/'evidence.json', value, pins)
    assert path.read_bytes() == expected
    assert pins == {'evidence.json': hashlib.sha256(expected).hexdigest()}


def test_stream_writer_encoding_failure_preserves_target_and_removes_temporary(tmp_path):
    from myfuzz.integration.compiled_f6_saved_outputs import write_pinned_json
    path = tmp_path/'evidence.json'
    path.write_bytes(b'old')
    pins = {}
    with pytest.raises(ValueError):
        write_pinned_json(path, {'events': list(range(20000)), 'invalid': float('nan')}, pins)
    assert path.read_bytes() == b'old'
    assert pins == {}
    assert list(tmp_path.iterdir()) == [path]


def test_stream_writer_checks_bytes_after_replace(tmp_path, monkeypatch):
    from myfuzz.integration import compiled_f6_saved_outputs as saved
    replace = saved.os.replace
    def corrupt(source, target):
        replace(source, target)
        target.write_bytes(b'corrupt')
    monkeypatch.setattr(saved.os, 'replace', corrupt)
    pins = {}
    with pytest.raises(ValueError, match='initial-bytes'):
        saved.write_pinned_json(tmp_path/'evidence.json', {'ok': True}, pins)
    assert not pins
    assert sorted(p.name for p in tmp_path.iterdir()) == ['evidence.json']
