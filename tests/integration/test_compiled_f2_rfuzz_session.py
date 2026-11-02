"""F2 RFuzz lifecycle controls. Software doubles never confer native authority."""
from copy import deepcopy
from types import SimpleNamespace
import pytest


def test_fresh_document_requires_actual_full_success():
    from myfuzz.integration.compiled_f2_rfuzz_session import f2_fresh_verification
    replay = dict(matches=True, first_difference=None, verification_scope='full',
        scope='full_fresh_prefix_real_RTL_and_live_read_versions', actual_prefix={},
        actual_events=[], execution_audit={'closed': True}, actual_semantic_hash='same')
    plan = {'semantic_hash': 'same', 'records': []}
    document = f2_fresh_verification(replay, plan)
    assert document['verification_scope'] == replay['verification_scope']
    assert document['verification_scope_basis'] == replay['scope']
    assert document['matches'] is True
    for key, replacement in [('matches', False), ('first_difference', '/raw'),
                             ('verification_scope', None), ('actual_events', None),
                             ('execution_audit', {'closed': False})]:
        altered = deepcopy(replay)
        altered[key] = replacement
        with pytest.raises(ValueError, match='full-fresh|fresh-material'):
            f2_fresh_verification(altered, plan)


def test_session_pin_collection_requires_transport_and_actual_trace(tmp_path):
    from myfuzz.integration.compiled_f2_rfuzz_session import pin_f2_session_files
    names = ['seed.bin', 'receipts.jsonl', 'online_session_manifest.json',
             'online_plan.json', 'online_final_trace.json']
    for name in names:
        (tmp_path / name).write_bytes(b'{}')
    hashes = pin_f2_session_files(tmp_path)
    assert set(hashes) == {str(tmp_path / name) for name in names}
    (tmp_path / 'seed.bin').unlink()
    with pytest.raises(ValueError, match='transport-file-required'):
        pin_f2_session_files(tmp_path)


def software_session(tmp_path, monkeypatch, *, replay_error=None, client_returncode=0):
    import json
    import myfuzz.integration.compiled_f2_rfuzz_session as mod
    output = tmp_path / 'out'; output.mkdir()
    (output / 'generated').mkdir()
    (output / 'generated' / 'harness_set.json').write_text('{}')
    session = output / 'session'; session.mkdir()
    cache = tmp_path / 'cache'; cache.mkdir()
    calls = []
    from myfuzz.scenario.replay import ScenarioTrace
    from dataclasses import asdict
    actual_trace = ScenarioTrace('planhash', 'complete', [{'raw': 1}], {'cpu': 1}, 'semantic', 'manifest')
    plan = {'semantic_hash': 'same', 'records': []}
    envelope = dict(matches=True, first_difference=None, verification_scope='full',
        scope='full_fresh_prefix_real_RTL_and_live_read_versions',
        actual_prefix=deepcopy(plan), actual_events=[{'raw': 1}],
        execution_audit={'closed': True}, actual_semantic_hash='same',
        expected_semantic_hash='same', original_build={'original': True}, fresh_build={'fresh': True})
    class Runtime:
        finished = False
        path = {'selected': True}
        execution_binding = SimpleNamespace(document=lambda: {'path_id': 'F2', 'runtime_path_id': 'runtime'})
        trace = actual_trace
        session = SimpleNamespace(manifest_document={}, encode_plan=lambda:b'{}')
        def __init__(self, **kwargs):
            calls.append(('construct', kwargs))
            kwargs['build_audit_sink']({'constructed': True})
        def finish(self):
            self.finished = True
            return deepcopy(plan)
        def replay(self, expected, *, audit_sink):
            calls.append(('replay', expected))
            audit_sink(deepcopy(envelope))
            if replay_error:
                raise replay_error
            return deepcopy(envelope)
        def execution_audit(self):return {'closed': True}
    def live(**kwargs):
        calls.append(('live', kwargs))
        for name in ('seed.bin', 'receipts.jsonl', 'online_session_manifest.json',
                     'online_plan.json', 'online_final_trace.json'):
            (session / name).write_bytes(b'{}')
        (session/'seed.bin').write_bytes(kwargs['seed_records'][0])
        (session/'online_final_trace.json').write_text(json.dumps(asdict(actual_trace)))
        (session/'online_run_identity.json').write_bytes(b'{}')
        from hashlib import sha256
        kwargs['executor']._live_context = {'online_artifact_commitment': {
            'artifacts': {path.name:sha256(path.read_bytes()).hexdigest() for path in session.iterdir() if path.name != 'online_run_identity.json'},
            'identity_file_sha256':sha256((session/'online_run_identity.json').read_bytes()).hexdigest()}}
        return SimpleNamespace(client_returncode=client_returncode)
    monkeypatch.setattr(mod, 'CompiledF2Runtime', Runtime)
    monkeypatch.setattr(mod, 'build_compiled_f2_rfuzz_executor', lambda runtime, **kw: SimpleNamespace(runtime=runtime))
    monkeypatch.setattr(mod, 'f2_seed_record', lambda path:b'legal123')
    monkeypatch.setattr(mod, 'run_scenario_rfuzz_live', live)
    monkeypatch.setattr(mod, 'verify_online_run_identity', lambda *a, **kw:{})
    monkeypatch.setattr(mod, 'compiled_document_sha256', lambda doc:'compiled')
    monkeypatch.setattr(mod, 'diagnostic_build_snapshot', lambda runtime, **kw:{'actual': True})
    monkeypatch.setattr(mod, 'build_compiled_f2_build_join', lambda **kw:dict(status='refused' if kw['error'] else 'complete', original=kw['original']))
    monkeypatch.setattr(mod, 'verify_compiled_f2_build_join', lambda *a, **kw:None)
    monkeypatch.setattr(mod, 'join_compiled_f2_receipts', lambda *a, **kw:{'status': 'ok'})
    monkeypatch.setattr(mod, 'capture_f2_report_material', lambda **kw:dict(assertions={'cases': []}, assertion_evidence={'cases': []}))
    args = dict(artifacts={}, compiled_inputs={'compiled': {}}, base_dir=tmp_path,
        cache_dir=cache, run_id='run', session_dir=session, output_dir=output,
        client_binary=tmp_path/'client', budget_seconds=1, max_tests=1,
        search_seed=1, max_runs_per_batch=1)
    return mod, args, calls, output


def test_wrapper_forwards_legal_seed_and_exports_actual_fresh(tmp_path, monkeypatch):
    mod, args, calls, output = software_session(tmp_path, monkeypatch)
    outcome = mod.run_f2_live_and_fresh(**args)
    assert next(row[1] for row in calls if row[0] == 'live')['seed_records'] == (b'legal123',)
    assert outcome['replay']['actual_events'] == [{'raw': 1}]
    assert (output/'compiled_f2_fresh_events.json').is_file()
    assert len(outcome['saved_output_hashes']) == 10
    assert len(outcome['transport_files']) == 6


def test_wrapper_nonzero_client_cannot_return_success(tmp_path, monkeypatch):
    mod, args, calls, output = software_session(tmp_path, monkeypatch, client_returncode=2)
    with pytest.raises(ValueError, match='client-failed'):
        mod.run_f2_live_and_fresh(**args)
    assert not any(row[0] == 'replay' for row in calls)


def test_wrapper_keeps_replay_primary_and_raw_material(tmp_path, monkeypatch):
    primary = RuntimeError('fresh failed')
    mod, args, calls, output = software_session(tmp_path, monkeypatch, replay_error=primary)
    with pytest.raises(RuntimeError) as caught:
        mod.run_f2_live_and_fresh(**args)
    assert caught.value is primary
    assert (output/'compiled_f2_fresh_events.json').is_file()


def test_constructor_failure_retains_sink_without_inventing_binding(tmp_path, monkeypatch):
    import json
    mod, args, _, output = software_session(tmp_path, monkeypatch)
    primary = RuntimeError('constructor refused')
    seen = []
    class RefusedRuntime:
        def __init__(self, **kwargs):
            snapshot = {'actual_partial_receipt': True}
            kwargs['build_audit_sink'](snapshot)
            snapshot.clear()
            raise primary
    monkeypatch.setattr(mod, 'CompiledF2Runtime', RefusedRuntime)
    def join(**kwargs):
        seen.append(kwargs)
        return {'status': 'refused', 'original': kwargs['original']}
    monkeypatch.setattr(mod, 'build_compiled_f2_build_join', join)
    with pytest.raises(RuntimeError) as caught:
        mod.run_f2_live_and_fresh(**args)
    assert caught.value is primary
    assert seen[-1]['execution_binding'] is None
    assert seen[-1]['original'] == {'actual_partial_receipt': True}
    assert json.loads((output/'compiled_f2_build_join.v1.json').read_bytes())['status'] == 'refused'


def test_cleanup_only_error_cannot_return_completed_outcome(tmp_path, monkeypatch):
    mod, args, _, _ = software_session(tmp_path, monkeypatch)
    original = mod.CompiledF2Runtime
    cleanup = OSError('terminal cleanup failed')
    class IncompleteRuntime(original):
        finish_calls = 0
        def finish(self):
            self.finish_calls += 1
            if self.finish_calls > 1:
                raise cleanup
            return super().finish()
        def replay(self, *args, **kwargs):
            value = super().replay(*args, **kwargs)
            self.finished = False
            return value
    monkeypatch.setattr(mod, 'CompiledF2Runtime', IncompleteRuntime)
    with pytest.raises(OSError) as caught:
        mod.run_f2_live_and_fresh(**args)
    assert caught.value is cleanup


@pytest.mark.parametrize('changed', ('none', 'seed', 'manifest', 'plan', 'trace'))
def test_initial_session_pins_require_same_call_material(tmp_path, monkeypatch, changed):
    import json
    from dataclasses import asdict
    import myfuzz.integration.compiled_f2_rfuzz_session as mod
    from myfuzz.scenario.replay import ScenarioTrace
    trace = ScenarioTrace('planhash', 'complete', [{'actual': 1}], {'cpu': 1}, 'semantic', 'manifest')
    runtime = SimpleNamespace(trace=trace, session=SimpleNamespace(
        manifest_document={'actual': 'manifest'}, encode_plan=lambda:b'{"actual":"plan"}'))
    contents = {'seed.bin': b'legal123',
        'online_session_manifest.json': b'{"actual":"manifest"}',
        'online_plan.json': b'{"actual":"plan"}',
        'online_final_trace.json': json.dumps(asdict(trace)).encode()}
    for name, raw in contents.items():
        (tmp_path/name).write_bytes(raw)
    if changed != 'none':
        name = {'seed':'seed.bin', 'manifest':'online_session_manifest.json',
                'plan':'online_plan.json', 'trace':'online_final_trace.json'}[changed]
        (tmp_path/name).write_bytes(b'{}')
    monkeypatch.setattr(mod, 'verify_online_run_identity', lambda *a, **kw:{})
    if changed == 'none':
        mod.validate_f2_session_material(tmp_path, runtime=runtime, seed_record=b'legal123')
    else:
        with pytest.raises(ValueError, match='same-call'):
            mod.validate_f2_session_material(tmp_path, runtime=runtime, seed_record=b'legal123')


@pytest.mark.parametrize('compressed', (False, True))
def test_same_call_chunked_trace_verification(tmp_path, monkeypatch, compressed):
    import json
    import myfuzz.integration.compiled_f2_rfuzz_session as mod
    from myfuzz.integration.scenario_rfuzz_live import _write_online_trace_jsonl, _write_online_trace_zlib
    from myfuzz.scenario.replay import ScenarioTrace
    trace = ScenarioTrace('planhash', 'complete', [{'actual': 1}], {'cpu': 1}, '', 'manifest')
    trace = (_write_online_trace_zlib if compressed else _write_online_trace_jsonl)(tmp_path, trace)
    runtime = SimpleNamespace(trace=trace, session=SimpleNamespace(
        manifest_document={}, encode_plan=lambda:b'{}'))
    for name, raw in {'seed.bin':b'legal123', 'online_session_manifest.json':b'{}', 'online_plan.json':b'{}'}.items():
        (tmp_path/name).write_bytes(raw)
    monkeypatch.setattr(mod, 'verify_online_run_identity', lambda *a, **kw:{})
    mod.validate_f2_session_material(tmp_path, runtime=runtime, seed_record=b'legal123')
    # Change the same-call event while leaving the saved transport metadata intact.
    changed = ScenarioTrace(trace.genome_sha256, trace.status, [{'actual': 2}],
        trace.local_ticks, trace.semantic_sha256, trace.manifest_sha256)
    runtime.trace = changed
    with pytest.raises(ValueError, match='same-call-trace-event'):
        mod.validate_f2_session_material(tmp_path, runtime=runtime, seed_record=b'legal123')


from tests.scenario.test_capability_compiled_assertions import admitted, inputs as typed_inputs


def test_wrapper_captures_real_typed_projection_from_source_backed_binding(tmp_path, monkeypatch, admitted):
    from myfuzz.integration.compiled_runtime_report import capture_f2_report_material
    compiled, typed = typed_inputs(admitted)
    evidence = typed['assertion_evidence']
    mod, args, _, _ = software_session(tmp_path, monkeypatch)
    base = mod.CompiledF2Runtime
    class SourceBackedRuntime(base):
        path = next(path for path in compiled['paths'] if path['path_id'] == evidence['path_id'])
        run_id = evidence['run_id']
        execution_binding = SimpleNamespace(document=lambda:deepcopy(evidence['execution_binding']))
        def assertion_results(self):return deepcopy(typed['assertion_results'])
        def assertion_case_evidence(self):return deepcopy(evidence['cases'])
    monkeypatch.setattr(mod, 'CompiledF2Runtime', SourceBackedRuntime)
    monkeypatch.setattr(mod, 'capture_f2_report_material', capture_f2_report_material)
    args['compiled_inputs']['compiled'] = compiled
    # This fixture does not fabricate a generated harness_set operational tier.
    args['output_dir'].joinpath('generated/harness_set.json').write_text('null')
    outcome = mod.run_f2_live_and_fresh(**args)
    rows = outcome['assertion_material']['capability_report']['assertion_results']
    assert len(rows) == 2 and all(row['status'] == 'passed' for row in rows)
    assert outcome['assertion_material']['assertion_evidence'] == evidence
    path = next(path for path in outcome['assertion_material']['capability_report']['paths']
                if path['path_id'] == evidence['path_id'])
    assert not any(tier['claimed'] for tier in path['tiers'] if tier['tier'] != 'Catalog')


def test_coherent_disk_rewrite_cannot_rebase_live_commitment(tmp_path):
    import json
    from hashlib import sha256
    from myfuzz.integration.compiled_f2_rfuzz_session import verify_f2_live_commitment
    trace = tmp_path/'online_final_trace.json'
    identity = tmp_path/'online_run_identity.json'
    trace.write_bytes(b'{"events":[]}\n')
    identity.write_bytes(b'{"original":true}\n')
    commitment = {'artifacts': {trace.name:sha256(trace.read_bytes()).hexdigest()},
        'identity_file_sha256':sha256(identity.read_bytes()).hexdigest()}
    executor = SimpleNamespace(_live_context={'online_artifact_commitment':deepcopy(commitment)})
    verify_f2_live_commitment(tmp_path, executor=executor)
    trace.write_bytes(b'{\n  "events": []\n}\n')
    # Disk declarations can be rewritten coherently; the live commitment cannot.
    identity.write_text(json.dumps({'artifacts':{trace.name:sha256(trace.read_bytes()).hexdigest()}}))
    with pytest.raises(ValueError, match='initial-bytes'):
        verify_f2_live_commitment(tmp_path, executor=executor)


def test_actual_identity_writer_exports_detached_initial_commitment():
    import json
    from hashlib import sha256
    from tests.integration.test_online_run_identity import OnlineRunIdentityTests
    from myfuzz.integration.scenario_rfuzz_live import _write_online_run_identity
    case = OnlineRunIdentityTests()
    case.setUp()
    try:
        captured = []
        digest = _write_online_run_identity(case.output, session_manifest=case.manifest,
            plan_bytes=case.plan, trace=case.trace, client_binary=case.binary,
            run_config={'duration_seconds': 1, 'max_tests': 2}, commitment_sink=captured.append)
        assert len(captured) == 1
        material = captured[0]
        identity_path = case.output/'online_run_identity.json'
        assert material['identity_sha256'] == digest
        assert material['identity_file_sha256'] == sha256(identity_path.read_bytes()).hexdigest()
        assert material['artifacts'] == json.loads(identity_path.read_bytes())['identity']['artifacts']
        original = deepcopy(material)
        identity_path.write_bytes(b'{}')
        assert captured[0] == original
    finally:
        case.tearDown()


def test_failure_build_export_keeps_partial_when_binding_export_fails(tmp_path, monkeypatch):
    import json
    mod, args, _, output = software_session(tmp_path, monkeypatch, client_returncode=2)
    base = mod.CompiledF2Runtime
    def broken_binding():
        raise RuntimeError('binding diagnostic unavailable')
    class Runtime(base):
        execution_binding = SimpleNamespace(document=broken_binding)
    monkeypatch.setattr(mod, 'CompiledF2Runtime', Runtime)
    with pytest.raises(ValueError, match='client-failed') as caught:
        mod.run_f2_live_and_fresh(**args)
    assert any('binding diagnostic unavailable' in note for note in caught.value.__notes__)
    assert json.loads((output/'compiled_f2_build_join.v1.json').read_bytes())['status'] == 'refused'
