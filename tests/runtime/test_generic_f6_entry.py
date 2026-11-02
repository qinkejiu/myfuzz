"""F6 single-flow CLI delegates to the existing directed executor."""

import json
from pathlib import Path

import pytest

from myfuzz.runtime.generic_campaign import GenericScenarioRefused, load_descriptor, run_descriptor


@pytest.fixture
def descriptor(tmp_path):
    root = tmp_path / 'scenario'
    root.mkdir()
    for name in ('compose.json', 'supplement.json', 'capability.json'):
        (root / name).write_text('{}')
    data = {'schema_version': 'generic_scenario_descriptor.v1', 'scenario_id': 'f6-test',
        'root': 'scenario', 'compose': 'compose.json', 'supplement': 'supplement.json',
        'capability': 'capability.json', 'flow_ids': ['F6'],
        'executors': {'F6': 'compiled_f6_cpu_dma'}, 'f4_records': None,
        'f2_records': None, 'f6_records': ['0110c00008000000'], 'rounds': 256}
    path = tmp_path / 'descriptor.json'
    path.write_text(json.dumps(data))
    return load_descriptor(path, base_dir=tmp_path)


@pytest.mark.parametrize('mode', ['original', 'fresh'])
def test_f6_routes_descriptor_records_to_existing_file_executor(
        descriptor, tmp_path, monkeypatch, mode):
    from myfuzz.integration import compiled_execution_files

    seen = {}
    def run(**kwargs):
        seen.update(kwargs)
        assert json.loads(Path(kwargs['records_path']).read_text()) == ['0110c00008000000']
        assert not Path(kwargs['output_dir']).exists()
        return {'status': 'complete', 'runtime_admitted': True, 'case_count': 1,
                'fresh_verification': {'matches': True, 'completed': True, 'verification_scope': 'full'}}
    monkeypatch.setattr(compiled_execution_files, 'run_compiled_execution_files', run)
    result = run_descriptor(descriptor, flow='F6', mode=mode,
        case_root=tmp_path / 'evidence', base_dir=tmp_path, cache_dir=tmp_path / 'cache')
    assert seen['executor'] == 'compiled_f6_cpu_dma'
    assert seen['max_cases'] == 1 and seen['rounds_per_case'] == 256
    assert seen['output_dir'] == tmp_path / 'evidence' / mode
    assert result['replay_matches'] is True and result['case_count'] == 1
    assert result['plan_identity_sha256'] is None
    assert result['backend'] == 'compiled_f6_standalone'
    assert result['replay_scope'] == 'within_invocation'
    assert result['evidence_dir'] == str(tmp_path / 'evidence' / mode)
    assert json.loads((tmp_path / 'evidence' / mode / 'summary.json').read_text()) == result


@pytest.mark.parametrize('records', [['F2:0110c00008000000'], ['F6:00'], ['0110c00008000000']])
def test_f6_explicit_records_refuse_wrong_flow_or_width_before_executor(
        descriptor, tmp_path, monkeypatch, records):
    from myfuzz.integration import compiled_execution_files
    monkeypatch.setattr(compiled_execution_files, 'run_compiled_execution_files',
        lambda **kwargs: pytest.fail('executor must not start'))
    with pytest.raises(GenericScenarioRefused):
        run_descriptor(descriptor, flow='F6', mode='original', case_root=tmp_path / 'run',
            base_dir=tmp_path, sequence=records)


def _trace_inputs():
    identities = [{c: {'component':c,'execution_nonce':n*32,'pid':p,
                        'build_digest':b*64,'binary_sha256':h*64}
                   for c,n,p,b,h in [('cpu',n,100+i,'a','b'),('dma',m,200+i,'c','d')]}
                  for i,(n,m) in enumerate([('1','2'),('3','4')])]
    rows=[]
    for phase in identities:
        for component,identity in phase.items():
            nonce = identity['execution_nonce']
            rows.append({'component':component,'identity':dict(identity),'complete':True,
                         'records':[{'sequence':1,'reset_epoch':0,
                            'command':f'CMD {nonce} 1 STEP 0','reply':f'RESULT {nonce} 1 0 1 x'}]})
    return identities, rows


@pytest.mark.parametrize('bad', [None, 'missing', 'duplicate', 'binary', 'pid'])
def test_f6_export_joins_original_and_fresh_by_audited_nonce(descriptor, tmp_path, monkeypatch, bad):
    from myfuzz.integration import compiled_execution_files
    ids, rows = _trace_inputs()
    if bad == 'missing': rows.pop()
    if bad == 'duplicate': rows.append(dict(rows[0]))
    if bad == 'binary': rows[0]['identity']['binary_sha256'] = 'f'*64
    if bad == 'pid': rows[0]['identity']['pid'] += 1
    class Trace:
        def export_sessions(self): return rows
    def run(**kwargs):
        output = Path(kwargs['output_dir']); output.mkdir()
        (output/'compiled_f6_prefix.json').write_text(json.dumps(
            {'original_execution_audit':{'identities':ids[0]}}))
        (output/'compiled_f6_fresh_execution_audit.json').write_text(json.dumps({'identities':ids[1]}))
        return {'status':'complete','runtime_admitted':True,'case_count':1,
                'fresh_verification':{'matches':True,'completed':True,'verification_scope':'full'}}
    monkeypatch.setattr(compiled_execution_files, 'run_compiled_execution_files', run)
    args=dict(flow='F6',mode='original',case_root=tmp_path/'run',base_dir=tmp_path,command_trace=Trace())
    if bad:
        with pytest.raises(GenericScenarioRefused): run_descriptor(descriptor, **args)
        return
    run_descriptor(descriptor, **args)
    original=json.loads((tmp_path/'run/original/local_commands.json').read_text())
    fresh=json.loads((tmp_path/'run/original/fresh_local_commands.json').read_text())
    assert original['sessions']['cpu']['identity']['execution_nonce'] == '1'*32
    assert fresh['sessions']['cpu']['identity']['execution_nonce'] == '3'*32
    assert original['sessions']['dma']['identity']['execution_nonce'] == '2'*32
    assert fresh['sessions']['dma']['identity']['execution_nonce'] == '4'*32
    from scripts.measure_local_coverage import select_recorded_session
    for document, digest, nonce in ((original,'a'*64,'1'*32),(fresh,'a'*64,'3'*32)):
        commands, replies, binary = select_recorded_session(document, 'cpu', digest)
        assert commands == [f'CMD {nonce} 1 STEP 0']
        assert replies == [f'RESULT {nonce} 1 0 1 x']
        assert binary == 'b'*64


def test_f6_export_preserves_incomplete_session_for_coverage_refusal(descriptor, tmp_path, monkeypatch):
    from myfuzz.integration import compiled_execution_files
    from scripts.measure_local_coverage import select_recorded_session
    ids, rows = _trace_inputs(); rows[0]['complete'] = False
    class Trace:
        def export_sessions(self): return rows
    def run(**kwargs):
        output = Path(kwargs['output_dir']); output.mkdir()
        (output/'compiled_f6_prefix.json').write_text(json.dumps({'original_execution_audit':{'identities':ids[0]}}))
        (output/'compiled_f6_fresh_execution_audit.json').write_text(json.dumps({'identities':ids[1]}))
        return {'status':'complete','runtime_admitted':True,'case_count':1,
                'fresh_verification':{'matches':True,'completed':True,'verification_scope':'full'}}
    monkeypatch.setattr(compiled_execution_files, 'run_compiled_execution_files', run)
    run_descriptor(descriptor, flow='F6', mode='original',case_root=tmp_path/'run',
                   base_dir=tmp_path,command_trace=Trace())
    doc=json.loads((tmp_path/'run/original/local_commands.json').read_text())
    assert doc['sessions']['cpu']['complete'] is False
    with pytest.raises(ValueError,match='incomplete-local-command-trace'):
        select_recorded_session(doc,'cpu','a'*64)


def test_f6_explicit_record_selects_valid_flow_hex(descriptor, tmp_path, monkeypatch):
    from myfuzz.integration import compiled_execution_files
    def run(**kwargs):
        assert json.loads(Path(kwargs['records_path']).read_text()) == ['0110c00008000000']
        return {'status': 'complete', 'runtime_admitted': True, 'case_count': 1,
                'fresh_verification': {'matches': True, 'completed': True, 'verification_scope': 'full'}}
    monkeypatch.setattr(compiled_execution_files, 'run_compiled_execution_files', run)
    result = run_descriptor(descriptor, flow='F6', mode='original', case_root=tmp_path / 'run',
        base_dir=tmp_path, sequence=['F6:0110c00008000000'])
    assert result['replay_matches'] is True


def test_shipped_f6_descriptor_points_to_real_inputs():
    root = Path(__file__).resolve().parents[2]
    path = root / 'configs/scenarios/compiled-f6-ibex-wbdmac/generic_scenario.json'
    desc = load_descriptor(path, base_dir=root)
    assert desc.flow_ids == ('F6',)
    assert desc.executor('F6') == 'compiled_f6_cpu_dma'


@pytest.mark.parametrize('report', [
    {'status': 'complete', 'runtime_admitted': True, 'case_count': 1,
     'fresh_verification': {'matches': False, 'completed': True, 'verification_scope': 'full'}},
    {'status': 'complete', 'runtime_admitted': False, 'case_count': 1,
     'fresh_verification': {'matches': True, 'completed': True, 'verification_scope': 'full'}},
    {'status': 'complete', 'runtime_admitted': True, 'case_count': 1,
     'fresh_verification': {'matches': True, 'completed': True, 'verification_scope': 'partial'}},
])
def test_f6_summary_never_promotes_incomplete_executor_report(
        descriptor, tmp_path, monkeypatch, report):
    from myfuzz.integration import compiled_execution_files
    monkeypatch.setattr(compiled_execution_files, 'run_compiled_execution_files', lambda **kwargs: report)
    result = run_descriptor(descriptor, flow='F6', mode='original', case_root=tmp_path / 'run',
        base_dir=tmp_path)
    assert result['replay_matches'] is False


@pytest.mark.parametrize('mode', ['original', 'fresh'])
def test_scenario_cli_dispatches_f6_to_standalone_executor(tmp_path, monkeypatch, capsys, mode):
    from scripts import run_generic_scenario as cli
    from myfuzz.integration import compiled_execution_files
    seen = {}
    def run(**kwargs):
        seen.update(kwargs)
        return {'status': 'complete', 'runtime_admitted': True, 'case_count': 1,
                'fresh_verification': {'matches': True, 'completed': True, 'verification_scope': 'full'}}
    monkeypatch.setattr(compiled_execution_files, 'run_compiled_execution_files', run)
    root = Path(__file__).resolve().parents[2]
    result = cli.main(['--descriptor', str(root / 'configs/scenarios/compiled-f6-ibex-wbdmac/generic_scenario.json'),
        '--flow', 'F6', '--mode', mode, '--case', str(tmp_path / 'run'),
        '--record', 'F6:0110c00008000000'])
    output = json.loads(capsys.readouterr().out)
    assert result == 0 and output['backend'] == 'compiled_f6_standalone'
    assert output['plan'] is None and seen['executor'] == 'compiled_f6_cpu_dma'
    assert output['replay_scope'] == 'within_invocation'
    assert output['evidence_dir'] == str(tmp_path / 'run' / mode)


@pytest.mark.parametrize('error_type', [ValueError, RuntimeError])
def test_f6_backend_failure_returns_structured_refusal_with_evidence(
        tmp_path, monkeypatch, capsys, error_type):
    from scripts import run_generic_scenario as cli
    from myfuzz.integration import compiled_execution_files
    def run(**kwargs):
        output = Path(kwargs['output_dir'])
        output.mkdir()
        (output / 'report.json').write_text('{"status":"incomplete"}')
        raise error_type('actual F6 refusal')
    monkeypatch.setattr(compiled_execution_files, 'run_compiled_execution_files', run)
    root = Path(__file__).resolve().parents[2]
    result = cli.main(['--descriptor', str(root / 'configs/scenarios/compiled-f6-ibex-wbdmac/generic_scenario.json'),
        '--flow', 'F6', '--mode', 'fresh', '--case', str(tmp_path / 'run')])
    output = json.loads(capsys.readouterr().out)
    assert result == 2 and output['status'] == 'refused'
    assert output['detail']['error_type'] == error_type.__name__
    assert output['detail']['error'] == 'actual F6 refusal'
    assert output['detail']['evidence_dir'] == str(tmp_path / 'run' / 'fresh')
    assert (tmp_path / 'run' / 'fresh' / 'report.json').is_file()



@pytest.mark.parametrize('execution_mode,mode,count', [('search','original',0), ('develop','original',0), ('acceptance','original',1), ('search','fresh',1)])
def test_f6_execution_policy_and_original_only_recording(descriptor, tmp_path, monkeypatch, execution_mode, mode, count):
    from myfuzz.integration import compiled_execution_files
    ids, rows = _trace_inputs()
    class Trace:
        def export_sessions(self): return rows[:2] if count == 0 else rows
    def run(**kwargs):
        assert kwargs['replay_count'] == count
        out = Path(kwargs['output_dir']); out.mkdir()
        (out/'compiled_f6_prefix.json').write_text(json.dumps({'original_execution_audit': {'identities': ids[0]}}))
        if count:
            (out/'compiled_f6_fresh_execution_audit.json').write_text(json.dumps({'identities': ids[1]}))
        return {'status':'complete','runtime_admitted':True,'case_count':1,
            'fresh_verification': {'matches':True,'completed':True,'verification_scope':'full'} if count else None}
    monkeypatch.setattr(compiled_execution_files, 'run_compiled_execution_files', run)
    result = run_descriptor(descriptor, flow='F6', mode=mode, execution_mode=execution_mode,
        case_root=tmp_path/'run', base_dir=tmp_path, command_trace=Trace())
    assert result['replay_matches'] is (True if count else None)
    assert (tmp_path/'run'/mode/'local_commands.json').exists()
    assert (tmp_path/'run'/mode/'fresh_local_commands.json').exists() == bool(count)
