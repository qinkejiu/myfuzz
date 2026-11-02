"""Save same-call typed F2 reports and reject byte substitutions."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from myfuzz.integration import compiled_execution_files as files
from tests.scenario.test_capability_compiled_assertions import admitted, inputs as assertion_inputs
from tests.integration.test_compiled_f2_runtime_report import runtime_from_evidence


def save(output,compiled,runtime):
    target=getattr(files,'_save_f2_runtime_report',None)
    assert target is not None,'F2 final report output integration missing'
    return target(output,compiled=compiled,runtime=runtime,harness_set=None,
        fresh_verification={'matches':True,'first_difference':None,'verification_scope':'full'})


def test_saves_all_three_crosschecked_documents(tmp_path,admitted):
    compiled,kwargs=assertion_inputs(admitted)
    material=save(tmp_path,compiled,runtime_from_evidence(kwargs))
    expected={'capability_report.json':'capability_report',
        'compiled_assertion_results.v1.json':'assertions',
        'compiled_assertion_evidence.v1.json':'assertion_evidence'}
    for filename,key in expected.items():
        assert json.loads((tmp_path/filename).read_text())==material[key]
    assert len(material['capability_report']['assertion_results'])==2


@pytest.mark.parametrize('filename',['capability_report.json','compiled_assertion_results.v1.json',
    'compiled_assertion_evidence.v1.json'])
def test_coherent_saved_document_substitution_refuses(tmp_path,admitted,monkeypatch,filename):
    compiled,kwargs=assertion_inputs(admitted)
    original=files._save
    def swap(path,doc):
        original(path,doc)
        if Path(path).name==filename:
            changed=deepcopy(doc);changed['substituted']=True
            Path(path).write_text(json.dumps(changed))
    monkeypatch.setattr(files,'_save',swap)
    with pytest.raises(ValueError,match='saved-output-mismatch'):
        save(tmp_path,compiled,runtime_from_evidence(kwargs))


@pytest.mark.parametrize('fail_final_report',[False,True])
def test_constructor_failure_keeps_actual_startup_build_diagnostics(tmp_path,fail_final_report):
    from unittest.mock import patch
    from tests.integration.test_compiled_f4_storage_producer import ROOT
    config=ROOT/'configs/scenarios/compiled-f4-obi-apb-timer'
    partial={'receipts':{},'preparation_observations':{},
        'execution_audit':{'identities':{'processor':{'pid':123,'reaped':True}},
            'exits':{'processor':{'returncode':0,'reaped':True}},'closed':True}}
    def fail(**kwargs):
        kwargs['build_audit_sink'](deepcopy(partial))
        raise RuntimeError('startup-primary')
    output=tmp_path/'out'
    original_save=files._save
    def save_output(path,document):
        if fail_final_report and Path(path).name=='report.json':
            raise OSError('final-report-write-failed')
        return original_save(path,document)
    with patch.object(files,'create_compiled_execution',side_effect=fail), \
            patch.object(files,'_save',side_effect=save_output):
        with pytest.raises(RuntimeError,match='startup-primary') as caught:
            files.run_compiled_execution_files(base_dir=ROOT,
                compose_path=config/'compose.json',capability_paths=[config/'test_capability.json'],
                supplement_path=config/'execution_supplement.json',
                records_path=config/'f2_read_records.json',executor='compiled_f2_obi_apb',
                output_dir=output,cache_dir=tmp_path/'cache',heavy_lock=tmp_path/'worker.lock',
                max_cases=1)
    if fail_final_report:
        assert 'final-report-write-failed' in '\n'.join(caught.value.__notes__)
    saved=output/'compiled_f2_build_join.v1.json'
    assert saved.is_file(),'constructor build audit sink was dropped'
    join=json.loads(saved.read_text())
    assert join['status']=='refused' and join['original']==partial
    assert join['execution_binding_sha256'] is None
    assert join['error']=='startup-primary'
    assert not (output/'prefix.json').exists()
    assert not (output/'compiled_assertion_results.v1.json').exists()


def test_failure_report_write_cannot_replace_pre_generation_primary(tmp_path):
    from unittest.mock import patch
    from tests.integration.test_compiled_f4_storage_producer import ROOT
    records=tmp_path/'records.json';records.write_text('["04100040"]')
    missing=tmp_path/'missing-compose.json'
    original_save=files._save
    def fail_report(path,document):
        if Path(path).name=='report.json':raise OSError('report-export-secondary')
        return original_save(path,document)
    with patch.object(files,'_save',side_effect=fail_report):
        with pytest.raises(FileNotFoundError) as caught:
            files.run_compiled_execution_files(base_dir=ROOT,compose_path=missing,
                capability_paths=(),supplement_path=tmp_path/'supplement.json',
                records_path=records,executor='compiled_f2_obi_apb',output_dir=tmp_path/'out',
                cache_dir=tmp_path/'cache',heavy_lock=tmp_path/'worker.lock',max_cases=1)
    assert caught.value.filename==str(missing)
    assert 'report-export-secondary' in '\n'.join(caught.value.__notes__)


@pytest.mark.parametrize('filename',['prefix.json','events.json','execution_audit.json','comparison.json','artifact_hashes.json','top-events.json'])
@pytest.mark.parametrize('timing',['early-semantic','late-semantic','late-format','clean'])
def test_fresh_saved_substitution_refuses_against_live_envelope(tmp_path,monkeypatch,filename,timing):
    """Exercise the shared file driver with an explicit non-native runtime double."""
    from types import SimpleNamespace
    from tests.integration.test_compiled_execution_files import inputs
    base,compose,capabilities,supplement,records=inputs(tmp_path)
    envelope={'matches':True,'first_difference':None,'verification_scope':'full',
        'actual_prefix':{'assertions':[{'status':'passed'}]},
        'actual_events':[{'event_id':1}], 'execution_audit':{'closed':True},
        'original_build':{},'fresh_build':{}}
    class Runtime:
        finished=False
        trace=SimpleNamespace(events=[])
        def submit(self,record):return {'status':'certified'}
        def finish(self):self.finished=True;return {'semantic_hash':'a'*64,'records':[]}
        def execution_audit(self):return {'closed':True}
        def replay(self,plan,*,audit_sink):audit_sink(deepcopy(envelope));return deepcopy(envelope)
    monkeypatch.setattr(files,'prepare_compiled_execution_files',lambda **kw:({},
        {'compiled':{'paths':[{'flow_id':'F4','status':'executable'}]}},
        {'execution_supported':1}))
    monkeypatch.setattr(files,'compile_candidate_layout',lambda path:SimpleNamespace(decode=lambda row:None))
    monkeypatch.setattr(files,'_layout_document',lambda layout:{})
    monkeypatch.setattr(files,'create_compiled_execution',lambda **kw:Runtime())
    monkeypatch.setattr(files,'_diagnostic_build_snapshot',lambda runtime:{})
    original_save=files._save
    def swap(path,document):
        original_save(path,document)
        target=tmp_path/'out'/('events.json' if filename=='top-events.json' else 'fresh-1/'+filename)
        trigger=(Path(path).name=='replays.json' if timing.startswith('late') else Path(path)==target)
        if trigger and timing!='clean':
            changed=json.loads(target.read_text()) if timing=='late-format' else {'substituted':True}
            target.write_text(json.dumps(changed,indent=7))
    monkeypatch.setattr(files,'_save',swap)
    output=tmp_path/'out'
    def execute():
        return files.run_compiled_execution_files(base_dir=base,compose_path=compose,
            capability_paths=capabilities,supplement_path=supplement,records_path=records,
            output_dir=output,cache_dir=tmp_path/'cache',executor='compiled_f4_obi_apb',
            max_cases=1,replay_count=2)
    if timing=='clean':
        from hashlib import sha256
        assert execute()['status']=='completed'
        assert not (output/'.incomplete').exists()
        for index in (1,2):
            directory=output/f'fresh-{index}'
            hashes=json.loads((directory/'artifact_hashes.json').read_text())
            assert all(sha256((directory/name).read_bytes()).hexdigest()==digest
                       for name,digest in hashes.items())
    else:
        with pytest.raises(ValueError,match='saved-output-mismatch|saved-output-drift'):
            execute()
        assert (output/'.incomplete').exists()
        assert json.loads((output/'report.json').read_text())['status']=='incomplete'
