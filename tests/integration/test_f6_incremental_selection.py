"""The F6 controller selects only after the previous native submission."""
import pytest
from myfuzz.integration import compiled_execution_files as files


def test_incremental_f6_executes_only_real_budget_prefix(monkeypatch):
    clock=[0.0]; calls=[]
    class Selector:
        def choose(self):
            calls.append('choose'); return 'F6:0102030405060708'
        def settle(self,row): calls.append(('settle',row))
    class Runtime:
        def submit(self,raw):
            calls.append(('submit',raw)); clock[0]+=2
    monkeypatch.setattr(files.time,'monotonic',lambda:clock[0])
    records,elapsed=files._submit_f6_records(Runtime(),['0102030405060708','1112131415161718'],
        check_sources=lambda:calls.append('check'), max_wall_seconds=1,
        record_selector=Selector(),selected_count=3)
    assert records==['0102030405060708'] and elapsed==2
    assert calls==['choose','check',('submit',bytes.fromhex(records[0])),('settle','F6:'+records[0])]


def test_f6_fresh_checks_saved_decision_before_dut_submission():
    class Selector:
        def choose(self): return 'F6:0102030405060708'
    class Runtime:
        def submit(self,raw): pytest.fail('DUT must not execute a different saved decision')
    with pytest.raises(ValueError,match='replay decision'):
        files._submit_f6_records(Runtime(),['0102030405060708'],check_sources=lambda:None,
            max_wall_seconds=None,record_selector=Selector(),selected_count=1,
            expected_records=['F6:1112131415161718'])


def test_f6_failed_submit_never_settles_record():
    calls=[]
    class Selector:
        def choose(self): return 'F6:0102030405060708'
        def settle(self,row): calls.append(row)
    class Runtime:
        def submit(self,raw): raise ValueError('DUT error')
    with pytest.raises(ValueError,match='DUT error'):
        files._submit_f6_records(Runtime(),['0102030405060708'],check_sources=lambda:None,
            max_wall_seconds=None,record_selector=Selector(),selected_count=1)
    assert calls == []


def test_f6_catalog_is_not_limited_by_requested_case_count(tmp_path,monkeypatch):
    from pathlib import Path
    from myfuzz.runtime import generic_campaign
    root=Path(__file__).resolve().parents[2]
    descriptor=generic_campaign.load_descriptor(root/'configs/scenarios/compiled-f6-ibex-wbdmac/generic_scenario.json',base_dir=root)
    captured={}
    def run(**kwargs):
        captured.update(kwargs)
        kwargs['output_dir'].mkdir(parents=True)
        return {'status':'complete','runtime_admitted':True,'case_count':1,'budget_ended':False}
    monkeypatch.setattr(files,'run_compiled_execution_files',run)
    rows=[f'F6:{value:016x}' for value in range(17)]
    selector=object()
    summary=generic_campaign.run_descriptor(descriptor,flow='F6',mode='original',case_root=tmp_path,
        base_dir=root,sequence=rows,execution_mode='search',execution_case_capacity=1,
        record_selector=selector,selected_count=1)
    assert summary['case_count']==1
    assert summary['requested_case_count']==1
    assert captured['max_cases']==1 and captured['selected_count']==1
    assert captured['record_selector'] is selector


def test_f6_fresh_replays_repeated_record_beyond_catalog_size(tmp_path,monkeypatch):
    from pathlib import Path
    from myfuzz.runtime import generic_campaign
    root=Path(__file__).resolve().parents[2]
    descriptor=generic_campaign.load_descriptor(root/'configs/scenarios/compiled-f6-ibex-wbdmac/generic_scenario.json',base_dir=root)
    def run(**kwargs):
        kwargs['output_dir'].mkdir(parents=True)
        return {'status':'complete','runtime_admitted':True,'case_count':2,
            'fresh_verification':{'matches':True,'completed':True,'verification_scope':'full'}}
    monkeypatch.setattr(files,'run_compiled_execution_files',run)
    summary=generic_campaign.run_descriptor(descriptor,flow='F6',mode='fresh',case_root=tmp_path,
        base_dir=root,sequence=['F6:0110c00008000000'],execution_mode='acceptance',
        execution_case_capacity=2,record_selector=object(),selected_count=2,
        expected_records=['F6:0110c00008000000']*2)
    assert summary['case_count']==2 and summary['requested_case_count']==2
    assert summary['replay_matches'] is True
    assert summary['verification']['within_invocation']['status']=='verified'
