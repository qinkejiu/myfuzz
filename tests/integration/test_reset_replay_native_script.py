"""The completed reset entry keeps failure and replay gates visible."""
import json
import pytest
from scripts import run_reset_replay_native as script
from scripts.run_reset_recovery_native import ResetRecoverySelector, ResetProbeComplete


def test_continue_only_after_real_reset_probe_succeeds(tmp_path, monkeypatch):
    selector=script.ContinuingResetSelector('reset-ram',output=None,
        reset_policy='warm_all',recovery_dir=tmp_path)
    def probe(self):
        self.outcome='verified';self.reset_report={};raise ResetProbeComplete()
    monkeypatch.setattr(ResetRecoverySelector,'_reset_probe',probe)
    monkeypatch.setattr(selector,'_export',lambda:None)
    monkeypatch.setattr(selector,'result',lambda:{'status':'verified'})
    selector._reset_probe()
    assert selector.reset_report == {'terminal_probe':False,'normal_campaign_completion':False}
    assert (tmp_path/'result.json').is_file()
    def fail(self):
        self.outcome='mismatch';self.outcome_detail='no proof';raise ResetProbeComplete()
    monkeypatch.setattr(ResetRecoverySelector,'_reset_probe',fail)
    with pytest.raises(ValueError,match='not-verified'):selector._reset_probe()


@pytest.mark.parametrize('args,policy', [([], 'warm_all'), (['--reset-policy','cold_all'], 'cold_all')])
def test_entry_requires_matching_fresh_replay(tmp_path,monkeypatch,args,policy):
    import myfuzz.runtime.generic_campaign as campaign
    monkeypatch.setattr(campaign,'load_descriptor',lambda *a,**kw:object())
    def run(*args,**kwargs):
        assert kwargs['execution_mode']=='acceptance'
        assert kwargs['execution_case_capacity']==8
        assert kwargs['record_selector'].reset_policy==policy
        kwargs['record_selector'].outcome='verified'
        return {'replay_matches':True, 'case_count':2, 'requested_case_count':2,
                'flow_case_counts':{'F1':2,'F3':2,'F6':1}}
    monkeypatch.setattr(campaign,'run_descriptor',run)
    assert script.main(['--native','--output',str(tmp_path/'pass'),*args])==0
    summary=json.loads((tmp_path/'pass'/'original'/'summary.json').read_text())
    assert summary['selected_case_count']==2
    assert summary['executed_flow_case_count']==5
    assert summary['reset_policy']==policy
    def failed(*args,**kwargs):
        kwargs['record_selector'].outcome='verified'
        return {'replay_matches':False}
    monkeypatch.setattr(campaign,'run_descriptor',failed)
    assert script.main(['--native','--output',str(tmp_path/'fail')])==1
