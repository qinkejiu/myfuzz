"""Discovery replay is driven by observed certified relation features."""
import json
import pytest
from myfuzz.search import native


@pytest.mark.parametrize('rows,expected,reason', [
    ([],False,'not-requested'),
    ([{'features':{'frontier':['planned']}}],False,'not-requested'),
    ([{'features':{'relation':[]}}],False,'not-requested'),
    ([{'features':{'relation':['certified-write-read']}}],True,'new-certified-relation')])
def test_selective_search_replay_uses_observed_relations(rows, expected, reason):
    assert native._replay_policy('search','original',rows) == (expected, reason)


@pytest.mark.parametrize('execution_mode,mode,record,interesting,full', [
    ('search','original',False,False,False),
    ('search','original',True,False,True),
    ('search','original',False,True,True),
    ('acceptance','original',False,False,True),
    ('search','fresh',False,False,True),
    (None,'original',False,False,True),
    ('develop','original',False,False,True)])
def test_prefix_evidence_has_explicit_lightweight_contract(tmp_path,execution_mode,mode,record,interesting,full):
    prefix={'semantic_hash':'semantic','records':[{'actual':True}]}
    native._save_execution_prefix(tmp_path,prefix,[{'event':1}], execution_mode=execution_mode,
        mode=mode, recorded=record, interesting=interesting, plan_sha256='plan', executed_cases=1)
    saved=json.loads((tmp_path/'prefix.json').read_text())
    assert (tmp_path/'events.json').exists() == full
    if full:
        assert saved == prefix
    else:
        assert saved == {'schema_version':'dependency_search_prefix_summary.v1','semantic_hash':'semantic',
            'plan_sha256':'plan','executed_case_count':1,'full_prefix_saved':False}


@pytest.mark.parametrize('execution_mode,mode,expected,reason', [
    ('develop','original',False,'not-requested'),
    ('search','fresh',True,'fresh'),
    ('acceptance','original',True,'acceptance'),
    (None,'original',True,'legacy')])
def test_discoveries_do_not_override_other_execution_modes(execution_mode,mode,expected,reason):
    assert native._replay_policy(execution_mode,mode,[{'features':{'relation':['actual']}}]) == (expected,reason)
