"""Raw summaries preserve the public session boundary without altering evidence."""
import json
import pytest
from myfuzz.search import native, workflow
from myfuzz.runtime import generic_campaign
from myfuzz.integration import compiled_execution_files


@pytest.mark.parametrize('writer', [native.save, lambda path,value:generic_campaign._json(value,path), compiled_execution_files._save])
def test_only_summary_documents_receive_candidate_boundary(tmp_path, monkeypatch, writer):
    seen=[]
    def candidate(value):
        seen.append(value)
        return {**value, 'verification': {'session_boundary': {'status':'pending','matches':None}}}
    monkeypatch.setattr(workflow, 'candidate_summary', candidate, raising=False)
    value={'status':'completed'}
    writer(tmp_path/'summary.json',value)
    writer(tmp_path/'evidence.json',value)
    assert len(seen) == 1
    assert json.loads((tmp_path/'summary.json').read_text())['verification']['session_boundary']['status'] == 'pending'
    assert json.loads((tmp_path/'evidence.json').read_text()) == value
    assert value == {'status':'completed'}


def test_fresh_candidate_requires_matching_verified_public_summary(tmp_path):
    reference={'mode':'original','semantic_hash':'hash','verification':{'session_boundary':{'status':'pending','matches':None}}}
    with pytest.raises(ValueError,match='unverified'):
        native._require_original_boundary(tmp_path,reference)
    public={**reference,'verification':{'session_boundary':{'status':'verified','matches':True}}}
    (tmp_path/'search-summary.json').write_text(json.dumps(public))
    native._require_original_boundary(tmp_path,reference)
    public['semantic_hash']='other'
    (tmp_path/'search-summary.json').write_text(json.dumps(public))
    with pytest.raises(ValueError,match='binding mismatch'):
        native._require_original_boundary(tmp_path,reference)


def test_legacy_original_needs_no_boundary_sidecar(tmp_path):
    native._require_original_boundary(tmp_path,{'mode':'original'})


@pytest.mark.parametrize('boundary', [{'status':'failed','matches':False}, {'status':'verified','matches':False}])
def test_failed_original_boundary_never_admits_fresh(tmp_path, boundary):
    with pytest.raises(ValueError,match='unverified'):
        native._require_original_boundary(tmp_path,{'verification':{'session_boundary':boundary}})
