"""Runner drains archived real CPU taps; this is not a new RTL execution."""
import copy
import gzip
import hashlib
import json
from dataclasses import replace
from pathlib import Path
import pytest
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.local_harness.native_physical_observation import verify_cpu_obi_protocol_traces

ROOT=Path(__file__).resolve().parents[2]
SAVED=ROOT/'docs/reports/evidence/ibex-raw-obi-20261017/first.json.gz'
SNAPSHOT=ROOT/'docs/reports/evidence/ibex-raw-obi-20261017/historical-provenance-bytes'
SAVED_SHA256='dfe6ef46f0d378a2b76010abb7dc6cbcb816d81a889bd453939fe9f037c36f1d'
PROVENANCE_PATHS={
    ('source_verification','lock_sha256'):'configs/soc/sources.lock.json',
    ('driver_header_sources',0,'sha256'):'src/myfuzz/local_harness/rtl/local_driver_v1.h',
    ('selected_template','executor','binding','implementation_sources',0,'sha256'):'src/myfuzz/local_harness/runtime_renderer.py',
    ('selected_template','executor','binding','implementation_sources',1,'sha256'):'src/myfuzz/local_harness/template_contracts.py',
}
DERIVED_PATHS={('selected_template','executor','identity_sha256'),('artifact_digest',)}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _digest(document, *, ascii_only):
    return _sha(json.dumps(document,sort_keys=True,separators=(',', ':'),
        ensure_ascii=ascii_only).encode())


def _at(document,path):
    for part in path:document=document[part]
    return document


def _changed_leaves(left,right,prefix=()):
    assert type(left) is type(right),prefix
    if isinstance(left,dict):
        assert left.keys()==right.keys(),prefix
        return {path for key in left for path in _changed_leaves(left[key],right[key],prefix+(key,))}
    if isinstance(left,list):
        assert len(left)==len(right),prefix
        return {path for i in range(len(left)) for path in _changed_leaves(left[i],right[i],prefix+(i,))}
    return {prefix} if left!=right else set()


def _verify_document_digests(document):
    executor=document['selected_template']['executor']
    assert executor['identity_sha256']==_digest({k:v for k,v in executor.items()
        if k!='identity_sha256'},ascii_only=True)
    assert document['artifact_digest']==_digest({k:v for k,v in document.items()
        if k!='artifact_digest'},ascii_only=False)


def _load_saved():
    raw=SAVED.read_bytes()
    assert _sha(raw)==SAVED_SHA256,'archived raw fixture hash mismatch'
    return json.loads(gzip.decompress(raw))


def _verify_fixture_documents(current,historical):
    manifest=json.loads((SNAPSHOT/'manifest.json').read_text())
    assert manifest['schema_version']=='historical_obi_provenance_bytes.v1'
    files={row['path']:row for row in manifest['files']}
    assert set(files)==set(PROVENANCE_PATHS.values())
    for field,path in PROVENANCE_PATHS.items():
        row=files[path]
        compressed=(SNAPSHOT/row['file']).read_bytes()
        assert _sha(compressed)==row['compressed_sha256'],path
        historical_sha=_sha(gzip.decompress(compressed))
        assert historical_sha==row['sha256']==_at(historical,field),path
        assert _sha((ROOT/path).read_bytes())==_at(current,field),path
    for document in (current,historical):_verify_document_digests(document)
    assert _changed_leaves(current,historical) <= set(PROVENANCE_PATHS)|DERIVED_PATHS


@pytest.fixture(scope='module')
def current_artifact():
    from tests.local_harness.test_obi_cpu_protocol_taps import artifact
    return artifact()


@pytest.fixture(scope='module')
def artifact(current_artifact):
    result=current_artifact
    saved=_load_saved()
    historical=saved['identity']['runtime_artifact']
    # Current physical/SV/CPP mappings equal the archive. Host source bytes differ;
    # these snapshots do not establish current native execution equivalence.
    _verify_fixture_documents(result.runtime_document,historical)
    assert _sha(result.runtime_sv.encode()) == historical['runtime_sv_sha256']
    assert _sha(result.cpp_text.encode()) == historical['cpp_sha256']
    replay_artifact=replace(result,runtime_document=historical,
        source_verification=historical['source_verification'])
    assert verify_cpu_obi_protocol_traces(replay_artifact)
    return replay_artifact


@pytest.mark.parametrize('side',('historical','current'))
def test_archived_fixture_rejects_wrong_provenance_even_with_valid_derived_digests(current_artifact,artifact,side):
    current=copy.deepcopy(current_artifact.runtime_document)
    historical=copy.deepcopy(artifact.runtime_document)
    changed=historical if side=='historical' else current
    changed['selected_template']['executor']['binding']['implementation_sources'][0]['sha256']='0'*64
    executor=changed['selected_template']['executor']
    executor['identity_sha256']=_digest({k:v for k,v in executor.items() if k!='identity_sha256'},ascii_only=True)
    changed['artifact_digest']=_digest({k:v for k,v in changed.items() if k!='artifact_digest'},ascii_only=False)
    with pytest.raises(AssertionError,match='runtime_renderer.py'):
        _verify_fixture_documents(current,historical)


def test_archived_fixture_rejects_changed_physical_trace_mapping(current_artifact,artifact):
    historical=copy.deepcopy(artifact.runtime_document)
    historical['base_protocol_traces']['traces'][0]['signals']['req']='forged_req'
    historical['artifact_digest']=_digest({k:v for k,v in historical.items() if k!='artifact_digest'},ascii_only=False)
    with pytest.raises(AssertionError,match='base_protocol_traces'):
        _verify_fixture_documents(current_artifact.runtime_document,historical)


class SavedSampleSession:
    """Finite original receipts only. No CPU or IP value computation here."""
    _physical_tick_samples_enabled=True
    reset_epoch=0
    max_local_ticks_per_step=1
    max_transaction_events_per_step=0
    def __init__(self,artifact,samples):
        self.artifact=artifact;self.source=copy.deepcopy(samples)
        self.local_ticks=0;self.queued=[]
    def begin_case(self,case):pass
    def end_case(self):pass
    def step_local(self,inputs):
        assert not inputs
        sample=self.source[self.local_ticks]
        self.local_ticks+=1
        assert sample['local_tick']==self.local_ticks
        self.queued.append(copy.deepcopy(sample))
        return {}
    def drain_tick_samples(self):
        rows,self.queued=self.queued,[]
        return rows


def replay(artifact,*,tamper=False):
    saved=_load_saved()
    session=SavedSampleSession(artifact,saved['samples'])
    runner=ScenarioRunner(sessions={'renamed-session':session},
        ownership=compile_ownership((),()),bindings=())
    runner.begin_test('saved-real-obi-samples')
    for _ in range(100):runner.step('renamed-session')
    if tamper:
        for row in runner._events._records:
            if row.get('event_type')=='transaction_response' and row['endpoint_id']=='processor.instruction':
                row['payload']['value'] ^= 1
                break
    return runner,saved


def test_runner_produces_two_endpoint_events_proofs_and_coverage_from_saved_real_samples(artifact):
    runner,saved=replay(artifact)
    rows=runner.events
    raw={row['event_id']:row for row in rows if row.get('kind')=='local_tick_sample'}
    assert len(raw)==200
    assert all(row['component']=='renamed-session' for row in raw.values())
    for sample in saved['samples']:
        actual=next(row for row in raw.values() if row['local_tick']==sample['local_tick'] and row['phase']=='pre')
        assert actual['outputs']==sample['pre']
    events=[row for row in rows if row.get('event_type')=='transaction_response']
    assert len(events)==52
    ids=[r['local_event_id'] for r in rows if r.get('local_event_id')]
    assert len(ids)==len(set(ids))
    assert {row['endpoint_id'] for row in events}=={'processor.data','processor.instruction'}
    assert all(row['raw_event_refs'][0] in raw for row in events)
    assert not any(row.get('event_type')=='protocol_violation' for row in rows)
    report=runner.protocol_trace_set_reports()['renamed-session']
    assert runner.protocol_trace_set_reports()['renamed-session']==report
    for endpoint,count in [('processor.data',3),('processor.instruction',49)]:
        proof=report['endpoints'][endpoint]['evidence']
        assert proof['counts']['verified']==count and not proof['diagnostics']
        assert report['endpoints'][endpoint]['coverage']['counts']['response:'+endpoint+':ok']==count
    assert report['endpoints']['processor.data']['coverage']['counts']['transaction:processor.data:write']==2
    assert report['endpoints']['processor.data']['coverage']['counts']['transaction:processor.data:read']==1
    assert all('protocol_taps' in row['outputs'] and 'backend' in row['outputs'] for row in raw.values())


def test_tampered_instruction_projection_preserves_other_endpoint_certification(artifact):
    runner,_=replay(artifact,tamper=True)
    report=runner.protocol_trace_set_reports()['renamed-session']['endpoints']
    assert report['processor.instruction']['evidence']['diagnostics']['projection_mismatch']==1
    assert report['processor.instruction']['evidence']['counts']['verified']==0
    assert report['processor.data']['evidence']['counts']['verified']==3
    assert not report['processor.data']['evidence']['diagnostics']


def test_forged_multi_endpoint_metadata_refuses_before_drain(artifact):
    doc=copy.deepcopy(artifact.runtime_document)
    doc['base_protocol_traces']['traces'][0]['signals']['req']='d_req_valid'
    session=SavedSampleSession(replace(artifact,runtime_document=doc),[])
    runner=ScenarioRunner(sessions={'cpu':session},ownership=compile_ownership((),()),bindings=())
    with pytest.raises(ValueError,match='protocol-trace-contract-mismatch'):
        runner._protocol_trace_set('cpu',session)
    assert session.local_ticks==0


def test_disabled_raw_stream_preserves_existing_no_protocol_projection(artifact):
    session=SavedSampleSession(artifact,[])
    session._physical_tick_samples_enabled=False
    runner=ScenarioRunner(sessions={'cpu':session},ownership=compile_ownership((),()),bindings=())
    assert runner._protocol_trace_set('cpu',session) is None
    assert runner.protocol_trace_set_reports()=={}
