"""Runner drains archived real CPU taps; this is not a new RTL execution."""
import copy
import gzip
import json
from dataclasses import replace
from pathlib import Path
import pytest
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.ownership import compile_ownership

ROOT=Path(__file__).resolve().parents[2]
SAVED=ROOT/'docs/reports/evidence/ibex-raw-obi-20261017/first.json.gz'


@pytest.fixture(scope='module')
def artifact():
    from tests.local_harness.test_obi_cpu_protocol_taps import artifact
    result=artifact()
    saved=json.loads(gzip.decompress(SAVED.read_bytes()))
    historical=saved['identity']['runtime_artifact']
    # The repository lock may advance independently. Keep the archived source
    # identity while proving all executable bytes and observation mappings match.
    ignored={'source_verification','artifact_digest'}
    assert {k:v for k,v in result.runtime_document.items() if k not in ignored}=={
        k:v for k,v in historical.items() if k not in ignored}
    return replace(result,runtime_document=historical,source_verification=historical['source_verification'])


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
    saved=json.loads(gzip.decompress(SAVED.read_bytes()))
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
