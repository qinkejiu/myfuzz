"""Single-outstanding, no-ID OBI: synthetic protocol acceptance only."""
from copy import deepcopy
import pytest
from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer
from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
from myfuzz.scenario.ip_protocol_evidence import IpProtocolEvidenceConsumer
from myfuzz.scenario.ip_base_coverage import IpBaseCoverageConsumer

WIDTHS = dict(req=1,gnt=1,addr=32,we=1,wdata=32,be=4,rvalid=1,rdata=32,error=1)
TRACE = dict(schema_version='ip_protocol_trace.v1',protocol='obi',endpoint_id='data',
    clock_domain='core',max_wait_cycles=4,max_outstanding=1,
    signals={r:'tap_'+r for r in WIDTHS},signal_widths=WIDTHS)
CFG = dict(component_id='new-same-protocol-cpu',instance_id='cpu',protocol_trace=TRACE)


def raw(tick, *, epoch=0, **values):
    signals={r:0 for r in WIDTHS};signals.update(be=15);signals.update(values)
    return dict(event_id=tick,kind='local_tick_sample',component='cpu',local_tick=tick,
        phase='pre',reset_epoch=epoch,observation_schema_version='ip_raw_observation.v1',
        outputs={'backend':{'tap_'+r:v for r,v in signals.items()}})


def journal(*, corrupt=False):
    normalizer=IpProtocolEventNormalizer(**CFG);rows=[]
    for tick, values in enumerate((dict(req=1,addr=0x100,we=1,wdata=53),
          dict(req=1,gnt=1,addr=0x100,we=1,wdata=53),dict(),
          dict(rvalid=1,req=1,gnt=1,addr=0x100),dict(rvalid=1,rdata=53)),1):
        event=raw(tick,**values);event['event_id']=len(rows)+1;rows.append(event)
        for projected in normalizer.consume_local_tick(event,reset_epoch=0):
            projected['kind']=projected['event_type'];projected['event_id']=len(rows)+1
            if corrupt and projected['event_type']=='transaction_response':
                projected['payload']['value'] ^= 1
            rows.append(projected)
    return rows


def test_normalizer_checker_evidence_and_coverage_on_same_protocol_new_name():
    checker=IpProtocolChecker(**CFG)
    rows=journal()
    for row in rows:
        if row['kind']=='local_tick_sample':
            assert not checker.consume_local_tick(row,reset_epoch=0)
    proof=IpProtocolEvidenceConsumer({'cpu':CFG},runtime_contract_sha256='a'*64)
    for row in rows:proof.consume(row)
    report=proof.report()
    assert report['counts']==dict(verified=2,pending=0)
    assert not report['diagnostics']
    assert all(r['transaction_key'] is None and r['identity_gap']=='protocol_has_no_transaction_id'
               for r in report['certificates'])
    coverage=IpBaseCoverageConsumer(component_id=CFG['component_id'],instance_id='cpu',endpoint_protocols={'data':'obi'})
    coverage.consume(rows,start_cursor=0)
    counts=coverage.snapshot()['counts']
    assert counts['transaction:data:read']==counts['transaction:data:write']==1
    assert counts['response:data:ok']==2


def test_forged_projection_is_not_certified():
    proof=IpProtocolEvidenceConsumer({'cpu':CFG},runtime_contract_sha256='a'*64)
    for row in journal(corrupt=True):proof.consume(row)
    assert not proof.report()['certificates']
    assert proof.report()['diagnostics']['projection_mismatch']>=1


@pytest.mark.parametrize('values,code',[
    ([dict(rvalid=1)],'obi_response_without_prior_grant'),
    ([dict(req=1,gnt=1,rvalid=1)],'obi_response_without_prior_grant'),
    ([dict(req=1,addr=4),dict(req=1,addr=8)],'obi_request_changed_while_waiting'),
    ([dict(req=1),dict()], 'obi_request_withdrawn_before_grant'),
    ([dict(req=1,gnt=1),dict(req=1,gnt=1)],'obi_single_outstanding_overlap'),
    ([dict(req=1)]*4,'obi_request_wait_budget_exceeded'),
    ([dict(req=1,gnt=1)]+[dict()]*4,'obi_response_wait_budget_exceeded'),
])
def test_protocol_violations(values,code):
    checker=IpProtocolChecker(**CFG);found=[]
    for tick,value in enumerate(values,1):
        found.extend(checker.consume_local_tick(raw(tick,**value),reset_epoch=0))
    assert code in [r['payload']['violation_code'] for r in found]


def test_timeout_does_not_release_pending_and_reset_cancels():
    normalizer=IpProtocolEventNormalizer(**CFG);events=[]
    for tick in range(1,6):
        events.extend(normalizer.consume_local_tick(raw(tick,req=int(tick==1),gnt=int(tick==1)),reset_epoch=0))
    assert sum(r['event_type']=='transaction_timeout' for r in events)==1
    cancelled=normalizer.consume_local_tick(raw(6,epoch=1),reset_epoch=1)
    assert len(cancelled)==1 and cancelled[0]['event_type']=='transaction_cancel'
    assert cancelled[0]['reset_epoch']==0
    assert not normalizer.consume_local_tick(raw(7,epoch=1),reset_epoch=1)


def test_read_only_and_speculative_grant_and_irrelevant_read_wdata():
    trace=deepcopy(TRACE)
    for role in ('we','wdata','be','error'):
        trace['signals'].pop(role);trace['signal_widths'].pop(role)
    config={**CFG,'protocol_trace':trace}
    checker=IpProtocolChecker(**config)
    assert not checker.consume_local_tick(raw(1,gnt=1),reset_epoch=0)
    full=IpProtocolChecker(**CFG)
    assert not full.consume_local_tick(raw(1,req=1,wdata=1),reset_epoch=0)
    assert not full.consume_local_tick(raw(2,req=1,gnt=1,wdata=2),reset_epoch=0)


@pytest.mark.parametrize('mutation', ['missing-bound','pipelined','partial-write-shape','bad-width'])
def test_unsupported_contracts_refuse(mutation):
    trace=deepcopy(TRACE)
    if mutation=='missing-bound':trace.pop('max_outstanding')
    if mutation=='pipelined':trace['max_outstanding']=2
    if mutation=='partial-write-shape':trace['signals'].pop('be');trace['signal_widths'].pop('be')
    if mutation=='bad-width':trace['signal_widths']['be']=8
    with pytest.raises(ValueError):IpProtocolChecker(**{**CFG,'protocol_trace':trace})


def test_raw_grant_tamper_and_missing_projection_do_not_certify():
    for mode in ('grant', 'missing'):
        rows=journal()
        if mode=='grant':
            next(r for r in rows if r['kind']=='local_tick_sample'
                 and r['local_tick']==2)['outputs']['backend']['tap_gnt']=0
        else:
            rows=[r for r in rows if r['kind']!='transaction_accept']
            for index,row in enumerate(rows,1):row['event_id']=index
        proof=IpProtocolEvidenceConsumer({'cpu':CFG},runtime_contract_sha256='a'*64)
        for row in rows:proof.consume(row)
        assert not proof.report()['certificates']
        assert proof.report()['diagnostics']


def test_error_response_and_reset_rejects_stale_response():
    normalizer=IpProtocolEventNormalizer(**CFG)
    normalizer.consume_local_tick(raw(1,req=1,gnt=1),reset_epoch=0)
    result=normalizer.consume_local_tick(raw(2,rvalid=1,error=1),reset_epoch=0)
    assert result[0]['event_type']=='transaction_response' and result[0]['payload']['error']
    checker=IpProtocolChecker(**CFG)
    assert not checker.consume_local_tick(raw(1,req=1,gnt=1),reset_epoch=0)
    assert not checker.consume_local_tick(raw(2,epoch=1),reset_epoch=1)
    stale=checker.consume_local_tick(raw(3,epoch=1,rvalid=1),reset_epoch=1)
    assert stale[0]['payload']['violation_code']=='obi_response_without_prior_grant'
