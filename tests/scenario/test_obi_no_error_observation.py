"""Missing OBI error role is unobserved, independently of completion."""
from copy import deepcopy
import pytest
from tests.scenario.test_ip_protocol_obi import CFG,raw
from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer
from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
from myfuzz.scenario.ip_protocol_evidence import IpProtocolEvidenceConsumer
from myfuzz.scenario.ip_base_coverage import IpBaseCoverageConsumer


@pytest.mark.parametrize('error',[None,0,1])
def test_completion_error_capability_is_preserved(error):
    config=deepcopy(CFG)
    if error is None:
        config['protocol_trace']['signals'].pop('error');config['protocol_trace']['signal_widths'].pop('error')
    normalizer=IpProtocolEventNormalizer(**config);checker=IpProtocolChecker(**config);rows=[]
    for tick,values in enumerate((dict(req=1,gnt=1,addr=0x100),dict(rvalid=1,rdata=85,error=error or 0)),1):
        sample=raw(tick,**values);sample['event_id']=len(rows)+1;rows.append(sample)
        assert not checker.consume_local_tick(sample,reset_epoch=0)
        for event in normalizer.consume_local_tick(sample,reset_epoch=0):
            event.update(kind=event['event_type'],event_id=len(rows)+1);rows.append(event)
    response=next(r for r in rows if r['kind']=='transaction_response')
    assert response['payload']['error'] is error if error is None else response['payload']['error']==error
    proof=IpProtocolEvidenceConsumer({'cpu':config},runtime_contract_sha256='a'*64)
    for row in rows:proof.consume(row)
    report=proof.report();assert not report['diagnostics'];assert report['counts']['verified']==1
    certificate=report['certificates'][0]
    assert certificate['outcome']==('completed_error_unobserved' if error is None else 'error' if error else 'ok')
    coverage=IpBaseCoverageConsumer(component_id=CFG['component_id'],instance_id='cpu',endpoint_protocols={'data':'obi'})
    coverage.consume(rows,start_cursor=0);counts=coverage.snapshot()['counts']
    if error is None:
        assert counts.get('response:data:ok',0)==counts.get('response:data:error',0)==0
        assert counts['response:data:error_unobserved']==1
    else:assert counts['response:data:error' if error else 'response:data:ok']==1


@pytest.mark.parametrize('width',[2,True])
def test_contradictory_error_role_width_refused(width):
    config=deepcopy(CFG);config['protocol_trace']['signal_widths']['error']=width
    with pytest.raises(ValueError):IpProtocolEventNormalizer(**config)
