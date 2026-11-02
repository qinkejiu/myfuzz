"""Offline report consistency, not live authority or a native acceptance gate."""
from copy import deepcopy
import pytest
from scripts.verify_generic_apb_mmio import check_unknown_effects,check_recordings


def prefix():
    return dict(schema_version='compiled_mmio_prefix.v1',records=[dict(flow='F2',raw='00100040',
        certificate=dict(schema_version='compiled_mmio_case.v1',flow_id='F2',status='observed',
            internal_storage_version='unknown',cross_case_origin='unknown',reward_eligible=False,
            component_semantic_effect='unsupported',exact_hops=dict(proof_scope='native_OBI_APB_MMIO_return_dependent_RAM_no_internal_version')))],
        feedback=dict(certified=0,storage_reward=0))


def test_transport_is_not_internal_storage_or_reward():
    assert len(check_unknown_effects(prefix()))==1


@pytest.mark.parametrize('field,value',[('internal_storage_version',{'version':1}),('cross_case_origin','known'),
    ('reward_eligible',True),('component_semantic_effect','certified'),('status','certified')])
def test_storage_claims_are_rejected(field,value):
    p=prefix();p['records'][0]['certificate'][field]=value
    with pytest.raises(ValueError):check_unknown_effects(p)


def recording():
    from tests.local_harness.test_wire import EXECUTION,result_payload,result_line
    identity=dict(pid=7,execution_nonce=EXECUTION)
    audit=dict(closed=True,identities={'component':identity},exits={'component':dict(returncode=0,reaped=True)})
    trace=dict(sessions={'component':dict(complete=True,identity=identity,
        records=[dict(sequence=1,tick_before=0,tick_after=1,reply=result_line(result_payload()))])})
    return trace,audit


def test_original_wire_is_reparsed_against_actual_identity_and_ticks():
    trace,audit=recording();assert check_recordings(trace,audit)=={'component':1}


def test_missing_wire_recording_is_only_allowed_as_explicit_partial(tmp_path):
    from scripts.verify_generic_apb_mmio import read_phase_recordings
    _,audit=recording()
    with pytest.raises(FileNotFoundError):read_phase_recordings(tmp_path,audit)
    assert read_phase_recordings(tmp_path,audit,allow_missing=True)=={
        'status':'unavailable','reason':'local_commands.json missing'}


@pytest.mark.parametrize('change',['nonce','exit','incomplete','tick'])
def test_inconsistent_recording_is_rejected(change):
    trace,audit=recording()
    if change=='nonce':audit['identities']['component']['execution_nonce']='f'*32
    if change=='exit':audit['exits']['component']['returncode']=1
    if change=='incomplete':trace['sessions']['component']['complete']=False
    if change=='tick':trace['sessions']['component']['records'][0]['tick_after']=2
    with pytest.raises(ValueError):check_recordings(trace,audit)


def test_independent_cross_accepts_equal_actual_prefix_without_rewriting_pending_summary():
    from scripts.verify_generic_apb_mmio import check_saved_cross
    p=prefix();p['records'][0]['value']=7;p['online_plan']={'source':{'data_hex':'1122'}}
    summary={'verification':{'cross_invocation':{'status':'pending','matches':None}}}
    before=deepcopy(summary)
    result=check_saved_cross(p,deepcopy(p),summary)
    assert result['matches'] is True and result['status']=='verified'
    assert result['summary_cross_invocation']['status']=='pending' and summary==before


@pytest.mark.parametrize('change',['raw','plan','event'])
def test_pending_summary_cannot_hide_an_actual_cross_difference(change):
    from scripts.verify_generic_apb_mmio import check_saved_cross
    p=prefix();p['records'][0]['value']=7;p['online_plan']={'source':{'data_hex':'1122'}};p['actual_events']=[{'value':4}]
    q=deepcopy(p)
    if change=='raw':q['records'][0]['raw']='ff'
    if change=='plan':q['online_plan']['source']['data_hex']='1123'
    if change=='event':q['actual_events'][0]['value']=5
    with pytest.raises(ValueError):check_saved_cross(p,q,{'verification':{'cross_invocation':{'status':'pending'}}})


def test_wishbone_observations_remain_unknown_not_OBI():
    p=prefix();c=p['records'][0]['certificate'];c['native_cpu_protocol']='wishbone'
    c['exact_hops'].update(native_protocol='wishbone',proof_scope='actual_CPU_native_MMIO_return_dependent_RAM_no_internal_version')
    assert check_unknown_effects(p)


def test_native_cpu_reference_preserves_wishbone_read_SEL_zero():
    from scripts.verify_generic_apb_mmio import native_beat_reference
    beat={'byte_enable':0,'rdata':85}
    assert native_beat_reference({'native_cpu':beat},'wishbone') is beat
    assert beat['byte_enable']==0
    assert native_beat_reference({'native_cpu':beat,'native_obi':deepcopy(beat)},'obi')==beat
    with pytest.raises(ValueError):native_beat_reference({'native_obi':beat},'wishbone')
    with pytest.raises(ValueError):native_beat_reference({'native_cpu':beat,'native_obi':beat},'wishbone')
    with pytest.raises(ValueError):native_beat_reference({'native_cpu':beat,'native_obi':{'byte_enable':15}},'obi')


def test_saved_cpu_collection_delegates_actual_artifact_protocol(monkeypatch):
    from scripts.verify_generic_apb_mmio import collect_saved_cpu
    from myfuzz.integration import mmio_cpu_adapter
    document={'kind':'wishbone_cpu'};binding={'cpu_adapter':{'protocol':'wishbone','traces':{},'error_policy':{}}}
    calls=[]
    def collect(events,component,**kwargs):
        calls.append((component,kwargs));return {('data',1):{'byte_enable':0}}
    monkeypatch.setattr(mmio_cpu_adapter,'collect_native_cpu_beats',collect)
    protocol,beats=collect_saved_cpu([], 'cpu',document,binding,{})
    assert protocol=='wishbone' and beats['data',1]['byte_enable']==0
    assert calls[0][1]['runtime_document'] is document
    bad=deepcopy(binding);bad['cpu_adapter']['protocol']='obi'
    with pytest.raises(ValueError):collect_saved_cpu([],'cpu',document,bad,{})
    with pytest.raises(ValueError):collect_saved_cpu([],'cpu',{'kind':'unknown'},binding,{})


def test_AHB_uses_the_same_adapter_dispatch_without_OBI_relabelling(monkeypatch):
    from scripts.verify_generic_apb_mmio import collect_saved_cpu,native_beat_reference
    from myfuzz.integration import mmio_cpu_adapter
    document={'kind':'ahb_lite_cpu'}
    binding={'cpu_adapter':{'protocol':'ahb-lite','traces':{'manager_domain':'measured'},'error_policy':{}}}
    called=[]
    def collect(events,component,**kwargs):
        called.append(kwargs);return {('data',1):{'byte_enable':0,'address':0xc0010000}}
    monkeypatch.setattr(mmio_cpu_adapter,'collect_native_cpu_beats',collect)
    protocol,beats=collect_saved_cpu([],'cpu',document,binding,{})
    assert protocol=='ahb-lite' and called[0]['runtime_document'] is document
    assert native_beat_reference({'native_cpu':beats['data',1]},protocol)['byte_enable']==0
    with pytest.raises(ValueError):native_beat_reference({'native_obi':beats['data',1]},protocol)
    p=prefix();c=p['records'][0]['certificate'];c['native_cpu_protocol']=protocol
    c['exact_hops'].update(native_protocol=protocol,proof_scope='actual_CPU_native_MMIO_return_dependent_RAM_no_internal_version')
    assert check_unknown_effects(p)


def test_axi_lite_real_beats_preserve_sampled_read_strobe():
    from scripts.verify_generic_apb_mmio import native_beat_reference
    p=prefix();c=p['records'][0]['certificate'];c['native_cpu_protocol']='axi4-lite'
    c['exact_hops'].update(native_protocol='axi4-lite',
        proof_scope='actual_CPU_native_MMIO_return_dependent_RAM_no_internal_version')
    assert check_unknown_effects(p)
    beat={'byte_enable':0,'sampled_wstrb':0,'rdata':85}
    assert native_beat_reference({'native_cpu':beat},'axi4-lite') is beat
    with pytest.raises(ValueError):native_beat_reference({'native_obi':beat},'axi4-lite')


@pytest.mark.parametrize('channel',['data','memory'])
def test_normalized_data_beats_keep_actual_source_transaction_channel(monkeypatch,channel):
    from scripts import verify_generic_apb_mmio as checker
    p=prefix();cert=p['records'][0]['certificate'];value=85;result=value^0x5a5
    tx={'source_component':'cpu','channel_id':channel,'source_sequence':1}
    ram_tx={**tx,'source_sequence':2}
    read={'acceptance_event':1,'response_event':3,'address':0x40001000,'rdata':value}
    ram_beat={'address':0x1000,'value':result}
    cert.update(joins=[{'delivery_event':3,'acceptance_event':1,'native_APB_event':2,
        'source_transaction':tx,'write':False,'value':value}],RAM_event=4,result_value=result)
    cert['exact_hops'].update(data_hops=[{'delivery_event':3,'native_cpu':read,
        'native_acceptance_event':1,'native_response_event':3}],
        ram_write_hop={'native_cpu':ram_beat,'address':0x1000,'value':result})
    p.update(execution_binding={},trace_local_ticks={},actual_events=[
        {'event_id':1,'kind':'mmio_acceptance','source_transaction':tx},
        {'event_id':2,'kind':'local_tick_sample','phase':'pre','component':'peripheral',
            'producer_event_id':8,'outputs':{'backend':dict(psel=1,penable=1,pready=1,pslverr=0,pwrite=0,paddr=0,prdata=value)}},
        {'event_id':3,'kind':'mmio_delivery','producer_event_id':8,'source_transaction':tx,
            'write':False,'offset':0,'address':0x40001000},
        {'event_id':4,'kind':'memory_write','component':'cpu','transaction':ram_tx,
            'value':result,'byte_enable':15,'address':0x1000}])
    monkeypatch.setattr(checker,'collect_saved_cpu',lambda *args:('obi',{('data',1):read,('data',2):ram_beat}))
    signals={name:name for name in ('psel','penable','pready','pslverr','pwrite','paddr','prdata')}
    artifacts={'cpu':{},'peripheral':{'base_protocol_trace':{'signals':signals}}}
    assert checker.check_actual_hops(p,artifacts)['read_values']==[value]
    # AHB source channel memory is distinct from the parser's data classification.
    assert tx['channel_id']==ram_tx['channel_id']==channel
    cert['exact_hops']['ram_write_hop']['native_cpu']={'address':0x1004,'value':result}
    with pytest.raises((ValueError,KeyError)):
        checker.check_actual_hops(p,artifacts)
