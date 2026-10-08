from copy import deepcopy
from myfuzz.scenario.retirement_delivery import RetirementRouterLinker
from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract, PULP_GPIO_PROBES


def key(n=1, case='a', epoch=0):
    return dict(execution_id='e', testcase_id=case, source_component='cpu', source_epoch=epoch, channel_id='data', source_sequence=n)


def match(keys=None):
    m = dict(status='accepted', event_id=20, producer_event_id=19, cpu_scope=dict(execution_id='e', source_component='cpu', source_epoch=0), order=3, pc=128, insn=0x23, transaction_keys=keys or [key()], byte_cells=[dict(writer_event_ids=['boot']*4, writer_kinds=['INITIAL_IMAGE']*4, versions=[[0,0]]*4)], instruction_responses=[dict(event_id=5, snapshot={'data_hex':'23000000'})], source_refs=[], provenance={'origin_status':'unknown'})
    ik=key();ik['channel_id']='instr'
    m['instruction_responses'][0].update(transaction=ik,address=128,rdata=0x23,error=0)
    m['instruction_responses'][0]['snapshot'].update(value=0x23,**deepcopy(m['byte_cells'][0]))
    m['data_beats']=[dict(transaction=k,event_id=6,raw_address=4096,aligned_address=4096,address=4096,write=1,wdata=42,be=15,response=dict(transaction=k,event_id=7,rdata=0,error=0)) for k in m['transaction_keys']]
    return m



def delivery(k=None):
    d = dict(event_id=10, source_transaction=k or key(), device_id='gpio', address=4096, offset=0, beat_bytes=4, byte_enable=15, write=True, write_value=42, read_value=None, delivery_order=1, target_delivery_order=1, target_request={'request_id':'req'}, target_response={'request_id':'req','error':0})
    common=dict(schema_version='gpio_target_transport.v1',status='observed',phase='pre', source_transaction=d['source_transaction'],command_scope=dict(component='gpio',reset_epoch=0,command_sequence=1),access_id="access-1",observation_contract=pulp_gpio_observation_contract(),raw_offset=0,decoded_offset=0,write=True,wdata=42,local_tick=1)
    d['target_access_id']='access-1'
    d['target_request']=dict(common,backend=dict(gpio_req_valid=1,gpio_req_ready=1,gpio_req_addr=0,gpio_req_write=1,gpio_req_wdata=42,gpio_req_be=15))
    d['target_response']=dict(common,backend=dict(gpio_rsp_valid=1,gpio_rsp_ready=1,gpio_rsp_rdata=0,gpio_rsp_error=0))
    d['target_response']['local_tick']=3
    d['target_apb_access']=dict(common,schema_version='gpio_target_observation.v1',kind='gpio_apb_access',local_tick=2,pre=dict(gpio_probe_psel=1,gpio_probe_penable=1,gpio_probe_apb_addr=0,gpio_probe_pwrite=1,gpio_probe_pwdata=42,gpio_probe_pready=1,gpio_probe_pslverr=0,gpio_probe_prdata=0),post={},target_response=dict(rdata=0,error=0))
    for phase in ('pre','post'):
        for name in PULP_GPIO_PROBES:d['target_apb_access'][phase].setdefault('gpio_probe_'+name,0)
    return d



def test_delivery_before_retirement_and_repeat_detached():
    l=RetirementRouterLinker(); d=delivery(); m=match()
    assert l.consume_delivery(d)==()
    out=l.consume_match(m); assert out[0]['status']=='linked_raw'
    assert out[0]['instruction_all_beats_linked'] is True
    assert out[0]['retirement_event_id']==20 and out[0]['delivery_event_id']==10
    assert l.consume_match(m)==() and l.consume_delivery(d)==()
    d['write_value']=99
    assert out[0]['consumer_resource']['write_value']==42


def test_crosscase_and_same_value_are_distinct():
    l=RetirementRouterLinker(); l.consume_delivery(delivery(key(case='b')))
    assert l.consume_match(match())==()
    assert len(l.finalize())==2


def test_two_beats_wait_for_all():
    l=RetirementRouterLinker(); l.consume_match(match([key(),key(2)]))
    assert l.consume_delivery(delivery())[0]['instruction_all_beats_linked'] is False
    assert l.consume_delivery(delivery(key(2)))[0]['instruction_all_beats_linked'] is True


def test_conflict_persists_after_eviction():
    l=RetirementRouterLinker(max_pending_transactions=1,max_completed_keys=1)
    l.consume_delivery(delivery()); bad=delivery();bad['write_value']=99
    assert l.consume_delivery(bad)[0]['status']=='ambiguous'
    l.consume_delivery(delivery(key(2)))
    assert l.consume_match(match())[0]['status']!='linked_raw'


def test_missing_witness_and_malformed_identity():
    l=RetirementRouterLinker(); d=delivery(); del d['target_response']
    l.consume_delivery(d)
    assert l.consume_match(match())[0]['reason']=='missing_actual_target_witness'
    l=RetirementRouterLinker(); d=delivery();d['source_transaction']['extra']=1
    assert l.consume_delivery(d)[0]['status']=='rejected'
    l.consume_delivery(delivery())
    assert l.consume_match(match())[0]['status']=='ambiguous'


def test_advanced_reset_cancels_and_repeated_reset_cannot_restore():
    l=RetirementRouterLinker();l.consume_delivery(delivery())
    s=dict(execution_id='e',source_component='cpu',source_epoch=1)
    assert l.consume_reset(s)[0]['status']=='incomplete'
    assert l.consume_match(match())[0]['status']=='rejected'
    assert l.consume_reset(s)[0]['status']=='rejected'


def test_nonaccepted_match_never_links():
    l=RetirementRouterLinker();l.consume_delivery(delivery());m=match();m['status']='ambiguous'
    assert l.consume_match(m)[0]['status']=='ambiguous'
    m['status']='accepted';assert l.consume_match(m)[0]['status']=='ambiguous'


def test_modified_handshake_and_wrong_access_cannot_certify():
    for field,value in [('gpio_req_addr',4),('gpio_req_ready',0),('gpio_req_wdata',43)]:
        l=RetirementRouterLinker();d=delivery();d['target_request']['backend'][field]=value
        l.consume_delivery(d);assert l.consume_match(match())[0]['status']=='incomplete'


def test_incomplete_first_beat_cannot_make_all_beats_linked():
    l=RetirementRouterLinker();l.consume_match(match([key(),key(2)]))
    d=delivery();del d['target_response'];l.consume_delivery(d)
    assert l.consume_delivery(delivery(key(2)))[0]['instruction_all_beats_linked'] is False


def test_origin_requires_canonical_registry_documents():
    l=RetirementRouterLinker();l.consume_delivery(delivery());m=match()
    m['source_refs']=['fake'];m['provenance']['origin_status']='known'
    for cell in m['byte_cells']:cell['writer_kinds']=['INSTRUCTION_SOURCE']*4;cell['writer_event_ids']=['fake']*4
    m['instruction_responses'][0]['snapshot'].update(deepcopy(m['byte_cells'][0]))
    out=l.consume_match(m,registered_origins=[{'role':'fuzz_source','input_kind':'instruction','component':'cpu'}])
    assert out[0]['known_fuzz_origin'] is False


def test_cancel_keeps_terminal_uncertainty():
    l=RetirementRouterLinker();l.consume_delivery(delivery())
    assert l.consume_cancel(key())[0]['status']=='incomplete'
    assert l.consume_match(match())[0]['status']!='linked_raw'


def test_reset_cannot_use_forgotten_epoch_to_restore_old_epoch():
    l=RetirementRouterLinker(max_pending_transactions=1,max_completed_keys=1)
    l.consume_delivery(delivery(key(epoch=8)))
    l.consume_delivery(delivery(key(2,epoch=8)))
    l.consume_delivery(delivery(key(3,epoch=8)))
    assert l.consume_reset(dict(execution_id='e',source_component='cpu',source_epoch=1))[0]['status']=='rejected'


def test_origin_canonical_known_fuzz_and_fixed_support():
    from myfuzz.scenario.source_provenance import SourceAdmission, AdmissionRegistry
    for role in ('fuzz_source','fixed_support'):
        a=SourceAdmission.create(case_id='a',case_index=0,source_id='source',path_id='path',direction='CPU_TO_IP',component='cpu',action_id='writer',role=role,input_kind='instruction',input_sha256='a'*64)
        registry=AdmissionRegistry();registry.register(a)
        l=RetirementRouterLinker(admission_registry=registry);m=match();m['source_refs']=['writer']
        m['provenance'].update(origin_status='known',origin_admission_ids=[a.admission_id])
        for c in m['byte_cells']:c['writer_kinds']=['INSTRUCTION_SOURCE']*4;c['writer_event_ids']=['writer']*4
        m['instruction_responses'][0]['snapshot'].update(deepcopy(m['byte_cells'][0]))
        l.consume_delivery(delivery())
        out=l.consume_match(m,registered_origins=[a.document()])[0]
        assert out['known_fuzz_origin']==(role=='fuzz_source')


def test_observed_epoch_survives_pending_and_terminal_evictions():
    l=RetirementRouterLinker(max_pending_transactions=1,max_completed_keys=1)
    l.consume_delivery(delivery(key(epoch=8)));l.finalize()
    d=delivery(key());d['source_transaction']['source_component']='other'
    l.consume_delivery(d);l.finalize()
    assert l.consume_reset(dict(execution_id='e',source_component='cpu',source_epoch=1))[0]['status']=='rejected'


def test_modified_frozen_instruction_evidence_is_rejected():
    l=RetirementRouterLinker();l.consume_delivery(delivery());m=match()
    m['instruction_responses'][0]['snapshot']['data_hex']='ffffffff'
    assert l.consume_match(m)[0]['status']=='rejected'


def test_live_tuple_frozen_fields_match_json_list_cells():
    l=RetirementRouterLinker();l.consume_delivery(delivery());m=match()
    snapshot=m['instruction_responses'][0]['snapshot']
    for n in ('writer_event_ids','writer_kinds'):
        snapshot[n]=tuple(snapshot[n])
    snapshot['versions']=tuple(tuple(v) for v in snapshot['versions'])
    assert l.consume_match(m)[0]['status']=='linked_raw'


def test_same_key_target_value_conflict_with_retired_producer_rejected():
    l=RetirementRouterLinker();d=delivery();d['write_value']=99
    for field in ('target_request','target_response','target_apb_access'):d[field]['wdata']=99
    d['target_request']['backend']['gpio_req_wdata']=99
    d['target_apb_access']['pre']['gpio_probe_pwdata']=99
    l.consume_delivery(d)
    out=l.consume_match(match())[0]
    assert out['status']=='rejected' and out['reason']=='producer_target_payload_conflict'


def test_missing_producer_beat_cannot_link():
    l=RetirementRouterLinker();l.consume_delivery(delivery());m=match();del m['data_beats']
    assert l.consume_match(m)[0]['reason']=='missing_retired_producer_beats'


def test_strict_contract_and_apb_access_required():
    for field in ('observation_contract','target_apb_access'):
        l=RetirementRouterLinker();d=delivery()
        if field=='observation_contract':
            d['target_request'][field]={};d['target_response'][field]={};d['target_apb_access'][field]={}
        else:del d[field]
        l.consume_delivery(d);assert l.consume_match(match())[0]['status']=='incomplete'


def test_malformed_nested_fields_are_total_and_create_barrier():
    for field,value in [('provenance',[]),('cpu_scope',[]),('byte_cells',[[]]),('instruction_responses',[[]])]:
        l=RetirementRouterLinker();m=match();m[field]=value
        assert l.consume_match(m)[0]['status']=='rejected'
        l.consume_delivery(delivery());assert l.consume_match(match())[0]['status']!='linked_raw'
    for part in ('target_request','target_response','target_apb_access'):
        l=RetirementRouterLinker();d=delivery();d[part]=[]
        l.consume_delivery(d);assert l.consume_match(match())[0]['status']=='incomplete'


def test_registry_authority_required_even_for_valid_self_declared_documents():
    from myfuzz.scenario.source_provenance import SourceAdmission
    a=SourceAdmission.create(case_id='other-case',case_index=0,source_id='source',path_id='path',direction='IP_TO_CPU',component='cpu',action_id='writer',role='fuzz_source',input_kind='instruction',input_sha256='a'*64)
    l=RetirementRouterLinker();m=match();m['source_refs']=['writer']
    m['provenance'].update(origin_status='known',origin_admission_ids=[a.admission_id])
    for c in m['byte_cells']:c['writer_kinds']=['INSTRUCTION_SOURCE']*4;c['writer_event_ids']=['writer']*4
    m['instruction_responses'][0]['snapshot'].update(deepcopy(m['byte_cells'][0]))
    l.consume_delivery(delivery());assert l.consume_match(m,registered_origins=[a.document()])[0]['known_fuzz_origin'] is False


def test_matcher_exports_detached_actual_retired_beats():
    from myfuzz.scenario.cpu_retirement import CpuRetirementMatcher
    sw=0x0020a023;scope=dict(execution_id='e',source_component='cpu',source_epoch=0)
    m=CpuRetirementMatcher();ik=key();ik['channel_id']='instr'
    m.consume(dict(kind='instr_response',transaction=ik,address=128,rdata=sw,error=0,snapshot=dict(data_hex=sw.to_bytes(4,'little').hex(),value=sw,writer_event_ids=['boot']*4,writer_kinds=['INITIAL_IMAGE']*4,versions=[[0,0]]*4)))
    accepted=dict(kind='data_accept',transaction=key(),event_id=6,address=4096,raw_address=4096,aligned_address=4096,write=1,wdata=42,be=15)
    m.consume(accepted);m.consume(dict(kind='data_response',transaction=key(),event_id=7,rdata=0,error=0))
    result=m.consume(dict(scope,kind='cpu_retire',order=1,pc_rdata=128,insn=sw,trap=0,rs1_addr=1,rs1_rdata=4096,rs2_addr=2,rs2_rdata=42,rd_addr=0,rd_wdata=0,mem_addr=4096,mem_rmask=0,mem_wmask=15,mem_rdata=0,mem_wdata=42))[0]
    assert result['status']=='accepted' and result['data_beats'][0]['wdata']==42
    assert result['data_beats'][0]['response']['event_id']==7
    accepted['wdata']=99;assert result['data_beats'][0]['wdata']==42


def test_apb_probe_shapes_and_order_are_required():
    for mutate in ('missing_post_probe','same_tick','bool_probe','request_scope'):
        l=RetirementRouterLinker();d=delivery()
        if mutate=='missing_post_probe':del d['target_apb_access']['post']['gpio_probe_out']
        elif mutate=='same_tick':d['target_apb_access']['local_tick']=d['target_request']['local_tick']
        elif mutate=='bool_probe':d['target_apb_access']['pre']['gpio_probe_psel']=True
        else:d['target_request']['command_scope']['component']='other'
        l.consume_delivery(d);assert l.consume_match(match())[0]['status']=='incomplete'


def test_same_value_distinct_fullkeys_link_separate_deliveries():
    l=RetirementRouterLinker()
    l.consume_delivery(delivery(key(2)));l.consume_delivery(delivery(key()))
    first=l.consume_match(match())[0]
    second=match([key(2)]);second['event_id']=21;second['order']=4
    other=l.consume_match(second)[0]
    assert first['fullkey']['source_sequence']==1 and other['fullkey']['source_sequence']==2
    assert first['status']==other['status']=='linked_raw'


def test_prefetch_and_data_crosscase_preserve_actual_case_identities():
    l=RetirementRouterLinker();m=match();m['testcase_id']='current-B'
    m['instruction_responses'][0]['transaction']['testcase_id']='prefetch-A'
    l.consume_delivery(delivery());out=l.consume_match(m)[0]
    assert out['status']=='linked_raw'
    assert out['fullkey']['testcase_id']=='a'
    assert out['producer_resource']['instruction_responses'][0]['transaction']['testcase_id']=='prefetch-A'


def test_read_response_enabled_bytes_must_match_target():
    l=RetirementRouterLinker();m=match();d=delivery()
    m['data_beats'][0].update(write=0,wdata=0)
    m['data_beats'][0]['response']['rdata']=42
    d.update(write=False,write_value=None,read_value=42)
    for part in ('target_request','target_response','target_apb_access'):
        d[part].update(write=False,wdata=None)
    d['target_request']['backend'].update(gpio_req_write=0,gpio_req_wdata=0)
    d['target_response']['backend']['gpio_rsp_rdata']=42
    apb=d['target_apb_access'];apb['pre'].update(gpio_probe_pwrite=0,gpio_probe_prdata=42)
    apb['target_response']['rdata']=42
    l.consume_delivery(d);assert l.consume_match(m)[0]['status']=='linked_raw'
    l=RetirementRouterLinker();m['data_beats'][0]['response']['rdata']=99
    l.consume_delivery(d);assert l.consume_match(m)[0]['status']=='rejected'


def test_pinned_gpio_partial_write_and_decoded_probe_rejected():
    for fault in ('partial','decode'):
        l=RetirementRouterLinker();m=match();d=delivery()
        if fault=='partial':
            m['data_beats'][0]['be']=1;d['byte_enable']=1;d['target_request']['backend']['gpio_req_be']=1
        else:d['target_apb_access']['pre']['gpio_probe_decoded_word']=1
        l.consume_delivery(d);assert l.consume_match(m)[0]['status']=='incomplete'
