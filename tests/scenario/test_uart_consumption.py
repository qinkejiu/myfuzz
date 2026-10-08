import pytest
import importlib


def test_tracker_module_exists_and_malformed_events_are_total():
    spec = importlib.util.find_spec('myfuzz.scenario.uart_consumption')
    assert spec is not None
    tracker = importlib.import_module(spec.name).UartConsumptionTracker()
    for event in (None, [], {'kind': 'uart_tick_observation'}):
        assert tracker.consume(event)[0]['status'] == 'incomplete'


def tick(n, pre=None, post=None):
    p = dict(sync_intq=1,rx_sync=1,rx_in=1,rx_enable=1,idle=1,bit_cnt=0,
             tick_baud=0,sreg=0,rx_valid=0,rx_data=0,frame_err=0,parity_err=0,
             nco=1,rxnf_enable=0,sys_loopback=0,line_loopback=0,parity_en=0,parity_odd=0,
             fifo_wvalid=0,fifo_wready=1,fifo_rvalid=0,fifo_rdata_re=0,
             fifo_data=0,fifo_head=0,fifo_depth=0,fifo_wptr=0,fifo_rptr=0,
             fifo_under_rst=0,fifo_clear=0,fifo_incr_wptr=0,fifo_incr_rptr=0)
    from myfuzz.local_harness.opentitan_uart_fifo_contract import UART_FIFO_PROBES, uart_fifo_observation_contract
    p=dict({k:0 for k in UART_FIFO_PROBES},**p)
    a=dict(p,**(pre or {})); b=dict(a,**(post or {}))
    if a['rx_enable'] and a['idle'] and not a['rx_in'] and b['idle']==0:
        if not post or 'baud_div' not in post:b['baud_div']=8
        if not post or 'tick_baud' not in post:b['tick_baud']=0
    return dict(kind='uart_tick_observation',component='uart',reset_epoch=0,
                local_tick=n,event_id=f't{n}',command_scope=dict(component='uart',reset_epoch=0,command_sequence=1),
                observation_contract=uart_fifo_observation_contract(),receipt_id={'execution':'process','sequence':1},
                pre={'probe_uart_'+k:v for k,v in a.items()},
                post={'probe_uart_'+k:v for k,v in b.items()})


def test_unknown_fifo_slot_is_retained_and_popped_without_origin():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    out=t.consume(tick(0,dict(fifo_wvalid=1,fifo_incr_wptr=1),
                       dict(fifo_depth=1,fifo_wptr=1,fifo_rvalid=1)))
    assert any(r['kind']=='uart_fifo_push' and r['origin_status']=='unknown' for r in out)
    out=t.consume(tick(1,dict(fifo_depth=1,fifo_wptr=1,fifo_rvalid=1,
                              fifo_rdata_re=1,fifo_incr_rptr=1),
                       dict(fifo_depth=0,fifo_rptr=1,fifo_rvalid=0)))
    assert any(r['kind']=='uart_fifo_pop' and r['origin_status']=='unknown' for r in out)


def test_mismatch_barrier_survives_clear_but_real_reset_restores_baseline():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    assert t.consume(tick(0,post=dict(fifo_depth=2)))[-1]['status']=='incomplete'
    t.consume(tick(1,dict(fifo_depth=2,fifo_clear=1),dict(fifo_depth=0)))
    assert t._states['uart']['degraded']
    t.consume(dict(kind='uart_reset',component='uart',reset_epoch=1,local_tick=2,
                   event_id='reset',command_scope=dict(component='uart',reset_epoch=1,command_sequence=1),physical_reset=True))
    assert not t._states['uart']['degraded']


def test_actual_start_and_false_start_have_distinct_terminal_records():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    out=t.consume(tick(0,dict(rx_in=0),dict(idle=0,bit_cnt=10,sreg=0)))
    assert any(r['kind']=='uart_rx_receiver_start' for r in out)
    out=t.consume(tick(1,dict(idle=0,bit_cnt=10,tick_baud=1,rx_in=1),
                       dict(idle=1,bit_cnt=0)))
    assert any(r['kind']=='uart_rx_receiver_terminal' and r['reason']=='false_start' for r in out)


def test_unsupported_input_selection_never_accepts_receiver_origin():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    out=t.consume(tick(0,dict(rx_in=0,sys_loopback=1),dict(idle=0,bit_cnt=10)))
    assert any(r['kind']=='uart_rx_receiver_start' and r['origin_status']=='unknown' for r in out)


def test_tick_requires_authenticated_contract_and_all_probe_widths():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    e=tick(0);e['observation_contract']={}
    assert UartConsumptionTracker().consume(e)[0]['reason']=='unauthenticated_uart_tick'


def test_same_edge_clear_push_is_observed_but_not_retained():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    out=t.consume(tick(0,dict(fifo_clear=1,fifo_wvalid=1,fifo_incr_wptr=1)))
    assert any(r['kind']=='uart_fifo_push' and r['retained'] is False for r in out)
    assert not t._states['uart']['queue']


def test_malformed_unhashable_scope_is_total():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    assert UartConsumptionTracker().consume({'component': []})[0]['status']=='incomplete'


def test_exact_physical_refs_propagate_two_flops_before_start():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    ref=dict(frame_id='f',action_id='a',admission_id='ad',bit_index=0,
             bit_value=0,drive_tick=0,receipt={'execution':'process','sequence':1})
    e=tick(0,dict(sync_intq=1,rx_sync=1),dict(sync_intq=0,rx_sync=1))
    e['physical_rx_ref']=ref;e['physical_rx_value']=0
    t.consume(e)
    e=tick(1,dict(sync_intq=0,rx_sync=1),dict(sync_intq=0,rx_sync=0))
    e['physical_rx_ref']=dict(ref,drive_tick=1);e['physical_rx_value']=0
    t.consume(e)
    e=tick(2,dict(sync_intq=0,rx_sync=0,rx_in=0),dict(idle=0,bit_cnt=10,sreg=0))
    e['physical_rx_ref']=dict(ref,drive_tick=2);e['physical_rx_value']=0
    out=t.consume(e)
    start=next(r for r in out if r['kind']=='uart_rx_receiver_start')
    assert start['input_ref']==ref


def test_native_watermark_irq_uses_pre_queue_not_post_depth():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    out=t.consume(tick(0,dict(fifo_wvalid=1,fifo_incr_wptr=1,watermark_threshold=1,
                              intr_enable_rx_watermark=1),
                       dict(fifo_depth=1,fifo_wptr=1,fifo_rvalid=1,
                            event_rx_watermark=1,irq_rx_watermark=0)))
    irq=next(r for r in out if r['kind']=='uart_irq_update' and r['irq_class']=='rx_watermark')
    assert irq['pre_entry_ids']==[] and irq['post_output']==0


def test_contract_float_parameter_is_rejected():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    e=tick(0);e['observation_contract']['fifo_depth']=64.0
    assert UartConsumptionTracker().consume(e)[0]['reason']=='unauthenticated_uart_tick'


def test_complete_token_is_bound_to_next_actual_push_not_equal_byte():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    t.consume(tick(0,dict(rx_in=0),dict(idle=0,bit_cnt=10)))
    shift=0
    complete=None
    for i in range(10):
        bit=int(i==9);new=(bit<<10)|(shift>>1)
        out=t.consume(tick(i+1,dict(idle=0,bit_cnt=10-i,tick_baud=1,
                                   rx_in=bit,sreg=shift),
                          dict(idle=int(i==9),bit_cnt=9-i,sreg=new,
                               rx_valid=int(i==9))))
        if i==9:complete=next(r for r in out if r['kind']=='uart_rx_receiver_complete')
        shift=new
    out=t.consume(tick(11,dict(idle=1,sreg=shift,rx_valid=1,
                               fifo_wvalid=1,fifo_incr_wptr=1),
                        dict(rx_valid=0,fifo_depth=1,fifo_wptr=1,fifo_rvalid=1)))
    push=next(r for r in out if r['kind']=='uart_fifo_push')
    assert push['receiver_id']==complete['receiver_id']


def test_frame_validation_without_runtime_drives_cannot_promote():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    out=t.consume(dict(kind='uart_frame_validation',component='uart',reset_epoch=0,
                       local_tick=0,event_id='v',command_scope=dict(component='uart',reset_epoch=0,command_sequence=1),frame_id='f',
                       waveform_matched=True,source_drive_refs=[]))
    assert out[0]['status']=='incomplete'


def test_full_fifo_pop_has_no_combinational_write_credit():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    for n in range(64):
        t.consume(tick(n,dict(fifo_depth=n,fifo_wptr=n%64,fifo_rvalid=int(n>0),
                              fifo_wvalid=1,fifo_incr_wptr=1),
                       dict(fifo_depth=n+1,fifo_wptr=(n+1)%64,fifo_rvalid=1,
                            fifo_wready=int(n+1<64))))
    out=t.consume(tick(64,dict(fifo_depth=64,fifo_wptr=0,fifo_wready=0,
                               fifo_wvalid=1,fifo_rvalid=1,fifo_rdata_re=1,
                               fifo_incr_rptr=1),
                        dict(fifo_depth=63,fifo_rptr=1,fifo_wready=1)))
    assert any(r['kind']=='uart_fifo_pop' for r in out)
    assert not any(r['kind']=='uart_fifo_push' for r in out)
    assert len(t._states['uart']['queue'])==63


def test_nonempty_simultaneous_push_pop_keeps_old_head_identity():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    first=t.consume(tick(0,dict(fifo_wvalid=1,fifo_incr_wptr=1),
                           dict(fifo_depth=1,fifo_wptr=1,fifo_rvalid=1)))
    old=next(r for r in first if r['kind']=='uart_fifo_push')['entry_id']
    out=t.consume(tick(1,dict(fifo_depth=1,fifo_wptr=1,fifo_rvalid=1,
                              fifo_rdata_re=1,fifo_incr_rptr=1,
                              fifo_wvalid=1,fifo_incr_wptr=1),
                       dict(fifo_wptr=2,fifo_rptr=1)))
    assert next(r for r in out if r['kind']=='uart_fifo_pop')['entry_id']==old
    assert t._states['uart']['queue'][0]['entry_id']!=old


def test_terminal_post_configuration_change_invalidates_receiver_candidate():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    t.consume(tick(0,dict(rx_in=0),dict(idle=0,bit_cnt=10,nco=2)))
    assert t._states['uart']['receiver']['candidate'] is False


@pytest.mark.parametrize('admitted_byte,tamper', [(0,None),(1,None),(0,'key'),(0,'request'),(0,'response'),(0,'error_bool'),(0,'capture_bool'),(0,'tl_address_alias'),(0,'delayed'),(0,'cross_case'),(0,'trailing'),(0,'bootstrap'),(0,'unregistered'),(0,'window'),(0,'response_context'),(0,'bootstrap_badwaveform'),(0,'response_context_none')])
def test_full_exact_validated_frame_can_append_receiver_retention_proof(admitted_byte,tamper):
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    from myfuzz.scenario.source_provenance import AdmissionRegistry,SourceAdmission
    from myfuzz.scenario.ownership import compile_ownership,InputField,InputOwner
    import hashlib,json
    source_doc=dict(action_id='a',component='uart',port='uart_rx_byte',value=admitted_byte,bit_offset=0,width=8,kind='source_event')
    digest=hashlib.sha256(json.dumps(source_doc,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    a=SourceAdmission.create(case_id='A',case_index=0,source_id='rx',path_id='p',
        direction='IP_TO_CPU',component='uart',action_id='a',role='fuzz_source',
        input_kind='source_event',input_sha256=digest)
    registry=AdmissionRegistry();registry.register(a)
    owner=compile_ownership((InputField('uart','uart_rx_byte',8),),
                            (InputOwner('uart','uart_rx_byte',0,8,'source','rx'),))
    t=UartConsumptionTracker(admission_registry=None if tamper in ('bootstrap','bootstrap_badwaveform') else AdmissionRegistry() if tamper=='unregistered' else registry,ownership=owner)
    refs=[];q0=q1=1;idle=1;count=0;shift=0
    for n in range(43):
        slot=n//4;value=0 if slot<9 else 1
        ref=dict(frame_id='f',action_id='a',admission_id=None if tamper in ('bootstrap','bootstrap_badwaveform') else a.admission_id,
                 bit_index=min(slot,9),bit_value=value,drive_tick=n,
                 receipt_id={'execution':'process','sequence':1})
        if n<40:refs.append(ref)
        start=bool(idle and not q1);sample=bool(not idle and n in range(4,41,4))
        newshift=(q1<<10)|(shift>>1) if sample else shift
        postcount=10 if start else count-1 if sample else count
        postidle=0 if start else int(count==1) if sample else idle
        e=tick(n,dict(sync_input=value,sync_intq=q0,rx_sync=q1,rx_in=q1,idle=idle,bit_cnt=count,
                      tick_baud=int(sample),sreg=shift,rx_valid=int(n==41),
                      fifo_wvalid=int(n==41),fifo_incr_wptr=int(n==41),
                      fifo_depth=int(n>41),fifo_wptr=int(n>41),fifo_rvalid=int(n>41)),
               dict(sync_intq=value,rx_sync=q0,idle=postidle,bit_cnt=postcount,
                    sreg=0 if start else newshift,rx_valid=int(sample and count==1),
                    fifo_depth=int(n>=41),fifo_wptr=int(n>=41),fifo_rvalid=int(n>=41)))
        if n<40:e.update(physical_rx_ref=ref,physical_rx_value=value)
        t.consume(e)
        q0,q1=value,q0;idle,count,shift=postidle,postcount,0 if start else newshift
    validation=dict(kind='uart_frame_validation',component='uart',reset_epoch=0,
        local_tick=42,event_id='validation',command_scope=dict(component='uart',reset_epoch=0,command_sequence=1),frame_id='f',
        action_id='a',admission_id=None if tamper in ('bootstrap','bootstrap_badwaveform') else a.admission_id,waveform_matched=tamper!='bootstrap_badwaveform',
        source_drive_refs=refs)
    out=() if tamper=='delayed' else t.consume(validation)
    if admitted_byte:
        assert out[0]['reason']=='uart_source_action_bytes_mismatch'
    elif tamper in ('bootstrap','bootstrap_badwaveform','unregistered'):
        assert out[0]['reason']=='unproven_uart_source_authority'
        assert not t._states['uart']['degraded']
        assert len(t._states['uart']['queue'])==1
        assert t._states['uart']['frames']['f']['finalized_unknown']
        if tamper=='unregistered':
            t.admission_registry.register(a)
            again=t.consume(validation)
            assert not any(r.get('status')=='accepted' for r in again)
            assert not t._states['uart']['frames']['f']['validated']
    else:
        if tamper!='delayed':
            assert any(r['kind']=='uart_consumption_match' and r['status']=='accepted'
                       and r['proof_scope']=='uart_fifo_retention' for r in out)
        key=dict(execution_id='cpu',testcase_id='B' if tamper=='cross_case' else 'A',source_component='cpu',source_epoch=0,channel_id='data',source_sequence=1)
        delivery=dict(source_transaction=key,device_id='uart',address=0x40000018,offset=24,write=False,value=0,be=15,window_base=0x40000000,window_size=0x1000)
        context=dict(access_id='access',source_transaction=key,raw_offset=24,write=False,byte_enable=15,
                     address=0x40000018,window_base=0x40000000,window_size=0x1000,route_context_mode='router',delivery_context=delivery)
        req=tick(43,dict(fifo_depth=1,fifo_wptr=1,fifo_rvalid=1,fifo_rdata_re=1,
                        fifo_incr_rptr=1,a_accept=1,tl_a_valid=1,tl_a_ready=1,
                        tl_a_opcode=4,tl_a_address=24,tl_a_mask=15,tl_a_source=7,
                        reg_re=1,reg_rdata_re=1,reg_addr=24),
                 dict(fifo_depth=0,fifo_rptr=1,fifo_rvalid=0,captured_source=7))
        if tamper=='tl_address_alias':req['pre']['probe_uart_tl_a_address']=0x10018
        req['access']=context;t.consume(req)
        rsp=tick(44,dict(fifo_wptr=1,fifo_rptr=1,d_accept=1,tl_d_valid=1,
                        tl_d_ready=1,tl_d_source=7,tl_d_opcode=1,captured_source=7))
        rsp['access']=dict(context,address=0x50000018) if tamper=='response_context' else context;t.consume(rsp)
        if tamper=='response_context_none':t._states['uart']['access_ticks'][(1,44)]['access']=None
        if tamper=='trailing':
            trailing=tick(45,dict(fifo_wptr=1,fifo_rptr=1))
            trailing['access']=context;t.consume(trailing)
        access=dict(kind='uart_rdata_access',component='uart',reset_epoch=0,
            local_tick=45 if tamper=='trailing' else 44,event_id='access-final',command_scope=req['command_scope'],
            **context,request_tick=43,response_tick=44,read_value=0,error=0,
            actual_request_event_id=req['event_id'],actual_response_event_id=rsp['event_id'],
            read_capture=dict(pre=req['pre'],post=req['post'],actual_receipt_ref=dict(command_scope=req['command_scope'],local_tick=43)),
            response_capture=dict(pre=rsp['pre'],post=rsp['post'],actual_receipt_ref=dict(command_scope=rsp['command_scope'],local_tick=44)))
        if tamper=='window':access['window_base']=0x50000000
        if tamper=='key':access['source_transaction']=dict(key,source_sequence=2)
        if tamper=='request':access['actual_request_event_id']='other'
        if tamper=='error_bool':access['error']=False
        if tamper=='capture_bool':access['read_capture']['pre']=dict(req['pre'],probe_uart_reg_error=False)
        if tamper=='response':access['response_capture']['pre']=dict(rsp['pre'],probe_uart_tl_d_source=8)
        out=t.consume(access)
        if tamper=='delayed':
            assert not out
            out=t.consume(validation)
            assert any(r.get('proof_scope')=='uart_fifo_read_consumption' and r.get('status')=='accepted' for r in out)
        elif tamper and tamper not in ('cross_case','trailing'):
            assert not any(r.get('status')=='accepted' for r in out)
        else:
            assert any(r.get('proof_scope')=='uart_fifo_read_consumption' and r.get('status')=='accepted' for r in out)
            proof=next(r for r in out if r.get('proof_scope')=='uart_fifo_read_consumption')
            assert proof['source_admission']['case_id']=='A'
            if tamper=='cross_case':assert proof['source_transaction']['testcase_id']=='B'
            assert not t.consume(access)



def test_native_sample_data_error_blocks_token_to_push_binding():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    # An actual data-path inconsistency is a validation barrier, not a new origin.
    out=t.consume(tick(0,dict(rx_valid=1,rx_data=3,fifo_data=4,
                              fifo_wvalid=1,fifo_incr_wptr=1),
                       dict(fifo_depth=1,fifo_wptr=1,fifo_rvalid=1)))
    assert any(r.get('reason')=='uart_receiver_fifo_data_mismatch' for r in out)


def test_tick_receipt_sequence_must_equal_actual_command_scope():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    e=tick(0);e['receipt_id']['sequence']=2
    assert UartConsumptionTracker().consume(e)[0]['reason']=='uart_command_receipt_mismatch'


def test_physical_ref_does_not_bypass_actual_sync_input():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    for n in range(3):
        e=tick(n,dict(sync_input=1,sync_intq=int(n==0),rx_sync=int(n<2),rx_in=int(n<2)),
               dict(sync_intq=0,rx_sync=int(n==0),idle=int(n<2),bit_cnt=10 if n==2 else 0))
        e.update(physical_rx_value=0,physical_rx_ref=dict(frame_id='f',action_id='a',admission_id='ad',
            bit_index=0,bit_value=0,drive_tick=n,receipt_id=e['receipt_id']))
        out=t.consume(e)
    start=next(r for r in out if r['kind']=='uart_rx_receiver_start')
    assert start['input_ref'] is None


def test_native_start_requires_baud_half_bit_initialization():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    out=UartConsumptionTracker().consume(tick(0,dict(rx_in=0),dict(idle=0,bit_cnt=10,baud_div=7)))
    assert any(r.get('reason')=='receiver_start_transition_mismatch' for r in out)


def test_non_json_metadata_is_rejected_without_non_json_report():
    import json
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    e=tick(0);e['event_id']=object()
    out=UartConsumptionTracker().consume(e)
    assert out[0]['status']=='incomplete'
    json.dumps(out,allow_nan=False)


def test_direct_unrouted_read_does_not_erase_fifo_generation_authority():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker();t.consume(tick(0))
    e=dict(kind='uart_rdata_access',component='uart',reset_epoch=0,local_tick=0,
           event_id='direct',command_scope=dict(component='uart',reset_epoch=0,command_sequence=1),
           source_transaction=None,raw_offset=24,write=False,byte_enable=15)
    assert t.consume(e)[0]['status']=='incomplete'
    assert not t._states['uart']['degraded']


def test_identical_irq_snapshot_does_not_duplicate_native_episode():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker();t.consume(tick(0))
    assert not any(r['kind']=='uart_irq_update' for r in t.consume(tick(1)))


def test_first_actual_reset_can_establish_fresh_component_scope():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    e=dict(kind='uart_reset',component='uart',reset_epoch=1,local_tick=0,event_id='r',
           command_scope=dict(component='uart',reset_epoch=1,command_sequence=1),physical_reset=True)
    assert UartConsumptionTracker().consume(e)[0]['kind']=='uart_fifo_reset'


def test_event_id_boolean_is_not_an_observation_identity():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    e=tick(0);e['event_id']=True
    assert UartConsumptionTracker().consume(e)[0]['status']=='incomplete'


def test_process_receipt_scope_cannot_change_inside_hardware_epoch():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker();t.consume(tick(0))
    e=tick(1);e['receipt_id']['execution']='different-process'
    assert t.consume(e)[0]['reason']=='uart_process_receipt_scope_changed'


def test_receiver_shift_cannot_jump_between_native_samples():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker();t.consume(tick(0,dict(rx_in=0),dict(idle=0,bit_cnt=10)))
    out=t.consume(tick(1,dict(idle=0,bit_cnt=10,tick_baud=1,rx_in=0,sreg=2),
                       dict(bit_cnt=9,sreg=1)))
    assert any(r.get('reason')=='receiver_sample_transition_mismatch' for r in out)


def test_active_access_snapshot_capacity_loss_is_persistent_barrier():
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker(max_pending=1)
    context=dict(access_id='a',source_transaction=None,raw_offset=24,write=False,byte_enable=15)
    for n in range(2):
        e=tick(n);e['access']=context;out=t.consume(e)
    assert any(r.get('reason')=='uart_access_snapshot_capacity_exceeded' for r in out)
    assert t._states['uart']['degraded']
    assert len(t._states['uart']['access_ticks'])<=1


@pytest.mark.parametrize('field,value,reason', [
    ('source_epoch',1,'uart_source_epoch_mismatch'),
    ('schema_version','uart_tick_observation.v99','unknown_uart_event_version')])
def test_optional_event_version_and_source_epoch_are_strict(field,value,reason):
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    e=tick(0);e[field]=value
    assert UartConsumptionTracker().consume(e)[0]['reason']==reason


@pytest.mark.parametrize('queued', [False,True])
def test_routed_empty_or_unknown_read_preserves_generation(queued):
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    t=UartConsumptionTracker()
    key=dict(execution_id='cpu',testcase_id='A',source_component='cpu',source_epoch=0,channel_id='data',source_sequence=1)
    if queued:t.consume(tick(0,dict(fifo_wvalid=1,fifo_incr_wptr=1),dict(fifo_depth=1,fifo_wptr=1,fifo_rvalid=1)))
    req_tick=int(queued);rsp_tick=req_tick+1
    ctx=dict(access_id='empty',source_transaction=key,raw_offset=24,write=False,byte_enable=15,
             address=24,window_base=0,window_size=None,route_context_mode='direct',delivery_context={})
    req=tick(req_tick,dict(fifo_depth=int(queued),fifo_wptr=int(queued),fifo_rvalid=int(queued),
                    fifo_incr_rptr=int(queued),fifo_rdata_re=1,a_accept=1,tl_a_valid=1,tl_a_ready=1,
                    tl_a_opcode=4,tl_a_address=24,tl_a_mask=15,tl_a_source=7,
                    reg_re=1,reg_rdata_re=1,reg_addr=24),dict(captured_source=7,fifo_depth=0,fifo_rvalid=0,fifo_rptr=int(queued)))
    req['access']=ctx;t.consume(req)
    rsp=tick(rsp_tick,dict(fifo_wptr=int(queued),fifo_rptr=int(queued),d_accept=1,tl_d_valid=1,tl_d_ready=1,tl_d_source=7,tl_d_opcode=1,captured_source=7))
    rsp['access']=ctx;t.consume(rsp)
    out=t.consume(dict(kind='uart_rdata_access',component='uart',reset_epoch=0,local_tick=rsp_tick,
        event_id='empty-final',command_scope=req['command_scope'],**ctx,
        request_tick=req_tick,response_tick=rsp_tick,read_value=0,error=0,
        actual_request_event_id=req['event_id'],actual_response_event_id=rsp['event_id'],
        read_capture=dict(pre=req['pre'],post=req['post'],actual_receipt_ref=dict(command_scope=req['command_scope'],local_tick=req_tick)),
        response_capture=dict(pre=rsp['pre'],post=rsp['post'],actual_receipt_ref=dict(command_scope=rsp['command_scope'],local_tick=rsp_tick))))
    assert out[0]['reason']==('uart_unknown_entry_origin' if queued else 'uart_empty_read')
    assert not t._states['uart']['degraded']


class NativeLifecycleFixture:
    """Explicit pinned receiver/FIFO/A-D edges, independent of model state."""
    def __init__(self, tracker, registry):
        self.tracker=tracker;self.registry=registry
        self.clock=0;self.epoch=0;self.counter=0;self.wptr=0;self.rptr=0;self.depth=0

    def event(self,n,pre=None,post=None,*,command=None):
        e=tick(n,pre,post)
        command=n+1 if command is None else command
        e.update(reset_epoch=self.epoch,event_id=f'native:{self.epoch}:{n}',
            command_scope=dict(component='uart',reset_epoch=self.epoch,command_sequence=command),
            receipt_id=dict(execution=f'process:{self.epoch}',sequence=command))
        return e

    def receive(self,*,validate=True):
        import hashlib,json
        from myfuzz.scenario.source_provenance import SourceAdmission
        self.counter+=1;seq=self.counter;base=self.clock
        action=f'action:{self.epoch}:{seq}';frame=f'uart-frame:{self.epoch}:{seq}'
        material=dict(action_id=action,component='uart',port='uart_rx_byte',value=0,bit_offset=0,width=8,kind='source_event')
        digest=hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        admission=SourceAdmission.create(case_id='source-case-A',case_index=seq,source_id='rx',path_id='p',direction='IP_TO_CPU',component='uart',action_id=action,role='fuzz_source',input_kind='source_event',input_sha256=digest)
        self.registry.register(admission)
        refs=[];q0=q1=1;idle=1;count=0;shift=0;reports=[]
        for i in range(43):
            n=base+i;slot=i//4;value=int(slot>=9)
            start=bool(idle and not q1);sample=bool(not idle and i in range(4,41,4))
            newshift=(q1<<10)|(shift>>1) if sample else shift
            nextcount=10 if start else count-1 if sample else count
            nextidle=0 if start else int(count==1) if sample else idle
            e=self.event(n,dict(sync_input=value,sync_intq=q0,rx_sync=q1,rx_in=q1,
                idle=idle,bit_cnt=count,tick_baud=int(sample),sreg=shift,rx_valid=int(i==41),
                fifo_wvalid=int(i==41),fifo_incr_wptr=int(i==41),fifo_depth=self.depth+int(i>41),
                fifo_wptr=(self.wptr+int(i>41))%64,fifo_rptr=self.rptr,fifo_rvalid=int(self.depth+int(i>41)>0)),
                dict(sync_intq=value,rx_sync=q0,idle=nextidle,bit_cnt=nextcount,
                    sreg=0 if start else newshift,rx_valid=int(sample and count==1),
                    fifo_depth=self.depth+int(i>=41),fifo_wptr=(self.wptr+int(i>=41))%64,
                    fifo_rvalid=int(self.depth+int(i>=41)>0),fifo_wready=int(self.depth+int(i>=41)<64)))
            if i<40:
                ref=dict(frame_id=frame,action_id=action,admission_id=admission.admission_id,
                         receipt_id=e['receipt_id'],bit_index=min(slot,9),bit_value=value,drive_tick=n)
                refs.append(ref);e.update(physical_rx_ref=ref,physical_rx_value=value)
            reports.extend(self.tracker.consume(e))
            q0,q1=value,q0;idle,count,shift=nextidle,nextcount,0 if start else newshift
        self.wptr=(self.wptr+1)%64;self.depth+=1;self.clock=base+43
        validation=dict(kind='uart_frame_validation',component='uart',reset_epoch=self.epoch,
            local_tick=base+39,event_id=f'validation:{self.epoch}:{seq}',
            command_scope=dict(component='uart',reset_epoch=self.epoch,command_sequence=base+40),
            frame_id=frame,action_id=action,admission_id=admission.admission_id,
            waveform_matched=True,source_drive_refs=refs)
        if validate:reports.extend(self.tracker.consume(validation))
        return validation,reports

    def read(self,*,clear_on_response=False):
        n=self.clock;seq=self.counter;command=n+1
        key=dict(execution_id='cpu-execution',testcase_id='read-case-B',source_component='cpu',source_epoch=0,channel_id='data',source_sequence=seq)
        delivery=dict(source_transaction=key,device_id='uart',address=0x40000018,offset=24,write=False,value=0,be=15,window_base=0x40000000,window_size=4096)
        ctx=dict(access_id=f'access:{self.epoch}:{seq}',source_transaction=key,raw_offset=24,write=False,byte_enable=15,address=0x40000018,window_base=0x40000000,window_size=4096,route_context_mode='router',delivery_context=delivery)
        req=self.event(n,dict(fifo_depth=self.depth,fifo_wptr=self.wptr,fifo_rptr=self.rptr,
            fifo_rvalid=1,fifo_rdata_re=1,fifo_incr_rptr=1,a_accept=1,
            tl_a_valid=1,tl_a_ready=1,tl_a_opcode=4,tl_a_address=24,tl_a_mask=15,
            reg_re=1,reg_rdata_re=1,reg_addr=24),
            dict(fifo_depth=self.depth-1,fifo_rptr=(self.rptr+1)%64,
                 fifo_rvalid=int(self.depth>1),fifo_wready=1),command=command)
        req['access']=ctx;reports=list(self.tracker.consume(req));self.rptr=(self.rptr+1)%64;self.depth-=1
        rsp=self.event(n+1,dict(fifo_depth=self.depth,fifo_rvalid=int(self.depth>0),fifo_wptr=self.wptr,fifo_rptr=self.rptr,d_accept=1,
            tl_d_valid=1,tl_d_ready=1,tl_d_opcode=1),command=command)
        if clear_on_response:
            rsp['pre']['probe_uart_fifo_clear']=1
            rsp['post'].update(probe_uart_fifo_wptr=0,probe_uart_fifo_rptr=0)
        rsp['access']=ctx;reports.extend(self.tracker.consume(rsp));self.clock=n+2
        if clear_on_response:self.wptr=self.rptr=0
        access=dict(kind='uart_rdata_access',component='uart',reset_epoch=self.epoch,
            local_tick=n+1,event_id=f'access-terminal:{self.epoch}:{seq}',command_scope=req['command_scope'],
            **ctx,request_tick=n,response_tick=n+1,read_value=0,error=0,
            actual_request_event_id=req['event_id'],actual_response_event_id=rsp['event_id'],
            read_capture=dict(pre=req['pre'],post=req['post'],actual_receipt_ref=dict(command_scope=req['command_scope'],local_tick=n)),
            response_capture=dict(pre=rsp['pre'],post=rsp['post'],actual_receipt_ref=dict(command_scope=rsp['command_scope'],local_tick=n+1)))
        reports.extend(self.tracker.consume(access));return access,reports


    def clear(self):
        e=self.event(self.clock,dict(fifo_depth=self.depth,fifo_rvalid=int(self.depth>0),
            fifo_wptr=self.wptr,fifo_rptr=self.rptr,fifo_clear=1),
            dict(fifo_depth=0,fifo_rvalid=0,fifo_wptr=0,fifo_rptr=0))
        reports=self.tracker.consume(e);self.clock+=1;self.depth=0;self.wptr=self.rptr=0
        return reports

    def reset(self):
        self.epoch+=1;self.counter=0;self.depth=0;self.wptr=self.rptr=0
        e=dict(kind='uart_reset',component='uart',reset_epoch=self.epoch,local_tick=self.clock,
            event_id=f'reset:{self.epoch}',physical_reset=True,
            command_scope=dict(component='uart',reset_epoch=self.epoch,command_sequence=0))
        return self.tracker.consume(e)


def lifecycle_tracker(**kwargs):
    from myfuzz.scenario.uart_consumption import UartConsumptionTracker
    from myfuzz.scenario.source_provenance import AdmissionRegistry
    from myfuzz.scenario.ownership import compile_ownership,InputField,InputOwner
    registry=AdmissionRegistry()
    owner=compile_ownership((InputField('uart','uart_rx_byte',8),),
        (InputOwner('uart','uart_rx_byte',0,8,'source','rx'),))
    tracker=UartConsumptionTracker(admission_registry=registry,ownership=owner,**kwargs)
    return tracker,NativeLifecycleFixture(tracker,registry)


def test_completed_native_lifecycles_exceed_256_without_capacity_loss():
    tracker,fixture=lifecycle_tracker();accepted=0;peak_frames=peak_pending=0
    for _ in range(260):
        _,a=fixture.receive();_,b=fixture.read();reports=a+b
        assert not any(r.get('status')=='incomplete' for r in reports),reports[-3:]
        accepted+=sum(r.get('proof_scope')=='uart_fifo_read_consumption' and r.get('status')=='accepted' for r in reports)
        state=tracker._states['uart'];peak_frames=max(peak_frames,len(state['frames']));peak_pending=max(peak_pending,len(state['pending']))
    assert accepted==260
    assert peak_frames<=2 and peak_pending<=1
    assert not tracker._states['uart']['degraded']


def test_gc_preserves_pop_and_read_until_delayed_validation():
    tracker,fixture=lifecycle_tracker(max_pending=4)
    validation,_=fixture.receive(validate=False);access,reports=fixture.read()
    assert not any(r.get('status')=='accepted' for r in reports)
    state=tracker._states['uart'];assert len(state['pending'])==len(state['frames'])==1
    proofs=tracker.consume(validation)
    assert [r['proof_scope'] for r in proofs]==['uart_fifo_retention','uart_fifo_read_consumption']
    assert not state['pending'] and not state['frames']
    assert not tracker.consume(access)
    assert not any(r.get('status')=='accepted' for r in tracker.consume(validation))


def test_gc_clear_waits_for_source_terminal_then_releases():
    tracker,fixture=lifecycle_tracker(max_pending=2)
    validation,_=fixture.receive(validate=False);fixture.clear()
    state=tracker._states['uart'];assert len(state['pending'])==len(state['frames'])==1
    proofs=tracker.consume(validation)
    assert len(proofs)==1 and proofs[0]['disposition']=='cleared'
    assert not state['pending'] and not state['frames']


def test_gc_clear_of_validated_source_releases_without_read():
    tracker,fixture=lifecycle_tracker();_,reports=fixture.receive()
    retention=next(r for r in reports if r.get('proof_scope')=='uart_fifo_retention')
    original=dict(retention)
    fixture.clear();state=tracker._states['uart']
    assert not state['pending'] and not state['frames']
    assert retention==original


def test_gc_does_not_release_old_live_fifo_origin_when_newer_frames_finish():
    tracker,fixture=lifecycle_tracker();first,_=fixture.receive();second,_=fixture.receive()
    _,a=fixture.read();state=tracker._states['uart']
    assert first['frame_id'] not in state['frames']
    assert second['frame_id'] in state['frames'] and len(state['queue'])==1
    _,b=fixture.read()
    assert [next(r for r in reports if r.get('proof_scope')=='uart_fifo_read_consumption')['frame_id']
            for reports in (a,b)]==[first['frame_id'],second['frame_id']]
    assert not state['pending'] and not state['frames']


def test_gc_reclaimed_canonical_frame_cannot_allocate_again():
    tracker,fixture=lifecycle_tracker();validation,_=fixture.receive();fixture.read()
    n=fixture.clock;ref=dict(validation['source_drive_refs'][0],drive_tick=n,
                            receipt_id=dict(execution='process:0',sequence=n+1))
    e=fixture.event(n,dict(sync_input=0),dict(sync_intq=0));e.update(physical_rx_ref=ref,physical_rx_value=0)
    out=tracker.consume(e)
    assert any(r.get('reason')=='stale_or_invalid_uart_frame_identity' for r in out)
    assert not any(r.get('status')=='accepted' for r in out)
    assert tracker._states['uart']['degraded']


def test_gc_real_unresolved_capacity_loss_requires_advanced_reset():
    tracker,fixture=lifecycle_tracker(max_pending=2)
    validations=[]
    for _ in range(3):
        validation,_=fixture.receive(validate=False);validations.append(validation);fixture.read()
    state=tracker._states['uart'];assert state['degraded']
    fixture.clear();assert state['degraded']
    assert not any(r.get('status')=='accepted' for r in tracker.consume(validations[0]))
    fixture.reset();assert not state['degraded']
    _,a=fixture.receive();_,b=fixture.read()
    assert any(r.get('proof_scope')=='uart_fifo_read_consumption' and r.get('status')=='accepted' for r in a+b)


def test_gc_clear_with_captured_pop_preserves_read_until_source_validation():
    tracker,fixture=lifecycle_tracker();validation,_=fixture.receive(validate=False)
    _,reports=fixture.read(clear_on_response=True)
    state=tracker._states['uart']
    assert not any(r.get('status')=='accepted' for r in reports)
    assert len(state['pending'])==len(state['frames'])==1
    proofs=tracker.consume(validation)
    assert [r['proof_scope'] for r in proofs]==['uart_fifo_retention','uart_fifo_read_consumption']
    assert all(r['entry_id'][2]==0 and r['disposition']=='popped' for r in proofs)
    assert state['generation']==1 and not state['pending'] and not state['frames']


def test_gc_reset_cancels_pending_delayed_validation_and_stale_epochs():
    tracker,fixture=lifecycle_tracker();validation,_=fixture.receive(validate=False);fixture.read()
    fixture.reset();state=tracker._states['uart']
    assert not state['pending'] and not state['frames'] and state['frame_sequence_highwater']==0
    assert not any(r.get('status')=='accepted' for r in tracker.consume(validation))
    assert state['degraded']


def test_gc_canonical_frame_wrong_epoch_cannot_become_opaque_fallback():
    tracker,fixture=lifecycle_tracker();n=fixture.clock
    e=fixture.event(n,dict(sync_input=0),dict(sync_intq=0))
    e.update(physical_rx_value=0,physical_rx_ref=dict(frame_id='uart-frame:1:1',action_id='a',
        admission_id='unknown',bit_index=0,bit_value=0,drive_tick=n,receipt_id=e['receipt_id']))
    out=tracker.consume(e)
    assert any(r.get('reason')=='stale_or_invalid_uart_frame_identity' for r in out)
    assert not tracker._states['uart']['frames']
