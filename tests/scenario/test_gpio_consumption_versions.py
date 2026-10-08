from copy import deepcopy
from myfuzz.scenario.gpio_consumption import GpioConsumptionTracker
from myfuzz.local_harness.pulp_gpio_probe_contract import PULP_GPIO_PROBES,pulp_gpio_observation_contract


def probes(**fields):
    p={'gpio_probe_'+n:0 for n in PULP_GPIO_PROBES};p['gpio_in']=0
    p.update({'gpio_probe_'+k:v for k,v in fields.items()})
    active=p['gpio_probe_psel'] & p['gpio_probe_penable'] & p['gpio_probe_pwrite']
    p['gpio_probe_write']=active
    word=p['gpio_probe_decoded_word']
    if active:
        if word in (3,4,5):p['gpio_probe_write_out']=0xffffffff
        elif word in (17,18,19):p['gpio_probe_write_out']=0xffffffff<<32
        if word==1:p['gpio_probe_write_gpioen']=0xffffffff
        elif word==15:p['gpio_probe_write_gpioen']=0xffffffff<<32
        if word==6:p['gpio_probe_write_inten']=0xffffffff
        elif word==20:p['gpio_probe_write_inten']=0xffffffff<<32
        if word in (7,8,21,22):p['gpio_probe_write_inttype']=0xffff << ({7:0,8:16,21:32,22:48}[word])
    return p


def tick(n,pre=None,post=None,component='gpio',epoch=0):
    return dict(kind='gpio_tick_observation',event_id=n,component=component,reset_epoch=epoch,source_epoch=epoch,local_tick=n,observation_contract=pulp_gpio_observation_contract(),pre=pre or probes(),post=post or probes())


def access(n=1,offset=12,value=1,old=0,new=1):
    e=tick(n,probes(psel=1,penable=1,pwrite=1,pwdata=value,pready=1,apb_addr=offset,decoded_word=(offset>>2)&31,out=old),probes(out=new))
    e.update(kind='gpio_apb_access',status='observed',phase='pre',access_id='access-'+str(n),raw_offset=offset,decoded_offset=((offset>>2)&31)<<2,write=True,wdata=value,source_transaction=dict(execution_id='e',testcase_id='a',source_component='cpu',source_epoch=0,channel_id='data',source_sequence=n),command_scope=dict(component='gpio',reset_epoch=0,command_sequence=n),target_response=dict(rdata=0,error=0))
    return e


def events(out,kind):return [e for e in out if e['kind']==kind]


def test_equal_value_commits_have_distinct_per_bit_versions_and_aliases():
    t=GpioConsumptionTracker();a=t.consume(access())[0];b=t.consume(access(2,0x8c,1,1,1))[0]
    assert a['kind']==b['kind']=='gpio_register_commit'
    assert b['changed_mask']==0 and b['decoded_offset']==12 and b['raw_offset']==0x8c
    assert a['bit_resources'][0]['version']!=b['bit_resources'][0]['version']


def test_set_clear_keep_old_bit_dependencies():
    t=GpioConsumptionTracker();first=t.consume(access(value=3,new=3))[0]
    second=t.consume(access(2,16,4,3,7))[0]
    assert second['bit_resources'][0]==first['bit_resources'][0]
    assert second['bit_resources'][2]['dependencies'][0]['version']==first['bit_resources'][2]['version']
    third=t.consume(access(3,20,2,7,5))[0]
    assert third['bit_resources'][1]['value']==0


def test_neighbor_enable_updates_stages_and_disabled_holds():
    t=GpioConsumptionTracker();pre=probes(gpioen=2,input_clock_enable=1);pre['gpio_in']=1
    post=probes(gpioen=2,input_clock_enable=1,sync0=1)
    out=t.consume(tick(1,pre,post));sample=events(out,'gpio_input_sample')[0]
    assert sample['stages']['sync0'][0]['value']==1
    assert sample['stages']['sync0'][0]['origin_status']=='unknown'
    out=t.consume(tick(2,post,probes(gpioen=2,input_clock_enable=1,sync1=1,rise=1)));assert events(out,'gpio_input_sample')[0]['enabled_mask']==15
    disabled=probes(sync0=1)
    t=GpioConsumptionTracker();out=t.consume(tick(3,disabled,disabled));assert events(out,'gpio_input_sample')[0]['enabled_mask']==0


def test_corrupted_stage_or_probe_contract_cannot_prove():
    for fault in ('stage','contract','missing'):
        t=GpioConsumptionTracker();e=tick(1,probes(input_clock_enable=1,gpioen=1),probes(input_clock_enable=1,gpioen=1))
        if fault=='stage':e['post']['gpio_probe_sync1']=1
        elif fault=='contract':e['observation_contract']={}
        else:del e['pre']['gpio_probe_native_irq']
        assert events(t.consume(e),'gpio_consumption_match')[0]['status']!='accepted'


def test_multi_pin_trigger_dedup_post_then_pre_and_status_priority():
    t=GpioConsumptionTracker();pre=probes(gpioen=3,inten=3,inttype=5,input_clock_enable=1,sync0=3)
    post=probes(gpioen=3,inten=3,inttype=5,input_clock_enable=1,sync1=3,rise=3,irq_trigger_mask=3,native_irq=1)
    out=t.consume(tick(1,pre,post));tr=events(out,'gpio_irq_trigger')[0]
    assert [c['pin'] for c in tr['causes']]==[0,1]
    pre2=deepcopy(post);post2=probes(gpioen=3,inten=3,inttype=5,input_clock_enable=1,padin_latch=3,status=3,fall=3)
    out=t.consume(tick(2,pre2,post2));assert not events(out,'gpio_irq_trigger')
    assert events(out,'gpio_irq_observation')[0]['trigger_id']==tr['trigger_id']


def test_status_read_uses_pre_return_and_new_event_priority():
    t=GpioConsumptionTracker();e=access(offset=36,value=0,old=0,new=0)
    e.update(write=False,wdata=None,read_rdata=1)
    e['pre']=probes(psel=1,penable=1,pwrite=0,pready=1,apb_addr=36,decoded_word=9,prdata=1,status=1,native_irq=1,irq_trigger_mask=2,gpioen=2,inten=2,inttype=4,sync1=2,rise=2,input_clock_enable=1)
    e['post']=probes(status=3,gpioen=2,inten=2,inttype=4,input_clock_enable=1,padin_latch=2,fall=2);e['target_response']['rdata']=1
    out=t.consume(e);r=events(out,'gpio_register_read')[0]
    assert r['read_value']==1 and r['status_outcome']=='new_event_priority' and r['post_value']==3
    e2=deepcopy(e);e2.update(event_id=2,local_tick=2,access_id='access-2');e2['source_transaction']['source_sequence']=2
    e2['pre'].update(gpio_probe_native_irq=0,gpio_probe_irq_trigger_mask=0,gpio_probe_status=3,gpio_probe_prdata=3,gpio_probe_sync1=0,gpio_probe_rise=0);e2['post']=probes(gpioen=2,inten=2,inttype=4,input_clock_enable=1);e2['read_rdata']=3;e2['target_response']['rdata']=3
    r=events(t.consume(e2),'gpio_register_read')[0];assert r['status_outcome']=='cleared' and r['read_value']==3


def test_reset_requires_advanced_epoch_and_old_events_rejected():
    t=GpioConsumptionTracker();t.consume(access())
    assert t.consume(dict(kind='gpio_reset',component='gpio',reset_epoch=1,event_id=2))[0]['status']=='observed'
    assert t.consume(access(3))[0]['status']=='rejected'
    assert t.consume(dict(kind='gpio_reset',component='gpio',reset_epoch=1,event_id=4))[0]['status']=='rejected'


def test_admission_without_actual_applied_receipt_is_unknown():
    t=GpioConsumptionTracker();t.consume(dict(kind='source_admission',event_id=1,action_id='pin'))
    pre=probes(gpioen=1,input_clock_enable=1);pre['gpio_in']=1
    sample=events(t.consume(tick(2,pre,probes(gpioen=1,input_clock_enable=1,sync0=1))),'gpio_input_sample')[0]
    assert sample['stages']['sync0'][0]['origin_status']=='unknown'


def admission_tracker():
    from myfuzz.scenario.source_provenance import AdmissionRegistry,SourceAdmission
    registry=AdmissionRegistry();a=SourceAdmission.create(case_id='source-case',case_index=0,source_id='pin8',path_id='path',direction='IP_TO_CPU',component='gpio',action_id='pin8',role='fuzz_source',input_kind='source_event',input_sha256='a'*64)
    registry.register(a)
    from myfuzz.scenario.ownership import compile_ownership,InputField,InputOwner
    ownership=compile_ownership((InputField('gpio','gpio_in',32),),(InputOwner('gpio','gpio_in',0,8,'bound','a.gpio_out'),InputOwner('gpio','gpio_in',8,1,'source','pin8'),InputOwner('gpio','gpio_in',9,23,'fixed','fixed')))
    return GpioConsumptionTracker(admission_registry=registry,ownership=ownership),a


def applied(n,value=1,lo=8,width=1):
    return dict(kind='gpio_input_applied',event_id=100+n,actual_receipt_event_id=n,actual_input_value=value<<lo,component='gpio',reset_epoch=0,local_tick=n,port='gpio_in',value=value,bit_lo=lo,width=width,origin=dict(kind='source_admission',action_id='pin8'))


def test_mixed_known_pin8_and_unknown_low_bits_persist_on_held_drive():
    t,a=admission_tracker();drive=applied(1);drive['actual_input_value']=257;t.consume(drive);pre=probes(gpioen=256,input_clock_enable=4);pre['gpio_in']=257
    post=probes(gpioen=256,input_clock_enable=4,sync0=256);post['gpio_in']=257
    out=t.consume(tick(1,pre,post));sample=events(out,'gpio_input_sample')[0]
    assert sample['stages']['sync0'][8]['origin_status']=='known'
    assert sample['stages']['sync0'][0]['origin_status']=='unknown'
    pre2=deepcopy(post);pre2['gpio_in']=257
    post2=probes(gpioen=256,input_clock_enable=4,sync0=256,sync1=256,rise=256);post2['gpio_in']=257
    out=t.consume(tick(2,pre2,post2));sample=events(out,'gpio_input_sample')[0]
    assert sample['stages']['sync0'][8]['origin_status']=='known'
    assert sample['stages']['sync1'][8]['origin_status']=='known'


def test_unconfirmed_input_and_superseded_actions_cannot_inherit_sample():
    t,a=admission_tracker();e=applied(1);del e['actual_receipt_event_id']
    assert t.consume(e)[0]['status']=='rejected'
    t,a=admission_tracker();earlier=applied(1,value=0);earlier['actual_receipt_event_id']=0;t.consume(earlier)
    next_drive=applied(1,value=1);next_drive['actual_receipt_event_id']=1;next_drive['event_id']=102
    assert events(t.consume(next_drive),'gpio_consumption_match')[0]['reason']=='superseded_before_sample'
    pre=probes(gpioen=256,input_clock_enable=4);pre['gpio_in']=256
    post=probes(gpioen=256,input_clock_enable=4,sync0=256);post['gpio_in']=256
    out=t.consume(tick(1,pre,post))
    origin=events(out,'gpio_input_sample')[0]['stages']['sync0'][8]['origin_refs'][0]
    assert origin['action_id']=='pin8'


def test_gaps_and_unknown_scope_remain_uncertain_until_real_reset():
    t,a=admission_tracker();t.consume(tick(1));assert t.consume(tick(3))[0]['status']=='ambiguous'
    t.consume(applied(4));pre=probes(gpioen=256,input_clock_enable=4);pre['gpio_in']=256
    out=t.consume(tick(4,pre,probes(gpioen=256,input_clock_enable=4,sync0=256)))
    assert not any(e.get('origin_status')=='known' for e in out)
    t=GpioConsumptionTracker();t.consume(None);out=t.consume(tick(1));assert events(out,'gpio_input_sample')[0]['status']=='incomplete'


def test_dependency_payload_does_not_embed_growing_history():
    t=GpioConsumptionTracker();t.consume(access())
    for n in range(2,20):last=t.consume(access(n,16,1,1,1))[0]
    dependency=last['bit_resources'][0]['dependencies'][0]
    assert 'dependencies' not in dependency


def test_wrong_owned_source_bit_is_unknown():
    t,a=admission_tracker();e=applied(1,lo=0)
    assert t.consume(e)[-1]['origin_status']=='unknown'


def test_first_pre_high_is_observation_not_invented_rising_trigger():
    t=GpioConsumptionTracker();pre=probes(gpioen=1,inten=1,inttype=1,input_clock_enable=1,sync1=1,rise=1,irq_trigger_mask=1,native_irq=1)
    post=probes(gpioen=1,inten=1,inttype=1,input_clock_enable=1,padin_latch=1,status=1,fall=1)
    out=t.consume(tick(1,pre,post));assert not events(out,'gpio_irq_trigger')
    assert events(out,'gpio_irq_observation')[0]['status']=='incomplete'


def test_same_tick_input_retry_idempotent_conflict_ambiguous():
    t,a=admission_tracker();e=applied(1)
    t.consume(e);assert t.consume(e)==()
    changed=deepcopy(e);changed['value']=0;changed['actual_input_value']=0
    assert t.consume(changed)[0]['status']=='ambiguous'


def test_config_write_induced_trigger_retains_exact_commit_versions():
    t=GpioConsumptionTracker();e=access(offset=4,value=1,old=0,new=0)
    e['pre'].update(gpio_probe_gpioen=0,gpio_probe_inten=1,gpio_probe_inttype=1,gpio_probe_sync1=1,gpio_probe_rise=1)
    e['post'].update(gpio_probe_gpioen=1,gpio_probe_inten=1,gpio_probe_inttype=1,gpio_probe_sync1=1,gpio_probe_rise=1,gpio_probe_input_clock_enable=1,gpio_probe_irq_trigger_mask=1,gpio_probe_native_irq=1)
    commit=t.consume(e)[0]
    out=t.consume(tick(1,e['pre'],e['post']));trigger=events(out,'gpio_irq_trigger')[0]
    assert trigger['causes'][0]['configuration']['gpioen'][0]['version']==commit['bit_resources'][0]['version']


def test_native_status_or_and_read_clear_observations_checked():
    t=GpioConsumptionTracker();pre=probes(gpioen=1,inten=1,inttype=1,input_clock_enable=1,sync1=1,rise=1,irq_trigger_mask=1,native_irq=1,status=2)
    post=probes(gpioen=1,inten=1,inttype=1,input_clock_enable=1,padin_latch=1,fall=1,status=0)
    assert t.consume(tick(1,pre,post))[0]['status']=='rejected'


def test_binding_requires_exact_source_resource_refs_and_owned_bits():
    t,a=admission_tracker();e=access(value=3,new=3);e['component']='a';e['command_scope']['component']='a'
    t.consume(e);t.consume(tick(1,e['pre'],e['post'],component='a'))
    source=t.output_resources_at('a',0,1)[:8]
    drive=applied(1,value=3,lo=0,width=8);drive['origin']=dict(kind='binding',source_component='a',source_port='gpio_out',source_bit_lo=0,producer_reset_epoch=0,producer_local_tick=1,producer_phase='post',producer_resource_refs=source,delivery_event_id=50)
    assert t.consume(drive)[-1]['origin_status']=='known'
    bad=deepcopy(drive);bad['actual_receipt_event_id']=300;bad['origin']['producer_resource_refs'][0]['version']+=1
    assert t.consume(bad)[-1]['origin_status']=='unknown'


def test_malformed_identity_total_and_failed_target_barrier():
    for field,bad in [('component',[]),('event_id',{}),('reset_epoch',False)]:
        t=GpioConsumptionTracker();e=tick(1);e[field]=bad
        assert t.consume(e)[0]['status']=='rejected'
    t=GpioConsumptionTracker();e=tick(1);e['kind']='gpio_access_terminal';e['status']='uncertain'
    assert t.consume(e)[0]['status']=='incomplete'
    assert events(t.consume(tick(1)),'gpio_input_sample')[0]['status']=='incomplete'


def test_unobserved_register_stage_change_between_ticks_cannot_promote():
    t,a=admission_tracker();t.consume(tick(1));t.consume(applied(2))
    pre=probes(gpioen=256,input_clock_enable=4);pre['gpio_in']=256
    post=probes(gpioen=256,input_clock_enable=4,sync0=256)
    assert t.consume(tick(2,pre,post))[0]['status'] in ('ambiguous','rejected')


def test_config_versions_and_repeat_drive_no_native_edge():
    t,a=admission_tracker();pre=probes(gpioen=256,input_clock_enable=4,sync0=256,sync1=256,padin_latch=256)
    pre['gpio_in']=256;post=deepcopy(pre)
    t.consume(applied(1));out=t.consume(tick(1,pre,post));assert not events(out,'gpio_irq_trigger')
    e=applied(2);t.consume(e);out=t.consume(tick(2,pre,post));assert not events(out,'gpio_irq_trigger')


def link_for(e):
    return dict(kind='cpu_retired_transaction_target_delivery',event_id=1000,fullkey=e['source_transaction'],status='linked_raw',known_fuzz_origin=True,source_refs=[],registered_origins=[],proof_scope='retired_instruction_transaction_delivery',consumer_resource=dict(device_id=e['component'],target_access_id=e['access_id'],offset=e['raw_offset'],write=e['write'],write_value=e['wdata'],target_apb_access=e))


def test_late_retirement_proof_registry_required_and_prefix_immutable():
    t=GpioConsumptionTracker();e=access();commit=t.consume(e)[0];saved=deepcopy(commit)
    out=t.consume(link_for(e));assert out[0]['status']=='unknown'
    assert commit==saved
    t=GpioConsumptionTracker();e=access();t.consume(e);l=link_for(e);l['consumer_resource']['write_value']=99
    assert t.consume(l)[0]['status']=='rejected'


def test_trusted_retirement_documents_can_append_source_proof_after_commit():
    from myfuzz.scenario.source_provenance import AdmissionRegistry,SourceAdmission
    registry=AdmissionRegistry();a=SourceAdmission.create(case_id='source-case',case_index=0,source_id='cpu-code',path_id='path',direction='CPU_TO_IP',component='cpu',action_id='code',role='fuzz_source',input_kind='instruction',input_sha256='a'*64);registry.register(a)
    t=GpioConsumptionTracker(admission_registry=registry);e=access();t.consume(e);l=link_for(e)
    l['source_refs']=['code'];l['registered_origins']=[a.document()]
    assert t.consume(l)[0]['status']=='accepted'


def test_output_resources_are_exact_phase_tick_and_binding_rejects_latest_guess():
    t,a=admission_tracker();e=access(value=3,new=3);e['component']='a';e['command_scope']['component']='a'
    t.consume(e);t.consume(tick(1,e['pre'],e['post'],component='a'))
    refs=t.output_resources_at('a',0,1,'post')[:8]
    assert len(refs)==8 and refs[0]['value']==1
    assert t.output_resources_at('a',0,999)==[]
    drive=applied(1,value=3,lo=0,width=8);drive['origin']=dict(kind='binding',source_component='a',source_port='gpio_out',source_bit_lo=0,producer_reset_epoch=0,producer_local_tick=1,producer_phase='post',producer_resource_refs=refs,delivery_event_id=50)
    assert t.consume(drive)[-1]['origin_status']=='known'
    bad=deepcopy(drive);bad['actual_receipt_event_id']=301;bad['origin']['producer_local_tick']=999
    assert t.consume(bad)[-1]['origin_status']=='unknown'


def test_output_cache_eviction_is_explicit_and_cannot_restore_uniqueness():
    t=GpioConsumptionTracker(max_completed_accesses=1)
    out=t.consume(tick(1))
    assert events(out,'gpio_consumption_match')[0]['reason']=='gpio_evidence_capacity_exceeded'
    assert t.output_resources_at('gpio',0,1,'pre')==[]
    out=t.consume(tick(2));assert events(out,'gpio_input_sample')[0]['status']=='incomplete'


def test_malformed_probe_decode_and_write_masks_rejected():
    for fault in ('decode','mask'):
        t=GpioConsumptionTracker();e=access()
        if fault=='decode':e['pre']['gpio_probe_decoded_word']=0
        else:e['pre']['gpio_probe_write_out']=0
        assert t.consume(e)[0]['status']=='rejected'


def test_finalize_and_reset_keep_unsampled_drive_and_missing_commit_explicit():
    t,a=admission_tracker();t.consume(applied(1))
    out=t.finalize();assert events(out,'gpio_consumption_match')[0]['reason']=='input_drive_not_sampled'
    t,a=admission_tracker();t.consume(applied(1));out=t.consume(dict(kind='gpio_reset',component='gpio',reset_epoch=1,event_id=5))
    assert any(e.get('reason')=='reset_cancelled_input_drive' for e in out)


def test_whole_applied_receipt_mismatch_and_stale_producer_epoch_unknown():
    t,a=admission_tracker();t.consume(applied(1));pre=probes(gpioen=256,input_clock_enable=4);pre['gpio_in']=257
    out=t.consume(tick(1,pre,probes(gpioen=256,input_clock_enable=4,sync0=256)))
    assert events(out,'gpio_input_sample')[0]['stages']['sync0'][8]['origin_status']=='unknown'
    t,a=admission_tracker();e=access(value=3,new=3);e['component']='a';e['command_scope']['component']='a'
    t.consume(e);t.consume(tick(1,e['pre'],e['post'],component='a'));refs=t.output_resources_at('a',0,1)[:8]
    t.consume(dict(kind='gpio_reset',component='a',reset_epoch=1,event_id=200))
    drive=applied(2,value=3,lo=0,width=8);drive['origin']=dict(kind='binding',source_component='a',source_port='gpio_out',source_bit_lo=0,producer_reset_epoch=0,producer_local_tick=1,producer_phase='post',producer_resource_refs=refs,delivery_event_id=50)
    assert t.consume(drive)[-1]['origin_status']=='unknown'


def test_public_paired_tick_authentication_is_total_and_pure():
    from myfuzz.scenario.gpio_consumption import is_authenticated_gpio_tick
    valid=tick(1);assert is_authenticated_gpio_tick(valid)
    for faulty in (None,[],dict(valid,observation_contract={}),dict(valid,component=[])):
        assert not is_authenticated_gpio_tick(faulty)
    before=deepcopy(valid);assert is_authenticated_gpio_tick(valid) and valid==before


def test_shared_cache_eviction_degrades_existing_other_component():
    t,a=admission_tracker();t.max_completed_accesses=2
    t.consume(tick(1));t.consume(tick(1,component='other'))
    assert t.consume(applied(2))[-1]['origin_status']=='unknown'


def test_native_status_versions_reference_trigger_sample_and_status_read():
    t=GpioConsumptionTracker();pre=probes(gpioen=1,inten=1,inttype=1,input_clock_enable=1,sync0=1)
    post=probes(gpioen=1,inten=1,inttype=1,input_clock_enable=1,sync1=1,rise=1,irq_trigger_mask=1,native_irq=1)
    t.consume(tick(1,pre,post))
    after=probes(gpioen=1,inten=1,inttype=1,input_clock_enable=1,padin_latch=1,fall=1,status=1)
    out=t.consume(tick(2,post,after));resources=events(out,'gpio_input_sample')[0]['status_resources']
    assert resources[0]['value']==1 and resources[0]['dependencies']
    e=access(3,36,0,0,0);e.update(write=False,wdata=None,read_rdata=1)
    e['pre']=probes(psel=1,penable=1,pready=1,apb_addr=36,decoded_word=9,status=1,prdata=1)
    e['post']=probes();e['target_response']['rdata']=1
    read=events(t.consume(e),'gpio_register_read')[0]
    assert read['bit_resources'][0]['version']==resources[0]['version']
    assert read['post_bit_resources'][0]['value']==0


def test_actual_access_cannot_change_unrelated_register_or_skip_stage_updates():
    for fault in ('unrelated','stage'):
        t=GpioConsumptionTracker();e=access()
        if fault=='unrelated':
            e['post'].update(gpio_probe_gpioen=1,gpio_probe_input_clock_enable=1)
        else:
            e['pre'].update(gpio_probe_gpioen=1,gpio_probe_input_clock_enable=1,gpio_probe_sync0=1)
            e['post'].update(gpio_probe_gpioen=1,gpio_probe_input_clock_enable=1)
        assert t.consume(e)[0]['status']=='rejected'


def test_disabled_first_tick_still_verifies_whole_drive_before_later_enable():
    t,a=admission_tracker();t.consume(applied(1));pre=probes();pre['gpio_in']=257
    t.consume(tick(1,pre,probes()))
    pre2=probes(psel=1,penable=1,pwrite=1,pwdata=256,pready=1,apb_addr=4,decoded_word=1);pre2['gpio_in']=257
    post2=probes(gpioen=256,input_clock_enable=4)
    t.consume(tick(2,pre2,post2))
    pre3=deepcopy(post2);pre3['gpio_in']=257
    out=t.consume(tick(3,pre3,probes(gpioen=256,input_clock_enable=4,sync0=256)))
    assert events(out,'gpio_input_sample')[0]['stages']['sync0'][8]['origin_status']=='unknown'


def test_exact_receipt_id_and_full_post_drive_are_required_in_disabled_group():
    for fault in ('receipt_id','post_input'):
        t,a=admission_tracker();drive=applied(1);e=tick(1)
        e['pre']['gpio_in']=256;e['post']['gpio_in']=256
        if fault=='receipt_id':drive['actual_receipt_event_id']=999
        else:e['post']['gpio_in']=257
        t.consume(drive);out=t.consume(e)
        assert events(out,'gpio_consumption_match')[0]['reason']=='actual_input_receipt_not_verified'
        assert t._states['gpio']['inputs'][8]['origin_status']=='unknown'
        assert not t._states['gpio']['inputs'][8].get('receipt_verified',False)


def test_grouped_binding_origin_refs_map_each_target_bit_exactly():
    t,a=admission_tracker();e=access(value=3,new=3);e['component']='a';e['command_scope']['component']='a'
    t.consume(e);t.consume(tick(1,e['pre'],e['post'],component='a'));refs=t.output_resources_at('a',0,1)[:8]
    drive=applied(1,value=3,lo=0,width=8);drive['origin']=dict(kind='binding',source_component='a',source_port='gpio_out',source_bit_lo=0,producer_reset_epoch=0,producer_local_tick=1,producer_phase='post',producer_resource_refs=refs,delivery_event_id=50)
    out=t.consume(drive)[-1]['bit_resources']
    for offset,resource in enumerate(out):
        assert len(resource['origin_refs'])==1
        assert resource['origin_refs'][0]['bit']==offset
        assert resource['origin_refs'][0]['version']==refs[offset]['version']
