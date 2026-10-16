"""Pure software controls; no constructor, subprocess or native model."""
import copy
import importlib
import pytest


def gate():
    try:return importlib.import_module('myfuzz.scenario.boom_gpio_irq_verification')
    except ModuleNotFoundError:pytest.fail('IRQ gate source missing')


def test_default_entry_does_not_run_native(monkeypatch,capsys):
    g=gate()
    monkeypatch.setattr(g,'verify',lambda **kw:pytest.fail('native gate invoked'))
    assert g.main([])==0
    assert 'not_executed' in capsys.readouterr().out


def test_mret_requires_exact_actual_qualified_decode():
    g=gate()
    row=dict(system_return=1,csr_cmd=4,csr_addr=0x302,csr_evec=0x80000054,mepc=0x80000054)
    assert g.qualified_return(row,0x80000054)
    for key,value in [('csr_addr',0x102),('csr_addr',0x7b2),('csr_cmd',0),('system_return',0),('csr_evec',0x80000058)]:
        assert not g.qualified_return(row|{key:value},0x80000054)


def test_fixed_pulse_requires_64_actual_ticks_and_meip_matches():
    g=gate()
    pulses=[dict(kind='pulse_start',start_cpu_tick=3,end_cpu_tick_exclusive=67)]
    samples=[dict(cycle=i,irq_input=int(3<=i<67),probes_pre={'meip':int(3<=i<67)},probes_post={'meip':int(3<=i<67)}) for i in range(1,70)]
    g.validate_pulse(pulses,samples,suppressed=False)
    for mutation in ('extend','missing','meip'):
        p=copy.deepcopy(pulses);s=copy.deepcopy(samples)
        if mutation=='extend':p[0]['end_cpu_tick_exclusive']+=1
        if mutation=='missing':s.pop(8)
        if mutation=='meip':s[5]['probes_post']['meip']=0
        with pytest.raises(ValueError):g.validate_pulse(p,s,suppressed=False)
    for sample in samples:
        sample['irq_input']=sample['probes_pre']['meip']=sample['probes_post']['meip']=0
    g.validate_pulse(pulses,samples,suppressed=True)
    with pytest.raises(ValueError):g.validate_pulse(pulses,samples,suppressed=False)


def test_scoped_normalization_preserves_arbitrary_nested_payload():
    g=gate();ids={'cpu_execution':'cpu-uuid','gpio_execution':'gpio-uuid','coherent_stream':'stream-uuid','runner_execution':'runner-uuid'}
    events=[{'schema_version':'boom_routing_observation.v1','execution_id':'cpu-uuid','source_transaction':{'execution_id':'cpu-uuid'},'payload':{'source_transaction':{'execution_id':'cpu-uuid'}}},
            {'kind':'coherent_accepted_raw','raw_event_scope':'stream-uuid','execution_id':'cpu-uuid','native_event':{'data':'cpu-uuid'}}]
    result=g.normalize_rows(events,ids)
    assert result[0]['execution_id']!='cpu-uuid'
    assert result[0]['source_transaction']['execution_id']!='cpu-uuid'
    assert result[0]['payload']==events[0]['payload'] and result[1]['native_event']==events[1]['native_event']
    assert events[0]['execution_id']=='cpu-uuid'


def test_missing_actual_chain_is_never_positive():
    g=gate()
    for run in ({},{'error':None,'last_cpu_outputs':{'ram_3028':(1<<32)|1}}, {'error':None,'source_events':[]}):
        with pytest.raises(ValueError):g.validate_run(run,suppressed=False)


def test_raw_commands_and_coherent_rows_must_bind_same_actual_edges():
    g=gate();execution='actual-uuid'
    sample=dict(cycle=1,irq_input=0,events=[dict(channel='A',address=0x3000)],probes_pre={'meip':0},probes_post={'meip':0})
    run=dict(identities={'cpu_execution':execution},cpu_samples=[sample],
        cpu_commands=[dict(operation='STEP_IRQ',execution_id=execution,args=[0],response=copy.deepcopy(sample))],
        runtime_events=[dict(kind='coherent_accepted_raw',execution_id=execution,local_tick=1,native_event=copy.deepcopy(sample['events'][0]))],
        source_events=[dict(kind='boom_irq_passive_sample',local_tick=1,irq_input=0,probes_pre={'meip':0},probes_post={'meip':0})])
    g.validate_transport(run)
    for kind in ('command','scope','raw','probe'):
        bad=copy.deepcopy(run)
        if kind=='command':bad['cpu_commands'][0]['args']=[1]
        if kind=='scope':bad['cpu_commands'][0]['execution_id']='other'
        if kind=='raw':bad['runtime_events'][0]['native_event']['address']+=4
        if kind=='probe':bad['source_events'][0]['probes_post']['meip']=1
        with pytest.raises(ValueError):g.validate_transport(bad)


def test_freeze_and_default_are_tool_free(monkeypatch,tmp_path):
    import subprocess
    from pathlib import Path
    g=gate()
    for name in ('run','Popen','check_output'):
        monkeypatch.setattr(subprocess,name,lambda *a,**kw:pytest.fail('tool/model invoked'))
    root=Path(__file__).resolve().parents[2]
    frozen=g.prepare_freeze(root)
    assert frozen['native_run'] is False
    assert 'src/myfuzz/scenario/boom_gpio_irq_verification.py' in frozen['files']
    g.verify_freeze(root,frozen)
    g.main(['--repo',str(root),'--write-freeze',str(tmp_path/'freeze.json')])


def test_fresh_prefix_preserves_nested_data_and_retains_startup_process():
    g=gate()
    ids=dict(cpu_execution='cpu-a',cpu_startup_execution='start-a',gpio_execution='gpio-a',coherent_stream='stream-a',runner_execution='runner-a')
    first=dict(identities=ids,fault_mode='positive',lifecycles={'cpu':[{'pid':11},{'pid':12}],'gpio':[{'pid':13}]})
    for key in ('cpu_samples','delivery_control','cpu_outputs','last_cpu_outputs','gpio_samples','coherent_report','coherent_coverage','events','runtime_events','source_events','gpio_events','router_deliveries','cpu_commands','gpio_commands','cpu_transport_reads','gpio_transport_reads'):
        first[key]=[]
    first['coherent_report']={};first['coherent_coverage']={}
    first['cpu_commands']=[dict(schema_version='boom_irq_gate_command.v1',execution_id='start-a',operation='EXTERNAL',args=[0x4000,0x5000],response={'ok':True})]
    first['runtime_events']=[dict(kind='coherent_accepted_raw',execution_id='cpu-a',raw_event_scope='stream-a',native_event={'data':17})]
    fresh=copy.deepcopy(first)
    fresh['identities']={k:v.replace('-a','-b') for k,v in ids.items()}
    fresh['cpu_commands'][0]['execution_id']='start-b'
    fresh['runtime_events'][0].update(execution_id='cpu-b',raw_event_scope='stream-b')
    fresh['lifecycles']={'cpu':[{'pid':21},{'pid':22}],'gpio':[{'pid':23}]}
    g.compare_fresh(first,fresh)
    fresh['runtime_events'][0]['native_event']['data']=18
    with pytest.raises(ValueError):g.compare_fresh(first,fresh)
    fresh=copy.deepcopy(first)
    with pytest.raises(ValueError):g.compare_fresh(first,fresh)


@pytest.fixture
def software_chain():
    from myfuzz.local_harness.boom_irq_contract import PROBES
    g=gate();samples=[];source=[]
    for tick in range(1,101):
        p={name:0 for name in PROBES};p.update(meip=int(4<=tick<68),mepc=0x80000054,csr_pc=0x80000054)
        if tick==6:p.update(rob_exception=1,rob_cause=g.CAUSE,csr_exception=1,csr_cause=g.CAUSE,csr_evec=g.ISR)
        if tick==80:p.update(system_return=1,csr_cmd=4,csr_addr=0x302,csr_evec=0x80000054)
        sample=dict(cycle=tick,irq_input=p['meip'],events=[],probes_pre=copy.deepcopy(p),probes_post=copy.deepcopy(p));samples.append(sample)
    raw_pre=dict(interrupt=0,physical={'interrupt':0,'gpio_in':1})
    raw_post=dict(interrupt=1,physical={'interrupt':1,'gpio_in':1})
    run=dict(error=None,status='complete',identities={'cpu_execution':'cpu-uuid','gpio_execution':'gpio-uuid'},
        identity={'sessions':{'gpio':{'identity':{'runtime_artifact':{'physical_exports':[dict(physical_port=n,runtime_name=n) for n in ('interrupt','gpio_in')]}}}}},
        gpio_trigger_tracker_installed=False,
        lifecycles={'cpu':[dict(pid=11,closed=True,exit=0),dict(pid=12,closed=True,exit=0)],'gpio':[dict(pid=13,closed=True,exit=0)]},
        coherent_report=dict(structural_error=False,stream_closed=True),uncertain_keys=[],cpu_samples=samples,
        events=[dict(component='cpu',local_tick=3,outputs={'boot_ready':1}),
            dict(kind='source_injection',action_id='pin-rise',component='gpio',port='gpio_in',value=1),
            dict(kind='local_tick_sample',component='gpio',local_tick=8,phase='post',outputs=copy.deepcopy(raw_post)),
            dict(kind='source_start',source_tick=8,cpu_tick=3,source_event_id=1,source=['gpio','irq'],target=['cpu','irq']),
            dict(kind='pulse_start',start_cpu_tick=4,end_cpu_tick_exclusive=68,source_event_id=1,source=['gpio','irq'],target=['cpu','irq'])],
        gpio_events=[dict(kind='gpio_tick_observation',local_tick=8,reset_epoch=0,
            command_scope=dict(component='gpio',reset_epoch=0,command_sequence=1),pre={'interrupt':0,'gpio_in':1},post={'interrupt':1,'gpio_in':1})],
        gpio_commands=[dict(receipt=dict(sequence=1,execution='gpio-uuid',payload={'samples':[dict(local_tick=8,pre=raw_pre,post=raw_post)]}))],
        delivery_control=[dict(cycle=s['cycle'],requested_irq=s['irq_input'],delivered_irq=s['irq_input']) for s in samples],
        source_events=source,runtime_events=[],router_deliveries=[],
        last_cpu_outputs=dict(ram_3010=g.CAUSE,ram_3018=0x80000054,ram_3020=1,ram_3028=(1<<32)|1))
    for i,(value,at,dt,gt) in enumerate(((0,1,2,4),(1,20,21,10),(0,30,31,20))):
        key=dict(execution_id='cpu-uuid',source_sequence=i+1);request=dict(channel='A',opcode=4,size=2,source=i,address=0x4024,mask=0xf0,data=0)
        response=dict(channel='D',opcode=1,size=2,source=i,data=value<<32,external=True)
        samples[at-1]['events']=[copy.deepcopy(request)];samples[dt-1]['events']=[copy.deepcopy(response)]
        access=dict(kind='gpio_apb_access',source_transaction=copy.deepcopy(key),access_id=i+1,status='observed',write=False,decoded_offset=0x24,read_rdata=value,local_tick=gt,phase='pre')
        run['gpio_events'].append(access)
        source.extend([dict(kind='boom_external_a_queued',local_tick=at,source_transaction=copy.deepcopy(key),native_request=copy.deepcopy(request)),dict(kind='boom_external_d_accepted',local_tick=dt,source_transaction=copy.deepcopy(key),native_response=copy.deepcopy(response))])
        run['router_deliveries'].append(dict(source_transaction=copy.deepcopy(key),target_access_id=i+1,target_apb_access=copy.deepcopy(access),read_value=value<<32))
    for tick,address,value in ((10,0x3010,g.CAUSE),(12,0x3018,0x80000054),(40,0x3020,1),(41,0x3024,0),(42,0x3028,1),(82,0x302c,1)):
        samples[tick-1]['events'].append(dict(channel='A',opcode=0,address=address,data=value<<((address&7)*8)))
    for index,row in enumerate(run['events'],1):row['event_id']=index
    _sync_transport(run)
    return run


def test_complete_software_chain_is_explicitly_a_fixture(software_chain):
    result=gate().validate_run(software_chain,suppressed=False)
    assert result['status_reads']==[0,1,0]


def _sync_transport(run):
    routing=[r for r in run['source_events'] if r['kind']!='boom_irq_passive_sample']
    run['source_events']=[dict(kind='boom_irq_passive_sample',local_tick=s['cycle'],irq_input=s['irq_input'],probes_pre=copy.deepcopy(s['probes_pre']),probes_post=copy.deepcopy(s['probes_post'])) for s in run['cpu_samples']]+routing
    run['runtime_events']=[dict(kind='coherent_accepted_raw',execution_id='cpu-uuid',local_tick=s['cycle'],native_event=copy.deepcopy(e)) for s in run['cpu_samples'] for e in s['events']]
    for i,row in enumerate(run['runtime_events'],1):row['raw_event_id']=i
    run['cpu_commands']=[dict(operation='STEP_IRQ',execution_id='cpu-uuid',args=[s['irq_input']],response=copy.deepcopy(s)) for s in run['cpu_samples']]


@pytest.mark.parametrize('mutation',['reap','gpio_edge','target_data','ram','mret','rob','csr','foreground_store','status_clear'])
def test_positive_refuses_missing_or_changed_actual_link(software_chain,mutation):
    g=gate();run=copy.deepcopy(software_chain)
    if mutation=='reap':run['lifecycles']['cpu'][0]['exit']=-9
    if mutation=='gpio_edge':run['gpio_events'][0]['post']['interrupt']=0
    if mutation=='target_data':run['router_deliveries'][1]['read_value']=0
    if mutation=='ram':run['last_cpu_outputs']['ram_3028']=1
    if mutation in ('mret','rob','csr'):
        for s in run['cpu_samples']:
            for phase in ('probes_pre','probes_post'):
                if mutation=='mret':s[phase]['csr_addr']=0x102
                if mutation=='rob':s[phase]['rob_exception']=0
                if mutation=='csr':s[phase]['csr_exception']=0
    if mutation=='foreground_store':run['cpu_samples'][81]['events']=[e for e in run['cpu_samples'][81]['events'] if e['address']!=0x302c]
    if mutation=='status_clear':run['gpio_events'][-1]['read_rdata']=1
    _sync_transport(run)
    with pytest.raises(ValueError):g.validate_run(run,suppressed=False)


def test_failed_factory_restores_capture_and_retains_failure_without_construction(monkeypatch,tmp_path):
    import subprocess
    from myfuzz.scenario import boom_gpio_irq_runner as factory
    from myfuzz.local_harness import boom_irq_scenario_session as adapter
    g=gate();native=adapter.GeneratedBoomIrqCpuSession;gpio=factory.GeneratedPulpGpioSession
    for name in ('run','Popen','check_output'):
        monkeypatch.setattr(subprocess,name,lambda *a,**kw:pytest.fail('tool/model invoked'))
    def fail(**kw):raise ValueError('software fixture refused before constructor')
    monkeypatch.setattr(factory,'make_boom_gpio_irq_runner',fail)
    run=g._run_one(repo=tmp_path,cpu_output=tmp_path,cache_dir=tmp_path)
    assert run['error']['type']=='ValueError' and not run['lifecycles']['cpu']
    assert adapter.GeneratedBoomIrqCpuSession is native and factory.GeneratedPulpGpioSession is gpio
    assert not g._CAPTURE_LOCK.locked()


def test_only_declared_target_receipt_transaction_slots_are_normalized():
    g=gate();ids={'cpu_execution':'uuid'}
    row=dict(kind='mmio_delivery',source_transaction={'execution_id':'uuid'},
        target_apb_access={'source_transaction':{'execution_id':'uuid'}},
        target_request={'source_transaction':{'execution_id':'uuid'}},
        target_response={'source_transaction':{'execution_id':'uuid'}},payload={'target_request':{'source_transaction':{'execution_id':'uuid'}}})
    result=g.normalize_rows([row],ids)[0]
    assert result['target_apb_access']['source_transaction']['execution_id']!='uuid'
    assert result['target_request']['source_transaction']['execution_id']!='uuid'
    assert result['target_response']['source_transaction']['execution_id']!='uuid'
    assert result['payload']==row['payload']


def test_suppression_requires_real_source_but_no_isr_and_same_requested_pattern(software_chain):
    g=gate();run=copy.deepcopy(software_chain)
    for s in run['cpu_samples']:
        s['irq_input']=0
        for phase in ('probes_pre','probes_post'):
            s[phase].update(meip=0,rob_exception=0,csr_exception=0,system_return=0)
        s['events']=[e for e in s['events'] if not (e.get('source') in (1,2) or (e.get('address',0)>=0x3010 and e.get('address',0)<0x3030))]
    for r in run['delivery_control']:r['delivered_irq']=0
    run['last_cpu_outputs'].update(ram_3010=0,ram_3018=0,ram_3020=0,ram_3028=0)
    run['gpio_events']=run['gpio_events'][:2]
    run['router_deliveries']=run['router_deliveries'][:1]
    routing=[r for r in run['source_events'] if r['kind']!='boom_irq_passive_sample'][:2]
    run['source_events']=[dict(kind='boom_irq_passive_sample',local_tick=s['cycle'],irq_input=0,probes_pre=copy.deepcopy(s['probes_pre']),probes_post=copy.deepcopy(s['probes_post'])) for s in run['cpu_samples']]+routing
    run['runtime_events']=[dict(kind='coherent_accepted_raw',execution_id='cpu-uuid',local_tick=s['cycle'],native_event=copy.deepcopy(e)) for s in run['cpu_samples'] for e in s['events']]
    for i,row in enumerate(run['runtime_events'],1):row['raw_event_id']=i
    run['cpu_commands']=[dict(operation='STEP_IRQ',execution_id='cpu-uuid',args=[0],response=copy.deepcopy(s)) for s in run['cpu_samples']]
    _sync_transport(run)
    assert g.validate_run(run,suppressed=True)['suppressed']
    with pytest.raises(ValueError):g.validate_run(run,suppressed=False)
    run['delivery_control'][3]['requested_irq']=0;run['delivery_control'][70]['requested_irq']=1
    with pytest.raises(ValueError):g.validate_run(run,suppressed=True)


def test_exclusive_gzip_retains_unknown_partial_without_rewriting(tmp_path):
    import gzip,json
    g=gate();document=dict(error={'type':'Unknown'},cpu_transport_reads=[{'raw_line':'not-json\n'}],cpu_samples=[])
    path=tmp_path/'partial.json.gz';g.save_run(path,document)
    assert json.loads(gzip.decompress(path.read_bytes()))==document
    with pytest.raises(FileExistsError):g.save_run(path,{})


def test_gpio_wire_normalizes_only_typed_protocol_execution_slot():
    g=gate();ids={'gpio_execution':'a'*32}
    rows=[dict(execution_id='a'*32,raw_line='RESULT '+'a'*32+' 1 0 1 7b7d\n'),dict(execution_id='a'*32,raw_line='unknown '+'a'*32+' payload\n')]
    result=g.normalize_gpio_wire(rows,ids)
    assert result[0]['raw_line']=='RESULT declared:gpio_execution 1 0 1 7b7d\n'
    assert result[1]['raw_line']==rows[1]['raw_line']
    with pytest.raises(ValueError):g.normalize_gpio_wire([dict(execution_id='a'*32,raw_line='ACKED '+'b'*32+' 1 0\n')],ids)


@pytest.mark.parametrize('mutation',['mret_before_trap','isr_store_after_return','late_initial_clear','isr_read_before_trap'])
def test_actual_temporal_chain_refuses_reordered_evidence(software_chain,mutation):
    g=gate();run=copy.deepcopy(software_chain)
    if mutation=='mret_before_trap':
        for phase in ('probes_pre','probes_post'):
            saved=copy.deepcopy(run['cpu_samples'][79][phase]);run['cpu_samples'][79][phase]['system_return']=0
            run['cpu_samples'][1][phase].update({k:saved[k] for k in ('system_return','csr_cmd','csr_addr','csr_evec','mepc')})
    if mutation=='isr_store_after_return':
        for s in run['cpu_samples']:
            selected=[r for r in s['events'] if r['channel']=='A' and r.get('address')==0x3028]
            s['events']=[r for r in s['events'] if r not in selected]
            run['cpu_samples'][90]['events'].extend(selected)
    if mutation in ('late_initial_clear','isr_read_before_trap'):
        pair=0 if mutation=='late_initial_clear' else 1
        at,dt=(14,15) if pair==0 else (4,5)
        rows=[r for r in run['source_events'] if r['kind'] in ('boom_external_a_queued','boom_external_d_accepted')]
        q,c=rows[pair*2:pair*2+2]
        for sample in run['cpu_samples']:
            sample['events']=[e for e in sample['events'] if not ((e['channel']=='A' and e.get('source')==pair and e.get('address')==0x4024) or (e['channel']=='D' and e.get('source')==pair))]
        run['cpu_samples'][at-1]['events'].append(copy.deepcopy(q['native_request']))
        run['cpu_samples'][dt-1]['events'].append(copy.deepcopy(c['native_response']))
        q['local_tick']=at;c['local_tick']=dt
    _sync_transport(run)
    with pytest.raises(ValueError):g.validate_run(run,suppressed=False)


@pytest.mark.parametrize('mutation',['source_id','binding','trigger'])
def test_pulse_must_bind_actual_gpio_producer_identity(software_chain,mutation):
    g=gate();run=copy.deepcopy(software_chain)
    pulse=next(r for r in run['events'] if r.get('kind')=='pulse_start')
    source=next(r for r in run['events'] if r.get('kind')=='source_start')
    if mutation=='source_id':source['source_event_id']=1;pulse['source_event_id']=2
    if mutation=='binding':pulse['source']=['unrelated','irq']
    if mutation=='trigger':pulse['source_trigger']={'sample_event_id':999}
    with pytest.raises(ValueError):g.validate_run(run,suppressed=False)


@pytest.mark.parametrize('mutation',['producer_tick','producer_phase','producer_value','gpio_command','gpio_phase','source_route','target_port','source_cpu_tick','optional_absence','tracker_claim'])
def test_exact_physical_producer_and_binding_controls(software_chain,mutation):
    g=gate();run=copy.deepcopy(software_chain)
    producer=next(r for r in run['events'] if r.get('kind')=='local_tick_sample')
    source=next(r for r in run['events'] if r.get('kind')=='source_start')
    pulse=next(r for r in run['events'] if r.get('kind')=='pulse_start')
    if mutation=='producer_tick':producer['local_tick']+=1
    if mutation=='producer_phase':producer['phase']='pre'
    if mutation=='producer_value':producer['outputs']['interrupt']=0
    if mutation=='gpio_command':run['gpio_events'][0]['command_scope']['command_sequence']=2
    if mutation=='gpio_phase':run['gpio_commands'][0]['receipt']['payload']['samples'][0]['post']['physical']['interrupt']=0
    if mutation=='source_route':source['source']=['unrelated','irq']
    if mutation=='target_port':pulse['target']=['cpu','wrong']
    if mutation=='source_cpu_tick':source['cpu_tick']+=1
    if mutation=='optional_absence':source['source_trigger']=None
    if mutation=='tracker_claim':run['gpio_trigger_tracker_installed']=True
    with pytest.raises(ValueError):g.validate_run(run,suppressed=False)


def test_source_and_temporal_witnesses_retain_actual_refs(software_chain):
    g=gate();result=g.validate_run(software_chain,suppressed=False)
    source=result['source_witness'];timing=result['temporal_witness']
    assert source['producer_event_id']==3 and source['source_trigger'] is None and not source['tracker_installed']
    assert timing['csr_tick']==6 and timing['mret_pre_tick']==80
    assert timing['status_accesses'][1]['a_tick']==20
    assert timing['result_acceptances']['3028']['local_tick']==42
    assert all(type(r['raw_event_id']) is int for r in timing['result_acceptances'].values())


def test_rob_csr_pre_post_order_is_measured_not_guessed(software_chain):
    g=gate();run=copy.deepcopy(software_chain)
    run['cpu_samples'][5]['probes_pre']['rob_exception']=0
    run['cpu_samples'][5]['probes_post']['csr_exception']=0
    _sync_transport(run)
    with pytest.raises(ValueError):g.validate_run(run,suppressed=False)
    run['cpu_samples'][5]['probes_pre']['csr_exception']=0
    run['cpu_samples'][5]['probes_post']['csr_exception']=1
    _sync_transport(run)
    assert g.validate_run(run,suppressed=False)['temporal_witness']['csr_phase']=='post'


def test_initial_gpio_clear_must_precede_real_gpio_edge(software_chain):
    g=gate();run=copy.deepcopy(software_chain)
    run['gpio_events'][1]['local_tick']=9
    run['router_deliveries'][0]['target_apb_access']['local_tick']=9
    with pytest.raises(ValueError):g.validate_run(run,suppressed=False)
