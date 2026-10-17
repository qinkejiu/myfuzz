import sys
sys.dont_write_bytecode=True
import tarfile,gzip,json,hashlib
from pathlib import Path
archive=Path('docs/reports/evidence/p6-native-online-directed-20261018/remote-records.tar.gz')
def canon(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def require(v,msg):
 if not v:raise ValueError(msg)
summary={'scope':'independent saved-data audit only, no project import or gate/checker invocation','archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'runs':{}}
with tarfile.open(archive) as tar:
 def read(name):
  raw=tar.extractfile(name).read();return json.loads(gzip.decompress(raw) if name.endswith('.gz') else raw)
 for group,count in (('positive',3),('controlled-response',1)):
  base='run-attempt3/'+group+'/'
  result=read(base+'result.json.gz');first=read(base+'first.json.gz');comparison=read(base+'fresh-comparison.json.gz');fresh=comparison['actual_trace'];plan=read(base+'plan.json');events=first['events']
  require(first==fresh,group+' entire first/fresh document differs')
  require(first['status']=='complete',group+' trace incomplete')
  require(first['semantic_sha256']==hashlib.sha256(canon({k:first[k] for k in ('events','local_ticks','status')})).hexdigest(),'semantic digest')
  require(first['genome_sha256']==hashlib.sha256(tar.extractfile(base+'plan.json').read()).hexdigest(),'full plan digest')
  require([e['event_id'] for e in events]==list(range(1,len(events)+1)),'event identity continuity')
  require(len(plan['instruction_slots'])==97 and plan['instruction_slots'][-1]==['cpu',3584,1],'slot/guard policy')
  identities=result['initial_process_identities'];processes=result['processes'];require(len(processes)==4 and all(p['terminal_returncode']==0 for p in processes),'first/fresh actual lifecycle records')
  for component in ('cpu','gpio0'):
   pair=[p for p in processes if p['component']==component];require(len(pair)==2 and pair[0]['pid']!=pair[1]['pid'] and pair[0]['execution_nonce']!=pair[1]['execution_nonce'] and pair[0]['artifact_digest']==pair[1]['artifact_digest'] and pair[0]['reset_epoch']==pair[1]['reset_epoch']==0,'fresh process scope')
  cases=[];cpu_steps=[e for e in events if e.get('component')=='cpu' and 'outputs'in e];accepts={};consumed={};pending=None;seq=0;pending_after_tick={}
  marker=result['actual_runner_identity']['sessions']['cpu']['identity']['runtime_artifact']['instruction_identity_observation']
  for event in cpu_steps:
   out=event['outputs'];require(len(out['driver_samples'])==1,'CPU sample truncation')
   sample=out['driver_samples'][0];pre=sample['pre']['backend'];post=sample['post']['backend']
   require(sample['local_tick']==event['local_tick'],'CPU raw tick')
   require(not pre['m_fault'] and not post['m_fault'],'native adapter fault')
   require(out['data_req_accepted']==int(bool(pre['m_req_valid'] and pre['m_req_ready'])),'actual accept')
   require(out['data_rsp_consumed']==int(bool(pre['m_rsp_valid'] and pre['m_rsp_ready'])),'actual consume')
   if out['data_rsp_consumed']:
    require(pending is not None,'unsourced response')
    require(out['data_rsp_source_sequence']==pending and out['data_rsp_source_epoch']==0,'response key')
    require(out['data_rsp_rdata']==pre['m_rsp_rdata'],'response raw value')
    consumed[pending]=event;pending=None
   if out['data_req_accepted']:
    require(pending is None,'more than one actual outstanding')
    seq+=1;pending=seq;accepts[seq]=event
   pending_after_tick[event['local_tick']]=pending
  require(pending is None,'final accepted response pending')
  require([s['local_tick'] for s in cpu_steps]==list(range(1,first['local_ticks']['cpu']+1)),'CPU ticks missing')
  prior_end=plan['warmup_advances'] and result['cases'][0]['receipt']['event_start']; previous_ticks=None
  for i in range(count):
   case=read(base+f'case-{i+1}.json.gz');receipt=case['receipt'];fragment=receipt['events'];actual=case['case'];raw=bytes.fromhex(case['raw_hex']);slot=512+32*i
   require(fragment==events[receipt['event_start']:receipt['event_end']],'case event slice')
   if i:require(previous_ticks==receipt['local_ticks_before'] and receipt['event_start']==prior_end,'cross case continuity')
   previous_ticks=receipt['local_ticks_after'];prior_end=receipt['event_end']
   require(case['process_identities']==identities,'same original scope')
   require(receipt['local_ticks_after']['cpu']-receipt['local_ticks_before']['cpu']==128,'CPU case bound')
   require(pending_after_tick[receipt['local_ticks_before']['cpu']] is None and pending_after_tick[receipt['local_ticks_after']['cpu']] is None,'case accepted CPU pending not drained')
   source=actual['source'];expected_kind='gpio0.pin_byte' if i==1 else 'cpu.instructions'
   require(case['selected_source']==expected_kind and source['action_id'].endswith(':'+expected_kind),'source identity')
   require(actual['case_id']==f'online-{i}-'+hashlib.sha256(raw).hexdigest()[:24],'raw candidate binding')
   insts=[e for e in fragment if e.get('kind')=='instruction_source'];require(len(insts)==1 and insts[0]['address']==slot,'packet instruction input')
   fetches=[(n,e) for n,e in accepts.items() if e['outputs']['data_addr']==slot and e['outputs']['driver_samples'][0]['pre']['physical'][marker]==1]
   require(len(fetches)==1,'actual packet fetch not unique')
   fetched=consumed[fetches[0][0]]['outputs']['data_rsp_rdata'];require(fetched==int.from_bytes(bytes.fromhex(insts[0]['data_hex']),'little'),'actual CPU fetch bytes differ from source')
   admissions=[e for e in fragment if e.get('kind')=='source_admission' and e['admission']['action_id']==source['action_id']]
   require(len(admissions)==1 and admissions[0]['event_id']<fetches[0][1]['event_id'],'fetch before recorded source admission')
   require(insts[0]['producer_event_id']==fetches[0][1]['event_id'],'source journal import not on first actual fetch step')
   if expected_kind=='cpu.instructions':
    word=int.from_bytes(bytes.fromhex(source['data_hex']),'little');require(word==(raw[3]<<20)|(10<<7)|0x13,'raw CPU source payload')
    require(insts[0]['data_hex']==source['data_hex'] and insts[0]['source_event_id']==source['action_id'],'source byte admission')
   else:
    require(source['value']==raw[3] and insts[0]['data_hex']=='13000000','IP raw payload/fixed NOP')
    injected=[e for e in fragment if e.get('kind')=='source_injection'];require(len(injected)==1 and injected[0]['value']==source['value'] and injected[0]['source_ref']=='external_gpio_pins','real IP injection')
   steps=[e for e in fragment if e.get('component')=='cpu' and 'outputs'in e]
   before=[e for e in cpu_steps if e['local_tick']==receipt['local_ticks_before']['cpu']][0]
   for edge,addr in ((before,slot),(steps[-1],slot+32)):
    backend=edge['outputs']['driver_samples'][-1]['post']['backend'];physical=edge['outputs']['driver_samples'][-1]['post']['physical']
    require(backend['m_req_valid']==1 and backend['m_req_write']==0 and backend['m_req_addr']==addr and backend['m_rsp_valid']==0 and physical[marker]==1,'actual unaccepted fetch boundary')
   require(case['actual_next_slot']==slot+32,'next slot metadata')
   delivery=[e for e in fragment if e.get('kind')=='mmio_delivery'];accepted=[e for e in fragment if e.get('kind')=='mmio_acceptance']
   require([(e['write'],e['offset']) for e in delivery]==[(True,12),(False,12),(False,8),(True,12)],'MMIO order')
   require(len(accepted)==4,'queue not drained')
   for delivered in delivery:
    matches=[e for e in accepted if e['source_transaction']==delivered['source_transaction']];require(len(matches)==1 and matches[0]['event_id']<delivered['event_id'],'queue join')
    key=delivered['source_transaction']['source_sequence'];native=accepts[key];require(native['outputs']['data_addr']==delivered['address'] and native['event_id']==matches[0]['producer_event_id'],'actual CPU request to router')
    require(native['outputs']['data_write']==int(delivered['write']) and native['outputs']['data_be']==15,'actual CPU MMIO request fields')
    if delivered['write']:require(native['outputs']['data_wdata']==delivered['write_value'],'actual CPU MMIO data')
   a,b=delivery[1]['read_value'],delivery[2]['read_value'];require(a==delivery[0]['write_value'],'real PADOUT readback')
   if i==1:require(b==source['value'],'IP input was not read')
   reads=[]
   for d in delivery[1:3]:
    response=consumed[d['source_sequence']];require(response['event_id']>d['event_id'],'CPU response order');reads.append(response['outputs']['data_rsp_rdata'])
   ram=[e for e in fragment if e.get('kind')=='memory_write' and e.get('address')==256];require(len(ram)==1,'one joint store')
   native_ram=accepts[ram[0]['transaction']['source_sequence']];require(native_ram['outputs']['data_write']==1 and native_ram['outputs']['data_wdata']==ram[0]['value'] and native_ram['outputs']['data_addr']==256,'RAM actual CPU write')
   require(ram[0]['value']==reads[0]^reads[1] and delivery[-1]['write_value']==ram[0]['value'],'CPU actual consumed relation')
   expected=a^b;delta=ram[0]['value']^expected;require(delta==(1 if group=='controlled-response' else 0),'independent expected relation check')
   gpio=[e for e in fragment if e.get('kind')=='local_tick_sample' and e.get('component')=='gpio0'];pre=[e for e in gpio if e['phase']=='pre'];post=[e for e in gpio if e['phase']=='post']
   requests=[e for e in pre if e['outputs']['backend']['gpio_req_valid']==1 and e['outputs']['backend']['gpio_req_ready']==1];responses=[e for e in pre if e['outputs']['backend']['gpio_rsp_valid']==1 and e['outputs']['backend']['gpio_rsp_ready']==1]
   require(len(requests)==len(responses)==4,'actual target req/rsp pending imbalance')
   for d,q,r in zip(delivery,requests,responses):
    qb=q['outputs']['backend'];rb=r['outputs']['backend'];require(qb['gpio_req_addr']==d['offset'] and qb['gpio_req_write']==int(d['write']) and qb['gpio_req_be']==15 and q['local_tick']<r['local_tick'],'actual target transaction')
    if d['write']:require(qb['gpio_req_wdata']==d['write_value'],'actual target write data')
    else:require(rb['gpio_rsp_rdata']==d['read_value'] and rb['gpio_rsp_error']==0,'retained real target read')
   require(post[-1]['outputs']['gpio_out']==delivery[-1]['write_value'],'actual final GPIO pin')
   require(all(e['outputs']['gpio_in_sync']==b for e in post[-4:]),'actual pin synchronizer')
   cases.append({'index':i,'source_id':expected_kind,'raw_hex':case['raw_hex'],'before_ticks':receipt['local_ticks_before'],'after_ticks':receipt['local_ticks_after'],'next_slot':slot+32,'actual_A':a,'actual_B':b,'cpu_read_values':reads,'actual_RAM_and_GPIO':ram[0]['value'],'expected_actual_target_XOR':expected,'difference':delta,'actual_target_request_response_count':4,'actual_fetch_word':fetched,'accepted_CPU_pending_before_after':[pending_after_tick[receipt['local_ticks_before']['cpu']],pending_after_tick[receipt['local_ticks_after']['cpu']]],'pending_reconstruction':'4 queue accepts/deliveries and4 target req/resps; actual next unaccepted instruction with no valid response; native single-outstanding tracker drained'})
  require(len(result['controlled_response_records'])==(2 if group=='controlled-response' else 0),'fault count')
  if group=='controlled-response':
   for f in result['controlled_response_records']:require(f['actual_target_response']==[62,0] and f['delivered_response']==[63,0] and f['transaction']['source_sequence']==14,'one actual XOR1')
  summary['runs'][group]={'entire_first_fresh_document_equal':True,'event_count':len(events),'local_ticks':first['local_ticks'],'plan_sha256':first['genome_sha256'],'semantic_sha256':first['semantic_sha256'],'case_audits':cases,'scope_note':'No APB PSEL/PENABLE protocol tap/raw full DriverReceipt journal in this legacy GPIO artifact; actual pinned APB target backend req/rsp +GPIO physical samples audited. Provenance remains unknown transport candidates, not authenticated terminal edges.'}
summary['conclusion']='bounded actual directed CPU/IP/CPU and controlled-response fresh data relations independently accepted; no IRQ/retirement/source/closed-loop certificate grant'
Path('/tmp/p6-native-independent-dataflow-audit-20261018.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
print(json.dumps(summary,sort_keys=True,indent=2))
