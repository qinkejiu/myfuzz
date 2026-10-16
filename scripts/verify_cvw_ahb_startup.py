"""Source preparation and scheduled CVW→Caliptra passive AHB observation gate.

Default invocation hashes source only. Native execution is separately opt-in,
nonblocking-canonical-lock protected, and retains every original API receipt.
"""
from __future__ import annotations
import argparse
import copy
from dataclasses import asdict
import fcntl
import json
from pathlib import Path
import re
import subprocess
from scripts.verify_cva6_full_axi_observer import sha,encoded,confined,write_new,write_gzip

FREEZE_SCHEMA='cvw_ahb_startup_gate_source_freeze.v1'
EVENT_SCHEMA='bounded_cpu_ahb_observation.v1'
CASE_ID='cvw-sha-directed'
LIMIT=20000
RESULT=0xc0001000
CANONICAL_LOCK=Path('/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock')
EXTRA_SOURCES=(
 'scripts/verify_cvw_ahb_startup.py','scripts/verify_cva6_full_axi_observer.py',
 'src/myfuzz/scenario/cvw_caliptra_example.py','src/myfuzz/scenario/cvw_gpio_example.py',
 'src/myfuzz/integration/cvw_pulp_online.py',
 'tests/integration/test_cvw_cpu_caliptra_chain_real.py',
 'tests/local_harness/test_cvw_ahb_gate.py',
 'configs/cpus/cvw/component_profile.json',
 'configs/peripherals/caliptra_sha256/component_profile.json',
 'configs/soc/sources.lock.json','configs/soc/closures/cvw.json',
 'configs/soc/closures/caliptra_sha256.json',
 'docs/reports/evidence/cvw-ahb-source-audit-20261017/first.json.gz',
 'docs/reports/evidence/cvw-ahb-source-audit-20261017/audit-receipt.json',
 'docs/reports/evidence/ahb-register-identity-20261017/old-caliptra-target-artifact.json.gz')

def _source_names():
 from myfuzz.local_harness.build import _discover_host_sources
 return {*_discover_host_sources(),*EXTRA_SOURCES}

def prepare_freeze(repo):
 repo=Path(repo).resolve()
 return dict(schema_version=FREEZE_SCHEMA,source_only=True,native_run=False,
   cpu_step_limit=LIMIT,memory_seed=17,program_bytes=1024,
   files={name:sha(confined(repo/name,repo).read_bytes()) for name in sorted(_source_names())})

def verify_freeze(repo,document):
 if (not isinstance(document,dict) or document.get('schema_version')!=FREEZE_SCHEMA
     or document.get('source_only') is not True or document.get('native_run') is not False
     or any(type(document.get(k)) is not int or document[k]!=v for k,v in
            [('cpu_step_limit',LIMIT),('memory_seed',17),('program_bytes',1024)])
     or set(document.get('files',{}))!=_source_names()):
  raise ValueError('AHB gate source freeze contract')
 if prepare_freeze(repo)!=document:raise ValueError('AHB gate source freeze changed')

def advance_until_flag(recorder,cpu,*,limit=LIMIT,events=None):
 if type(limit) is not int or not 0<limit<=LIMIT:raise ValueError('CPU step bound')
 for _ in range(limit):
  recorder.advance(('cpu',))
  if (any(e.get('kind')=='memory_write' and e.get('address')==RESULT+64
          for e in (cpu.service.events if events is None else events())) and cpu.pending_responses==0):return True
 return False

def expected_scope(execution):
 return dict(execution_id=execution,testcase_id=CASE_ID,reset_epoch=0,
             source_component='cpu',endpoint_id='cpu.external_bus')

def normalize_observer(events,execution):
 result=copy.deepcopy(events)
 for row in result:
  if row.get('schema_version')!=EVENT_SCHEMA:raise ValueError('foreign observer schema')
  if row.get('scope')!=expected_scope(execution):raise ValueError('observer scope differs from issued execution')
  row['scope']['execution_id']='DECLARED_CPU_EXECUTION'
  if row.get('kind')=='ahb_startup_receipt':
   receipt=row['raw_receipt']
   if receipt['execution']!=execution:raise ValueError('startup receipt execution')
   receipt['execution']='DECLARED_CPU_EXECUTION'
 return result

def assert_imported_once(events,runner_events):
 imported=[{k:copy.deepcopy(v) for k,v in row.items()
            if k not in ('component','event_id','producer_event_id')}
           for row in runner_events if row.get('schema_version')==EVENT_SCHEMA]
 if imported!=events:raise ValueError('Runner observer import differs or repeats')

def project_rows(sample,mapping):
 from myfuzz.scenario.ahb_cpu_events import SHAPE
 if set(mapping)!=set(SHAPE):raise ValueError('actual ABI lacks all thirteen AHB roles')
 return {p:{role:sample[p]['protocol_taps'][name] for role,name in mapping.items()}
         for p in ('pre','post')}

def replay_actual_prefix(document):
 from myfuzz.scenario.ahb_cpu_events import AhbCpuObserver,bind_ahb_trace
 from myfuzz.local_harness.ahb_startup import configure_observer_startup,validate_startup_page
 artifact=document['artifact'];execution=document['native_execution']
 endpoint,mapping,trace=bind_ahb_trace(artifact)
 observer=AhbCpuObserver(component_id='cpu',endpoint_id=endpoint)
 observer.contract['trace_binding']=trace
 contract=configure_observer_startup(observer,artifact)
 observer.begin_scope(execution_id=execution,testcase_id=CASE_ID,reset_epoch=0)
 observer.begin_startup(contract)
 records=document['driver_receipts'];pages=contract['page_count']
 if len(records)<=pages:raise ValueError('startup and first command prefix required')
 for index,record in enumerate(records,1):
  receipt=record['receipt'];before=max(0,index-pages-1)
  startup=index<=pages
  if (record['operation']!=('READ_AHB_STARTUP' if startup else 'STEP_MEMORY')
      or receipt['status']!='result' or receipt['execution']!=execution
      or type(receipt['sequence']) is not int or receipt['sequence']!=index
      or any(type(receipt.get(k)) is not int or receipt[k]!=v for k,v in
        [('tick_before',before),('tick_after',0 if startup else before+1),('new_ticks',0 if startup else 1)])):
   raise ValueError('actual CPU receipt identity/ticks')
  payload=receipt['payload']
  if payload['kind']!='ahb_lite_cpu':raise ValueError('CPU receipt kind')
  if startup:
   if record['fields']!=[index-1] or payload['samples']!=[]:
    raise ValueError('startup zero clock receipt fields')
   observer.record_startup_receipt(receipt)
   for raw in validate_startup_page(payload['observations']['ahb_startup'],contract,expected_page=index-1):
    observer.observe_startup(raw,rows=project_rows(raw['sample'],mapping))
   if index==pages:observer.finish_startup()
  else:
   sample,=payload['samples'];backend=sample['pre']['backend']
   fields=[backend[k] for k in ('m_req_ready','m_rsp_valid','m_rsp_rdata','m_rsp_error')]
   if (record['fields']!=fields or sample['local_tick']!=before+1
       or payload['pre_backend']!=backend):raise ValueError('CPU command pre edge binding')
   observer.observe(sample,rows=project_rows(sample,mapping))
 if (observer.events!=document['runtime_events'] or observer.counts!=document['counts']
     or observer.pending!=document['pending'] or not observer.measured_reset_to_command_prefix):
  raise ValueError('saved full raw prefix does not reproduce observer')
 return observer

def normalize_receipts(records,execution,component):
 result=copy.deepcopy(records)
 allowed={'cpu':{'READ_AHB_STARTUP','STEP_MEMORY'},'sha':{'ACCESS_AHB_REG'}}[component]
 for row in result:
  if row['operation'] not in allowed or row['receipt']['execution']!=execution:
   raise ValueError('actual receipt operation/execution')
  row['receipt']['execution']='DECLARED_'+component.upper()+'_EXECUTION'
 return result

def validate_lifecycle(rows,execution):
 if len(rows)!=1:raise ValueError('one actual process per component required')
 row=rows[0]
 if (type(row.get('pid')) is not int or row['pid']<=0 or row.get('ready') is not True
     or row.get('closed') is not True or row.get('execution')!=execution
     or type(row.get('returncode')) is not int or row['returncode']!=0
     or type(row.get('poll_after_close')) is not int or row['poll_after_close']!=0):
  raise ValueError('native process not successfully ready/closed/reaped')

class Capture:
 """Passive instance wrappers retain real classes and forward each call once."""
 def __init__(self,session,component,shared):
  self.session=session;self.component=component;self.shared=shared
  self.receipts=[];self.lifecycle=[];self.runtime_events=[];self.errors=[]
  self._seen={};self._bytes=0
  self.service_events=[];self.deliveries=[];self.acceptances=[];self._stream_heads={}
  self.stream_contexts=[];self.outputs=[];self._step_index=0;self._step_receipt_start=0
  original_command=session.command;original_begin=session.begin_case
  original_end=session.end_case;original_abort=session._abort
  original_step=session.step_local
  def command(operation,fields):
   if shared['failed']:raise RuntimeError('gate capture poisoned before native command')
   self.note_process(True)
   attempt=dict(operation=operation,fields=list(fields),receipt=None)
   self.receipts.append(attempt)
   try:
    receipt=original_command(operation,fields)
    attempt['receipt']=asdict(receipt)
    self._bytes+=len(encoded(attempt))
    if self._bytes>128*1024*1024:raise ValueError('gate receipt byte budget')
    return receipt
   except Exception as error:
    shared['failed']=True;attempt['error']=dict(type=type(error).__name__,detail=str(error));raise
  def begin(case):
   try:
    result=original_begin(case);self.note_process(True);return result
   finally:self.note_process(False);self.collect()
  def step(inputs):
   self._step_index+=1;self._step_receipt_start=len(self.receipts)
   failure=None
   try:
    result=original_step(inputs);self.outputs.append(copy.deepcopy(result));return result
   except Exception as error:
    failure=error;shared['failed']=True;raise
   finally:
    try:self.collect()
    except Exception as error:
     shared['failed']=True
     self.errors.append(dict(stage='step_capture',type=type(error).__name__,detail=str(error)))
     if failure is None:raise
  def abort():
   self.note_process(False)
   try:return original_abort()
   finally:self.reaped();self.collect()
  def end():
   self.note_process(False)
   try:return original_end()
   finally:self.reaped();self.collect()
  session.command=command;session.begin_case=begin;session.step_local=step
  session._abort=abort;session.end_case=end
 def collect(self):
  for event in getattr(self.session,'runtime_events',[]):
   index=event['observer_record_index']
   if index not in self._seen:
    preserved=copy.deepcopy(event)
    self.runtime_events.append(preserved);self._seen[index]=preserved
   elif self._seen[index]!=event:raise ValueError('observer reused raw record index with different payload')
  for name,owner,attribute in (('service_events',getattr(self.session,'service',None),'events'),
      ('deliveries',getattr(self.session,'router',None),'deliveries'),
      ('acceptances',getattr(self.session,'router',None),'acceptances')):
   stream=getattr(owner,attribute,[])
   head,offset=self._stream_heads.get(name,(None,0))
   if not stream:continue
   if stream[0] is not head:offset=0
   additions=copy.deepcopy(list(stream[offset:]))
   for row in additions:
    self.stream_contexts.append(dict(stream=name,stream_index=len(getattr(self,name)),
       step_index=self._step_index,local_tick=self.session.local_ticks,
       receipt_index=(len(self.receipts)-1 if len(self.receipts)>self._step_receipt_start else None)))
    getattr(self,name).append(row)
   self._stream_heads[name]=(stream[0],len(stream))
 def note_process(self,ready):
  process=getattr(self.session,'_process',None)
  # GeneratedLocalSession stores the transport under _proc.
  if process is None:process=getattr(self.session,'_proc',None)
  if process is None:return
  if not isinstance(process,subprocess.Popen):raise ValueError('actual native Popen handle required')
  if self.lifecycle:
   self.lifecycle[0]['ready'] |= ready
   return
  self._process=process
  row=dict(pid=process.pid,args=list(process.args),execution=self.session._execution,
           ready=ready,closed=False,returncode=None,poll_after_close=None)
  self.lifecycle.append(row)
  try:
   binary=Path(process.args[0]);raw=(binary.parent/'manifest.json').read_bytes()
   row.update(binary_sha256_at_capture=sha(binary.read_bytes()),
              build_manifest_sha256_at_capture=sha(raw))
  except Exception as error:
   self.errors.append(dict(stage='process_capture',type=type(error).__name__,detail=str(error)))
   raise
 def reaped(self):
  if self.lifecycle:
   process=self._process;row=self.lifecycle[0]
   row.update(closed=process.returncode is not None,returncode=process.returncode,
              poll_after_close=process.poll())

def binary_document(session,capture):
 binary=session._binary
 raw=(binary.parent/'manifest.json').read_bytes()
 return dict(executable=dict(path=str(binary),sha256=sha(binary.read_bytes())),
             build_manifest_raw=raw.decode(),build_manifest=json.loads(raw),
             build_manifest_sha256=sha(raw),lifecycle=copy.deepcopy(capture.lifecycle))

def validate_binary(row,identity,execution):
 validate_lifecycle(row['lifecycle'],execution)
 life=row['lifecycle'][0];raw=row['build_manifest_raw'].encode();manifest=row['build_manifest']
 if (not re.fullmatch('[0-9a-f]{64}',row['executable']['sha256'])
     or encoded(json.loads(raw))!=encoded(manifest) or sha(raw)!=row['build_manifest_sha256']
     or manifest['schema_version']!='local_harness_build_cache.v1'
     or encoded(manifest['identity'])!=encoded(identity['build_identity'])
     or manifest['binary_sha256']!=row['executable']['sha256']
     or life['binary_sha256_at_capture']!=row['executable']['sha256']
     or life['build_manifest_sha256_at_capture']!=row['build_manifest_sha256']
     or life['args']!=[row['executable']['path']]):
  raise ValueError('actual binary/cache/source identity crosslink')

def validate_native_paths(repo,output,lock):
 repo=confined(repo);output=confined(output);lock=confined(lock)
 if lock!=CANONICAL_LOCK:raise ValueError('canonical nonblocking heavy lock required')
 if Path(__file__).resolve()!=repo/'scripts/verify_cvw_ahb_startup.py':
  raise ValueError('native gate must execute its own independent source snapshot')
 if output.exists() or output.is_relative_to(repo) or repo.is_relative_to(output):
  raise ValueError('native output must be new and separate from source')
 return repo,output,lock

def _plain(value):
 return json.loads(encoded(value))

def manifest_for_runner(runner,identity):
 from myfuzz.scenario.contracts import ScenarioManifest
 return ScenarioManifest.from_runner_identity(identity,scenario_id=CASE_ID,
    schedule_order=('cpu','sha'),scheduler_policy_id='cpu-only-router-target-v1',
    budget=runner._resource_budget,reset_timings={key:dict(
      schema_version='generated_local_reset.v1',artifact_digest=session.artifact.runtime_document['artifact_digest'],
      driver_sha256=session.artifact.runtime_document['cpp_sha256'],
      hold_cycles=session.artifact.runtime_document['driver_reset']['reset_assert_ticks'],
      release_cycles=session.artifact.runtime_document['driver_reset']['reset_release_ticks'])
      for key,session in runner.sessions.items()})

def run_one(repo,destination,name):
 # No factory/prepare/begin is reachable from default source-only entry.
 from myfuzz.scenario.cvw_caliptra_example import make_cvw_caliptra_chain,cvw_caliptra_program
 from myfuzz.scenario.batch import ScenarioBatchRecorder
 from myfuzz.scenario.contracts import ResourceBudget,ScenarioManifest
 from myfuzz.scenario.genome import ScenarioGenome
 from myfuzz.scenario.ownership import compile_ownership
 from myfuzz.scenario.runner import ScenarioRunner
 cpu,target,router,memory=make_cvw_caliptra_chain(cache_dir=destination/'cache')
 shared=dict(failed=False)
 captures={key:Capture(session,key,shared) for key,session in [('cpu',cpu),('sha',target)]}
 runner=ScenarioRunner(sessions={'cpu':cpu,'sha':target},ownership=compile_ownership((),()),bindings=())
 runner.set_resource_budget(ResourceBudget(max_wall_time_ms=600000,
   max_local_cycles_per_component=740000,max_scheduler_steps=760000,
   max_materialized_bytes_per_memory=0x10000,max_quiesce_steps=0))
 template=ScenarioGenome(testcase_id=CASE_ID,direction='CPU_TO_IP',path_id='cvw-caliptra',
   schedule_order=('cpu','sha'),max_steps=LIMIT,actions=(),quiesce_steps=0)
 recorder=ScenarioBatchRecorder(template,runner)
 error=None;trace=None;identity=None;stopped=False;post_drain=None;binary={};collection_errors=[]
 try:
  identity=runner.identity_document()
  manifest_for_runner(runner,identity)
  recorder.begin()
  stopped=advance_until_flag(recorder,cpu,events=lambda:captures['cpu'].service_events)
  if not stopped:raise ValueError('original directed stop not reached within 20000 CPU steps')
 except Exception as exc:error=exc
 finally:
  if recorder._begin_attempted:
   try:trace=recorder.finish()
   except Exception as exc:
    if error is None:error=exc
  for session in (cpu,target):
   try:session.end_case()
   except Exception as exc:
    if error is None:error=exc
 for component,session in [('cpu',cpu),('sha',target)]:
  try:binary[component]=binary_document(session,captures[component])
  except Exception as exc:
   collection_errors.append(dict(component=component,stage='binary_manifest',detail=str(exc)))
   if error is None:error=exc
 try:
  before=len(runner.events)
  runner._append_external_events('cpu',before)
  runner._append_external_events('sha',before)
  post_drain=len(runner.events)-before
 except Exception as exc:
  if error is None:error=exc
 words=[]
 try:words=[memory.read(RESULT+i*4,4,transaction_id=f'gate-check-{i}').value for i in range(17)]
 except Exception as exc:
  if error is None:error=exc
 document=_plain(dict(schema_version='cvw_ahb_startup_gate_run.v1',
   provenance='actual_generated_session_attempt',native_run=bool(captures['cpu'].lifecycle),
   program=dict(origin='unchanged_factory_static_program',bytes=1024,
                hex=cvw_caliptra_program().hex(),sha256=sha(cvw_caliptra_program())),memory_seed=17,
   status='complete' if error is None and trace is not None and trace.status=='complete' else 'failed',
   error=None if error is None else dict(type=type(error).__name__,detail=str(error)),
   identity=identity,artifact=cpu.artifact.runtime_document,target_artifact=target.artifact.runtime_document,
   native_execution=cpu._execution,target_execution=target._execution,binaries=binary,
   driver_receipts=captures['cpu'].receipts,target_driver_receipts=captures['sha'].receipts,
   runtime_events=captures['cpu'].runtime_events,runner_events=list(runner.events),
   counts=cpu._ahb_observer.counts,pending=cpu._ahb_observer.pending,
   outputs=captures['cpu'].outputs,stream_contexts=captures['cpu'].stream_contexts,
   measured_reset_to_command_prefix=cpu._ahb_observer.measured_reset_to_command_prefix,
   backend_pending=cpu.pending_responses,result=words,stop_reached=stopped,
   service_events=captures['cpu'].service_events,deliveries=captures['cpu'].deliveries,
   acceptances=captures['cpu'].acceptances,
   commands=[asdict(command) for command in recorder.commands],
   target_local_ticks=target.local_ticks,cpu_local_ticks=cpu.local_ticks,
   trace=None if trace is None else asdict(trace),post_drain_added_records=post_drain,
   collection_errors=collection_errors,
   capture_errors={key:capture.errors for key,capture in captures.items()},
   prefix_state='partial' if cpu._ahb_observer.pending is not None else 'no_pending_observed',
   source_authority=False,retirement_verified=False,protocol_completion_certified=False))
 if error is None:
  try:validate_native_run(document)
  except Exception as exc:
   error=exc;document.update(status='failed',error=dict(type=type(exc).__name__,detail=str(exc)))
 write_gzip(destination/(name+'.json.gz'),document)
 if error is not None:raise RuntimeError(name+' failed: '+str(error)) from error
 return document

def validate_stream_contexts(document):
 contexts=document['stream_contexts'];receipts=document['driver_receipts']
 for stream in ('service_events','deliveries','acceptances'):
  rows=[row for row in contexts if row['stream']==stream]
  if [row['stream_index'] for row in rows]!=list(range(len(document[stream]))):
   raise ValueError('pre-drain original stream context missing or duplicated')
  for row in rows:
   index=row['receipt_index']
   if type(index) is not int or not 0<=index<len(receipts):raise ValueError('current receipt context missing')
   receipt=receipts[index]['receipt']
   if (len(receipt['payload']['samples'])!=1 or row['local_tick']!=row['step_index']
       or receipt['tick_after']!=row['local_tick']):
    raise ValueError('original row context is not this CPU edge')
 if any(row['stream'] not in ('service_events','deliveries','acceptances') for row in contexts):
  raise ValueError('unknown original stream context')

def assert_service_imports(document):
 """Crosslink each original pre-drain row to the exact Runner imported row."""
 events=document['runner_events']
 for key,kinds in [('service_events',{'instruction_source','memory_initialization','memory_read','memory_write'}),
                   ('deliveries',{'mmio_delivery'}),('acceptances',{'mmio_acceptance'})]:
  original=document[key]
  imported=[{k:v for k,v in row.items() if k not in ('event_id','producer_event_id','component')}
            for row in events if row.get('kind') in kinds and row.get('component')=='cpu']
  expected=_plain(original)
  if key!='service_events':
   expected=[dict(row,kind=next(iter(kinds))) for row in expected]
  elif any(row.get('kind') not in kinds for row in expected):
   raise ValueError('unknown original memory service row')
  if imported!=expected:raise ValueError('original service/router rows differ from Runner: '+key)

def validate_chain(document):
 import hashlib
 words=document['result'];deliveries=document['deliveries']
 if len(words)!=17 or words[-1]!=1 or document['backend_pending']!=0 or not document['stop_reached']:
  raise ValueError('original flag/backend stop failed')
 for i,payload in enumerate((b'abc',b'abd')):
  if b''.join(word.to_bytes(4,'big') for word in words[i*8:i*8+8])!=hashlib.sha256(payload).digest():
   raise ValueError('real RAM digest differs')
 if (sum(row['write'] for row in deliveries)!=34
     or any(row['beat_bytes']!=4 or row['byte_enable']!=15 for row in deliveries)
     or len({row['source_sequence'] for row in deliveries})!=len(deliveries)
     or [row['offset'] for row in deliveries if not row['write'] and row['offset']>=0x100]!=list(range(0x100,0x120,4))*2):
  raise ValueError('actual routed SHA transfers differ')
 samples=[sample for record in document['driver_receipts'] for sample in record['receipt']['payload']['samples']]
 requests=[sample['pre']['backend'] for sample in samples if sample['pre']['backend']['m_req_valid'] and sample['pre']['backend']['m_req_ready']]
 mmio=[row for row in requests if 0xcfff0000<=row['m_req_addr']<0xcfff1000]
 if [(row['m_req_addr']-0xcfff0000,bool(row['m_req_write']),row['m_req_wdata'] if row['m_req_write'] else None) for row in mmio]!=[(row['offset'],row['write'],row['write_value']) for row in deliveries]:
  raise ValueError('actual CPU backend/router transfers differ')
 for delivery in deliveries:
  if not delivery['write']:
   responses=[row for row in document['outputs'] if row['data_rsp_consumed'] and row['data_rsp_source_sequence']==delivery['source_sequence']]
   if len(responses)!=1 or responses[0]['data_rsp_rdata']!=delivery['read_value']:
    raise ValueError('actual CPU backend/target read response differs')
 starts=[i for i,row in enumerate(deliveries) if row['write'] and row['offset']==0x10]
 if len(starts)!=2:raise ValueError('SHA start count')
 for index,payload in zip(starts,(b'abc',b'abd')):
  block=[int.from_bytes(payload+b'\x80','big')]+[0]*14+[24]
  if ([(row['offset'],row['write_value']) for row in deliveries[index-16:index]]!=[(0x80+4*i,v) for i,v in enumerate(block)]
      or deliveries[index]['write_value']!=5):raise ValueError('SHA block/control writes')
  end=next((i for i in range(index+1,len(deliveries)) if deliveries[i]['offset']==0x100),None)
  polls=deliveries[index+1:end]
  if not polls or any(row['write'] or row['offset']!=0x18 for row in polls) or not polls[-1]['read_value']&2:
   raise ValueError('SHA status polling')

def validate_target_physical(document):
 """Reconstruct measured target PRE address/data phases, not backend intent."""
 from myfuzz.local_harness.ahb_lite_register_template import BUS_SHAPE
 artifact=document['target_artifact'];trace=artifact['base_protocol_trace']
 pins=trace['signals'];widths={role:shape[1] for role,shape in BUS_SHAPE.items()}
 if (trace.get('protocol')!='ahb-lite' or trace.get('signal_widths')!=widths
     or set(pins)!=set(widths) or len(set(pins.values()))!=len(pins)):
  raise ValueError('target physical AHB trace shape')
 for role,(direction,width) in BUS_SHAPE.items():
  abi=[row for row in artifact['structural_abi']['ports']
       if row.get('endpoint_id')==trace['endpoint_id'] and row.get('role')==role]
  backend=[row for row in artifact['backend_ports'] if row.get('name')==pins[role]]
  if (len(abi)!=1 or (abi[0]['direction'],abi[0]['width'])!=(direction,width)
      or len(backend)!=1 or (backend[0]['direction'],backend[0]['width'],backend[0]['role'],backend[0]['channel'])!=('output',width,role,'ip_protocol_trace')):
   raise ValueError('target physical trace does not bind actual structural ABI')
 samples=[sample for record in document['target_driver_receipts'] for sample in record['receipt']['payload']['samples']]
 if not samples or len(samples)>740000:raise ValueError('target physical sample bound')
 pending=None;completed=[];hold=None;tick=0
 for sample in samples:
  tick+=1
  if type(sample['local_tick']) is not int or sample['local_tick']!=tick:
   raise ValueError('target raw tick gap')
  rows={phase:{role:sample[phase]['backend'][name] for role,name in pins.items()}
        for phase in ('pre','post')}
  for row in rows.values():
   if any(type(row[role]) is not int or not 0<=row[role]<1<<width for role,width in widths.items()):
    raise ValueError('target physical role width')
   if row['hreadyin']!=row['hreadyout']:raise ValueError('target fabric ready echo differs')
  pre=rows['pre']
  address=tuple(pre[role] for role in ('hsel','htrans','haddr','hwrite','hsize'))
  if hold is not None and address!=hold:raise ValueError('target address stall changed')
  if pending is not None and pending['hwrite']:
   if 'held_wdata' in pending and pre['hwdata']!=pending['held_wdata']:
    raise ValueError('target write data changed during stalled data phase')
   if not pre['hreadyout']:pending['held_wdata']=pre['hwdata']
  if pending is not None and pre['hreadyout']:
   if pre['hresp']!=0:raise ValueError('target physical error response')
   completed.append((pending['haddr'],bool(pending['hwrite']),
                     pre['hwdata'] if pending['hwrite'] else pre['hrdata']))
   pending=None
  accepted=pre['hsel'] and pre['htrans']&2
  hold=address if accepted and not pre['hreadyin'] else None
  if accepted and pre['hreadyin']:
   if pending is not None:raise ValueError('target address accepted before old data completion')
   if pre['hsize']!=2 or pre['haddr']%4 or pre['haddr']>=4096:
    raise ValueError('target measured transfer outside declared full-word shape')
   pending={key:pre[key] for key in ('haddr','hwrite')}
 if pending is not None or hold is not None:raise ValueError('target physical prefix incomplete')
 expected=[(row['offset'],row['write'],row['write_value'] if row['write'] else row['read_value']) for row in document['deliveries']]
 if completed!=expected:raise ValueError('target accepted/data physical transfers differ from router')
 return completed

def validate_target_receipts(document):
 records=document['target_driver_receipts'];deliveries=document['deliveries']
 if len(records)!=len(deliveries):raise ValueError('target access count differs from actual router deliveries')
 tick=0
 for index,(record,delivery) in enumerate(zip(records,deliveries),1):
  receipt=record['receipt'];payload=receipt['payload'];samples=payload['samples']
  fields=[int(delivery['write']),delivery['offset'],delivery['write_value'] if delivery['write'] else 0,15]
  if (record['operation']!='ACCESS_AHB_REG' or record['fields']!=fields
      or receipt['execution']!=document['target_execution'] or receipt['sequence']!=index
      or receipt['status']!='result' or type(receipt['sequence']) is not int
      or any(type(receipt[k]) is not int for k in ('tick_before','tick_after','new_ticks'))
      or receipt['tick_before']!=tick
      or not 1<=len(samples)<=37 or receipt['new_ticks']!=len(samples)
      or receipt['tick_after']!=tick+len(samples)
      or [sample['local_tick'] for sample in samples]!=list(range(tick+1,tick+len(samples)+1))
      or payload['kind']!='ahb_lite_register_observe' or payload['error']!=0
      or not delivery['write'] and payload['rdata']!=delivery['read_value']):
   raise ValueError('actual target receipt/router/tick binding differs')
  tick+=len(samples)
 if tick!=document['target_local_ticks']:raise ValueError('target contains extra unaccounted clocks')

def validate_native_run(document):
 if (document['status']!='complete' or document['native_run'] is not True
     or document.get('provenance')!='actual_generated_session_attempt'
     or not 1<=document['cpu_local_ticks']<=LIMIT or document['post_drain_added_records']!=0
     or document['measured_reset_to_command_prefix'] is not True
     or document['collection_errors'] or any(document['capture_errors'].values())
     or document.get('memory_seed')!=17 or document['program']['bytes']!=1024
     or len(bytes.fromhex(document['program']['hex']))!=1024
     or sha(bytes.fromhex(document['program']['hex']))!=document['program']['sha256']
     or any(command!={'schedule':['cpu']} for command in document['commands'])
     or len(document['commands'])!=document['cpu_local_ticks']):
  raise ValueError('actual CPU-only bounded gate failed')
 for component,key in [('cpu','native_execution'),('sha','target_execution')]:
  execution=document[key]
  if not re.fullmatch('[0-9a-f]{32}',execution):raise ValueError('issued native nonce absent')
  validate_binary(document['binaries'][component],document['identity']['sessions'][component]['identity'],execution)
 if document['native_execution']==document['target_execution']:raise ValueError('component executions reused')
 normalize_observer(document['runtime_events'],document['native_execution'])
 normalize_receipts(document['driver_receipts'],document['native_execution'],'cpu')
 normalize_receipts(document['target_driver_receipts'],document['target_execution'],'sha')
 assert_imported_once(document['runtime_events'],document['runner_events'])
 validate_stream_contexts(document)
 assert_service_imports(document)
 validate_target_receipts(document)
 validate_target_physical(document)
 observer=replay_actual_prefix(document)
 if document['prefix_state']!=('partial' if observer.pending is not None else 'no_pending_observed'):
  raise ValueError('physical pending prefix qualification')
 validate_chain(document)


def normalize_runner(events,execution):
 result=copy.deepcopy(events)
 for index,row in enumerate(result):
  if row.get('schema_version')==EVENT_SCHEMA:
   result[index]=normalize_observer([row],execution)[0]
 return result

def compare_prefixes(first,fresh):
 for document in (first,fresh):validate_native_run(document)
 for key in ('native_execution','target_execution'):
  if first[key]==fresh[key]:raise ValueError('fresh issued execution reused')
 for component in ('cpu','sha'):
  if first['binaries'][component]['lifecycle'][0]['pid']==fresh['binaries'][component]['lifecycle'][0]['pid']:
   raise ValueError('fresh native PID reused')
  a=copy.deepcopy(first['binaries'][component]);b=copy.deepcopy(fresh['binaries'][component])
  del a['lifecycle'];del b['lifecycle']
  if a!=b:raise ValueError('fresh actual binary/cache identity differs')
 for name in ('program','memory_seed','identity','artifact','target_artifact','counts','pending','backend_pending','result',
              'service_events','deliveries','acceptances','outputs','stream_contexts','commands','target_local_ticks','cpu_local_ticks','prefix_state'):
  if first[name]!=fresh[name]:raise ValueError('fresh entire prefix differs: '+name)
 if normalize_observer(first['runtime_events'],first['native_execution'])!=normalize_observer(fresh['runtime_events'],fresh['native_execution']):
  raise ValueError('fresh entire observer prefix differs')
 if normalize_runner(first['runner_events'],first['native_execution'])!=normalize_runner(fresh['runner_events'],fresh['native_execution']):
  raise ValueError('fresh entire Runner prefix differs')
 for field,key,component in [('driver_receipts','native_execution','cpu'),('target_driver_receipts','target_execution','sha')]:
  if normalize_receipts(first[field],first[key],component)!=normalize_receipts(fresh[field],fresh[key],component):
   raise ValueError('fresh entire actual receipt prefix differs: '+component)


def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1])
 parser.add_argument('--write-freeze',type=Path)
 parser.add_argument('--run-native',action='store_true')
 parser.add_argument('--output',type=Path);parser.add_argument('--heavy-lock',type=Path)
 parser.add_argument('--freeze',type=Path);parser.add_argument('--freeze-sha256')
 args=parser.parse_args(argv)
 if not args.run_native:
  document=prepare_freeze(args.repo)
  if args.write_freeze:write_new(args.write_freeze,encoded(document))
  else:print(encoded(document).decode(),end='')
  return 0
 if any(value is None for value in (args.output,args.heavy_lock,args.freeze,args.freeze_sha256)):
  parser.error('native execution requires output, canonical heavy-lock and frozen source receipt/hash')
 repo,output,lock=validate_native_paths(args.repo,args.output,args.heavy_lock)
 freeze=confined(args.freeze);raw=freeze.read_bytes()
 if sha(raw)!=args.freeze_sha256:raise ValueError('source freeze receipt SHA differs')
 verify_freeze(repo,json.loads(raw))
 with lock.open('rb') as stream:
  fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
  output.mkdir()
  write_new(output/'source-freeze.json',raw)
  try:
   first=run_one(repo,output,'first');fresh=run_one(repo,output,'fresh')
   compare_prefixes(first,fresh)
  except Exception as error:
   write_new(output/'failure.json',encoded(dict(schema_version='cvw_ahb_startup_gate_failure.v1',
      error_type=type(error).__name__,detail=str(error),source_authority=False,
      note='Original per-run archives, if issued, are retained; no later native command is attempted.')))
   raise
  write_new(output/'pass.json',encoded(dict(schema_version='cvw_ahb_startup_gate_pass.v1',
     grade='actual_generated_native_observation_only',source_authority=False,
     protocol_completion_certified=False,retirement_verified=False,
     first_sha256=sha((output/'first.json.gz').read_bytes()),
     fresh_sha256=sha((output/'fresh.json.gz').read_bytes()))))
 return 0

if __name__=='__main__':raise SystemExit(main())
