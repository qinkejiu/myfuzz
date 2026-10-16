"""Prepare or run a narrowly bounded generated CVA6 AXI observation gate.

Default invocation does not generate, elaborate, build or execute native code.
Actual execution requires --run-native and the externally scheduled heavy lock.
All artifacts retain original payloads; comparison normalizes typed identities.
"""
from __future__ import annotations
import argparse
import copy
from dataclasses import asdict, is_dataclass
import fcntl
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess

FREEZE_SCHEMA='cva6_full_axi_native_gate_source_freeze.v1'
EVENT_SCHEMA='bounded_full_axi_observation.v1'
EXECUTION='DECLARED_NATIVE_EXECUTION'
STEPS=650
CASE_ID='cva6-full-axi-observer-ram'
COMPONENT='cva6'
NATIVE_ROOT=Path('/root/fanzehui')
EXTRA_SOURCES=(
 'scripts/verify_cva6_full_axi_observer.py',
 'tests/local_harness/test_cva6_axi4_service_real.py',
 'tests/local_harness/test_cva6_full_axi_gate.py',
 'configs/cpus/cva6/component_profile.json','configs/soc/sources.lock.json',
 'configs/soc/closures/cva6.json',
 'third_party/docs/task-13/cva6-fixed/run/boot/boot.bin')


def sha(data):return hashlib.sha256(data).hexdigest()
def _default(value):
 if is_dataclass(value):return asdict(value)
 raise TypeError('non-documentary gate value: '+type(value).__name__)
def encoded(value):
 return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False,default=_default)+'\n').encode()


def confined(path,root=NATIVE_ROOT):
 path=Path(path).absolute();root=Path(root).absolute()
 if any(p.is_symlink() for p in (path,*path.parents)):
  raise ValueError('gate path contains a symlink')
 resolved=path.resolve()
 if not resolved.is_relative_to(root.resolve()):raise ValueError('gate path outside allowed root')
 return resolved


def write_new(path,data):
 path=Path(path)
 if any(p.is_symlink() for p in (path,*path.parents)):
  raise ValueError('gate output contains a symlink')
 with path.open('xb') as stream:stream.write(data)


def write_gzip(path,document):
 path=Path(path)
 if any(p.is_symlink() for p in (path,*path.parents)):
  raise ValueError('gate output contains a symlink')
 with path.open('xb') as stream:
  with gzip.GzipFile(fileobj=stream,mode='wb',mtime=0) as zipped:zipped.write(encoded(document))
 return sha(path.read_bytes())


def _source_names():
 from myfuzz.local_harness.build import _discover_host_sources
 return {*_discover_host_sources(),*EXTRA_SOURCES}


def prepare_freeze(repo):
 repo=Path(repo).resolve()
 return {'schema_version':FREEZE_SCHEMA,'source_only':True,'native_run':False,
         'steps':STEPS,'memory_seed':0,
         'files':{name:sha(confined(repo/name,repo).read_bytes()) for name in sorted(_source_names())}}


def verify_freeze(repo,freeze,*,required=None):
 if (not isinstance(freeze,dict) or freeze.get('schema_version')!=FREEZE_SCHEMA
     or not isinstance(freeze.get('files'),dict)
     or freeze.get('source_only') is not True or freeze.get('native_run') is not False
     or type(freeze.get('steps')) is not int or freeze['steps']!=STEPS
     or type(freeze.get('memory_seed')) is not int or freeze['memory_seed']!=0):
  raise ValueError('gate source freeze malformed')
 required=_source_names() if required is None else set(required)
 if set(freeze['files'])!=required:raise ValueError('gate source freeze file set differs')
 for name,digest in freeze['files'].items():
  path=Path(name)
  if path.is_absolute() or '..' in path.parts:raise ValueError('gate source freeze unsafe path')
  actual=confined(Path(repo)/path,Path(repo))
  if sha(actual.read_bytes())!=digest:raise ValueError('gate source freeze changed: '+name)


def normalize_events(events,expected_execution):
 result=copy.deepcopy(events)
 for event in result:
  if event.get('schema_version')==EVENT_SCHEMA:
   scope=event.get('scope')
   if not isinstance(scope,dict) or not isinstance(scope.get('execution_id'),str):
    raise ValueError('typed native event execution identity missing')
   if scope['execution_id']!=expected_execution:raise ValueError('observer scope does not bind issued native execution')
   scope['execution_id']=EXECUTION
 return result


def normalize_receipts(receipts,expected_execution):
 result=copy.deepcopy(receipts)
 for record in result:
  if (record.get('operation')!='STEP_CVA6_AXI4' or not isinstance(record.get('receipt'),dict)
      or not isinstance(record['receipt'].get('execution'),str)):
   raise ValueError('typed driver receipt execution identity missing')
  if record['receipt']['execution']!=expected_execution:raise ValueError('driver scope does not bind issued native execution')
  record['receipt']['execution']=EXECUTION
 return result


def assert_imported_once(runtime_events,runner_events):
 imported=[{k:copy.deepcopy(v) for k,v in event.items()
            if k not in ('event_id','producer_event_id','component')}
           for event in runner_events if event.get('schema_version')==EVENT_SCHEMA]
 if imported!=runtime_events:raise ValueError('Runner import differs, is missing or duplicates a record')


def validate_lifecycle(lifecycles):
 if not isinstance(lifecycles,list) or len(lifecycles)!=1:
  raise ValueError('actual native close lifecycle must be unique')
 row=lifecycles[0]
 if (type(row.get('pid')) is not int or row['pid']<=0 or row.get('closed') is not True
     or type(row.get('returncode')) is not int or row['returncode']!=0
     or type(row.get('poll_after_close')) is not int or row['poll_after_close']!=0):
  raise ValueError('actual native close did not show a successful reap')


def compare_prefixes(first,fresh):
 for record in (first,fresh):
  validate_lifecycle(record['lifecycle'])
  if ('execution' in record['lifecycle'][0]
      and record['lifecycle'][0]['execution']!=record['native_execution']):
   raise ValueError('native process execution binding differs')
 if (first['native_execution']==fresh['native_execution']
     or first['lifecycle'][0]['pid']==fresh['lifecycle'][0]['pid']):
  raise ValueError('fresh native execution/process identity was reused')
 for name in ('samples','accepted','pending','identity','executable','build_manifest','build_manifest_raw','build_manifest_sha256'):
  if first.get(name)!=fresh.get(name):raise ValueError('fresh whole prefix differs: '+name)
 for name in ('runtime_events','runner_events'):
  validate_scopes(first[name],first['native_execution']);validate_scopes(fresh[name],fresh['native_execution'])
  if normalize_events(first[name],first['native_execution'])!=normalize_events(fresh[name],fresh['native_execution']):
   raise ValueError('fresh whole prefix differs: '+name)
 if normalize_receipts(first['driver_receipts'],first['native_execution'])!=normalize_receipts(fresh['driver_receipts'],fresh['native_execution']):
  raise ValueError('fresh whole prefix differs: driver_receipts')


def validate_scopes(events,execution):
 expected=dict(execution_id=execution,testcase_id=CASE_ID,reset_epoch=0,source_component=COMPONENT)
 for event in events:
  if event.get('schema_version')==EVENT_SCHEMA:
   if (event.get('scope')!=expected or event.get('component_id')!=COMPONENT
       or event.get('endpoint_id')!='axi' or 'component' in event and event['component']!=COMPONENT):
    raise ValueError('observer/Runner scope differs from actual issued fixed run')


def validate_binary_binding(document):
 try:
  exe=document['executable'];manifest=document['build_manifest']
  raw=document['build_manifest_raw'].encode();row=document['lifecycle'][0]
  expected=document['identity']['sessions'][COMPONENT]['identity']['build_identity']
  if (not re.fullmatch('[0-9a-f]{64}',exe['sha256'])
      or manifest['schema_version']!='local_harness_build_cache.v1'
      or json.loads(raw)!=manifest or sha(raw)!=document['build_manifest_sha256']
      or manifest['binary_sha256']!=exe['sha256'] or manifest['identity']!=expected
      or row['binary_sha256_at_capture']!=exe['sha256']
      or row['build_manifest_sha256_at_capture']!=document['build_manifest_sha256']
      or row['args']!=[exe['path']] or row.get('ready') is not True):
   raise ValueError('actual binary/build manifest crosslink differs')
 except (KeyError,TypeError,AttributeError) as exc:
  raise ValueError('actual binary/build manifest crosslink missing') from exc


def replay_actual_prefix(document):
 from myfuzz.scenario.full_axi_events import BoundedFullAxiObserver
 events=document['runtime_events']
 if not events:raise ValueError('actual observer stream is empty')
 scope=events[0]['scope']
 observer=BoundedFullAxiObserver(component_id=scope['source_component'])
 observer.begin_scope(execution_id=scope['execution_id'],testcase_id=scope['testcase_id'],reset_epoch=scope['reset_epoch'])
 for sample in document['samples']:observer.observe(sample)
 if (observer.events!=events or observer.accepted!=document['accepted']
     or observer.pending!=document['pending']):
  raise ValueError('actual saved raw prefix does not reproduce all observer records')


def validate_native_run(document):
 from myfuzz.local_harness.cva6_axi4_fields import CVA6_AXI_STEP_PORTS
 validate_lifecycle(document['lifecycle'])
 validate_binary_binding(document)
 validate_scopes(document['runtime_events'],document['native_execution'])
 validate_scopes(document['runner_events'],document['native_execution'])
 if (document['status']!='complete' or len(document['samples'])!=STEPS
     or len(document['driver_receipts'])!=STEPS or document['write_beats']!=2
     or document['read_beats']<2 or document['ram_values']!=[0x600dcafe]*2):
  raise ValueError('native fixed-program/step/result gate failed')
 if not re.fullmatch('[0-9a-f]{32}',document['native_execution']):
  raise ValueError('actual native execution nonce missing')
 if document['lifecycle'][0].get('execution')!=document['native_execution']:
  raise ValueError('actual issued execution differs from native process lifecycle')
 for i,(sample,record) in enumerate(zip(document['samples'],document['driver_receipts']),1):
  receipt=record['receipt'];row=sample['pre']['backend']
  fields=[0,0,*[row[name] for name in CVA6_AXI_STEP_PORTS[2:]]]
  if (record['operation']!='STEP_CVA6_AXI4' or record['fields']!=fields
      or receipt['status']!='result' or receipt['execution']!=document['native_execution']
      or receipt['sequence']!=i or receipt['tick_before']!=i-1
      or receipt['tick_after']!=i or receipt['new_ticks']!=1
      or receipt['payload']['samples']!=[sample]
      or receipt['payload']['pre_backend']!=row):
   raise ValueError('actual native receipt/sample edge binding differs')
 assert_imported_once(document['runtime_events'],document['runner_events'])
 if document['post_drain_added_records']!=0:raise ValueError('Runner tail drain duplicated records')
 replay_actual_prefix(document)


def _capturing_session_class():
 # Lazy import prevents default/prepare-only entry from constructing any driver.
 from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
 class CapturedCva6Session(GeneratedCva6Axi4Session):
  artifact_kind=GeneratedCva6Axi4Session.artifact_kind
  def __init__(self,*args,**kwargs):
   super().__init__(*args,**kwargs)
   self.gate_lifecycles=[];self.gate_driver_receipts=[];self._gate_bytes=0;self._gate_failed=False
  def _note_process(self,proc,ready):
   if not isinstance(proc,subprocess.Popen):raise RuntimeError('actual Popen handle missing')
   rows=[row for row in self.gate_lifecycles if row['pid']==proc.pid]
   if rows:return rows[0]
   row=dict(pid=proc.pid,args=list(proc.args),execution=self._execution,ready=ready,
            closed=False,returncode=None,poll_after_close=None)
   self.gate_lifecycles.append(row)
   try:
    binary=Path(proc.args[0]);manifest=binary.parent/'manifest.json'
    row.update(binary_sha256_at_capture=sha(binary.read_bytes()),
               build_manifest_sha256_at_capture=sha(manifest.read_bytes()))
   except Exception as exc:row['capture_error']={'type':type(exc).__name__,'detail':str(exc)}
   return row
  def _closed_process(self,proc,phase):
   if proc is not None:
    row=self._note_process(proc,False)
    row.update(returncode=proc.returncode,poll_after_close=proc.poll(),close_phase=phase,
               closed=self._process is None and proc.poll() is not None)
  def begin_case(self,testcase_id):
   super().begin_case(testcase_id)
   self._note_process(self._process,True)
  def _abort(self):
   proc=self._process
   try:super()._abort()
   finally:self._closed_process(proc,'startup_or_transport_abort')
  def command(self,operation,fields=()):
   if self._gate_failed or operation!='STEP_CVA6_AXI4' or len(self.gate_driver_receipts)>=STEPS:
    raise RuntimeError('native gate command budget/operation refused')
   receipt=super().command(operation,fields)
   record=dict(operation=operation,fields=list(fields),receipt=asdict(receipt))
   self.gate_driver_receipts.append(record);self._gate_bytes+=len(encoded(record))
   if self._gate_bytes>64*1024*1024:
    self._gate_failed=True
    raise RuntimeError('native gate receipt byte budget exceeded')
   return receipt
  def end_case(self):
   proc=self._process
   try:super().end_case()
   finally:self._closed_process(proc,'end_case')
 return CapturedCva6Session


def _run_one(artifact,repo,destination,name,program):
 from myfuzz.scenario.contracts import ResourceBudget
 from myfuzz.scenario.genome import MemoryImage,ScenarioGenome
 from myfuzz.scenario.memory import MemoryRegion,PersistentMemory
 from myfuzz.scenario.ownership import compile_ownership
 from myfuzz.scenario.replay import _record_with_runner
 from myfuzz.scenario.runner import ScenarioRunner
 memory=PersistentMemory(regions=(MemoryRegion('ram',0,0x20000),),initialization_seed=0,max_initialized_bytes=0x20000)
 cpu=_capturing_session_class()(artifact,base_dir=repo,cache_dir=destination/'cache',
                               memory=memory,command_timeout_seconds=60)
 runner=ScenarioRunner(sessions={'cva6':cpu},ownership=compile_ownership((),()),bindings=())
 runner.set_resource_budget(ResourceBudget(max_wall_time_ms=300000,
    max_materialized_bytes_per_memory=0x20000,max_local_cycles_per_component=STEPS,
    max_scheduler_steps=STEPS,max_quiesce_steps=0))
 case=ScenarioGenome(testcase_id=CASE_ID,direction='CPU_TO_IP',
  path_id='cva6-memory',schedule_order=('cva6',),max_steps=STEPS,actions=(),quiesce_steps=0,
  initial_images=(MemoryImage('program','cva6',0x10000,program.hex()),))
 trace=None;error=None;identity=None;post_drain=None
 try:
  identity=runner.identity_document()
  trace=_record_with_runner(case,runner)
  count=len(runner.events)
  runner._append_external_events('cva6',runner.events[-1]['event_id'])
  post_drain=len(runner.events)-count
 except Exception as exc:error=exc
 finally:
  try:cpu.end_case()
  except Exception as exc:
   if error is None:error=exc
 collection_errors=[];ram_values=[];executable=None;manifest=None;manifest_raw=None
 for address in (0x400,0x404):
  try:ram_values.append(memory.read(address,4,transaction_id='gate-readback').value)
  except Exception as exc:
   ram_values.append(None);collection_errors.append({'stage':'ram_readback','address':address,'type':type(exc).__name__,'detail':str(exc)})
   if error is None:error=exc
 try:
  binary=cpu._binary
  if binary is not None:
   executable={'path':str(binary),'sha256':sha(binary.read_bytes())}
   manifest_raw=(binary.parent/'manifest.json').read_text()
   manifest=json.loads(manifest_raw)
 except Exception as exc:
  collection_errors.append({'stage':'binary_manifest','type':type(exc).__name__,'detail':str(exc)})
  if error is None:error=exc
 document={'schema_version':'cva6_full_axi_native_gate_run.v1',
  'provenance':'actual_generated_session_attempt','native_run':bool(cpu.gate_lifecycles),
  'status':trace.status if trace is not None and error is None else 'failed',
  'error':None if error is None else {'type':type(error).__name__,'detail':str(error)},
  'identity':identity,'collection_errors':collection_errors,'executable':executable,
  'build_manifest':manifest,'build_manifest_raw':manifest_raw,
  'build_manifest_sha256':None if manifest_raw is None else sha(manifest_raw.encode()),
  'native_execution':cpu._execution,'lifecycle':cpu.gate_lifecycles,
  'driver_receipts':cpu.gate_driver_receipts,'runtime_events':copy.deepcopy(cpu.runtime_events),
  'runner_events':copy.deepcopy(list(runner.events)),'trace':None if trace is None else asdict(trace),
  'samples':[copy.deepcopy(e['raw_sample']) for e in cpu.runtime_events if e['kind']=='full_axi_raw'],
  'accepted':copy.deepcopy(cpu._axi_observer.accepted),'pending':cpu._axi_observer.pending,
  'write_beats':cpu.write_beats,'read_beats':cpu.read_beats,
  'ram_values':ram_values,
  'post_drain_added_records':post_drain,'retirement_verified':False,
  'source_authority':False,'protocol_completion_certified':False}
 document['prefix_state']='partial' if any(document['pending'].values()) else 'no_pending_observed'
 if error is None:
  try:validate_native_run(document)
  except Exception as exc:
   error=exc;document.update(status='failed',error={'type':type(exc).__name__,'detail':str(exc)})
 write_gzip(destination/(name+'.json.gz'),document)
 if error is not None:raise RuntimeError(name+' native gate failed: '+str(error)) from error
 return document


def run_native_gate(*,repo,output,heavy_lock,freeze_path,freeze_sha256):
 repo=confined(repo);output=confined(output);heavy_lock=confined(heavy_lock)
 freeze_path=confined(freeze_path)
 if repo!=Path(__file__).resolve().parents[1]:raise ValueError('gate must use its actual source checkout')
 if output.exists():raise ValueError('gate output must be new')
 if output.is_relative_to(repo) or repo.is_relative_to(output) or heavy_lock.is_relative_to(output):
  raise ValueError('gate output/lock/source overlap')
 raw=freeze_path.read_bytes()
 if sha(raw)!=freeze_sha256:raise ValueError('gate source freeze receipt SHA differs')
 freeze=json.loads(raw);verify_freeze(repo,freeze)
 with heavy_lock.open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  verify_freeze(repo,freeze)
  output.mkdir(parents=True,exist_ok=False)
  marker=output/'incomplete.json';write_new(marker,encoded({'native_status':'incomplete'}))
  summary={'schema_version':'cva6_full_axi_native_gate.v1','status':'failed',
           'freeze_sha256':freeze_sha256,'source_authority':False,'retirement_verified':False,
           'protocol_completion_certified':False}
  try:
   from tests.local_harness.test_cva6_axi4_service_real import artifact,store_load_program
   generated=artifact();program=store_load_program()
   write_new(output/'source-freeze.json',raw)
   write_new(output/'artifact.json',encoded({'runtime':generated.runtime_document,
      'source_verification':generated.source_verification,'structural_build':generated.structural.build_document}))
   write_new(output/'driver.cpp',generated.cpp_text.encode())
   write_new(output/'runtime.sv',generated.runtime_sv.encode())
   write_new(output/'structural.sv',generated.structural.wrapper_sv.encode())
   write_new(output/'program.bin',program)
   first=_run_one(generated,repo,output,'first',program)
   fresh=_run_one(generated,repo,output,'fresh',program)
   compare_prefixes(first,fresh);verify_freeze(repo,freeze)
   summary.update(status='pass',native_run=True,first_pid=first['lifecycle'][0]['pid'],
      fresh_pid=fresh['lifecycle'][0]['pid'],accepted=first['accepted'],pending=first['pending'],
      prefix_state=first['prefix_state'],raw_prefix_equal=True,whole_observer_prefix_equal=True,
      whole_runner_prefix_equal=True,whole_driver_prefix_equal=True,
      normalization_paths=['DriverReceipt.receipt.execution','bounded_full_axi_observation.v1.scope.execution_id'],
      artifacts={p.name:sha(p.read_bytes()) for p in output.iterdir() if p.is_file() and p!=marker})
  except Exception as exc:summary['error']={'type':type(exc).__name__,'detail':str(exc)}
  write_new(output/'summary.json',encoded(summary))
  if summary['status']=='pass':marker.unlink()
  if summary['status']!='pass':raise RuntimeError('CVA6 native gate failed; retained '+str(output))
  return summary


def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--write-freeze',type=Path)
 parser.add_argument('--run-native',action='store_true')
 parser.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1])
 parser.add_argument('--output',type=Path);parser.add_argument('--heavy-lock',type=Path)
 parser.add_argument('--freeze',type=Path);parser.add_argument('--freeze-sha256')
 args=parser.parse_args(argv)
 if args.write_freeze:
  if args.run_native:parser.error('freeze preparation and native execution are separate invocations')
  with args.write_freeze.open('xb') as stream:stream.write(encoded(prepare_freeze(args.repo)))
  print(json.dumps({'native':'not_executed','freeze_sha256':sha(args.write_freeze.read_bytes())}))
  return 0
 if not args.run_native:
  print(json.dumps({'native':'not_executed','status':'source_only_gate_prepared'}));return 0
 if any(value is None for value in (args.output,args.heavy_lock,args.freeze,args.freeze_sha256)):
  parser.error('--run-native requires --output --heavy-lock --freeze --freeze-sha256')
 summary=run_native_gate(repo=args.repo,output=args.output,heavy_lock=args.heavy_lock,
                 freeze_path=args.freeze,freeze_sha256=args.freeze_sha256)
 print(json.dumps(summary,sort_keys=True))
 return 0


if __name__=='__main__':raise SystemExit(main())
