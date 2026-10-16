"""Source-only controls for the future native gate. No compiler/model runs."""
import copy
import importlib
import json
from pathlib import Path
import pytest


def gate():
 try:return importlib.import_module('scripts.verify_cva6_full_axi_observer')
 except ModuleNotFoundError:pytest.fail('native gate source is missing')


def test_only_declared_execution_paths_are_normalized():
 g=gate();execution='a'*32
 event={'schema_version':'bounded_full_axi_observation.v1','kind':'full_axi_raw',
  'scope':dict(execution_id=execution,testcase_id='case',reset_epoch=0,source_component='cpu'),
  'raw_sample':{'execution_id':execution,'payload':execution},'payload':{'execution_id':execution}}
 normalized=g.normalize_events([event],execution)[0]
 assert normalized['scope']['execution_id']=='DECLARED_NATIVE_EXECUTION'
 assert normalized['payload']==event['payload'] and normalized['raw_sample']==event['raw_sample']
 assert event['scope']['execution_id']==execution
 receipt={'operation':'STEP_CVA6_AXI4','fields':[1], 'receipt':dict(execution=execution,payload={'execution':execution})}
 normalized=g.normalize_receipts([receipt],execution)[0]
 assert normalized['receipt']['execution']=='DECLARED_NATIVE_EXECUTION'
 assert normalized['receipt']['payload']==receipt['receipt']['payload']
 unrelated={'kind':'memory_commit','payload':{'execution_id':execution}}
 assert g.normalize_events([unrelated],execution)==[unrelated]


def test_runner_stream_import_must_be_exact_and_once():
 g=gate();events=[{'schema_version':'bounded_full_axi_observation.v1','kind':'full_axi_raw','raw_sample':{'data':9}}]
 imported=[dict(events[0],event_id=5,producer_event_id=4,component='cpu')]
 g.assert_imported_once(events,imported)
 for bad in ([],imported*2,[dict(imported[0],raw_sample={'data':10})]):
  with pytest.raises(ValueError,match='import'):g.assert_imported_once(events,bad)


@pytest.mark.parametrize('change',[{'returncode':None},{'poll_after_close':None},{'pid':0},{'closed':False},{'returncode':-9,'poll_after_close':-9}])
def test_actual_close_document_must_show_successful_reap(change):
 g=gate();row=dict(pid=123,returncode=0,poll_after_close=0,closed=True)
 g.validate_lifecycle([row])
 with pytest.raises(ValueError,match='close'):g.validate_lifecycle([row|change])
 with pytest.raises(ValueError,match='close'):g.validate_lifecycle([row,row])


def test_gzip_is_lossless_exclusive_and_symlink_safe(tmp_path):
 import gzip
 g=gate();p=tmp_path/'raw.json.gz';value={'data':2**63,'payload':{'execution_id':'do-not-rewrite'}}
 g.write_gzip(p,value)
 assert json.loads(gzip.decompress(p.read_bytes()))==value
 with pytest.raises(FileExistsError):g.write_gzip(p,{'data':0})
 link=tmp_path/'linked.json.gz';link.symlink_to(p)
 with pytest.raises((ValueError,FileExistsError)):g.write_gzip(link,value)
 assert json.loads(gzip.decompress(p.read_bytes()))==value


def test_confinement_rejects_ancestor_symlink_and_outside_root(tmp_path):
 g=gate();root=tmp_path/'allowed';root.mkdir();outside=tmp_path/'outside';outside.mkdir()
 assert g.confined(root/'new'/'output',root)==root/'new'/'output'
 with pytest.raises(ValueError,match='root'):g.confined(outside/'output',root)
 link=root/'alias';link.symlink_to(outside,target_is_directory=True)
 with pytest.raises(ValueError,match='symlink'):g.confined(link/'new',root)


def test_freeze_checks_full_source_set_and_no_payload_normalization(tmp_path):
 g=gate();repo=tmp_path/'source';repo.mkdir();(repo/'file.py').write_text('source')
 freeze={'schema_version':g.FREEZE_SCHEMA,'source_only':True,'native_run':False,'steps':650,'memory_seed':0,'files':{'file.py':g.sha((repo/'file.py').read_bytes())}}
 g.verify_freeze(repo,freeze,required={'file.py'})
 (repo/'file.py').write_text('changed')
 with pytest.raises(ValueError,match='freeze'):g.verify_freeze(repo,freeze,required={'file.py'})
 with pytest.raises(ValueError,match='freeze'):g.verify_freeze(repo,{'schema_version':g.FREEZE_SCHEMA,'files':{}},required={'file.py'})


def test_default_cli_does_not_construct_artifact_or_start_native(monkeypatch,capsys):
 g=gate()
 monkeypatch.setattr(g,'run_native_gate',lambda **kw:pytest.fail('native entry invoked'))
 assert g.main([])==0
 assert 'not_executed' in capsys.readouterr().out


def test_prefix_compare_keeps_raw_payload_and_requires_distinct_process_identity():
 g=gate();a={'samples':[{'data':17}],'runtime_events':[], 'runner_events':[], 'driver_receipts':[],
 'accepted':{'aw':2},'pending':{'read':1},'native_execution':'a'*32,'lifecycle':[dict(pid=11,closed=True,returncode=0,poll_after_close=0)]}
 b=copy.deepcopy(a);b['native_execution']='b'*32;b['lifecycle'][0]['pid']=12
 g.compare_prefixes(a,b)
 for bad in (dict(b,samples=[{'data':18}]),dict(b,native_execution=a['native_execution']),dict(b,lifecycle=a['lifecycle'])):
  with pytest.raises(ValueError):g.compare_prefixes(a,bad)
 assert a['pending']=={'read':1}


@pytest.fixture(scope='module')
def software_prefix():
 from dataclasses import asdict
 from myfuzz.local_harness.cva6_axi4_fields import CVA6_AXI_STEP_PORTS
 from myfuzz.local_harness.wire import parse_driver_receipt
 from myfuzz.scenario.full_axi_events import BoundedFullAxiObserver
 from myfuzz.scenario.runner import ScenarioRunner
 from myfuzz.scenario.ownership import compile_ownership
 from types import SimpleNamespace
 from tests.scenario.test_full_axi_events import edge,ar,aw,w
 samples=[edge(**ar(arlen=1),**aw(),**w(wlast=1)),
          edge(2,bvalid=1,bready=1,rvalid=1,rready=1),
          edge(3,**aw(awaddr=8),**w(wlast=1),rvalid=1,rready=1,rlast=1),
          edge(4,bvalid=1,bready=1)]
 samples.extend(edge(i) for i in range(5,651))
 observer=BoundedFullAxiObserver(component_id='cva6')
 observer.begin_scope(execution_id='a'*32,testcase_id='cva6-full-axi-observer-ram',reset_epoch=0)
 receipts=[]
 for i,sample in enumerate(samples,1):
  observer.observe(sample);row=sample['pre']['backend']
  payload=dict(schema_version='local_driver_result.v1',kind='cva6_packed_axi4_cpu',pre_backend=row,samples=[sample],observations={'physical':{}},rdata=0,error=0)
  raw=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
  line=f'RESULT {"a"*32} {i:x} {i-1:x} {i:x} {raw.hex()}'
  receipt=parse_driver_receipt(line,execution='a'*32,sequence=i,current_tick=i-1,kind='cva6_packed_axi4_cpu')
  receipts.append(dict(operation='STEP_CVA6_AXI4',fields=[0,0,*[row[p] for p in CVA6_AXI_STEP_PORTS[2:]]],receipt=asdict(receipt)))
 runner=ScenarioRunner(sessions={'cva6':SimpleNamespace(runtime_events=observer.events)},ownership=compile_ownership((),()),bindings=())
 runner._append_external_events('cva6',1)
 build_identity={'source_only_fixture':'not_a_native_build'}
 manifest={'schema_version':'local_harness_build_cache.v1','identity':build_identity,'binary_sha256':'f'*64}
 raw_manifest=json.dumps(manifest,sort_keys=True,separators=(',',':'))
 return dict(executable={'path':'software-fixture-binary','sha256':'f'*64},build_manifest=manifest,build_manifest_raw=raw_manifest,build_manifest_sha256=gate().sha(raw_manifest.encode()),identity={'sessions':{'cva6':{'identity':{'build_identity':build_identity}}}},provenance='constructed_software_fixture_not_native',status='complete',samples=samples,
    driver_receipts=receipts,runtime_events=observer.events,runner_events=list(runner.events),
    lifecycle=[dict(pid=123,closed=True,returncode=0,poll_after_close=0,ready=True,execution='a'*32,args=['software-fixture-binary'],binary_sha256_at_capture='f'*64,build_manifest_sha256_at_capture=gate().sha(raw_manifest.encode()))],native_execution='a'*32,
    accepted=observer.accepted,pending=observer.pending,read_beats=2,write_beats=2,
    ram_values=[0x600dcafe]*2,post_drain_added_records=0)


def test_actual_shape_prefix_checker_controls_are_software_only(software_prefix):
 g=gate();document=copy.deepcopy(software_prefix)
 g.validate_native_run(document)
 assert document['provenance']=='constructed_software_fixture_not_native'
 for mutate in ('sequence','input','last','sample','missing_import','reap'):
  bad=copy.deepcopy(document)
  if mutate=='sequence':bad['driver_receipts'][0]['receipt']['sequence']=2
  if mutate=='input':bad['driver_receipts'][0]['fields'][2]^=1
  if mutate=='last':bad['samples'][1]['pre']['backend']['axi_rlast']=1
  if mutate=='sample':bad['driver_receipts'][0]['receipt']['payload']['samples']=[]
  if mutate=='missing_import':bad['runner_events'].pop()
  if mutate=='reap':bad['lifecycle'][0]['poll_after_close']=None
  with pytest.raises(ValueError):g.validate_native_run(bad)


def test_fresh_entire_software_prefix_uses_only_typed_identity_paths(software_prefix):
 g=gate();first=copy.deepcopy(software_prefix);fresh=copy.deepcopy(first)
 fresh['native_execution']='b'*32;fresh['lifecycle'][0]['pid']=124;fresh['lifecycle'][0]['execution']='b'*32
 for event in fresh['runtime_events']:event['scope']['execution_id']='b'*32
 for event in fresh['runner_events']:event['scope']['execution_id']='b'*32
 for receipt in fresh['driver_receipts']:receipt['receipt']['execution']='b'*32
 g.compare_prefixes(first,fresh)
 fresh['runtime_events'][0]['raw_sample']['pre']['backend']['axi_rdata']=18
 with pytest.raises(ValueError):g.compare_prefixes(first,fresh)


def test_startup_abort_keeps_observed_pid_and_actual_close_result(monkeypatch):
 g=gate()
 from myfuzz.local_harness.session import GeneratedLocalSession
 class Process:
  pid=123;args=('software-fixture',);returncode=None
  def poll(self):return self.returncode
 def abort(cpu):cpu._process.returncode=-9;cpu._process=None
 monkeypatch.setattr(GeneratedLocalSession,'_abort',abort)
 monkeypatch.setattr(g.subprocess,'Popen',Process)
 cls=g._capturing_session_class();cpu=object.__new__(cls)
 cpu._process=Process();cpu._execution='a'*32;cpu.gate_lifecycles=[]
 cpu._abort()
 assert cpu.gate_lifecycles[0]['pid']==123
 assert cpu.gate_lifecycles[0]['poll_after_close']==-9
 assert cpu.gate_lifecycles[0]['closed'] is True
 assert cpu.gate_lifecycles[0]['ready'] is False


def test_failure_collection_retains_raw_even_if_ram_readback_fails(tmp_path,monkeypatch):
 import gzip
 from types import SimpleNamespace
 import myfuzz.scenario.memory as mem
 import myfuzz.scenario.runner as runner_module
 import myfuzz.scenario.replay as replay_module
 g=gate()
 class Memory:
  def __init__(self,**kw):pass
  def read(self,*a,**kw):raise ValueError('software readback collection failed')
 class Cpu:
  def __init__(self,*a,**kw):
   self.gate_lifecycles=[];self.gate_driver_receipts=[]
   self.runtime_events=[{'kind':'full_axi_raw','raw_sample':{'original_failure_edge':9}}]
   self._execution='a'*32;self._axi_observer=SimpleNamespace(accepted={},pending={})
   self.write_beats=self.read_beats=0
  def end_case(self):pass
 class Runner:
  def __init__(self,**kw):self.events=[]
  def set_resource_budget(self,budget):pass
  def identity_document(self):return {'provenance':'software_fixture'}
 def failed_record(*a):raise OSError('software native-step failure fixture')
 monkeypatch.setattr(g,'_capturing_session_class',lambda:Cpu)
 monkeypatch.setattr(mem,'PersistentMemory',Memory)
 monkeypatch.setattr(runner_module,'ScenarioRunner',Runner)
 monkeypatch.setattr(replay_module,'_record_with_runner',failed_record)
 with pytest.raises(RuntimeError,match='first native gate failed'):
  g._run_one(None,tmp_path,tmp_path,'first',b'fixture')
 document=json.loads(gzip.decompress((tmp_path/'first.json.gz').read_bytes()))
 assert document['samples']==[{'original_failure_edge':9}]
 assert document['error']['type']=='OSError'
 assert document['collection_errors']


def test_real_wire_result_status_is_admitted(software_prefix):
 assert software_prefix['driver_receipts'][0]['receipt']['status']=='result'
 gate().validate_native_run(copy.deepcopy(software_prefix))


def test_wrong_observer_and_runner_scope_cannot_hide_behind_normalization(software_prefix):
 g=gate();bad=copy.deepcopy(software_prefix)
 for collection in ('runtime_events','runner_events'):
  for event in bad[collection]:event['scope']['execution_id']='b'*32
 with pytest.raises(ValueError,match='scope'):g.validate_native_run(bad)
 with pytest.raises(ValueError,match='scope'):g.normalize_events(bad['runtime_events'],bad['native_execution'])


def test_wrong_fixed_case_epoch_component_are_rejected(software_prefix):
 g=gate()
 for key,value in (('testcase_id','other-case'),('reset_epoch',1),('source_component','other-source')):
  bad=copy.deepcopy(software_prefix)
  for collection in ('runtime_events','runner_events'):
   for event in bad[collection]:event['scope'][key]=value
  with pytest.raises(ValueError,match='scope'):g.validate_native_run(bad)


def test_missing_actual_binary_build_manifest_crosslink_refuses(software_prefix):
 g=gate();bad=copy.deepcopy(software_prefix)
 bad.pop('executable',None);bad.pop('build_manifest',None)
 with pytest.raises(ValueError,match='binary'):g.validate_native_run(bad)


def test_actual_freeze_preparation_reads_sources_only(monkeypatch):
 import subprocess
 g=gate()
 for name in ('run','check_output','Popen'):
  monkeypatch.setattr(subprocess,name,lambda *a,**k:pytest.fail('tool/native command during source preparation'))
 root=Path(__file__).resolve().parents[2]
 freeze=g.prepare_freeze(root);g.verify_freeze(root,freeze)
 assert freeze['native_run'] is False and freeze['steps']==650 and freeze['memory_seed']==0
 assert 'src/myfuzz/scenario/full_axi_events.py' in freeze['files']
 assert 'scripts/verify_cva6_full_axi_observer.py' in freeze['files']


def test_collector_command_limit_blocks_before_super_and_retains_failed_byte_edge(monkeypatch,software_prefix):
 from myfuzz.local_harness.session import GeneratedLocalSession
 from myfuzz.local_harness.wire import DriverReceipt
 g=gate();calls=[]
 receipt=DriverReceipt(**software_prefix['driver_receipts'][0]['receipt'])
 def command(cpu,operation,fields):calls.append(operation);return receipt
 monkeypatch.setattr(GeneratedLocalSession,'command',command)
 cls=g._capturing_session_class();cpu=object.__new__(cls)
 cpu.gate_driver_receipts=[];cpu._gate_bytes=64*1024*1024;cpu._gate_failed=False
 with pytest.raises(RuntimeError,match='byte budget'):cpu.command('STEP_CVA6_AXI4',())
 assert len(cpu.gate_driver_receipts)==1 and len(calls)==1
 with pytest.raises(RuntimeError):cpu.command('STEP_CVA6_AXI4',())
 assert len(calls)==1
 cpu.gate_driver_receipts=[{}]*650;cpu._gate_bytes=0;cpu._gate_failed=False
 with pytest.raises(RuntimeError):cpu.command('STEP_CVA6_AXI4',())
 assert len(calls)==1


def test_actual_binary_manifest_and_ready_hash_mutations_refuse(software_prefix):
 g=gate()
 for target in ('binary','ready_binary','manifest_identity','manifest_raw','ready_manifest','argv'):
  bad=copy.deepcopy(software_prefix)
  if target=='binary':bad['executable']['sha256']='0'*64
  if target=='ready_binary':bad['lifecycle'][0]['binary_sha256_at_capture']='0'*64
  if target=='manifest_identity':bad['build_manifest']['identity']={'changed':'source'}
  if target=='manifest_raw':bad['build_manifest_raw']+=' '
  if target=='ready_manifest':bad['lifecycle'][0]['build_manifest_sha256_at_capture']='0'*64
  if target=='argv':bad['lifecycle'][0]['args']=['other-binary']
  with pytest.raises(ValueError,match='binary'):g.validate_native_run(bad)


def test_issued_execution_must_also_match_the_process_lifecycle(software_prefix):
 g=gate();bad=copy.deepcopy(software_prefix);bad['lifecycle'][0]['execution']='b'*32
 with pytest.raises(ValueError,match='execution'):g.validate_native_run(bad)


def test_freeze_header_cannot_redeclare_fixed_native_budget(tmp_path):
 g=gate();(tmp_path/'file').write_bytes(b'fixture')
 freeze={'schema_version':g.FREEZE_SCHEMA,'source_only':True,'native_run':False,'steps':650,'memory_seed':0,'files':{'file':g.sha(b'fixture')}}
 for key,value in (('steps',1),('memory_seed',1),('source_only',False),('native_run',True)):
  with pytest.raises(ValueError,match='freeze'):g.verify_freeze(tmp_path,freeze|{key:value},required={'file'})
