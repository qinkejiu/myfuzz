"""Bounded startup software/standalone parser controls, never a DUT build."""
import copy
import json
from pathlib import Path
import subprocess
import pytest
from myfuzz.local_harness.ahb_startup import startup_contract,validate_startup_page
from myfuzz.scenario.ahb_cpu_events import SHAPE,AhbCpuObserver
from tests.local_harness.test_ahb_cpu_contract import generated


def record(index,asserted=1,**values):
 row=dict.fromkeys(SHAPE,0);row.update(hready=int(not asserted));row.update(values)
 return dict(startup_edge_index=index,reset_pre=asserted,reset_post=asserted,
  sample=dict(local_tick=index,pre=dict(protocol_taps=row),post=dict(protocol_taps=copy.deepcopy(row))))


def test_bounds_and_maximum():
 c=startup_contract(assert_ticks=1024,release_ticks=1024,snapshot_max={'protocol_taps':{r:(1<<w)-1 for r,w in SHAPE.items()}})
 assert c['total_ticks']==2048 and c['page_count']==64 and c['page_size']==32
 assert c['buffer_bound_bytes']<=8*1024*1024 and c['page_json_bound_bytes']<=1024*1024
 assert c['receipt_storage_bound_bytes']<=8*1024*1024
 for values in ((0,0),(1025,1),(1,-1),(True,1)):
  with pytest.raises(ValueError):startup_contract(assert_ticks=values[0],release_ticks=values[1],snapshot_max={})
 with pytest.raises(ValueError,match='bound'):
  startup_contract(assert_ticks=1024,release_ticks=1024,snapshot_max={'large':'f'*(2*1024*1024)})


def test_page_validation_and_exact_raw_preservation():
 c=startup_contract(assert_ticks=1,release_ticks=1,snapshot_max={})
 records=[record(1),record(2,0,hsel=1,htrans=2,haddr=4)]
 page=dict(schema_version='cpu_ahb_startup_page.v1',page_index=0,page_count=1,total_ticks=2,assert_ticks=1,release_ticks=1,records=records)
 assert validate_startup_page(page,c,expected_page=0)==records
 for key,value in [('page_index',1),('page_count',2),('total_ticks',3),('assert_ticks',True)]:
  with pytest.raises(ValueError):validate_startup_page(dict(page,**{key:value}),c,expected_page=0)
 for mutate in (lambda p:p['records'].pop(),lambda p:p['records'][1].update(startup_edge_index=1),lambda p:p['records'][1].update(reset_pre=1)):
  bad=copy.deepcopy(page);mutate(bad)
  with pytest.raises(ValueError):validate_startup_page(bad,c,expected_page=0)


def test_observer_release_address_then_command_write_data():
 o=AhbCpuObserver(component_id='cpu',endpoint_id='bus')
 o.begin_scope(execution_id='issued',testcase_id='case',reset_epoch=0)
 c=startup_contract(assert_ticks=1,release_ticks=1,snapshot_max={})
 o.begin_startup(c)
 o.observe_startup(record(1),rows={'pre':record(1)['sample']['pre']['protocol_taps'],'post':record(1)['sample']['post']['protocol_taps']})
 r=record(2,0,hsel=1,htrans=2,hwrite=1,haddr=0x100,hwdata=1)
 o.observe_startup(r,rows={p:r['sample'][p]['protocol_taps'] for p in ('pre','post')})
 o.finish_startup()
 row=dict.fromkeys(SHAPE,0)|dict(hready=1,hwdata=42,hwstrb=3)
 raw=dict(local_tick=1,pre=row,post=row);o.observe(raw)
 e=next(e for e in o.events if e['kind']=='ahb_complete')
 assert e['local_tick']==1 and e['measurement_tick']==3 and e['wdata']==42
 assert next(e for e in o.events if e['kind']=='ahb_raw' and e['tick_namespace']=='command')['raw_sample']==raw
 assert not any(e['kind']=='ahb_prefix_unknown' for e in o.events)
 assert o.measured_reset_to_command_prefix is True
 assert o.counts['accepted']==o.counts['completed']==1


def test_startup_counts_against_global_edges():
 o=AhbCpuObserver(component_id='cpu',endpoint_id='bus',max_edges=1)
 o.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 o.begin_startup(startup_contract(assert_ticks=1,release_ticks=1,snapshot_max={}))
 for i in (1,2):
  r=record(i,int(i==1))
  try:o.observe_startup(r,rows={p:r['sample'][p]['protocol_taps'] for p in ('pre','post')})
  except ValueError:break
 with pytest.raises(ValueError):o.require_active()
 assert o.events[-1]['possible_effects'] is True


def test_generated_driver_startup_capture_is_ahb_only(generated):
 artifact,cpu=generated;c=artifact.runtime_document['ahb_startup_contract'];cpp=artifact.cpp_text
 assert c['total_ticks']==16 and c['page_count']==1
 assert 'CommandSet::AhbStartup' in cpp and cpp.count('capture_ahb_startup(dut);')==2
 assert 'READ_AHB_STARTUP' in cpp and 'ahb_startup_next_page' in cpp
 assert 'tick(dut, &measured);' in cpp
 assert 'const auto reset_pre = static_cast<unsigned>(dut.reset);' in cpp
 assert 'const auto reset_post = static_cast<unsigned>(dut.reset);' in cpp
 assert '"READY local_driver.v1 "' in cpp
 assert cpu.identity_document()['ahb_observation_contract']['startup_capture']==c


def test_parser_optin_and_replay_revalidation(tmp_path):
 root=Path(__file__).resolve().parents[2]
 source=tmp_path/'parser.cpp';binary=tmp_path/'parser'
 source.write_text(r'''
#include "src/myfuzz/local_harness/rtl/local_driver_v1.h"
#include <cassert>
using namespace myfuzz::local_driver_v1;
int main() {
 const std::string line="CMD 0123456789abcdef0123456789abcdef 1 READ_AHB_STARTUP 0";
 assert(!parse_command(line).ok);
 auto p=parse_command(line,CommandSet::AhbStartup);assert(p.ok);
 BoundedReplay standard(4096,4096);
 assert(standard.accept(p.command,0,512).decision!=Decision::Fresh);
 BoundedReplay optin(4096,4096,CommandSet::AhbStartup);
 auto bad=p.command;bad.fields[0]=1;
 assert(optin.accept(bad,0,512).decision!=Decision::Fresh);
 assert(optin.accept(p.command,0,512).decision==Decision::Fresh);
 optin.finish(1,"preserved_fixture_reply");
 const auto cached=optin.accept(p.command,0,512);
 assert(cached.decision==Decision::Cached && cached.reply=="preserved_fixture_reply");
 auto conflict=parse_command("CMD 0123456789abcdef0123456789abcdef 1 READ_AHB_STARTUP 1",CommandSet::AhbStartup);
 assert(optin.accept(conflict.command,0,512).decision==Decision::Rejected);
 assert(!parse_command("CMD 0123456789abcdef0123456789abcdef 2 READ_AHB_STARTUP 40",CommandSet::AhbStartup).ok);
 assert(!parse_command("CMD 0123456789abcdef0123456789abcdef 2 READ_AHB_STARTUP 00",CommandSet::AhbStartup).ok);
 assert(!parse_command("CMD 0123456789abcdef0123456789abcdef 2 READ_AHB_STARTUP 0 0",CommandSet::AhbStartup).ok);
}
''')
 subprocess.run(['c++','-std=c++17','-I',str(root),str(source),'-o',str(binary)],check=True,capture_output=True)
 subprocess.run([str(binary)],check=True,capture_output=True)


def transport_fixture(cpu,monkeypatch,mutate=None,*,pipeline=False,execution='0123456789abcdef0123456789abcdef'):
 """Only wire/transport replaced; real AHB begin/observer/step executes."""
 from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
 from myfuzz.local_harness.wire import parse_driver_receipt
 calls=[];aborts=[]
 def begin(self,case):
  self._execution=execution;self._case_id=case
  self._sequence=0;self.local_ticks=0
 def command(self,op,fields):
  calls.append((op,fields));seq=self._sequence+1;before=self.local_ticks
  backend={r['name']:0 for r in self._artifact_document['backend_ports']}
  physical={r['runtime_name']:0 for r in self._artifact_document['physical_exports']}
  if op=='READ_AHB_STARTUP':
   c=self._ahb_startup_contract;page=fields[0];records=[]
   for index in range(page*32+1,min((page+1)*32,c['total_ticks'])+1):
    r=record(index,int(index<=c['assert_ticks']))
    if index==c['total_ticks'] and c['release_ticks']:
     for phase in ('pre','post'):r['sample'][phase]['protocol_taps'].update(hsel=1,htrans=2,haddr=0xc0000000)
    for phase in ('pre','post'):
     taps=r['sample'][phase]['protocol_taps']
     r['sample'][phase]=dict(protocol_taps={self._ahb_signal_map[k]:v for k,v in taps.items()},backend=copy.deepcopy(backend),physical=copy.deepcopy(physical))
    records.append(r)
   observations={'ahb_startup':dict(schema_version='cpu_ahb_startup_page.v1',page_index=page,page_count=c['page_count'],total_ticks=c['total_ticks'],assert_ticks=c['assert_ticks'],release_ticks=c['release_ticks'],records=records)}
   samples=[];after=before
  else:
   backend.update(dict(zip(('m_req_ready','m_rsp_valid','m_rsp_rdata','m_rsp_error'),fields)))
   taps={v:0 for v in self._ahb_signal_map.values()}
   if pipeline:
    step=before+1
    backend.update(m_req_addr=self.boot_base,m_req_be=15,
                   m_req_valid=int(step==2),m_rsp_ready=int(step==3))
    taps[self._ahb_signal_map['hready']]=int(step==3)
    taps[self._ahb_signal_map['hrdata']]=fields[2]
   s=dict(backend=backend,physical=physical,protocol_taps=taps)
   post=copy.deepcopy(s)
   if pipeline:
    post['backend'].update(m_req_valid=int(step==1),m_rsp_ready=int(step==2))
    post['protocol_taps'][self._ahb_signal_map['hready']]=int(step>=2)
   samples=[dict(local_tick=before+1,pre=s,post=post)]
   observations=dict(physical=physical);after=before+1
  payload=dict(schema_version='local_driver_result.v1',kind='ahb_lite_cpu',samples=samples,observations=observations,pre_backend=backend,rdata=0,error=0)
  if mutate:mutate(op,fields,payload)
  encoded=json.dumps(payload,sort_keys=True,separators=(',',':')).encode().hex()
  parsed=parse_driver_receipt(f'RESULT {self._execution} {seq:x} {before:x} {after:x} {encoded}',execution=self._execution,sequence=seq,current_tick=before,kind='ahb_lite_cpu')
  self._sequence=seq;self.local_ticks=after
  return parsed
 monkeypatch.setattr(GeneratedNativeMemorySession,'begin_case',begin)
 monkeypatch.setattr(GeneratedNativeMemorySession,'command',command)
 monkeypatch.setattr(cpu,'_abort',lambda:aborts.append(True))
 return calls,aborts


def test_session_real_result_pages_before_step(generated,monkeypatch):
 artifact,cpu=generated;calls,aborts=transport_fixture(cpu,monkeypatch)
 cpu.begin_case('case')
 assert calls==[('READ_AHB_STARTUP',(0,))] and cpu.local_ticks==0
 assert len(cpu._ahb_startup_receipts)==1 and cpu._ahb_startup_receipts[0]['status']=='result'
 assert cpu._ahb_startup_complete and not cpu._ahb_observer.measured_reset_to_command_prefix
 raw=[e for e in cpu.runtime_events if e['kind']=='ahb_raw']
 assert len(raw)==16 and all(e['tick_namespace']=='startup' for e in raw)
 cpu.step_local({})
 assert cpu.local_ticks==1 and cpu._ahb_observer.measured_reset_to_command_prefix
 assert not any(e['kind']=='ahb_prefix_unknown' for e in cpu.runtime_events)
 assert not aborts


@pytest.mark.parametrize('mutate',[
 lambda op,f,p:p['observations']['ahb_startup'].update(page_index=1),
 lambda op,f,p:p['observations']['ahb_startup']['records'].pop(),
 lambda op,f,p:p['observations']['ahb_startup']['records'][0].update(reset_pre=0),
 lambda op,f,p:p['observations']['ahb_startup']['records'][0]['sample']['pre']['protocol_taps'].clear(),
])
def test_page_failure_aborts_and_blocks_step_and_begin(generated,monkeypatch,mutate):
 artifact,cpu=generated;calls,aborts=transport_fixture(cpu,monkeypatch,mutate)
 with pytest.raises((ValueError,KeyError)):cpu.begin_case('case')
 assert aborts and not cpu._ahb_startup_complete
 assert cpu.runtime_events[-1]['diagnostic_receipt']['status']=='result'
 n=len(calls)
 with pytest.raises(Exception):cpu.step_local({})
 assert len(calls)==n
 # Failing a prior page must also refuse a second native begin before transport.
 from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
 monkeypatch.setattr(GeneratedNativeMemorySession,'begin_case',lambda *a:pytest.fail('native startup retried'))
 with pytest.raises(Exception):cpu.begin_case('case')


@pytest.mark.parametrize('generated',[(32,1)],indirect=True)
def test_late_page_failure_retains_current_and_all_previous_receipts(generated,monkeypatch):
 artifact,cpu=generated
 def mutate(op,fields,payload):
  if op=='READ_AHB_STARTUP' and fields==(1,):payload['observations']['ahb_startup']['records'][0]['sample']['pre']['protocol_taps'].clear()
 calls,aborts=transport_fixture(cpu,monkeypatch,mutate)
 with pytest.raises(KeyError):cpu.begin_case('case')
 assert len(cpu._ahb_startup_receipts)==2
 assert cpu.runtime_events[-1]['diagnostic_receipt']['sequence']==2
 assert sum(e['kind']=='ahb_raw' for e in cpu.runtime_events)==32
 assert cpu.local_ticks==0 and not cpu._ahb_startup_complete


def test_step_before_pages_refuses_transport(generated,monkeypatch):
 from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
 artifact,cpu=generated;calls,aborts=transport_fixture(cpu,monkeypatch)
 cpu._ahb_observer.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 with pytest.raises(Exception,match='startup'):GeneratedAhbMemorySession.command(cpu,'STEP_MEMORY',(0,0,0,0))
 assert not calls


@pytest.mark.parametrize('asserted,released',[(1,0),(1024,1024)])
def test_zero_release_and_maximum_capture_no_tick_rewrite(asserted,released):
 c=startup_contract(assert_ticks=asserted,release_ticks=released,snapshot_max={})
 o=AhbCpuObserver(component_id='cpu',endpoint_id='bus')
 o.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0);o.begin_startup(c)
 for index in range(1,c['total_ticks']+1):
  r=record(index,int(index<=asserted))
  o.observe_startup(r,rows={p:r['sample'][p]['protocol_taps'] for p in ('pre','post')})
 o.finish_startup();row=dict.fromkeys(SHAPE,0)|dict(hready=1)
 o.observe(dict(local_tick=1,pre=row,post=row))
 assert o.tick==c['total_ticks']+1
 assert o.measured_reset_to_command_prefix
 assert len([e for e in o.events if e['kind']=='ahb_raw'])==c['total_ticks']+1


def test_template_defaults_identical_for_other_kinds():
 import ast,gzip
 from myfuzz.local_harness import driver_renderer
 before=gzip.decompress(Path('docs/reports/evidence/cvw-ahb-startup-20261017/driver-renderer-before.py.gz').read_bytes()).decode()
 after=Path(driver_renderer.__file__).read_text()
 def template(source):
  tree=ast.parse(source)
  return next(n.value.value for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='template' for t in n.targets))
 old=template(before);new=template(after)
 replacements={'AHB_STARTUP_HELPERS':'','STARTUP_TICK':'tick(dut, nullptr);',
  'COMMAND_SET':'','AHB_STARTUP_VARIABLE':'','AHB_STARTUP_FINISH':'','OBSERVATIONS_EXPRESSION':'snapshot(dut)'}
 for key,value in replacements.items():new=new.replace('@'+key+'@',value)
 assert new==old


def test_actual_reset_tick_and_ready_bytes_preserved(generated):
 import gzip
 artifact,cpu=generated
 namespace={'__name__':'myfuzz.local_harness.saved_driver_renderer','__package__':'myfuzz.local_harness'}
 before=gzip.decompress(Path('docs/reports/evidence/cvw-ahb-startup-20261017/driver-renderer-before.py.gz').read_bytes())
 exec(compile(before,'saved_driver_renderer.py','exec'),namespace)
 from myfuzz.local_harness import render_local_runtime
 top=render_local_runtime(artifact.plan,artifact.structural,artifact.source_verification,base_dir=Path.cwd())
 old=namespace['render_local_driver'](top,base_dir=Path.cwd()).cpp_text;new=artifact.cpp_text
 def startup(cpp):return cpp[cpp.index('int main('):cpp.index('  BoundedReplay replay(')]
 assert startup(new).replace('capture_ahb_startup(dut);','tick(dut, nullptr);')==startup(old)
 def tick(cpp):return cpp[cpp.index('static void tick('):cpp.index('static std::string encode_hex(')].split('static std::vector<std::string> ahb_startup_records;')[0]
 assert tick(new)==tick(old)
 assert artifact.runtime_sv==top.runtime_sv


@pytest.mark.parametrize('kind',['native_memory_cpu','axi4_lite_cpu'])
def test_nonahb_memory_template_cpp_bytes_unchanged(generated,monkeypatch,kind):
 import gzip
 from dataclasses import replace
 from myfuzz.local_harness import driver_renderer,render_local_runtime
 artifact,cpu=generated
 top=render_local_runtime(artifact.plan,artifact.structural,artifact.source_verification,base_dir=Path.cwd())
 document=copy.deepcopy(top.runtime_document);document['kind']=kind
 # Synthetic kind controls only compare templates; not an admitted CPU profile.
 top=replace(top,runtime_document=document)
 before=gzip.decompress(Path('docs/reports/evidence/cvw-ahb-startup-20261017/driver-renderer-before.py.gz').read_bytes())
 namespace={'__name__':'myfuzz.local_harness.saved_driver_renderer','__package__':'myfuzz.local_harness'}
 exec(compile(before,'saved_driver_renderer.py','exec'),namespace)
 namespace['render_local_runtime']=lambda *a,**kw:top
 monkeypatch.setattr(driver_renderer,'render_local_runtime',lambda *a,**kw:top)
 assert namespace['render_local_driver'](top,base_dir=Path.cwd()).cpp_text==driver_renderer.render_local_driver(top,base_dir=Path.cwd()).cpp_text


def test_startup_receipts_are_global_raw_budgeted_and_not_replaced(generated,monkeypatch):
 artifact,cpu=generated;calls,aborts=transport_fixture(cpu,monkeypatch)
 receipts=cpu._ahb_startup_receipts
 cpu.begin_case('case')
 assert cpu._ahb_startup_receipts is receipts
 assert any(e['kind']=='ahb_startup_receipt' for e in cpu.runtime_events)
 assert cpu._ahb_observer._bytes>0


def test_startup_receipt_budget_fails_without_projecting_records(generated,monkeypatch):
 artifact,cpu=generated;calls,aborts=transport_fixture(cpu,monkeypatch)
 cpu._ahb_observer._limits=(100000,1,1000000,256)
 with pytest.raises(ValueError,match='budget'):cpu.begin_case('case')
 assert not any(e['kind']=='ahb_raw' for e in cpu.runtime_events)
 assert cpu.runtime_events[-2]['kind']=='ahb_startup_receipt'
 assert cpu.runtime_events[-1]['possible_effects'] is True and aborts


def test_page_completion_only_after_replay_finish(generated):
 artifact,cpu=generated;cpp=artifact.cpp_text
 assert cpp.index('++ahb_startup_next_page;')>cpp.index('replay.finish(command.sequence, terminal);')


def test_registry_keeps_other_kinds_closed():
 from myfuzz.local_harness.session import registered_operations
 assert 'READ_AHB_STARTUP' in registered_operations('ahb_lite_cpu')
 for kind in ('native_memory_cpu','axi4_lite_cpu','cva6_packed_axi4_cpu','obi_cpu','apb3_register_observe'):
  assert 'READ_AHB_STARTUP' not in registered_operations(kind)


def test_startup_budget_prevents_native_begin(generated,monkeypatch):
 from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
 artifact,cpu=generated
 cpu._ahb_observer._limits=(1,64*1024*1024,1000000,256)
 monkeypatch.setattr(GeneratedNativeMemorySession,'begin_case',lambda *a:pytest.fail('native started with impossible edge budget'))
 with pytest.raises(Exception,match='budget'):cpu.begin_case('case')
 assert cpu.runtime_events[-1]['possible_effects'] is False


@pytest.mark.parametrize('generated',[(32,1)],indirect=True)
def test_lost_page_reply_never_reuses_old_receipt(generated,monkeypatch):
 from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
 artifact,cpu=generated;calls,aborts=transport_fixture(cpu,monkeypatch)
 command=GeneratedNativeMemorySession.command
 def lost(self,operation,fields):
  if fields==(1,):raise OSError('lost startup reply')
  return command(self,operation,fields)
 monkeypatch.setattr(GeneratedNativeMemorySession,'command',lost)
 with pytest.raises(OSError):cpu.begin_case('case')
 assert cpu.runtime_events[-1]['diagnostic_receipt'] is None
 assert len(cpu._ahb_startup_receipts)==1 and aborts


def test_error_receipt_preserved_before_abort(generated,monkeypatch):
 from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
 from myfuzz.local_harness.wire import parse_driver_receipt
 artifact,cpu=generated;calls,aborts=transport_fixture(cpu,monkeypatch)
 def error(self,op,fields):
  return parse_driver_receipt(f'ERROR {self._execution} 1 0 protocol_environment startup_refused',execution=self._execution,sequence=1,current_tick=0,kind='ahb_lite_cpu')
 monkeypatch.setattr(GeneratedNativeMemorySession,'command',error)
 with pytest.raises(Exception,match='receipt'):cpu.begin_case('case')
 assert cpu.runtime_events[-1]['diagnostic_receipt']['status']=='error'
 assert cpu._ahb_startup_receipts[-1]['status']=='error' and aborts


def test_startup_identity_and_version_mutations_refuse(generated):
 from myfuzz.scenario.contracts import _verify_generated_session
 artifact,cpu=generated
 for mutate in (lambda d:d['runtime_artifact']['ahb_startup_contract'].update(page_count=2),
                lambda d:d['ahb_observation_contract']['startup_capture'].update(total_ticks=1),
                lambda d:d['runtime_artifact'].update(driver_schema_version='local_driver_generation.v1')):
  identity=copy.deepcopy(cpu.identity_document());mutate(identity)
  with pytest.raises(ValueError):_verify_generated_session(identity)


def test_model_complete_prefix_fresh_and_actual_runner_drain(generated,monkeypatch):
 from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
 from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
 from myfuzz.scenario.runner import ScenarioRunner
 from myfuzz.scenario.ownership import compile_ownership
 from myfuzz.scenario.event_journal import EventJournal
 artifact,first=generated
 second=GeneratedAhbMemorySession(artifact,base_dir=first.base_dir,cache_dir=first.cache_dir,
  memory=PersistentMemory(regions=(MemoryRegion('ram',0xc0000000,4096),),initialization_seed=0,max_initialized_bytes=4096))
 prefixes=[]
 for cpu,execution in ((first,'1'*32),(second,'2'*32)):
  calls,aborts=transport_fixture(cpu,monkeypatch,pipeline=True,execution=execution)
  cpu.memory.accept_instructions(cpu.boot_base,b'\x13\x00\x00\x00',source_event_id='software_instruction')
  cpu.begin_case('case')
  runner=ScenarioRunner(sessions={'cpu':cpu},ownership=compile_ownership((),()),bindings=())
  runner._events._records=EventJournal(chunk_size=2)
  runner._append_external_events('cpu',0)
  assert cpu.runtime_events==[]
  for step in range(3):
   cpu.step_local({});runner._append_external_events('cpu',step+1)
  count=len(runner._events);runner._append_external_events('cpu',4)
  assert len(runner._events)==count and not aborts
  events=[copy.deepcopy(e) for e in runner._events if e.get('schema_version')=='bounded_cpu_ahb_observation.v1']
  complete=next(e for e in events if e['kind']=='ahb_complete')
  assert complete['rdata']==19 and complete['local_tick']==3 and complete['measurement_tick']==19
  raw=[e for e in events if e['kind']=='ahb_raw'];refs={e['observer_record_index'] for e in raw}
  assert len(raw)==19 and len(refs)==19
  assert all(ref in refs for ref in complete['raw_event_refs'])
  assert cpu._ahb_observer.pending is None and cpu._ahb_observer.measured_reset_to_command_prefix
  assert cpu._ahb_observer.counts['accepted']==cpu._ahb_observer.counts['completed']==1
  # Normalize only the issued typed execution fields, leaving all raw samples.
  for e in events:
   assert e['scope']['execution_id']==execution
   e['scope']['execution_id']='ISSUED_SOFTWARE_EXECUTION'
   if e['kind']=='ahb_startup_receipt':
    assert e['raw_receipt']['execution']==execution
    e['raw_receipt']['execution']='ISSUED_SOFTWARE_EXECUTION'
  prefixes.append(events)
 assert prefixes[0]==prefixes[1]


def test_observer_cannot_claim_prefix_without_measured_reset_or_contiguous_tick():
 o=AhbCpuObserver(component_id='cpu',endpoint_id='bus');o.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 with pytest.raises(ValueError):o.begin_startup(dict(assert_ticks=0,total_ticks=0))
 o.begin_startup(startup_contract(assert_ticks=1,release_ticks=0,snapshot_max={}))
 r=record(1);o.observe_startup(r,rows={p:r['sample'][p]['protocol_taps'] for p in ('pre','post')});o.finish_startup()
 row=dict.fromkeys(SHAPE,0)|dict(hready=1)
 with pytest.raises(ValueError,match='tick'):o.observe(dict(local_tick=2,pre=row,post=row))
 assert o.measured_reset_to_command_prefix is False


def test_startup_raw_tick_must_match_native_index():
 o=AhbCpuObserver(component_id='cpu',endpoint_id='bus');o.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 o.begin_startup(startup_contract(assert_ticks=1,release_ticks=0,snapshot_max={}))
 r=record(1);r['sample']['local_tick']=2
 with pytest.raises(ValueError):o.observe_startup(r,rows={p:r['sample'][p]['protocol_taps'] for p in ('pre','post')})


def test_real_ready_admission_accepts_only_ahb_version(generated):
 artifact,cpu=generated
 assert cpu._expected_ready()==(artifact.runtime_document['artifact_digest'],8,8,'ahb_lite_cpu')
 for change in ({'driver_schema_version':'local_driver_generation.v1'}, {'kind':'native_memory_cpu'}):
  original=cpu._artifact_document
  cpu._artifact_document=copy.deepcopy(original);cpu._artifact_document.update(change)
  from dataclasses import replace
  original_artifact=cpu.artifact
  cpu.artifact=replace(original_artifact,runtime_document=copy.deepcopy(cpu._artifact_document))
  with pytest.raises(ValueError):cpu._expected_ready()
  cpu.artifact=original_artifact;cpu._artifact_document=original


@pytest.mark.parametrize('generated',[(1,0)],indirect=True)
def test_real_ahb_ready_allows_declared_zero_release(generated):
 artifact,cpu=generated
 assert cpu._expected_ready()[1:3]==(1,0)


def test_real_build_prepare_schema_keys_and_generated_reconstruction(generated,monkeypatch):
 from myfuzz.local_harness import build
 artifact,cpu=generated
 monkeypatch.setattr(build,'_toolchain',lambda:dict(verilator=dict(path='software_verilator'),cxx=dict(path='software_cxx'),ar=dict(path='software_ar')))
 identity,snapshots=build._prepare(artifact,cpu.base_dir)
 assert identity['artifact_digest']==artifact.runtime_document['artifact_digest']
 assert json.loads(snapshots['generated/artifact.json'])['ahb_startup_contract']==cpu._ahb_startup_contract
 assert snapshots['generated/driver.cpp']==artifact.cpp_text.encode()
 assert any(r['path']=='src/myfuzz/local_harness/ahb_startup.py' for r in identity['host_sources']['files'])
 # Identity is a source-only software tool fixture, never a compiled artifact.
 assert identity['toolchain']['verilator']['path']=='software_verilator'


@pytest.mark.parametrize('change',[
 {'driver_schema_version':'local_driver_generation.v1'},
 {'kind':'native_memory_cpu'},
 {'kind':'native_memory_cpu','driver_schema_version':'local_driver_generation.v1'},
])
def test_real_build_refuses_downgrade_and_other_kind_startup_key(generated,monkeypatch,change):
 from dataclasses import replace
 from myfuzz.local_harness import build
 from myfuzz.local_harness.renderer import _sha
 artifact,cpu=generated;document=copy.deepcopy(artifact.runtime_document);document.update(change)
 document['artifact_digest']=_sha({k:v for k,v in document.items() if k!='artifact_digest'})
 changed=replace(artifact,runtime_document=document)
 monkeypatch.setattr(build,'_toolchain',lambda:pytest.fail('tool reached for invalid schema'))
 with pytest.raises(build.LocalHarnessBuildError):build._prepare(changed,cpu.base_dir)


def test_real_ready_rejects_foreign_startup_key_but_keeps_standard_version(generated):
 from dataclasses import replace
 artifact,cpu=generated;document=copy.deepcopy(cpu._artifact_document)
 document.update(kind='native_memory_cpu',driver_schema_version='local_driver_generation.v1')
 cpu._artifact_document=document;cpu.artifact=replace(artifact,runtime_document=copy.deepcopy(document))
 with pytest.raises(ValueError,match='another runtime'):cpu._expected_ready()
 del document['ahb_startup_contract'];cpu.artifact=replace(artifact,runtime_document=copy.deepcopy(document))
 assert cpu._expected_ready()[3]=='native_memory_cpu'
