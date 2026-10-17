"""Source-only hook/renderer controls; no artifact planning or tool launch."""
import ast
import copy
import gzip
import hashlib
from pathlib import Path
from types import SimpleNamespace
import pytest
from myfuzz.local_harness import runtime_renderer as renderer
from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
from myfuzz.local_harness.ahb_manager_domain import software_manager_domain_contract
from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
from tests.local_harness.ahb_domain_support import command_sample,start_measured_prefix
from tests.local_harness.test_ahb_cpu_contract import generated
from myfuzz.scenario.ahb_cpu_events import SHAPE,AhbCpuObserver
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.memory import PersistentMemory,MemoryRegion


def test_renderer_exports_actual_wires_only():
 wires={r:'opaque_'+str(i) for i,r in enumerate(SHAPE)}
 ports=[];statements=[];tap_ports=[];traces=[]
 renderer._expose_cpu_ahb_trace('renamed.bus','clk',wires,ports,statements,tap_ports,traces)
 assert len(ports)==len(statements)==len(tap_ports)==13
 for r,w in SHAPE.items():
  row=next(t for t in tap_ports if t['role']==r)
  assert row['width']==w and row['source_wire']==wires[r]
  assert f"assign {row['name']} = {wires[r]};" in statements
 assert traces[0]['signal_widths']==SHAPE
 assert traces[0]['boundary']=='cpu_physical_abi'


def test_renderer_other_code_ast_unchanged():
 before=gzip.decompress(Path('docs/reports/evidence/cvw-ahb-implementation-20261017/runtime-renderer-before.py.gz').read_bytes()).decode()
 # Preserve this historical AHB extraction proof against the pre-storage increment.
 after=Path('.superpowers/apb-storage-probe-generation/runtime_renderer.before.py').read_text()
 current=ast.parse(Path(renderer.__file__).read_text())
 pinned=ast.parse(after)
 get_ahb=lambda tree:next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_expose_cpu_ahb_trace')
 assert ast.dump(get_ahb(current),include_attributes=False)==ast.dump(get_ahb(pinned),include_attributes=False)
 tree=ast.parse(after)
 wrapper=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='render_local_runtime')
 helper=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_render_admitted_runtime')
 call=wrapper.body[-1]
 assert isinstance(call,ast.Return) and isinstance(call.value,ast.Call)
 assert call.value.func.id=='_render_admitted_runtime'
 assert [a.id for a in call.value.args]==['plan','structural','verified','root']
 assert [(k.arg,k.value.id) for k in call.value.keywords]==[('native_raw','native_raw')]
 assert [a.arg for a in helper.args.args]==['plan','structural','verified','root']
 assert [a.arg for a in helper.args.kwonlyargs]==['native_raw']
 assert isinstance(helper.body[0],ast.Expr) and isinstance(helper.body[0].value,ast.Constant)
 # Exact inverse of root's pure extraction: admission prefix + unchanged body.
 wrapper.body=wrapper.body[:-1]+helper.body[1:]
 tree.body=[n for n in tree.body if n is not helper]
 tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name!='_expose_cpu_ahb_trace']
 class Remove(ast.NodeTransformer):
  def visit_Expr(self,n):
   if isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='_expose_cpu_ahb_trace':return None
   return self.generic_visit(n)
 assert ast.dump(Remove().visit(tree),include_attributes=False)==ast.dump(ast.parse(before),include_attributes=False)
 assert after.count('_expose_cpu_ahb_trace(')==2


def fake():
 cpu=object.__new__(GeneratedAhbMemorySession)
 cpu._execution='issued';cpu._case_id='case';cpu.reset_epoch=0
 cpu.artifact=SimpleNamespace(plan=SimpleNamespace(request=SimpleNamespace(instance_id='cpu')))
 cpu._ahb_manager_domain=software_manager_domain_contract(protocol_endpoint_id='bus')
 cpu._ahb_observer=AhbCpuObserver(component_id='cpu',endpoint_id='bus')
 cpu._ahb_observer.begin_scope(execution_id='issued',testcase_id='case',reset_epoch=0)
 start_measured_prefix(cpu._ahb_observer)
 cpu.runtime_events=cpu._ahb_observer.events;cpu._ahb_signal_map={r:r for r in SHAPE}
 cpu._last_ahb_receipt=None;cpu._pending=None;cpu._sequence_memory=0;cpu._quiescing=False
 cpu._artifact_document={'physical_exports':[]};cpu.boot_base=0
 cpu.memory=PersistentMemory(regions=(MemoryRegion('ram',0,4096),),initialization_seed=0,max_initialized_bytes=4096)
 cpu.memory_write_count=0;cpu.accepted_addresses=[];cpu.last_samples=()
 calls=[];aborts=[];cpu._abort=lambda:aborts.append(True)
 def command(operation,fields):
  calls.append(operation)
  cpu._ahb_command_attempted=True
  b=dict(zip(('m_req_ready','m_rsp_valid','m_rsp_rdata','m_rsp_error'),fields))
  b.update(m_req_valid=0,m_rsp_ready=0,m_req_addr=0,m_req_write=0,m_req_be=15,m_req_wdata=0)
  row={k:0 for k in SHAPE};row.update(hready=1)
  physical={'rt_lh_p_6_0_0':1,'rt_lh_p_8_0_0':1}
  s=dict(local_tick=len(calls),pre=dict(backend=b,physical=physical,protocol_taps=row),post=dict(backend=copy.deepcopy(b),physical=copy.deepcopy(physical),protocol_taps=copy.deepcopy(row)))
  receipt=SimpleNamespace(status='result',new_ticks=1,payload=dict(pre_backend=b,samples=[s],observations=dict(physical={})))
  cpu._last_ahb_receipt=receipt
  return receipt
 cpu.command=command
 return cpu,calls,aborts


def test_noop_hook_base_is_callable():
 assert GeneratedNativeMemorySession._observe_verified_memory_edge(object(),object()) is None


def test_actual_hook_before_service_and_long_lived_stream():
 cpu,calls,aborts=fake();stream=cpu.runtime_events
 cpu.step_local({});cpu.step_local({})
 command_raw=[e for e in stream if e['kind']=='ahb_raw' and e['tick_namespace']=='command']
 assert cpu.runtime_events is stream and len(command_raw)==2
 assert command_raw[0]['raw_sample']==cpu.last_samples[0] | {'local_tick':1}
 assert not aborts


@pytest.mark.parametrize('failure',[OSError('io'),TypeError('type'),AttributeError('attribute')])
def test_all_exception_service_poison_and_retry_guard(failure):
 cpu,calls,aborts=fake()
 def fail():raise failure
 cpu.memory.advance_step=fail
 with pytest.raises(type(failure)):cpu.step_local({})
 assert cpu.runtime_events[-1]['possible_effects'] and aborts
 n=len(calls)
 with pytest.raises(ProtocolEnvironmentError,match='not_active'):cpu.step_local({})
 assert len(calls)==n


def test_current_receipt_cleared_before_command_failure():
 cpu,calls,aborts=fake();cpu.step_local({})
 def fail(*a):raise OSError('lost reply')
 cpu.command=fail
 with pytest.raises(OSError):cpu.step_local({})
 assert cpu.runtime_events[-1]['diagnostic_receipt'] is None
 assert cpu.runtime_events[-1]['trusted_projection'] is False


def test_untrusted_receipt_preserved_without_projection():
 cpu,calls,aborts=fake();command=cpu.command
 def bad(*args):
  receipt=command(*args);receipt.payload['samples'][0]['pre']['backend']={};return receipt
 cpu.command=bad
 with pytest.raises(ProtocolEnvironmentError):cpu.step_local({})
 assert not any(e['kind']=='ahb_raw' and e['tick_namespace']=='command'
                for e in cpu.runtime_events)
 assert cpu.runtime_events[-1]['diagnostic_receipt']['payload']['samples'][0]['pre']['backend']=={}
 assert aborts


def test_observer_failure_preserves_raw_and_no_service():
 cpu,calls,aborts=fake();command=cpu.command
 def bad(*args):
  receipt=command(*args);receipt.payload['samples'][0]['pre']['protocol_taps']['haddr']=1<<34;return receipt
 cpu.command=bad
 with pytest.raises(ValueError,match='shape'):cpu.step_local({})
 assert any(e['kind']=='ahb_raw' for e in cpu.runtime_events) and aborts


def test_reset_cancel_precedes_transport(monkeypatch):
 cpu,calls,aborts=fake()
 cpu._ahb_observer.observe(command_sample(1,manager_ready=1,hsel=1,htrans=2))
 def reset(self):
  assert self.runtime_events[-1]['kind']=='ahb_reset'
  assert self.runtime_events[-1]['cancelled'] is not None
  return {}
 monkeypatch.setattr(GeneratedNativeMemorySession,'reset_local',reset)
 cpu.reset_local()
 assert cpu._ahb_observer.scope is None


def test_binding_uses_declared_abi_and_rejects_legacy_shape(generated):
 from myfuzz.scenario.ahb_cpu_events import bind_ahb_trace
 artifact,_cpu=generated;doc=artifact.runtime_document
 assert bind_ahb_trace(doc)[0]==doc['base_protocol_traces']['traces'][0]['endpoint_id']
 for broken in ({},dict(doc,protocol_tap_ports=doc['protocol_tap_ports'][:-1])):
  with pytest.raises(ValueError):bind_ahb_trace(broken)
 bad=copy.deepcopy(doc);bad['protocol_tap_ports'][0]['source_wire']='guessed_pin'
 with pytest.raises(ValueError):bind_ahb_trace(bad)
 legacy=copy.deepcopy(doc);legacy.pop('manager_domain')
 with pytest.raises(ValueError,match='manager-domain'):bind_ahb_trace(legacy)
 substituted=copy.deepcopy(doc)
 substituted['manager_domain']['roles']['manager_ready']=copy.deepcopy(
     substituted['manager_domain']['roles']['bus_reset_n'])
 with pytest.raises(ValueError):bind_ahb_trace(substituted)


def test_poisoned_reset_refuses_before_transport(monkeypatch):
 cpu,calls,aborts=fake();cpu._ahb_observer.poison('prior')
 monkeypatch.setattr(GeneratedNativeMemorySession,'reset_local',lambda s:pytest.fail('clocked reset'))
 with pytest.raises(ProtocolEnvironmentError,match='not_active'):cpu.reset_local()


def test_bad_inputs_before_command_has_no_possible_effects():
 cpu,calls,aborts=fake()
 with pytest.raises(ValueError):cpu.step_local({'unexpected':1})
 assert not calls and cpu.runtime_events[-1]['possible_effects'] is False


def test_native_base_noop_preserves_original_step_behavior():
 cpu,calls,aborts=fake()
 # Exercise actual generic step with its default observer, not the AHB override.
 cpu._observe_verified_memory_edge=lambda receipt:GeneratedNativeMemorySession._observe_verified_memory_edge(cpu,receipt)
 before=list(cpu.runtime_events)
 out=GeneratedNativeMemorySession.step_local(cpu,{})
 assert out['data_req_accepted']==0 and cpu.runtime_events==before and len(calls)==1


def test_historical_raw_never_acquires_missing_roles():
 import json
 from myfuzz.scenario.ahb_cpu_events import bind_ahb_trace
 root=Path('docs/reports/evidence/cvw-ahb-source-audit-20261017')
 artifact=json.loads(gzip.decompress((root/'artifact-aadf.json.gz').read_bytes()))
 with pytest.raises(ValueError,match='missing'):bind_ahb_trace(artifact)
 run=json.loads(gzip.decompress((root/'first.json.gz').read_bytes()))
 cpu,calls,aborts=fake();raw=run['cpu_samples'][0]
 cpu.last_samples=(raw,)
 with pytest.raises(KeyError):cpu._observe_verified_memory_edge(None)
 assert set(raw['pre']['physical'])=={'rt_lh_p_2_0_0','rt_lh_p_6_0_0','rt_lh_p_8_0_0'}


def test_actual_command_override_captures_current_return(monkeypatch):
 cpu,calls,aborts=fake()
 returned=SimpleNamespace(payload={'original':'receipt'})
 monkeypatch.setattr(GeneratedNativeMemorySession,'command',lambda s,*a:returned)
 assert GeneratedAhbMemorySession.command(cpu,'STEP_MEMORY',()) is returned
 assert cpu._last_ahb_receipt is returned
