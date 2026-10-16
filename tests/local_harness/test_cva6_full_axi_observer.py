"""Receipt/service boundary controls without native execution."""
import copy
from types import SimpleNamespace
import pytest
from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
from myfuzz.local_harness.cva6_axi4_fields import CVA6_AXI_WIDTHS,CVA6_AXI_STEP_PORTS
from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.contracts import ProtocolEnvironmentError


def fake():
 cpu=object.__new__(GeneratedCva6Axi4Session)
 cpu.source_component='renamed';cpu._execution='exec';cpu._case_id='case';cpu.reset_epoch=0
 cpu.memory=PersistentMemory(regions=(MemoryRegion('ram',0,8192),),initialization_seed=0,max_initialized_bytes=8192)
 cpu.service=MemoryService(cpu.memory,TransactionLedger());cpu.mmio_ledger=TransactionLedger()
 cpu.router=None;cpu.defer_mmio=False
 cpu.read_beats=cpu.write_beats=cpu.read_bursts=cpu.write_bursts=0
 cpu._clear();calls=[]
 def edge(**values):
  def command(operation,fields):
   calls.append(operation)
   row={'axi_'+r:0 for r in CVA6_AXI_WIDTHS}
   row.update({k:v for k,v in zip(CVA6_AXI_STEP_PORTS,fields) if k.startswith('axi_')})
   row.update({'axi_'+r:v for r,v in values.items()})
   return SimpleNamespace(status='ok',new_ticks=1,payload=dict(kind=cpu.artifact_kind,pre_backend=row,samples=[dict(local_tick=len(calls),pre=dict(backend=row),post=dict(backend=copy.deepcopy(row)))],observations=dict(physical={})))
  cpu.command=command
  return cpu.step_local({})
 return cpu,edge,calls


def test_session_exposes_measured_edge_and_blocks_poisoned_native_retry():
 cpu,edge,calls=fake();edge(arvalid=1,araddr=0x100,arsize=3,arburst=1,arid=12)
 stream=cpu.runtime_events
 assert stream[-1]['kind']=='full_axi_accept' and stream[-2]['raw_sample']==cpu.last_samples[0]
 with pytest.raises(ProtocolEnvironmentError,match='last'):
  edge(awvalid=1,awaddr=0x200,awsize=3,awburst=1,wvalid=1,wlast=0)
 count=len(calls)
 with pytest.raises(ProtocolEnvironmentError,match='not_active'):edge()
 assert len(calls)==count and cpu.runtime_events is stream


def test_service_failure_keeps_raw_edge_then_poison_before_next_ready_inputs():
 cpu,edge,calls=fake()
 def fail():raise ProtocolEnvironmentError('target failed after possible effect')
 cpu._commit_writes=fail
 with pytest.raises(ProtocolEnvironmentError,match='target failed'):edge(arvalid=1,arsize=3,arburst=1)
 assert any(e['kind']=='full_axi_raw' for e in cpu.runtime_events)
 assert cpu.runtime_events[-1]['category']=='diagnostic_unknown'
 assert cpu.runtime_events[-1]['possible_effects'] is True
 count=len(calls)
 with pytest.raises(ProtocolEnvironmentError,match='not_active'):edge()
 assert len(calls)==count


def test_untrusted_pre_receipt_is_diagnostic_without_projection():
 cpu,edge,calls=fake()
 with pytest.raises(ProtocolEnvironmentError,match='backend observation'):
  edge(arready=0)
 assert not any(e['kind']=='full_axi_raw' for e in cpu.runtime_events)
 assert cpu.runtime_events[-1]['trusted_projection'] is False
 assert cpu.runtime_events[-1]['diagnostic_receipt']['payload']['pre_backend']['axi_arready']==0
 count=len(calls)
 with pytest.raises(ProtocolEnvironmentError,match='not_active'):edge()
 assert len(calls)==count


def test_session_reset_cancels_observer_before_base_reset(monkeypatch):
 from myfuzz.local_harness.session import GeneratedLocalSession
 cpu,edge,calls=fake();edge(arvalid=1,arsize=3,arburst=1,wvalid=1,wlast=1)
 stream=cpu.runtime_events
 def base_reset(session):
  assert session.runtime_events is stream
  assert stream[-1]['kind']=='full_axi_reset'
  assert stream[-1]['cancelled']['read_beats_remaining']==1
  assert stream[-1]['cancelled']['buffered_wbeats']==1
  return {}
 monkeypatch.setattr(GeneratedLocalSession,'reset_local',base_reset)
 cpu.reset_local()
 assert cpu.runtime_events is stream and cpu._axi_observer.scope is None


@pytest.mark.parametrize('error',[OSError('target IO failed'),TypeError('target callback failed'),AttributeError('malformed receipt')])
def test_all_operational_failures_poison_before_native_retry(error):
 cpu,edge,calls=fake()
 def fail():raise error
 cpu._commit_writes=fail
 with pytest.raises(type(error)):edge()
 assert cpu.runtime_events[-1]['kind']=='full_axi_failure'
 assert cpu.runtime_events[-1]['trusted_projection'] is False
 count=len(calls)
 with pytest.raises(ProtocolEnvironmentError,match='not_active'):edge()
 assert len(calls)==count


@pytest.mark.parametrize('malformed',[None,{'pre':None}])
def test_malformed_receipt_objects_poison_without_trusted_projection(malformed):
 cpu,edge,calls=fake();edge()
 command=cpu.command
 def bad(*args):
  receipt=command(*args);receipt.payload['samples'][0]=malformed
  return receipt
 cpu.command=bad
 with pytest.raises(AttributeError):cpu.step_local({})
 assert sum(e['kind']=='full_axi_raw' for e in cpu.runtime_events)==1
 assert cpu.runtime_events[-1]['category']=='diagnostic_unknown'
 assert cpu.runtime_events[-1]['diagnostic_receipt']['payload']['samples']==[malformed]
 count=len(calls)
 with pytest.raises(ProtocolEnvironmentError,match='not_active'):cpu.step_local({})
 assert len(calls)==count
