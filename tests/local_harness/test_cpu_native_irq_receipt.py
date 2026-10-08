"""Native external input/taken receipts require actual complete CPU snapshots."""
import json
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
from myfuzz.scenario.router import DataflowRouter,DeviceWindow
from tests.local_harness.test_cpu_session import Target,NAMES
from tests.local_harness.test_renderer import ROOT

class CpuNativeIrqReceiptTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  from myfuzz.scenario.ibex_pulp_dual_source import _artifact
  cls.artifact=_artifact('configs/cpus/ibex_rvfi_local/component_profile.json','cpu')

 def cpu(self, enabled=True):
  memory=PersistentMemory(regions=(MemoryRegion('ram',0,0x30000),),initialization_seed=3,max_initialized_bytes=0x30000)
  cpu=GeneratedCve2Session(self.artifact,base_dir=ROOT,cache_dir=Path('/tmp/native-irq-unused'),memory=memory,
   router=DataflowRouter((DeviceWindow('target',0x40000000,0x1000,Target()),)),native_irq_receipts=enabled)
  cpu._case_id='stream';cpu._execution='a'*32;return cpu

 def context(self, epoch=0, event=7, expected=1):
  return dict(schema_version='native_irq_input_context.v1',binding_delivery_event_id=event,expected_input=expected,
   source_output_key=['uart',0,'rx_watermark',1],target_component='cpu',target_epoch=epoch)

 def receipt(self,cpu,values,*,taken=0,masked=0,irq_valid=0,mutation=None):
  physical={row['runtime_name']:('0'*row['hex_digits'] if row['width']>64 else 0)
   for row in cpu._artifact_document['physical_exports']}
  irq=next(row['runtime_name'] for row in cpu._artifact_document['physical_exports'] if row['physical_port']=='irq_external_i')
  physical[irq]=values[0];physical['probe_irq_taken_pre']=taken;physical['probe_irq_masked_pre']=masked
  post=deepcopy(physical)
  notification=next(row['runtime_name'] for row in cpu._artifact_document['physical_exports'] if row['physical_port']=='rvfi_ext_irq_valid')
  post[notification]=irq_valid
  pre=dict.fromkeys(NAMES,0);pre.update(zip(('i_req_ready','i_rsp_valid','i_rsp_rdata','i_rsp_error','d_req_ready','d_rsp_valid','d_rsp_rdata','d_rsp_error'),values[1:]))
  tick=cpu.local_ticks-cpu._tick_base+1;sequence=cpu._sequence+1
  payload=dict(kind='obi_cpu',samples=[dict(local_tick=tick,pre={'backend':pre,'physical':physical},post={'backend':pre,'physical':post})],
   pre_backend=pre,observations={'backend':pre,'physical':post},rdata=0,error=0)
  if mutation:mutation(payload,irq)
  receipt=DriverReceipt('result',cpu._execution,sequence,tick-1,tick,1,payload)
  cpu._sequence=sequence;cpu.local_ticks=cpu._tick_base+tick;return receipt

 def step(self,cpu,*,irq=1,**kwargs):
  with patch.object(cpu,'command',side_effect=lambda op,values:self.receipt(cpu,values,**kwargs)):
   return cpu.step_local({'irq':irq})

 def test_optin_requires_boolean_and_rvfi_and_contract_is_strict(self):
  from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract,validate_ibex_irq_receipt_contract
  for value in (1,0,1.0,None,'yes'):
   with self.subTest(value=value),self.assertRaises(ValueError):self.cpu(value)
  identity=self.cpu().identity_document();self.assertEqual(identity['cpu_native_irq_receipt_contract'],ibex_irq_receipt_contract())
  self.assertNotIn('cpu_native_irq_receipt_contract',self.cpu(False).identity_document())
  changed=ibex_irq_receipt_contract();changed['input_width']=1.0
  with self.assertRaises(ValueError):validate_ibex_irq_receipt_contract(changed)

 def test_real_input_take_and_notification_without_retirement(self):
  cpu=self.cpu();context=self.context();cpu.set_next_irq_input_context(context);context['expected_input']=0
  self.step(cpu,taken=1,irq_valid=1)
  sample=next(e for e in cpu.cpu_events if e['kind']=='cpu_external_irq_sample')
  taken=next(e for e in cpu.cpu_events if e['kind']=='cpu_external_irq_taken')
  notice=next(e for e in cpu.cpu_events if e['kind']=='cpu_irq_notification')
  self.assertEqual((sample['expected_input'],sample['actual_pre_input'],sample['actual_post_input']),(1,1,1))
  self.assertEqual(sample['binding_delivery_event_id'],7)
  self.assertEqual(sample['receipt_id'],{'execution':'a'*32,'sequence':1})
  self.assertEqual(taken['sample_ref'],{'command_scope':sample['command_scope'],'local_tick':sample['local_tick']})
  self.assertEqual(taken['take_key'],['cpu',0,1])
  self.assertEqual(notice['rvfi_ext_irq_valid'],1);self.assertEqual(notice['rvfi_valid'],0)
  self.assertFalse(any(e['kind']=='cpu_retire' for e in cpu.cpu_events))
  self.step(cpu,irq=0)
  self.assertNotIn('binding_delivery_event_id',cpu.cpu_events[-1]);self.assertIsNone(cpu.cpu_events[-1]['input_context'])

 def test_wrong_physical_pre_post_type_or_incomplete_reply_emits_no_irq(self):
  for mutation in ('pre','post','bool','float','missing','incomplete'):
   cpu=self.cpu();cpu.set_next_irq_input_context(self.context())
   def change(payload,irq):
    if mutation=='incomplete':payload['samples']=[]
    elif mutation=='missing':payload['samples'][0]['pre']['physical'].pop(irq)
    else:payload['samples'][0]['post' if mutation=='post' else 'pre']['physical'][irq]=True if mutation=='bool' else 1.0 if mutation=='float' else 0
   with self.subTest(mutation=mutation),self.assertRaises(ProtocolEnvironmentError):self.step(cpu,taken=1,mutation=change)
   self.assertFalse(cpu.cpu_events);self.assertIsNone(cpu._next_irq_input_context)

 def test_context_none_overwrite_error_finally_and_unknown_input(self):
  cpu=self.cpu();cpu.set_next_irq_input_context(self.context(event=7));cpu.set_next_irq_input_context(self.context(event=8))
  self.step(cpu);self.assertEqual(cpu.cpu_events[-1]['binding_delivery_event_id'],8)
  cpu.set_next_irq_input_context(self.context());cpu.set_next_irq_input_context(None)
  self.step(cpu);self.assertNotIn('binding_delivery_event_id',cpu.cpu_events[-1])
  cpu.set_next_irq_input_context(self.context())
  with patch.object(cpu,'command',side_effect=TimeoutError('incomplete')):
   with self.assertRaises(TimeoutError):cpu.step_local({'irq':1})
  self.assertIsNone(cpu._next_irq_input_context)

 def test_context_and_receipt_identity_types_fail_closed(self):
  for field,value in [('target_epoch',True),('expected_input',1.0),('binding_delivery_event_id',True),('target_component','other')]:
   cpu=self.cpu();context=self.context();context[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):cpu.set_next_irq_input_context(context)
  cpu=self.cpu();cpu.set_next_irq_input_context(self.context())
  with patch.object(cpu,'command',return_value=DriverReceipt('result','a'*32,True,0,1,1,{})):
   with self.assertRaises(ProtocolEnvironmentError):cpu.step_local({'irq':1})
  self.assertFalse(cpu.cpu_events);self.assertIsNone(cpu._next_irq_input_context)

 def test_receipt_events_carry_phase_explicit_serial_observation(self):
  cpu=self.cpu()
  names={row['physical_port']:row['runtime_name'] for row in cpu._artifact_document['physical_exports']}
  def mutation(payload,irq):
   pre=payload['samples'][0]['pre']['physical'];post=payload['samples'][0]['post']['physical']
   pre[names['irq_decision_serial']]=4;pre[names['irq_retirement_serial']]=0
   post[names['irq_decision_serial']]=0;post[names['irq_retirement_serial']]=4
  self.step(cpu,taken=1,irq_valid=1,mutation=mutation)
  sample=next(e for e in cpu.cpu_events if e['kind']=='cpu_external_irq_sample')
  taken=next(e for e in cpu.cpu_events if e['kind']=='cpu_external_irq_taken')
  observation=sample['irq_serial_observation']
  self.assertEqual(observation['schema_version'],'ibex_irq_serial_observation.v1')
  self.assertEqual(observation['sampling'],'pre_post_rising')
  self.assertEqual(observation['zero_semantics'],'no_provable_source_lineage')
  self.assertEqual(observation['decision'],{'physical_port':'irq_decision_serial','phase':'pre','value':4,'status':'observed'})
  self.assertEqual(observation['retirement'],{'physical_port':'irq_retirement_serial','phase':'post','value':4,'status':'observed'})
  self.assertEqual(taken['irq_serial_observation'],observation)
  json.dumps(cpu.cpu_events)

 def test_legacy_artifact_without_serial_exports_records_unobservable_serial(self):
  cpu=self.cpu()
  cpu._artifact_document['physical_exports']=[row for row in cpu._artifact_document['physical_exports']
   if row['physical_port'] not in ('irq_decision_serial','irq_retirement_serial')]
  self.step(cpu,taken=1,irq_valid=1)
  sample=next(e for e in cpu.cpu_events if e['kind']=='cpu_external_irq_sample')
  observation=sample['irq_serial_observation']
  self.assertEqual(observation['decision'],{'physical_port':'irq_decision_serial','phase':'pre','value':None,'status':'unobservable'})
  self.assertEqual(observation['retirement'],{'physical_port':'irq_retirement_serial','phase':'post','value':None,'status':'unobservable'})

 def test_masked_not_taken_and_legacy_mode_emit_no_take(self):
  cpu=self.cpu();self.step(cpu,masked=1,taken=0)
  self.assertEqual([e['kind'] for e in cpu.cpu_events],['cpu_external_irq_sample'])
  legacy=self.cpu(False);self.step(legacy,taken=1,irq_valid=1)
  self.assertFalse(legacy.cpu_events)

 def test_duplicate_parsed_receipt_cannot_emit_second_take(self):
  cpu=self.cpu();self.step(cpu,taken=1);last_count=len(cpu.cpu_events)
  def duplicate(op,values):
   cpu._sequence-=1;cpu.local_ticks-=1
   return self.receipt(cpu,values,taken=1)
  with patch.object(cpu,'command',side_effect=duplicate),self.assertRaises(ProtocolEnvironmentError):
   cpu.step_local({'irq':1})
  self.assertEqual(len(cpu.cpu_events),last_count)

 def test_non_rvfi_artifact_cannot_select_native_receipts(self):
  from dataclasses import replace
  artifact=deepcopy(self.artifact)
  artifact=replace(artifact,plan=replace(artifact.plan,profile=replace(artifact.plan.profile,component_id='ibex_obi_local')))
  memory=PersistentMemory(regions=(MemoryRegion('ram',0,0x30000),),initialization_seed=3,max_initialized_bytes=0x30000)
  with self.assertRaises(ValueError):GeneratedCve2Session(artifact,base_dir=ROOT,cache_dir=Path('/tmp/native-irq-unused'),memory=memory,
   router=DataflowRouter((DeviceWindow('target',0x40000000,0x1000,Target()),)),native_irq_receipts=True)

 def test_new_cpu_identity_requires_exact_contract_and_artifact(self):
  from myfuzz.scenario.contracts import _verify_generated_session
  identity=self.cpu().identity_document()
  _verify_generated_session(identity)
  changed=deepcopy(identity);changed['cpu_native_irq_receipt_contract']['input_width']=True
  with self.assertRaises(ValueError):_verify_generated_session(changed)
  changed=deepcopy(identity);changed['runtime_artifact']['physical_exports'][0]['width']=float(changed['runtime_artifact']['physical_exports'][0]['width'])
  with self.assertRaises(ValueError):_verify_generated_session(changed)

 def test_source_epoch_and_reset_clear_native_context(self):
  from types import SimpleNamespace
  from myfuzz.local_harness.session import GeneratedLocalSession
  cpu=self.cpu();cpu.reset_epoch=7;cpu.set_next_irq_input_context(self.context(epoch=7))
  self.step(cpu,taken=1)
  self.assertTrue(all(e['source_epoch']==7 for e in cpu.cpu_events))
  self.assertEqual(cpu.cpu_events[0]['command_scope']['reset_epoch'],7)
  cpu.set_next_irq_input_context(self.context(epoch=7));cpu._process=SimpleNamespace(poll=lambda:None)
  with patch.object(GeneratedLocalSession,'reset_local',side_effect=lambda:setattr(cpu,'reset_epoch',8)):
   cpu.reset_local()
  self.assertIsNone(cpu._next_irq_input_context);self.assertIsNone(cpu._native_irq_last_receipt)
  with self.assertRaises(ValueError):cpu.set_next_irq_input_context(self.context(epoch=7))

 def test_wrong_nonce_after_full_transport_shape_cannot_emit(self):
  from dataclasses import replace
  cpu=self.cpu();cpu.set_next_irq_input_context(self.context())
  def wrong_nonce(op,values):return replace(self.receipt(cpu,values,taken=1),execution='b'*32)
  with patch.object(cpu,'command',side_effect=wrong_nonce),self.assertRaises(ProtocolEnvironmentError):
   cpu.step_local({'irq':1})
  self.assertFalse(cpu.cpu_events);self.assertIsNone(cpu._next_irq_input_context)

 def test_native_reset_success_is_physical_and_failure_has_no_fact(self):
  from myfuzz.local_harness.session import GeneratedLocalSession
  from types import SimpleNamespace
  cpu=self.cpu();cpu._process=SimpleNamespace(poll=lambda:None)
  with patch.object(GeneratedLocalSession,'reset_local',return_value={'measured':'reset'}):cpu.reset_local()
  self.assertIs(cpu.cpu_events[-1]['physical_reset'],True)
  self.assertEqual(cpu.cpu_events[-1]['local_tick'],cpu.local_ticks)
  cpu.cpu_events.clear()
  with patch.object(GeneratedLocalSession,'reset_local',side_effect=TimeoutError()):
   with self.assertRaises(TimeoutError):cpu.reset_local()
  self.assertFalse(cpu.cpu_events)

 def test_native_fresh_process_success_fact_and_failure_no_fact(self):
  from myfuzz.local_harness.session import GeneratedLocalSession
  cpu=self.cpu();cpu._started_cpu=True
  with patch.object(GeneratedLocalSession,'begin_case',return_value=None):cpu.begin_case('next')
  self.assertIs(cpu.cpu_events[-1]['physical_reset'],True)
  self.assertEqual(cpu.cpu_events[-1]['reason'],'fresh_process')
  cpu.cpu_events.clear()
  with patch.object(GeneratedLocalSession,'begin_case',side_effect=TimeoutError()):
   with self.assertRaises(TimeoutError):cpu.begin_case('failed')
  self.assertFalse(cpu.cpu_events)
  legacy=self.cpu(False);legacy._started_cpu=True
  with patch.object(GeneratedLocalSession,'begin_case',return_value=None):legacy.begin_case('legacy')
  self.assertNotIn('physical_reset',legacy.cpu_events[-1])
