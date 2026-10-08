"""Native POST retirement scope comes from parsed driver receipts, never host step."""
import json
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch
import unittest
from tests.local_harness import test_cpu_native_irq_receipt as irq_tests
from myfuzz.scenario.contracts import ProtocolEnvironmentError

class CpuNativeRetirementReceiptTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):irq_tests.CpuNativeIrqReceiptTests.setUpClass()
 def fixture(self):return irq_tests.CpuNativeIrqReceiptTests()
 def mutate(self,cpu,valid=1):
  def change(payload,irq):
   post=payload['samples'][0]['post']['physical']
   for row in cpu._artifact_document['physical_exports']:
    if row['physical_port'] in ('rvfi_valid','rvfi_order','rvfi_insn','rvfi_pc_rdata'):
     post[row['runtime_name']]={'rvfi_valid':valid,'rvfi_order':1,'rvfi_insn':0x13,'rvfi_pc_rdata':0x1012c}[row['physical_port']]
  return change
 def mutate_serial(self,cpu,*,decision=4,retirement=4):
  def change(payload,irq):
   self.mutate(cpu)(payload,irq)
   post=payload['samples'][0]['post']['physical']
   for row in cpu._artifact_document['physical_exports']:
    if row['physical_port']=='irq_decision_serial':post[row['runtime_name']]=decision
    if row['physical_port']=='irq_retirement_serial':post[row['runtime_name']]=retirement
    if row['physical_port']=='rvfi_intr':post[row['runtime_name']]=1
  return change
 def test_retirement_records_post_serial_token_observation(self):
  helper=self.fixture();cpu=helper.cpu()
  helper.step(cpu,mutation=self.mutate_serial(cpu,decision=4,retirement=4))
  retire=next(e for e in cpu.cpu_events if e['kind']=='cpu_retire')
  observation=retire['irq_serial_observation']
  self.assertEqual(observation['schema_version'],'ibex_irq_serial_observation.v1')
  self.assertEqual(observation['sampling'],'post_rising')
  self.assertEqual(observation['width_bits'],64)
  self.assertEqual(observation['zero_semantics'],'no_provable_source_lineage')
  self.assertEqual(observation['decision'],{'physical_port':'irq_decision_serial','phase':'post','value':4,'status':'observed'})
  self.assertEqual(observation['retirement'],{'physical_port':'irq_retirement_serial','phase':'post','value':4,'status':'observed'})
  self.assertEqual(retire['observation']['physical']['rvfi_intr'],1)
  json.dumps(cpu.cpu_events)
 def test_legacy_artifact_without_serial_exports_records_unobservable_serial(self):
  helper=self.fixture();cpu=helper.cpu()
  cpu._artifact_document['physical_exports']=[row for row in cpu._artifact_document['physical_exports']
   if row['physical_port'] not in ('irq_decision_serial','irq_retirement_serial')]
  helper.step(cpu,mutation=self.mutate(cpu))
  retire=next(e for e in cpu.cpu_events if e['kind']=='cpu_retire')
  observation=retire['irq_serial_observation']
  self.assertEqual(observation['decision'],{'physical_port':'irq_decision_serial','phase':'post','value':None,'status':'unobservable'})
  self.assertEqual(observation['retirement'],{'physical_port':'irq_retirement_serial','phase':'post','value':None,'status':'unobservable'})
  self.assertEqual(observation['sampling'],'post_rising')
 def test_invalid_serial_observation_value_fails_closed(self):
  from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_serial_observation
  for value in (True,-1,1 << 64,'4',4.0):
   with self.subTest(value=value),self.assertRaises(ValueError):
    ibex_irq_serial_observation(sampling='post_rising',decision_value=value,
     retirement_value=0,decision_phase='post',retirement_phase='post')
  helper=self.fixture();cpu=helper.cpu()
  for value in (True,-1,1 << 64,'4',4.0):
   with self.subTest(value=value),self.assertRaises(ProtocolEnvironmentError):
    cpu._serial_observation({'irq_decision_serial':value},{'irq_retirement_serial':0},
     sampling='post_rising',decision_phase='post',retirement_phase='post')
 def test_retirement_matches_exact_sample_receipt_and_complete_post(self):
  helper=self.fixture();cpu=helper.cpu();helper.step(cpu,taken=1,irq_valid=1,mutation=self.mutate(cpu))
  sample=next(e for e in cpu.cpu_events if e['kind']=='cpu_external_irq_sample')
  retire=next(e for e in cpu.cpu_events if e['kind']=='cpu_retire')
  self.assertEqual(retire['schema_version'],'cpu_retire.v2');self.assertEqual(retire['phase'],'post')
  for key in ('receipt_id','receipt_ticks','command_scope','local_tick','observation_contract'):self.assertEqual(retire[key],sample[key])
  self.assertEqual(retire['actual_post_ref'],{'command_scope':retire['command_scope'],'local_tick':retire['local_tick'],'phase':'post'})
  self.assertEqual(retire['observation']['physical']['rvfi_valid'],1)
  self.assertEqual(len(retire['observation']['physical']),44)
 def test_bad_nonce_tick_partial_post_do_not_emit_retirement(self):
  for mode in ('nonce','tick','partial'):
   helper=self.fixture();cpu=helper.cpu()
   def command(op,values):
    receipt=helper.receipt(cpu,values,mutation=self.mutate(cpu))
    if mode=='nonce':return replace(receipt,execution='b'*32)
    if mode=='tick':return replace(receipt,tick_after=True)
    receipt.payload['samples'][0]['post']['physical'].pop(next(row['runtime_name'] for row in cpu._artifact_document['physical_exports'] if row['physical_port']=='rvfi_pc_rdata'))
    return receipt
   with self.subTest(mode=mode),patch.object(cpu,'command',side_effect=command),self.assertRaises(ProtocolEnvironmentError):cpu.step_local({'irq':1})
   self.assertFalse(any(e['kind']=='cpu_retire' for e in cpu.cpu_events))
 def test_no_rvfi_valid_notification_not_retirement_and_legacy_shape(self):
  helper=self.fixture();cpu=helper.cpu();helper.step(cpu,irq_valid=1,mutation=self.mutate(cpu,0))
  self.assertTrue(any(e['kind']=='cpu_irq_notification' for e in cpu.cpu_events));self.assertFalse(any(e['kind']=='cpu_retire' for e in cpu.cpu_events))
  legacy=helper.cpu(False);helper.step(legacy,mutation=self.mutate(legacy))
  event=next(e for e in legacy.cpu_events if e['kind']=='cpu_retire');self.assertNotIn('receipt_id',event);self.assertNotIn('schema_version',event)
 def test_startup_success_is_explicit_and_failure_no_fact(self):
  from myfuzz.local_harness.session import GeneratedLocalSession
  cpu=self.fixture().cpu()
  with patch.object(GeneratedLocalSession,'begin_case',return_value=None):cpu.begin_case('first')
  event=next(e for e in cpu.cpu_events if e['kind']=='cpu_native_startup')
  self.assertIs(event['physical_reset'],True);self.assertEqual(event['boot_base'],65536)
  self.assertEqual(event['artifact_digest'],cpu._artifact_document['artifact_digest'])
  self.assertEqual(event['reset_outcome'],{'schema_version':'native_cpu_reset_outcome.v1','assert_ticks':8,'release_ticks':8,
   'artifact_digest':cpu._artifact_document['artifact_digest'],'boot_base':65536,'source':'startup_ready'})
  self.assertNotIn('initial_csr',event)
  cpu=self.fixture().cpu()
  with patch.object(GeneratedLocalSession,'begin_case',side_effect=TimeoutError()):
   with self.assertRaises(TimeoutError):cpu.begin_case('failed')
  self.assertFalse(cpu.cpu_events)
 def test_v2_contract_is_explicit_and_typed(self):
  from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract,validate_ibex_irq_receipt_contract
  contract=ibex_irq_receipt_contract();self.assertEqual(contract['schema_version'],'ibex_native_irq_receipts.v2')
  contract['retirement_receipt']['rvfi_fields']=True
  with self.assertRaises(ValueError):validate_ibex_irq_receipt_contract(contract)
 def test_direct_wrong_post_phase_nonce_and_missing_receipt_rejected(self):
  helper=self.fixture();cpu=helper.cpu();captured=[]
  def command(op,values):
   receipt=helper.receipt(cpu,values,mutation=self.mutate(cpu));captured.append(receipt);return receipt
  with patch.object(cpu,'command',side_effect=command):cpu.step_local({'irq':1})
  before=cpu._physical_outputs({'observations':captured[0].payload['samples'][0]['pre']})
  after=cpu._physical_outputs({'observations':captured[0].payload['samples'][0]['post']})
  for physical,receipt in ((before,captured[0]),(after,None),(after,replace(captured[0],execution='b'*32))):
   with self.subTest(receipt=receipt is None),self.assertRaises(ProtocolEnvironmentError):cpu._retire(physical,receipt=receipt)
  self.assertEqual(sum(e['kind']=='cpu_retire' for e in cpu.cpu_events),1)
 def test_duplicate_order_is_not_a_new_retirement_receipt(self):
  helper=self.fixture();cpu=helper.cpu()
  helper.step(cpu,mutation=self.mutate(cpu));helper.step(cpu,mutation=self.mutate(cpu))
  retires=[e for e in cpu.cpu_events if e['kind']=='cpu_retire']
  self.assertEqual(len(retires),1);self.assertEqual(retires[0]['receipt_id']['sequence'],1)
 def test_failed_reset_has_no_native_reset_outcome(self):
  from types import SimpleNamespace
  from myfuzz.local_harness.session import GeneratedLocalSession
  cpu=self.fixture().cpu();cpu._process=SimpleNamespace(poll=lambda:None)
  with patch.object(GeneratedLocalSession,'reset_local',side_effect=TimeoutError()):
   with self.assertRaises(TimeoutError):cpu.reset_local()
  self.assertFalse(cpu.cpu_events)
