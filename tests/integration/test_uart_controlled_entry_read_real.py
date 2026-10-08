"""New v2 controlled entry/read gate; never upgrades a saved v1 prefix."""
from copy import deepcopy
import json
import os
from pathlib import Path
import unittest
from tests.integration import test_uart_native_irq_taken_real as native_fixture

SCOPES={'cpu_external_irq_taken','controlled_uart_external_irq_entry','cpu_retired_uart_rdata_read'}
_ENVELOPE={'event_id','producer_event_id','provenance','registered_origins','_known_fuzz_origin'}

def _assert_complete_controlled_scopes(testcase,events):
    for event in events:
        if event.get('status')=='incomplete' or 'certainty_barrier' in str(event.get('kind','')):
            testcase.fail('incomplete/barrier event_id={} kind={} reason={}'.format(
                event.get('event_id'),event.get('kind'),event.get('reason')))
    for scope in sorted(SCOPES):
        count=sum(event.get('status')=='accepted' and event.get('proof_scope')==scope
                  for event in events)
        testcase.assertEqual(count,4,scope)

def _certificate_matches(observed,reconstructed):
    return (set(observed)<=set(reconstructed)|_ENVELOPE and
        all(k in observed and native_fixture._wire_bytes(observed[k])==native_fixture._wire_bytes(v)
            for k,v in reconstructed.items()))

def _controlled_registry(manifest,events):
    from myfuzz.scenario.ibex_uart_online import make_ibex_uart_online_bootstrap
    from myfuzz.scenario.uart_irq_entry import ControlledUartBootstrapRegistry
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    configuration=manifest['runner']['controlled_uart_bootstrap_configuration']
    bootstrap=make_ibex_uart_online_bootstrap(instruction_start=configuration['instruction_start'],
        instruction_end=configuration['instruction_end'])
    fields=('image_id','event_id','component','address','data_hex','memory_id','generation','byte_offset')
    images=[{k:e[k] for k in fields} for e in events if e.get('kind')=='initial_image'
        and e.get('image_id') in ('cpu.main','cpu.isr')]
    registry=ControlledUartBootstrapRegistry.from_bootstrap(bootstrap,component='cpu',
        memory_metadata={'images':images},runtime_artifact=manifest['runner']['sessions']['cpu']['identity']['runtime_artifact'],
        observation_contract=ibex_irq_receipt_contract())
    if native_fixture._wire_bytes(registry.get('cpu')['configuration'])!=native_fixture._wire_bytes(configuration):
        raise ValueError('saved controlled bootstrap configuration differs')
    registrations=[e for e in events if e.get('kind')=='controlled_uart_bootstrap_registration']
    if (len(registrations)!=1 or native_fixture._wire_bytes(registrations[0]['registry'])!=native_fixture._wire_bytes(registry.document())
            or registrations[0]['event_id']<=max(e['event_id'] for e in images)):
        raise ValueError('actual controlled image registration missing or altered')
    return registry

@unittest.skipUnless(os.environ.get('MYFUZZ_UART_CONTROLLED_ENTRY_READ_REAL')=='1',
    'requires new frozen-source v2 controlled entry/read run')
class UartControlledEntryReadRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from myfuzz.integration.ibex_uart_online import _read_uart_online_trace
        from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
        output=os.environ.get('MYFUZZ_UART_CONTROLLED_ENTRY_READ_RUN_DIR')
        if not output:raise ValueError('MYFUZZ_UART_CONTROLLED_ENTRY_READ_RUN_DIR required')
        cls.output=Path(output).resolve();cls.plan_path=cls.output/'online_plan.json';cls.trace_path=cls.output/'online_final_trace.json'
        cls.trace=_read_uart_online_trace(cls.trace_path)
        _verify_online_run_identity(cls.output,plan_path=cls.plan_path,trace_path=cls.trace_path,trace=cls.trace)
        cls.plan=json.loads(cls.plan_path.read_bytes());cls.manifest=json.loads((cls.output/'online_session_manifest.json').read_bytes())
        cls.events=list(cls.trace.events);cls.by_id={e['event_id']:e for e in cls.events}
        contract=cls.manifest['runner']['sessions']['cpu']['identity'].get('cpu_native_irq_receipt_contract',{})
        if contract.get('schema_version')!='ibex_native_irq_receipts.v2':raise ValueError('old observer prefix cannot certify v2 entry/read')
        cls.index=native_fixture._verified_saved_native_index(cls.plan,cls.manifest)
        cls.registry=_controlled_registry(cls.manifest,cls.events)

    def models(self,mutation=None,trust_bootstrap=True,return_all=False):
        from myfuzz.scenario.source_provenance import AdmissionRegistry
        from myfuzz.scenario.ownership import compile_ownership,InputField,InputOwner
        from myfuzz.scenario.uart_consumption import UartConsumptionTracker
        from myfuzz.scenario.uart_irq_consumption import UartNativeIrqJoin
        from myfuzz.scenario.uart_irq_entry import UartControlledIrqEntryJoin
        from myfuzz.scenario.uart_retired_read import UartRetiredReadLinker
        authority=self.manifest['runner']['ownership']
        owner=compile_ownership(tuple(InputField(**x) for x in authority['fields']),tuple(InputOwner(**x) for x in authority['owners']))
        args=dict(admission_registry=AdmissionRegistry.from_document(self.plan['source_admissions']),ownership=owner,edge_index=self.index)
        fifo=UartConsumptionTracker(**args);native=UartNativeIrqJoin(**args);read=UartRetiredReadLinker(**args)
        entry=UartControlledIrqEntryJoin(bootstrap_registry=self.registry if trust_bootstrap else None)
        fifo_certificates=[];native_certificates=[];reports=[]
        fifo_kinds={'uart_tick_observation','uart_frame_validation','uart_rdata_access','uart_reset'}
        native_kinds=fifo_kinds|{'uart_irq_update','native_irq_binding_delivery','cpu_external_irq_sample','cpu_external_irq_taken','cpu_reset'}
        entry_kinds={'cpu_native_startup','cpu_reset','cpu_external_irq_sample','cpu_external_irq_taken','cpu_irq_notification','cpu_retire','instr_response'}
        read_kinds=fifo_kinds|{'instr_response','data_accept','data_response','cpu_retire','cpu_retirement_match','cpu_reset','cpu_flush'}
        for original in self.events:
            event=deepcopy(original)
            if mutation:
                event=mutation(event)
                if event is None:continue
            kind=event.get('kind')
            if kind in fifo_kinds:
                fifo_certificates.extend(r for r in fifo.consume(event) if r.get('status')=='accepted')
            if kind=='uart_consumption_match':
                scope=event.get('proof_scope')
                if event.get('status')=='accepted' and scope in ('uart_fifo_retention','uart_fifo_read_consumption'):
                    matched=next((r for r in fifo_certificates if _certificate_matches(event,r)),None)
                    if matched is None:continue
                    fifo_certificates.remove(matched)
                    if scope=='uart_fifo_retention':
                        generated=native.consume(event);native_certificates.extend(r for r in generated if r.get('status')=='accepted');reports.extend(generated)
                    reports.extend(read.consume(event))
                elif event.get('status')=='accepted' and scope=='cpu_external_irq_taken':
                    matched=next((r for r in native_certificates if _certificate_matches(event,r)),None)
                    if matched is not None:
                        native_certificates.remove(matched);reports.extend(entry.consume(event))
                elif event.get('status')=='incomplete' and str(event.get('reason','')).startswith('uart_'):
                    reports.extend(native.consume(event));reports.extend(read.consume(event))
                continue
            if kind in native_kinds:
                generated=native.consume(event);native_certificates.extend(r for r in generated if r.get('status')=='accepted');reports.extend(generated)
            if kind in entry_kinds:reports.extend(entry.consume(event))
            if kind in read_kinds:reports.extend(read.consume(event))
        if return_all:return reports
        return [r for r in reports if r.get('status')=='accepted' and r.get('proof_scope') in SCOPES]

    def test_actual_saved_and_reconstructed_scopes_with_original_roles(self):
        _assert_complete_controlled_scopes(self,self.events)
        reports=self.models(return_all=True)
        _assert_complete_controlled_scopes(self,reports)
        reconstructed=[r for r in reports if r.get('status')=='accepted' and r.get('proof_scope') in SCOPES]
        for scope in SCOPES:
            saved=[e for e in self.events if e.get('status')=='accepted' and e.get('proof_scope')==scope]
            actual=[r for r in reconstructed if r.get('proof_scope')==scope]
            self.assertEqual(len(saved),4,scope);self.assertEqual(len(actual),4,scope)
            for proof in saved:self.assertTrue(any(_certificate_matches(proof,r) for r in actual),scope)
        for proof in reconstructed:
            self.assertEqual(proof['generic_isr_origin'],'unknown');self.assertEqual(proof['operand_origin'],'unknown')
        entries=[r for r in reconstructed if r.get('proof_scope')=='controlled_uart_external_irq_entry']
        roles={a['role'] for p in entries for a in p['source_admissions']}
        self.assertTrue({'bootstrap','fuzz_source'}<=roles,roles)
        for p in entries:
            self.assertEqual(p['entry_scope'],'controlled_bootstrap_external_irq')
            self.assertEqual(self.by_id[p['first_retirement_event_id']]['pc_rdata'],p['entry_pc'])
            self.assertEqual(p['bootstrap_certificate_id'],self.registry.get('cpu')['certificate_id'])
            self.assertEqual(self.by_id[p['instruction_response_event_id']]['snapshot']['writer_kinds'],['INITIAL_IMAGE']*4)

    def test_fresh_entire_wire_prefix_equal(self):
        from myfuzz.integration.ibex_uart_online import replay_ibex_uart_online_files
        cache=Path(os.environ.get('MYFUZZ_UART_CONTROLLED_ENTRY_READ_CACHE_DIR',str(self.output.parent/(self.output.name+'-cache'))))
        result=replay_ibex_uart_online_files(cache_dir=cache,plan_path=self.plan_path,trace_path=self.trace_path)
        self.assertTrue(result.matches,result.difference_context);self.assertIsNone(result.first_difference)
        native_fixture._assert_full_wire_prefix(self,result.actual_trace.events,self.events)
        self.assertTrue(native_fixture._wire_bytes(result.actual_trace.local_ticks)==native_fixture._wire_bytes(self.trace.local_ticks))
        print(json.dumps({'controlled_entry_read_fresh_matches':True,'first_difference':None,'verification_scope':'full_wire_prefix','events':len(self.events)},sort_keys=True),flush=True)

    def test_required_witness_deletions_do_not_promote(self):
        for kind,scopes in (
            ('cpu_native_startup',{'controlled_uart_external_irq_entry'}),
            ('instr_response',{'controlled_uart_external_irq_entry','cpu_retired_uart_rdata_read'}),
            ('cpu_retire',{'controlled_uart_external_irq_entry','cpu_retired_uart_rdata_read'}),
            ('cpu_external_irq_sample',{'cpu_external_irq_taken','controlled_uart_external_irq_entry'}),
            ('native_irq_binding_delivery',{'cpu_external_irq_taken','controlled_uart_external_irq_entry'}),
            ('uart_frame_validation',SCOPES),
            ('uart_rdata_access',{'cpu_retired_uart_rdata_read'}),
            ('cpu_retirement_match',{'cpu_retired_uart_rdata_read'}),
        ):
            with self.subTest(witness=kind):
                reports=self.models(lambda e:None if e.get('kind')==kind else e)
                self.assertFalse(any(r['proof_scope'] in scopes for r in reports),kind)
        self.assertFalse(any(r['proof_scope']=='controlled_uart_external_irq_entry' for r in self.models(trust_bootstrap=False)))

    def test_selfsigned_certificate_and_missing_post_reference_rejected(self):
        def selfsigned(e):
            if e.get('status')=='accepted' and e.get('proof_scope')=='cpu_external_irq_taken':e['cpu_take_event_id']='self-signed'
            return e
        self.assertFalse(any(r['proof_scope']=='controlled_uart_external_irq_entry' for r in self.models(selfsigned)))
        def no_post(e):
            if e.get('kind')=='cpu_retire':e.pop('actual_post_ref',None)
            return e
        self.assertFalse(any(r['proof_scope'] in {'controlled_uart_external_irq_entry','cpu_retired_uart_rdata_read'} for r in self.models(no_post)))
        events=deepcopy(self.events)
        next(e for e in events if e.get('kind')=='controlled_uart_bootstrap_registration')['registry']['certificates'][0]['certificate_id']='self-signed'
        with self.assertRaises(ValueError):_controlled_registry(self.manifest,events)

class ControlledEntryReadWireHelpers(unittest.TestCase):
    @staticmethod
    def complete_reports():
        return [dict(status='accepted',proof_scope=scope,event_id=index)
                for index,scope in enumerate(sorted(SCOPES)*4)]

    def test_complete_scopes_require_four_each(self):
        reports=self.complete_reports()
        _assert_complete_controlled_scopes(self,reports)
        missing=next(r for r in reports if r['proof_scope']=='cpu_retired_uart_rdata_read')
        with self.assertRaisesRegex(AssertionError,'cpu_retired_uart_rdata_read'):
            _assert_complete_controlled_scopes(self,[r for r in reports if r is not missing])

    def test_complete_scopes_reject_incomplete_even_with_four_each(self):
        reports=self.complete_reports()+[dict(status='incomplete',event_id=99,
            kind='uart_retired_read_match',reason='raw_cpu_certainty_barrier')]
        with self.assertRaisesRegex(AssertionError,'99.*raw_cpu_certainty_barrier'):
            _assert_complete_controlled_scopes(self,reports)

    def test_complete_scopes_reject_barrier_without_incomplete_status(self):
        reports=self.complete_reports()+[dict(event_id=100,kind='cpu_certainty_barrier',
            reason='instruction_capacity_exceeded')]
        with self.assertRaisesRegex(AssertionError,'100.*instruction_capacity_exceeded'):
            _assert_complete_controlled_scopes(self,reports)

    def test_certificate_core_is_typed_and_envelope_cannot_selfsign(self):
        raw={'status':'accepted','proof_scope':'x','value':1}
        self.assertTrue(_certificate_matches(dict(raw,event_id=7),raw))
        for value in (True,1.0):self.assertFalse(_certificate_matches(dict(raw,value=value),raw))
        self.assertFalse(_certificate_matches({'status':'accepted','event_id':7},raw))
        self.assertFalse(_certificate_matches(dict(raw,forged=True),raw))
