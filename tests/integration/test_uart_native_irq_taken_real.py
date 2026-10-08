"""New saved native run and full fresh replay; root enables after source freeze.

Historical FIFO-only traces cannot satisfy this fixture. No handler/operand claim.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import unittest

def _wire_bytes(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def _assert_full_wire_prefix(testcase, actual, expected):
    testcase.assertEqual(len(actual),len(expected),'full wire prefix event count differs')
    for index,(left,right) in enumerate(zip(actual,expected)):
        if _wire_bytes(left)!=_wire_bytes(right):
            testcase.fail(f"full wire prefix differs: index={index} event_id={right.get('event_id')}")

def _verified_saved_native_index(plan, manifest):
    """Rebuild exact compiled authority already bound by the verified envelope."""
    from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
    def canonical(value):
        return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    try:
        paths=plan['runtime_paths']
        if canonical(paths)!=canonical(manifest['runtime_paths']):
            raise ValueError('saved native runtime path identity mismatch')
        subject=RuntimeEdgeIndex(paths,paths['declaration']['contract'])
        expected={'schema_version':'source_provenance_configuration.v1',
            'edge_index':subject.document(),'edge_index_sha256':subject.identity_sha256}
        if any(canonical(document['provenance_configuration'])!=canonical(expected)
               for document in (plan,manifest)):
            raise ValueError('saved native compiled index identity mismatch')
        return subject
    except (KeyError,TypeError,ValueError) as exc:
        raise ValueError('invalid saved native compiled index') from exc

@unittest.skipUnless(os.environ.get('MYFUZZ_UART_NATIVE_IRQ_REAL') == '1',
    'requires coordinated native source freeze and new saved native run')
class UartNativeIrqTakenRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from myfuzz.integration.ibex_uart_online import _read_uart_online_trace
        from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
        directory=os.environ.get('MYFUZZ_UART_NATIVE_IRQ_RUN_DIR')
        if not directory:raise ValueError('MYFUZZ_UART_NATIVE_IRQ_RUN_DIR must name the new native gate')
        cls.output=Path(directory).resolve();cls.plan_path=cls.output/'online_plan.json'
        cls.trace_path=cls.output/'online_final_trace.json'
        cls.trace=_read_uart_online_trace(cls.trace_path)
        cls.verified=_verify_online_run_identity(cls.output,plan_path=cls.plan_path,
            trace_path=cls.trace_path,trace=cls.trace)
        cls.plan=json.loads(cls.plan_path.read_bytes())
        cls.manifest=json.loads((cls.output/'online_session_manifest.json').read_bytes())
        cls.events=list(cls.trace.events)
        cls.by_id={e['event_id']:e for e in cls.events}
        cpu=cls.manifest['runner']['sessions']['cpu']['identity']
        if 'cpu_native_irq_receipt_contract' not in cpu:
            raise ValueError('saved prefix lacks new authenticated CPU native receipt mode')

    def model(self,mutation=None):
        from myfuzz.scenario.source_provenance import AdmissionRegistry
        from myfuzz.scenario.ownership import InputField,InputOwner,compile_ownership
        from myfuzz.scenario.uart_irq_consumption import UartNativeIrqJoin
        ownership=self.manifest['runner']['ownership']
        model=UartNativeIrqJoin(ownership=compile_ownership(
            tuple(InputField(**x) for x in ownership['fields']),
            tuple(InputOwner(**x) for x in ownership['owners'])),
            admission_registry=AdmissionRegistry.from_document(self.plan['source_admissions']),
            edge_index=_verified_saved_native_index(self.plan,self.manifest))
        reports=[]
        for original in self.events:
            # Accepted upstream retention is authenticated saved engine output;
            # native join's own derived reports must never be fed back as authority.
            if original.get('kind')=='uart_consumption_match':
                upstream = (original.get('proof_scope') == 'uart_fifo_retention'
                    or original.get('status') == 'incomplete' and str(original.get('reason','')).startswith('uart_'))
                if not upstream:continue
            event=deepcopy(original)
            if mutation:
                event=mutation(event)
                if event is None:continue
            reports.extend(model.consume(event))
        return [r for r in reports if r.get('status')=='accepted' and r.get('proof_scope')=='cpu_external_irq_taken']

    def test_actual_admitted_bootstrap_and_fuzz_native_chains(self):
        proofs=self.model();self.assertTrue(proofs)
        roles=set()
        for proof in proofs:
            self.assertEqual(proof['generic_isr_origin'],'unknown')
            self.assertEqual(proof['operand_origin'],'unknown')
            take=self.by_id[proof['cpu_take_event_id']]
            sample=self.by_id[proof['cpu_sample_event_id']]
            binding=self.by_id[sample['binding_delivery_event_id']]
            self.assertEqual(take['sample_event_id'],sample['event_id'])
            self.assertEqual(take['sample_ref'],{'command_scope':sample['command_scope'],'local_tick':sample['local_tick']})
            self.assertEqual(take['receipt_id'],sample['receipt_id'])
            self.assertEqual(sample['source_output_key'],binding['source_output_key'])
            self.assertEqual(sample['input_context']['binding_delivery_event_id'],binding['event_id'])
            self.assertEqual((sample['actual_pre_input'],sample['actual_post_input']),(binding['value'],binding['value']))
            self.assertEqual(sample['irq_taken_pre'],1)
            self.assertEqual(proof['source_output_key'],binding['source_output_key'])
            for event_id in proof['retention_proof_event_ids']:
                retained=self.by_id[event_id]
                self.assertTrue(retained['retained_at_push'])
                self.assertIn(retained['entry_id'],proof['source_entry_ids'])
                admission=retained['source_admission'];roles.add(admission['role'])
                self.assertIn(admission,proof['source_admissions'])
                self.assertTrue(admission['case_id'])
        self.assertTrue({'bootstrap','fuzz_source'}<=roles,roles)

    def test_full_saved_prefix_equals_fresh_authenticated_replay(self):
        from myfuzz.integration.ibex_uart_online import replay_ibex_uart_online_files
        cache=Path(os.environ.get('MYFUZZ_UART_NATIVE_IRQ_CACHE_DIR',str(self.output.parent/(self.output.name+'-cache'))))
        result=replay_ibex_uart_online_files(cache_dir=cache,plan_path=self.plan_path,trace_path=self.trace_path)
        self.assertTrue(result.matches,result.difference_context)
        self.assertIsNone(result.first_difference)
        _assert_full_wire_prefix(self,result.actual_trace.events,self.events)
        self.assertTrue(_wire_bytes(result.actual_trace.local_ticks)==_wire_bytes(self.trace.local_ticks),
            'full fresh replay local ticks differ')
        print(json.dumps({'native_fixture_fresh_matches':True,'first_difference':None,
            'verification_scope':'full_wire_prefix','events':len(self.events)},sort_keys=True),flush=True)

    def test_missing_native_witnesses_cannot_promote(self):
        def delete(kind):return lambda e:None if e.get('kind')==kind else e
        for label,mutation in (
            ('cause',delete('uart_irq_update')),
            ('entry',lambda e:None if e.get('kind')=='uart_consumption_match' and e.get('proof_scope')=='uart_fifo_retention' else e),
            ('binding',delete('native_irq_binding_delivery')),
            ('sample',delete('cpu_external_irq_sample')),
            ('taken',delete('cpu_external_irq_taken')),
            ('context',lambda e:({k:v for k,v in e.items() if k!='input_context'} if e.get('kind')=='cpu_external_irq_sample' else e)),
            ('schema',lambda e:dict(e,observation_contract={}) if e.get('kind')=='cpu_external_irq_sample' else e),
        ):
            with self.subTest(witness=label):self.assertFalse(self.model(mutation))

    def test_unwitnessed_cpu_epoch_transition_cannot_promote(self):
        # Reset-free online capture cannot certify a new epoch without actual
        # physical reset. Deliberately change measured CPU epoch, never infer it.
        def missing_reset(event):
            if event.get('kind')=='cpu_reset':return None
            if event.get('kind') in ('cpu_external_irq_sample','cpu_external_irq_taken'):
                event['reset_epoch']+=1
                event['command_scope']['reset_epoch']+=1
            return event
        self.assertFalse(self.model(missing_reset))
