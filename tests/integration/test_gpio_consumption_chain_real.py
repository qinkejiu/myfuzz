"""Actual two-GPIO physical consumption; CPU/operand origin stays unknown.

Opt in only after coordinated source freeze. All builds use the production
single-worker builder; no CPU RTL is generated. Repeated runs start fresh GPIO
processes and compare the complete detached semantic evidence prefix.
"""
from copy import deepcopy
from dataclasses import asdict
import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario.gpio_consumption import GpioConsumptionTracker
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.ownership import compile_ownership, InputField, InputOwner
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.source_provenance import AdmissionRegistry
from tests.local_harness.test_renderer import ROOT, real_plan


@unittest.skipUnless(os.environ.get('MYFUZZ_GPIO_PROBE_REAL') == '1',
                     'requires MYFUZZ_GPIO_PROBE_REAL=1 after coordinated source freeze')
class GpioConsumptionChainRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-gpio-consumption-chain-')
        cls.cache = Path(os.environ.get('MYFUZZ_GPIO_PROBE_CACHE_DIR',
                                       str(Path(cls.temp.name)/'cache')))
        cls.artifacts = {}
        for component in ('gpio_a','gpio_b'):
            plan = real_plan('configs/peripherals/pulp_gpio_causal_local/component_profile.json', component)
            top = render_local_runtime(plan, render_local_harness(plan),
                verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
            cls.artifacts[component] = render_local_driver(top, base_dir=ROOT)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_chain(self):
        sessions = {}
        for component, artifact in self.artifacts.items():
            session = GeneratedPulpGpioSession(artifact, base_dir=ROOT, cache_dir=self.cache)
            session.prepare_local()
            session.begin_case('gpio-physical-chain')
            sessions[component] = session
            self.addCleanup(session.end_case)
        ownership = compile_ownership(
            (InputField('gpio_a','gpio_in',32), InputField('gpio_b','gpio_in',32)),
            (InputOwner('gpio_a','gpio_in',0,32,'fixed','zero'),
             InputOwner('gpio_b','gpio_in',0,8,'bound','gpio_a.gpio_out'),
             InputOwner('gpio_b','gpio_in',8,24,'fixed','zero')))
        tracker = GpioConsumptionTracker(ownership=ownership, admission_registry=AdmissionRegistry())
        router = DataflowRouter(tuple(DeviceWindow(component,base,4096,sessions[component])
            for component,base in (('gpio_a',0x40001000),('gpio_b',0x40002000))))
        ledger = TransactionLedger()
        cursors = dict.fromkeys(sessions,0)
        journal = []; resources = []; next_id = 0; sequence = 0

        def drain(component):
            nonlocal next_id
            session = sessions[component]
            batch = deepcopy(session.gpio_events[cursors[component]:])
            cursors[component] = len(session.gpio_events)
            for fact in batch:
                next_id += 1; fact['event_id'] = next_id
            for index,fact in enumerate(batch):
                journal.append(deepcopy(fact))
                if fact['kind']=='gpio_input_applied':
                    continue  # handled just before its exact actual sample below
                if fact['kind']=='gpio_tick_observation' and index+1<len(batch):
                    marker = batch[index+1]
                    if marker['kind']=='gpio_input_applied':
                        self.assertEqual(marker['command_scope'],fact['command_scope'])
                        self.assertEqual(marker['local_tick'],fact['local_tick'])
                        self.assertEqual(marker['actual_input_value'],fact['pre']['gpio_in'])
                        self.assertEqual(marker['actual_input_value'],fact['post']['gpio_in'])
                        for segment in marker['segments']:
                            applied = {**marker, **segment, 'port':'gpio_in',
                                'actual_receipt_event_id':fact['event_id']}
                            resources.extend(tracker.consume(applied))
                resources.extend(tracker.consume(fact))
            session.drain_tick_samples()

        def access(component, offset, *, write=False, value=0):
            nonlocal sequence
            sequence += 1
            base = 0x40001000 if component=='gpio_a' else 0x40002000
            key = TransactionKey('gpio-chain','gpio-physical-chain','host',0,'data',sequence)
            response = router.transact(ledger,key,address=base+offset,
                write=write,wdata=value,be=15,beat_bytes=4)
            self.assertEqual(router.deliveries[-1]['target_apb_access']['status'],'observed')
            drain(component)
            return response, router.deliveries[-1]['target_apb_access']

        for offset,value in ((4,1),(24,1),(28,1)):
            access('gpio_b',offset,write=True,value=value)
        access('gpio_a',12,write=True,value=1)
        commit = next(r for r in reversed(resources)
                      if r['kind']=='gpio_register_commit' and r['component']=='gpio_a')
        producer_tick = sessions['gpio_a'].local_ticks
        output_refs = tracker.output_resources_at('gpio_a',0,producer_tick,'post')[:8]
        self.assertEqual(len(output_refs),8)
        self.assertEqual(output_refs[0]['version'],commit['bit_resources'][0]['version'])
        self.assertEqual(output_refs[0]['transaction'],commit['fullkey'])
        self.assertEqual(output_refs[0]['origin_status'],'unknown')
        next_id += 1
        binding_id = next_id
        binding_value = sum(ref['value'] << bit for bit,ref in enumerate(output_refs))
        self.assertEqual(binding_value,1)
        journal.append(dict(kind='binding_delivery',event_id=binding_id,
            status='logical_delivery',source_component='gpio_a',source_port='gpio_out',
            target_component='gpio_b',target_port='gpio_in',bit_lo=0,width=8,
            value=binding_value,producer_resource_refs=deepcopy(output_refs)))
        origin = dict(kind='binding',source_component='gpio_a',source_port='gpio_out',
            source_bit_lo=0,producer_reset_epoch=0,producer_local_tick=producer_tick,
            producer_phase='post',producer_resource_refs=output_refs,delivery_event_id=binding_id)
        sessions['gpio_b'].set_next_gpio_input_context(dict(component='gpio_b',
            segments=[dict(bit_lo=0,width=8,value=1,origin=origin)]))
        sessions['gpio_b'].step_local({'gpio_in':binding_value}); drain('gpio_b')
        applied_fact = next(f for f in reversed(journal) if f['kind']=='gpio_input_applied')
        self.assertEqual(applied_fact['segments'][0]['origin']['delivery_event_id'],binding_id)
        self.assertEqual(applied_fact['actual_input_value'],binding_value)
        next_id += 1
        journal.append(dict(kind='binding_actual_receipt',event_id=next_id,
            binding_delivery_event_id=binding_id,
            actual_gpio_input_applied_event_id=applied_fact['event_id'],
            actual_receipt_ref=deepcopy(applied_fact['actual_receipt_ref']),
            actual_input_value=applied_fact['actual_input_value']))
        for _ in range(3):
            sessions['gpio_b'].step_local({}); drain('gpio_b')
        triggers = [r for r in resources if r['kind']=='gpio_irq_trigger' and r['component']=='gpio_b']
        self.assertEqual(len(triggers),1)
        self.assertEqual(triggers[0]['mask'],1)
        self.assertEqual([c['pin'] for c in triggers[0]['causes']],[0])
        current = triggers[0]['causes'][0]['current_sample']
        self.assertEqual(current['origin_status'],'known')
        self.assertEqual(current['origin_refs'][0]['version'],output_refs[0]['version'])
        (padin,error),padin_access = access('gpio_b',8)
        self.assertEqual((padin,error),(1,0))
        padin_read = next(r for r in reversed(resources) if r['kind']=='gpio_register_read')
        self.assertEqual(padin_read['read_value'],padin_access['pre']['gpio_probe_padin_latch'])
        self.assertEqual(padin_read['bit_resources'][0]['origin_status'],'known')
        (status,error),status_access = access('gpio_b',36)
        self.assertEqual((status,error),(1,0))
        status_read = next(r for r in reversed(resources) if r['kind']=='gpio_register_read')
        self.assertEqual(status_read['read_value'],status_access['pre']['gpio_probe_status'])
        self.assertEqual(status_read['post_value'],0)
        self.assertEqual(status_read['status_outcome'],'cleared')
        # Native status resources must carry the actual trigger dependency;
        # a matching returned value alone is insufficient consumption evidence.
        self.assertTrue(status_read['bit_resources'][0]['dependencies'])
        (status,error),_ = access('gpio_b',36)
        self.assertEqual((status,error),(0,0))
        self.assertEqual(len([r for r in resources if r['kind']=='gpio_irq_trigger']),1)
        self.assertFalse(any(r['kind']=='gpio_consumption_match' and r.get('status')=='accepted'
                             for r in resources), 'no CPU retirement origin was supplied')
        self.assertFalse(any(r['kind']=='gpio_consumption_match' and r.get('status') in ('rejected','ambiguous')
                             for r in resources))
        for session in sessions.values():session.end_case()
        return dict(journal=journal,resources=resources,
                    router_deliveries=[{**d,'source_transaction':asdict(d['source_transaction'])}
                                       for d in router.deliveries],
                    proof_scope='gpio_native_physical_binding_consumption',
                    instruction_origin='unknown',operand_origin='unknown')

    def test_actual_padout_binding_synchronizer_irq_and_status_consumption_fresh_repeat(self):
        first = self.run_chain(); second = self.run_chain()
        self.assertEqual(first,second)
        destination = os.environ.get('MYFUZZ_GPIO_PROBE_EVIDENCE')
        if destination:
            directory=Path(destination);directory.mkdir(parents=True,exist_ok=True)
            (directory/'gpio-consumption-chain.json').write_text(
                json.dumps({'first':first,'second':second},sort_keys=True,indent=2)+'\n')


if __name__=='__main__':unittest.main()
