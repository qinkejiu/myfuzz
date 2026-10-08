"""Directed real-RTL measurement gate for the explicit passive GPIO variant.

Only run after coordinated source freeze; the production builder uses -j 1.
The direct ACCESS_GPIO cases deliberately apply a pin value with the access,
using the unchanged public driver command, to witness STATUS priority/PADIN
latency without a discovery readback or additional clock inside the access.
"""
from __future__ import annotations

import copy
from dataclasses import asdict
import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.pulp_gpio_probe_contract import PULP_GPIO_PROBES, pulp_gpio_observation_contract, pulp_gpio_probe_document
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from tests.local_harness.test_renderer import ROOT, real_plan


@unittest.skipUnless(os.environ.get('MYFUZZ_GPIO_PROBE_REAL') == '1',
                     'set MYFUZZ_GPIO_PROBE_REAL=1 only after coordinated source freeze')
class PulpGpioCausalProbeRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-causal-gpio-probe-')
        cls.cache = Path(os.environ.get('MYFUZZ_GPIO_PROBE_CACHE', str(Path(cls.temp.name)/'cache')))
        plan = real_plan('configs/peripherals/pulp_gpio_causal_local/component_profile.json', 'gpio_a')
        top = render_local_runtime(plan, render_local_harness(plan),
                                   verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        cls.artifact = render_local_driver(top, base_dir=ROOT)
        # Keep a detached authenticated export row. GPIO input is transported
        # in physical under the runtime name, without a top-level alias.
        inputs = [row for row in cls.artifact.runtime_document['physical_exports']
                  if row['physical_port'] == 'gpio_in' and row['direction'] == 'input'
                  and row['width'] == 32 and row['bit_lo'] == 0 and row['bit_hi'] == 31]
        if len(inputs) != 1:
            raise AssertionError('one authenticated full GPIO input export required')
        cls._gpio_input_export = copy.deepcopy(inputs[0])

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, name):
        gpio = GeneratedPulpGpioSession(self.artifact, base_dir=ROOT, cache_dir=self.cache)
        gpio.prepare_local()
        gpio.begin_case(name)
        self.addCleanup(gpio.end_case)
        return gpio

    def evidence(self, label, value):
        destination = os.environ.get('MYFUZZ_GPIO_PROBE_EVIDENCE')
        if destination:
            directory = Path(destination); directory.mkdir(parents=True, exist_ok=True)
            (directory/(label+'.json')).write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')

    @staticmethod
    def probes(snapshot):
        # Raw transport retains runtime signal keys. Decode only through the
        # immutable registered expression map; session facts normalize them.
        return {probe['physical_port']: snapshot['physical'][probe['runtime_name']]
                for probe in pulp_gpio_probe_document()['probes'].values()}

    def raw_input(self, snapshot):
        return snapshot['physical'][self._gpio_input_export['runtime_name']]

    def assert_samples(self, samples):
        self.assertTrue(samples)
        for sample in samples:
            for phase in ('pre', 'post'):
                physical = self.probes(sample[phase])
                for name, (width, _) in PULP_GPIO_PROBES.items():
                    value = physical['gpio_probe_'+name]
                    self.assertIs(type(value), int, (phase, name))
                    self.assertGreaterEqual(value, 0)
                    self.assertLess(value, 1 << width)
                self.assertEqual(physical['gpio_probe_native_irq'], sample[phase]['interrupt'])
                self.assertEqual(physical['gpio_probe_out'], sample[phase]['gpio_out'])
                self.assertEqual(physical['gpio_probe_dir'], sample[phase]['gpio_dir'])
                self.assertEqual(physical['gpio_probe_sync1'], sample[phase]['gpio_in_sync'])
                self.assertEqual(physical['gpio_probe_decoded_word'], (physical['gpio_probe_apb_addr'] >> 2) & 31)
            pre, post = (self.probes(sample[phase]) for phase in ('pre','post'))
            for pin in range(32):
                if pre['gpio_probe_input_clock_enable'] & (1 << (pin//4)):
                    for target, source in (('sync0','gpio_in'), ('sync1','gpio_probe_sync0'),
                                           ('padin_latch','gpio_probe_sync1')):
                        self.assertEqual((post['gpio_probe_'+target] >> pin)&1,
                                         ((self.raw_input(sample['pre']) if source=='gpio_in' else pre[source]) >> pin)&1)

    def routed(self, gpio):
        router = DataflowRouter((DeviceWindow('gpio_a', 0x40001000, 4096, gpio),))
        ledger = TransactionLedger()
        sequence = 0
        def access(offset, *, write=False, value=0):
            nonlocal sequence
            sequence += 1
            key = TransactionKey('probe-gate','probe-case','cpu',0,'data',sequence)
            before = len(gpio.gpio_events)
            result = router.transact(ledger,key,address=0x40001000+offset,
                                     write=write,wdata=value,be=15,beat_bytes=4)
            delivery = router.deliveries[-1]
            event = delivery['target_apb_access']
            self.assertEqual(event['status'],'observed')
            self.assertEqual(event['source_transaction'],asdict(key))
            self.assertEqual(event['observation_contract'],pulp_gpio_observation_contract())
            request, response = delivery['target_request'], delivery['target_response']
            self.assertEqual((request['status'],response['status']),('observed','observed'))
            self.assertLess(request['local_tick'],event['local_tick'])
            self.assertLess(event['local_tick'],response['local_tick'])
            self.assertEqual(request['access_id'],event['access_id'])
            self.assertEqual(response['access_id'],event['access_id'])
            receipt = next(e for e in gpio.gpio_events[before:] if e['kind']=='gpio_target_receipt')
            self.assertEqual(receipt['transport_sequence'], event['command_scope']['command_sequence'])
            samples = gpio.drain_tick_samples();self.assert_samples(samples)
            self.evidence(f'{self._testMethodName}-access-{sequence}',
                          {'event':event,'request':request,'response':response,'samples':samples})
            return result, event
        return access

    @staticmethod
    def raw_apb(reply):
        found = [s for s in reply.payload['samples']
                 if PulpGpioCausalProbeRealTests.probes(s['pre'])['gpio_probe_psel']==1
                 and PulpGpioCausalProbeRealTests.probes(s['pre'])['gpio_probe_penable']==1]
        if len(found)!=1: raise AssertionError('one actual APB ACCESS required')
        return found[0]

    def test_actual_padout_set_clear_alias_upper_masks_and_reset(self):
        gpio=self.session('probe-registers');access=self.routed(gpio)
        cases=((12,0xa5,0,0xa5),(16,2,0xa5,0xa7),(20,4,0xa7,0xa3),
               (12,0xa3,0xa3,0xa3),(140,0x123,0xa3,0x123))
        ids=[]
        for offset,value,old,new in cases:
            _,event=access(offset,write=True,value=value)
            ids.append(event['access_id'])
            self.assertEqual(event['pre']['gpio_probe_out'],old)
            self.assertEqual(event['post']['gpio_probe_out'],new)
            self.assertEqual(event['pre']['gpio_probe_write_out'],0xffffffff)
        self.assertEqual(len(ids),len(set(ids)))
        (value,error),_=access(12);self.assertEqual((value,error),(0x123,0))
        _,upper=access(0x4c,write=True,value=0xffffffff)
        self.assertEqual(upper['pre']['gpio_probe_write_out'],0xffffffff00000000)
        self.assertEqual(upper['pre']['gpio_probe_out'],upper['post']['gpio_probe_out'])
        prior=copy.deepcopy(gpio.gpio_events);previous_tick=gpio.local_ticks
        gpio.reset_local()
        (value,error),event=access(12)
        self.assertEqual((value,error),(0,0))
        self.assertEqual(event['reset_epoch'],1)
        self.assertEqual(event['command_scope']['reset_epoch'],1)
        self.assertEqual(event['command_scope']['command_sequence'],1)
        self.assertGreater(event['local_tick'],previous_tick)
        self.assertEqual(gpio.gpio_events[:len(prior)],prior)

    def test_padin_reads_pre_latch_separately_from_sync1(self):
        gpio=self.session('probe-padin');access=self.routed(gpio)
        access(4,write=True,value=1)
        reply=gpio.command('ACCESS_GPIO',(1,0,8,0,15))
        self.assert_samples(reply.payload['samples'])
        apb=self.raw_apb(reply);pre=self.probes(apb['pre']);post=self.probes(apb['post'])
        self.assertEqual(pre['gpio_probe_sync1'] & 1,1)
        self.assertEqual(pre['gpio_probe_padin_latch'] & 1,0)
        self.assertEqual(pre['gpio_probe_prdata'],0)
        self.assertEqual(reply.payload['rdata'],0)
        self.assertEqual(post['gpio_probe_padin_latch'] & 1,1)
        self.evidence(self._testMethodName,reply.payload)
        gpio.step_local({'gpio_in':1});self.assert_samples(gpio.drain_tick_samples())
        (value,error),event=access(8)
        self.assertEqual((value,error),(1,0))
        self.assertEqual(event['read_rdata'],event['pre']['gpio_probe_padin_latch'])

    def test_status_read_concurrent_trigger_prioritizes_new_event(self):
        gpio=self.session('probe-status');access=self.routed(gpio)
        for offset,value in ((4,3),(24,3),(28,5)):
            access(offset,write=True,value=value)
        gpio.step_local({'gpio_in':2})
        for _ in range(4):gpio.step_local({})
        settled=gpio.drain_tick_samples();self.assert_samples(settled)
        self.assertTrue(any(self.probes(s['pre'])['gpio_probe_irq_trigger_mask']==2
                            or self.probes(s['post'])['gpio_probe_irq_trigger_mask']==2 for s in settled))
        # A new bit0 rise travels through sync0/sync1 during req/setup, so
        # ACCESS pre sees trigger1 while returning the prior status2.
        reply=gpio.command('ACCESS_GPIO',(3,0,36,0,15))
        self.assert_samples(reply.payload['samples'])
        apb=self.raw_apb(reply);pre=self.probes(apb['pre']);post=self.probes(apb['post'])
        self.assertEqual(pre['gpio_probe_irq_trigger_mask'],1)
        self.assertEqual(pre['gpio_probe_native_irq'],1)
        self.assertEqual(pre['gpio_probe_status'],2)
        self.assertEqual((pre['gpio_probe_prdata'],reply.payload['rdata']),(2,2))
        self.assertEqual(post['gpio_probe_status'],3)
        self.evidence(self._testMethodName,reply.payload)
        gpio.step_local({'gpio_in':3});self.assert_samples(gpio.drain_tick_samples())
        (value,error),clear=access(36)
        self.assertEqual((value,error),(3,0))
        self.assertEqual(clear['post']['gpio_probe_status'],0)
        self.assertEqual(clear['status_read_outcome'],'cleared')
        (value,error),_=access(36);self.assertEqual((value,error),(0,0))

    def test_fresh_process_commands_have_stable_semantic_scope(self):
        def run():
            gpio=self.session('probe-fresh');access=self.routed(gpio)
            access(12,write=True,value=7);access(12)
            events=copy.deepcopy(gpio.gpio_events)
            gpio.end_case()
            return events
        first,second=run(),run()
        self.assertEqual(first,second)
        self.evidence(self._testMethodName,{'first':first,'second':second})


if __name__=='__main__':unittest.main()
