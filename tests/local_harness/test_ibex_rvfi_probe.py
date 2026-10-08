"""Official pinned RVFI exports and measured retirement transport."""
from pathlib import Path
import unittest
from tests.local_harness.test_renderer import real_plan
from myfuzz.local_harness import render_local_harness, verify_local_source_lock, render_local_runtime
ROOT = Path(__file__).resolve().parents[2]
class IbexRvfiProfileTests(unittest.TestCase):
    def test_all_official_rvfi_ports_are_authenticated_and_exported(self):
        plan = real_plan('configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu_rvfi')
        self.assertEqual('ibex_rvfi_local', plan.profile.component_id)
        widths = {port.name: port.width for port in plan.facts.ports}
        self.assertEqual(320, widths['rvfi_ext_mhpmcounters'])
        self.assertEqual(320, widths['rvfi_ext_mhpmcountersh'])
        self.assertEqual(64, widths['rvfi_order'])
        self.assertEqual(44, len([n for n in widths if n.startswith('rvfi_')]))
        self.assertEqual(64, widths['irq_decision_serial'])
        self.assertEqual(64, widths['irq_retirement_serial'])
        verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
        artifact = render_local_runtime(plan, render_local_harness(plan), verified, base_dir=ROOT)
        self.assertEqual(44, len([r for r in artifact.runtime_document['physical_exports'] if r['physical_port'].startswith('rvfi_')]))
        self.assertIn('u_component.u_dut.u_ibex.u_ibex_core', artifact.runtime_sv)

from types import SimpleNamespace
from unittest.mock import patch
from tests.local_harness import test_cpu_session as cpu_fixture
from myfuzz.local_harness.session import GeneratedLocalSession

class IbexRetirementTransportTests(unittest.TestCase):
    def setUp(self):
        cpu_fixture.GeneratedCpuSessionTests.setUp(self)
        self.cpu.artifact.plan.profile = SimpleNamespace(component_id='ibex_rvfi_local')
        self.cpu._rvfi_enabled = True
        names = {'rvfi_valid':1,'rvfi_order':64,'rvfi_insn':32,'rvfi_trap':1,'rvfi_intr':1,
                 'rvfi_halt':1,'rvfi_mode':2,'rvfi_ixl':2,'rvfi_pc_rdata':32,'rvfi_pc_wdata':32,
                 'rvfi_mem_addr':32,'rvfi_mem_rmask':4,'rvfi_mem_wmask':4,
                 'rvfi_mem_rdata':32,'rvfi_mem_wdata':32}
        self.cpu._artifact_document['physical_exports'] = [dict(runtime_name=n,physical_port=n,width=w,direction='output',bit_lo=0,hex_digits=(w+3)//4) for n,w in names.items()]
    def step(self, observed=None, rvfi=None):
        def receipt(op, fields):
            r=cpu_fixture.make_receipt(self.cpu,fields,observed or {})
            physical=dict.fromkeys([r['runtime_name'] for r in self.cpu._artifact_document['physical_exports']],0)
            physical.update(rvfi or {})
            r.payload['observations']={'backend':r.payload['pre_backend'],'physical':physical}
            r.payload['samples'][0]['pre']['physical']={'probe_irq_masked_pre':1,'probe_irq_taken_pre':0}
            r.payload['samples'][0]['post']={'backend':r.payload['pre_backend'],'physical':physical}
            return r
        with patch.object(GeneratedLocalSession,'command',side_effect=receipt):return self.cpu.step_local({})
    def test_identity_declares_sampling_schema_only_for_rvfi_variant(self):
        with patch.object(GeneratedLocalSession, 'identity_document', return_value={}):
            identity = self.cpu.identity_document()
        self.assertEqual('ibex_rvfi_observation.v1', identity['cpu_observation_schema_version'])
        self.assertEqual('post_rising', identity['cpu_retirement_sampling_edge'])
    def test_invalid_valid_does_not_retire_and_same_order_is_emitted_once(self):
        self.step(rvfi={'rvfi_valid':0,'rvfi_order':12})
        self.assertEqual([],self.cpu.cpu_events)
        row={'rvfi_valid':1,'rvfi_order':12,'rvfi_insn':0x0024a023,'rvfi_pc_rdata':0x10088,'rvfi_mem_addr':0x20000,'rvfi_mem_wmask':15,'rvfi_mem_wdata':42}
        self.step(rvfi=row);self.step(rvfi=row)
        events=[e for e in self.cpu.cpu_events if e['kind']=='cpu_retire']
        self.assertEqual(1,len(events));self.assertEqual(0x10088,events[0]['pc_rdata'])
        self.assertEqual('post_rising',events[0]['observation']['sampling_edge'])
        self.assertEqual(12,events[0]['observation']['physical']['rvfi_order'])
    def test_fresh_process_restart_advances_real_cpu_epoch(self):
        self.cpu._started_cpu = True
        self.step(rvfi={'rvfi_valid':1,'rvfi_order':7})
        with patch.object(GeneratedLocalSession, 'begin_case'):
            self.cpu.begin_case('new-process')
        self.assertEqual(1,self.cpu.reset_epoch)
        self.step(rvfi={'rvfi_valid':1,'rvfi_order':0})
        events=[e for e in self.cpu.cpu_events if e['kind']=='cpu_retire']
        self.assertEqual([0,1],[e['source_epoch'] for e in events])
        self.assertEqual('cpu_reset',self.cpu.cpu_events[-2]['kind'])
    def test_explicit_reset_restart_increments_epoch_exactly_once(self):
        self.cpu._started_cpu = True
        def reset_transport():
            self.cpu.reset_epoch += 1
            with patch.object(GeneratedLocalSession,'begin_case'):
                self.cpu.begin_case('reset-process')
            return {}
        with patch.object(GeneratedLocalSession,'reset_local',side_effect=reset_transport):
            self.cpu.reset_local()
        self.assertEqual(1,self.cpu.reset_epoch)
        self.assertEqual(1,len([e for e in self.cpu.cpu_events if e['kind']=='cpu_reset']))
    def test_retirement_order_regression_is_rejected(self):
        from myfuzz.scenario.contracts import ProtocolEnvironmentError
        self.step(rvfi={'rvfi_valid':1,'rvfi_order':7})
        with self.assertRaises(ProtocolEnvironmentError):
            self.step(rvfi={'rvfi_valid':1,'rvfi_order':6})
    def test_instruction_response_preserves_frozen_writer_snapshot(self):
        self.step({'i_req_valid':1,'i_req_addr':0x10000,'i_req_be':15})
        self.memory.write(0x10000,0xdeadbeef,width_bytes=4,byte_enable=15,writer_event_id='later')
        self.step({'i_rsp_ready':1})
        response=next(e for e in self.cpu.cpu_events if e['kind']=='instr_response')
        self.assertEqual(0x13,response['rdata']);self.assertEqual('13000000',response['snapshot']['data_hex'])
        self.assertEqual(1,response['transaction']['source_sequence'])
        self.assertNotIn('later',response['snapshot']['writer_event_ids'])
        json.dumps(self.cpu.cpu_events)

import os
import json
@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1', 'set MYFUZZ_SCENARIO_REAL=1')
class IbexRvfiRealTests(unittest.TestCase):
    def test_real_retirement_branch_flush_unaligned_and_cross_word_instruction(self):
        from myfuzz.local_harness.driver_renderer import render_local_driver
        from myfuzz.local_harness.build import build_local_harness
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
        from myfuzz.scenario.router import DataflowRouter, DeviceWindow
        from tests.local_harness.test_cpu_session import Target
        plan=real_plan('configs/cpus/ibex_rvfi_local/component_profile.json','cpu_rvfi')
        artifact=render_local_driver(render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
        cache=Path('/tmp/myfuzz-task4-ibex-rvfi-probe-cache-v1')
        binary=build_local_harness(artifact,base_dir=ROOT,cache_dir=cache)
        memory=PersistentMemory(regions=(MemoryRegion('ram',0,0x30000),),initialization_seed=9,max_initialized_bytes=0x30000)
        words=(0x000204b7,0x02a00113,0x0024a023,0x0004a183,0x00118193,0x0034a0a3,0x0080006f,0x0024a023)
        program=b''.join(w.to_bytes(4,'little') for w in words)+b'\x01\x00'+(0x00700213).to_bytes(4,'little')+b'\x01\x00'+(0x0000006f).to_bytes(4,'little')
        memory.preload(0x10080,program)
        target=Target()
        router=DataflowRouter((DeviceWindow('dummy',0x40000000,0x1000,target),))
        cpu=GeneratedCve2Session(artifact,base_dir=ROOT,cache_dir=cache,memory=memory,router=router)
        cpu._binary=binary;cpu.begin_case('rvfi-actual')
        try:
            for _ in range(200):cpu.step_local({})
            events=cpu.cpu_events;retired=[e for e in events if e['kind']=='cpu_retire']
            bypc={e['pc_rdata']:e for e in retired}
            self.assertTrue(retired);self.assertNotIn(0x1009c,bypc)
            self.assertEqual(0x00700213,bypc[0x100a2]['insn'])
            self.assertEqual(0x0001,bypc[0x100a0]['insn'])
            self.assertEqual(0x20001,bypc[0x10094]['mem_addr'])
            self.assertEqual(15,bypc[0x10094]['mem_wmask'])
            self.assertEqual(43,bypc[0x10094]['mem_wdata'])
            self.assertEqual(42,bypc[0x1008c]['mem_rdata'])
            beats=[e for e in events if e['kind']=='data_accept']
            self.assertEqual(4,len(beats))
            self.assertEqual([0x20000,0x20000,0x20000,0x20004],[e['raw_address'] for e in beats])
            self.assertEqual([15,15,14,1],[e['be'] for e in beats])
            self.assertEqual(len(retired),len({e['order'] for e in retired}))
            self.assertEqual(3,cpu.memory_write_count)
            self.assertTrue(all(e['observation']['physical']['rvfi_valid']==1 for e in retired))
            out=ROOT/'runs/task4-ibex-retire';out.mkdir(parents=True,exist_ok=True)
            (out/'cpu-events.json').write_text(json.dumps(events,indent=2)+'\n')
            cpu.reset_local()
            self.assertEqual('cpu_reset',cpu.cpu_events[-1]['kind'])
            for _ in range(80):cpu.step_local({})
            self.assertTrue(any(e['kind']=='cpu_retire' and e['source_epoch']==1 and e['order']==1 for e in cpu.cpu_events))
            cpu.end_case();cpu.begin_case('rvfi-restarted')
            for _ in range(80):cpu.step_local({})
            self.assertTrue(any(e['kind']=='cpu_retire' and e['source_epoch']==2 and e['order']==1 for e in cpu.cpu_events))
            # A deferred MMIO store is granted, then cancelled before target service.
            for index,word in enumerate((0x400004b7,0x02a00113,0x0024a023,0x0000006f)):
                memory.write(0x10080+index*4,word,width_bytes=4,byte_enable=15,writer_event_id='fixture-mmio-program')
            cpu.reset_local()
            for _ in range(80):
                cpu.step_local({})
                if router.pending_targets:break
            self.assertEqual(('dummy',),router.pending_targets)
            pending_epoch=cpu.reset_epoch
            cancelled=cpu.reset_local()
            self.assertEqual(1,len(cancelled['cancelled_target_requests']))
            self.assertEqual((),router.pending_targets)
            self.assertEqual([],target.writes)
            self.assertFalse(any(e['kind']=='cpu_retire' and e['source_epoch']==pending_epoch and e['pc_rdata']==0x10088 for e in cpu.cpu_events))
            (out/'cpu-lifecycle-events.json').write_text(json.dumps(cpu.cpu_events,indent=2)+'\n')
        finally:cpu.end_case()
