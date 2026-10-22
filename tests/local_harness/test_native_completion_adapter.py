from pathlib import Path
from dataclasses import replace
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory, ReadSnapshot
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.native_cpu_events import NativeBusObserver
from myfuzz.scenario.native_instruction_source_binding import NativeInstructionSourceBinding
from myfuzz.scenario.native_instruction_bus_completion import validate_issued_native_completion
from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.scenario.picorv32_native_cpu_example import DeferredNativeMemorySession
ROOT=Path(__file__).resolve().parents[2]
class NativeCompletionAdapterTests(unittest.TestCase):
    def test_completion_not_acceptance_and_errors_never_complete(self):
        source='''module tb;
logic clk=0,reset=1,valid=0,ready,reqvalid,reqready=0,rspvalid=0,rspready,rsperror=0,fault;
logic [31:0] addr=32'h100,wdata=0,rdata,reqaddr,reqwdata,rspdata=32'h12345678;
logic [3:0] strb=0,be; logic write; logic [1:0] code;
native_completion_memory_adapter #(.MAX_WAIT_CYCLES(4)) dut(
.clk(clk),.reset(reset),.valid_i(valid),.ready_o(ready),.addr_i(addr),.wdata_i(wdata),.wstrb_i(strb),.rdata_o(rdata),
.req_valid_o(reqvalid),.req_ready_i(reqready),.req_write_o(write),.req_addr_o(reqaddr),.req_wdata_o(reqwdata),.req_be_o(be),
.rsp_valid_i(rspvalid),.rsp_ready_o(rspready),.rsp_rdata_i(rspdata),.rsp_error_i(rsperror),.fault_o(fault),.fault_code_o(code));
task tick; #1;clk=1;#1;clk=0;#1;endtask
initial begin
 tick();reset=0;valid=1;#1;if(ready)$fatal(1,"early ready");tick();
 if(!reqvalid||be!=15||write)$fatal(1,"request");reqready=1;tick();reqready=0;
 if(ready||!rspready)$fatal(1,"early response");rspvalid=1;tick();rspvalid=0;
 if(!ready||rdata!=32'h12345678)$fatal(1,"completion data");
 addr=32'h104;#1;if(ready)$fatal(1,"unstable completion success");tick();
 if(!fault||code!=3)$fatal(1,"unstable completion fault");valid=0;addr=32'h100;
 reset=1;tick();reset=0;valid=1;tick();reqready=1;tick();reqready=0;
 rspvalid=1;rsperror=1;tick();rspvalid=0;if(!fault||ready||code!=1)$fatal(1,"error success");
 reset=1;tick();reset=0;valid=1;tick();repeat(4)tick();if(!fault||ready||code!=2)$fatal(1,"timeout success");
 reset=1;tick();reset=0;valid=1;tick();addr=32'h104;tick();if(!fault||ready||code!=3)$fatal(1,"unstable");
 $display("NATIVE_COMPLETION_OK");$finish;end
endmodule'''
        with TemporaryDirectory() as directory:
            directory=Path(directory);tb=directory/'tb.sv';tb.write_text(source)
            result=subprocess.run(['verilator','--binary','--timing','-Wno-fatal','-j','1','--top-module','tb','--Mdir',str(directory/'obj'),str(ROOT/'src/myfuzz/protocols/rtl/native_completion_memory_adapter.sv'),str(tb)],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr[-4000:])
            result=subprocess.run([str(directory/'obj/Vtb')],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('NATIVE_COMPLETION_OK',result.stdout)


class NativeBusObserverIdentityTests(unittest.TestCase):
    """Verified synthetic samples exercise the observer boundary without RTL."""

    def setUp(self):
        artifact = SimpleNamespace(runtime_document={'artifact_digest': 'digest'},
            plan=SimpleNamespace(request=SimpleNamespace(instance_id='cpu')))
        self.owner = SimpleNamespace(artifact=artifact, reset_epoch=0,
            _execution='execution', _sequence=0, _sequence_memory=0,
            _tick_base=0, _case_id='testcase',
            _native_source_completion_session=None)
        observer = object.__new__(NativeBusObserver)
        observer.session = self.owner
        observer.contract = {'instruction_marker': {'signal': 'instr'},
                             'endpoint_id': 'cpu', 'clock_domain': 'clk'}
        observer.trace = {'signals': {name: name for name in
            ('valid', 'ready', 'addr', 'wdata', 'wstrb', 'rdata')},
            'signal_widths': {'valid': 1, 'ready': 1, 'addr': 32,
                              'wdata': 32, 'wstrb': 4, 'rdata': 32},
            'max_wait_cycles': 4}
        observer.pending = None
        observer.epoch = None
        observer.execution = None
        observer.sequence = 0
        observer.tick = None
        observer.memory_sequence = 0
        observer.samples = []
        observer.offered = None
        observer.failed = False
        observer._source_completions = []
        self.observer = observer

    def phase(self, *, ready=0, rdata=0, valid=1, marker=1):
        return {'protocol_taps': {'valid': valid, 'ready': ready,
                'addr': 0x80000040, 'wdata': 0, 'wstrb': 0, 'rdata': rdata},
                'physical': {'instr': marker}}

    def edge(self, tick, pre, post, *, accepted=False, consumed=False,
             response=0x13, pending_response=None, be=15):
        backend = {'m_req_valid': int(accepted), 'm_req_ready': int(accepted),
                   'm_req_addr': 0x80000040, 'm_req_write': 0,
                   'm_req_be': be, 'm_req_wdata': 0,
                   'm_rsp_valid': int(consumed), 'm_rsp_ready': int(consumed),
                   'm_rsp_error': 0, 'm_rsp_rdata': response if consumed else 0}
        pre = {**pre, 'backend': backend}
        sample = {'local_tick': tick, 'pre': pre, 'post': post}
        self.owner._sequence = tick
        receipt = SimpleNamespace(status='result', new_ticks=1,
            execution='execution', sequence=tick, tick_before=tick - 1,
            tick_after=tick, payload={'samples': [sample]})
        return self.observer.observe(receipt, pending_response)

    def accept(self):
        key = self.edge(1, self.phase(), self.phase(), accepted=True)
        self.owner._sequence_memory = 1
        return key

    def snapshot(self, key):
        return ReadSnapshot(str(key), 'ram', 0, 0x40, b'\x13\x00\x00\x00',
            ((0, 1),) * 4, ('source',) * 4,
            writer_kinds=('INSTRUCTION_SOURCE',) * 4)

    def test_accepted_key_is_the_exact_object_required_by_read_binding(self):
        key = self.accept()
        self.assertIsInstance(key, TransactionKey)
        snapshot = self.snapshot(key)
        self.observer.bind_read_snapshot(key, snapshot)
        equal_key = TransactionKey(**vars(key))
        self.assertEqual(key, equal_key)
        with self.assertRaises(ValueError):
            self.observer.bind_read_snapshot(equal_key, snapshot)
        self.assertIs(self.observer.pending['key'], key)

    def test_default_off_response_and_post_ready_do_not_issue_completion(self):
        key = self.accept()
        self.observer.bind_read_snapshot(key, self.snapshot(key))
        self.edge(2, self.phase(), self.phase(ready=1, rdata=0x13),
                  consumed=True, pending_response=(0x13, 1))
        self.assertEqual('response', self.observer.pending['state'])
        self.assertEqual((), self.observer.drain_source_completions())
        self.edge(3, self.phase(ready=1, rdata=0x13),
                  self.phase(valid=0, marker=0))
        self.assertEqual((), self.observer.drain_source_completions())
        self.assertIsNone(self.observer.pending)

    def test_equal_replacement_snapshot_cannot_replace_original_pending_read(self):
        key = self.accept()
        original = self.snapshot(key)
        self.observer.bind_read_snapshot(key, original)
        equal = ReadSnapshot(**vars(original))
        self.assertEqual(original, equal)
        with self.assertRaises(ValueError):
            self.observer.bind_read_snapshot(key, equal)
        self.assertIs(self.observer.pending['read_snapshot'], original)

    def test_wrong_tick_response_mismatch_and_marker_change_refuse(self):
        for defect in ('wrong_tick', 'response_mismatch', 'marker_change'):
            with self.subTest(defect=defect):
                self.setUp()
                key = self.accept()
                self.observer.bind_read_snapshot(key, self.snapshot(key))
                if defect == 'response_mismatch':
                    with self.assertRaises(ValueError):
                        self.edge(2, self.phase(), self.phase(ready=1, rdata=0x13),
                                  consumed=True, response=0x14,
                                  pending_response=(0x13, 1))
                elif defect == 'marker_change':
                    with self.assertRaises(ValueError):
                        self.edge(2, self.phase(marker=0),
                                  self.phase(ready=1, rdata=0x13),
                                  consumed=True, pending_response=(0x13, 1))
                else:
                    self.edge(2, self.phase(), self.phase(ready=1, rdata=0x13),
                              consumed=True, pending_response=(0x13, 1))
                    with self.assertRaises(ValueError):
                        self.edge(4, self.phase(ready=1, rdata=0x13),
                                  self.phase(valid=0, marker=0))
                self.assertEqual((), self.observer.drain_source_completions())

    def test_nonfull_enable_and_data_read_issue_no_source_completion(self):
        with self.assertRaises(ValueError):
            self.edge(1, self.phase(), self.phase(), accepted=True, be=0)
        self.assertEqual((), self.observer.drain_source_completions())
        self.setUp()
        self.edge(1, self.phase(marker=0), self.phase(marker=0), accepted=True)
        self.owner._sequence_memory = 1
        self.edge(2, self.phase(marker=0),
                  self.phase(ready=1, rdata=0x13, marker=0),
                  consumed=True, pending_response=(0x13, 1))
        self.edge(3, self.phase(ready=1, rdata=0x13, marker=0),
                  self.phase(valid=0, marker=0))
        self.assertEqual((), self.observer.drain_source_completions())

    def test_enabled_completion_without_real_service_read_refuses(self):
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x80000000, 0x1000),),
                                  initialization_seed=1, max_initialized_bytes=64)
        self.owner.memory = memory
        self.owner.service = MemoryService(memory, TransactionLedger())
        self.owner._native_source_completion_session = object()
        self.accept()
        self.edge(2, self.phase(), self.phase(ready=1, rdata=0x13),
                  consumed=True, pending_response=(0x13, 1))
        with self.assertRaises(ValueError):
            self.edge(3, self.phase(ready=1, rdata=0x13),
                      self.phase(valid=0, marker=0))
        self.assertEqual((), self.observer.drain_source_completions())

    def issued_completion_with_isolated_binding_lookup(self):
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x80000000, 0x1000),),
                                  initialization_seed=1, max_initialized_bytes=64)
        memory.preload(0x80000040, b'\x13\x00\x00\x00')
        self.owner.memory = memory
        self.owner.service = MemoryService(memory, TransactionLedger())
        self.owner._native_source_completion_session = object()
        binding = NativeInstructionSourceBinding(
            'cpu', 'execution', 0, 0, object(), object(), object())
        key = self.accept()
        snapshot = self.owner.service.read(key, 0x80000040, width_bytes=4)
        self.observer.bind_read_snapshot(key, snapshot)
        self.edge(2, self.phase(), self.phase(ready=1, rdata=0x13),
                  consumed=True, pending_response=(0x13, 1))
        self.assertEqual((), self.observer.drain_source_completions())
        with patch('myfuzz.scenario.native_instruction_bus_completion.lookup_issued_source_for_read',
                   return_value=binding):
            self.edge(3, self.phase(ready=1, rdata=0x13),
                      self.phase(valid=0, marker=0))
        completions = self.observer.drain_source_completions()
        self.assertEqual(1, len(completions))
        return completions[0], binding, key, snapshot

    def test_issued_completion_requires_next_pre_and_revokes_read_handle(self):
        completion, binding, key, snapshot = self.issued_completion_with_isolated_binding_lookup()
        self.assertIs(completion.key, key)
        self.assertIs(completion.snapshot, snapshot)
        self.assertIs(completion.binding, binding)
        self.assertEqual('native_instruction_bus_completion.v1',
                         completion.schema_version)
        self.assertEqual('native_instruction_bus_transfer_completed',
                         completion.proof_scope)
        self.assertFalse(completion.grants_source_authority)
        from myfuzz.scenario.memory_service import _LOOKUP_ISSUED_READ
        with self.assertRaises(ValueError):
            _LOOKUP_ISSUED_READ(self.owner.service, self.owner.memory, key, snapshot)

    def test_replaced_completion_key_is_not_an_issued_result(self):
        completion, binding, key, _ = self.issued_completion_with_isolated_binding_lookup()
        equal_key = TransactionKey(**vars(key))
        object.__setattr__(completion, 'key', equal_key)
        with patch('myfuzz.scenario.native_instruction_bus_completion.validate_issued_binding',
                   return_value=binding):
            with self.assertRaises(ValueError):
                validate_issued_native_completion(self.observer, completion)

    def test_mutated_original_key_fields_refuse_issued_result(self):
        completion, binding, key, _ = self.issued_completion_with_isolated_binding_lookup()
        object.__setattr__(key, 'testcase_id', 'different-case')
        with patch('myfuzz.scenario.native_instruction_bus_completion.validate_issued_binding',
                   return_value=binding):
            with self.assertRaises(ValueError):
                validate_issued_native_completion(self.observer, completion)

    def test_replaced_completion_snapshot_and_changed_fields_refuse(self):
        for field in ('snapshot', 'binding', 'address', 'data', 'accepted_scope',
                      'response_scope', 'completion_scope', 'native_pre'):
            with self.subTest(field=field):
                self.setUp()
                completion, binding, _, snapshot = self.issued_completion_with_isolated_binding_lookup()
                replacement = {
                    'snapshot': ReadSnapshot(**vars(snapshot)),
                    'binding': replace(binding),
                    'address': completion.address + 4,
                    'data': b'\x14\x00\x00\x00',
                    'accepted_scope': ('changed', *completion.accepted_scope[1:]),
                    'response_scope': ('changed', *completion.response_scope[1:]),
                    'completion_scope': ('changed', *completion.completion_scope[1:]),
                    'native_pre': (*completion.native_pre[:-1], 0),
                }[field]
                object.__setattr__(completion, field, replacement)
                with patch('myfuzz.scenario.native_instruction_bus_completion.validate_issued_binding',
                           return_value=binding):
                    with self.assertRaises(ValueError):
                        validate_issued_native_completion(self.observer, completion)

    def test_reset_revokes_issued_completion_token(self):
        completion, binding, _, _ = self.issued_completion_with_isolated_binding_lookup()
        self.observer.cancel_reset()
        with patch('myfuzz.scenario.native_instruction_bus_completion.validate_issued_binding',
                   return_value=binding):
            with self.assertRaises(ValueError):
                validate_issued_native_completion(self.observer, completion)

    def test_epoch_change_revokes_token_even_if_epoch_value_returns(self):
        completion, binding, _, _ = self.issued_completion_with_isolated_binding_lookup()
        self.owner.reset_epoch = 1
        self.edge(1, self.phase(valid=0, marker=0),
                  self.phase(valid=0, marker=0))
        self.owner.reset_epoch = 0
        with patch('myfuzz.scenario.native_instruction_bus_completion.validate_issued_binding',
                   return_value=binding):
            with self.assertRaises(ValueError):
                validate_issued_native_completion(self.observer, completion)


class NativeServiceKeyIdentityTests(unittest.TestCase):
    def test_case_start_abort_and_finish_revoke_source_completion(self):
        session = object.__new__(GeneratedNativeMemorySession)
        calls = []
        observer = SimpleNamespace(failed=False, pending=None,
            revoke_source_completion=lambda: calls.append('revoke'))
        session._native_bus_observer = observer
        session._process = None
        with patch.object(GeneratedLocalSession, 'begin_case', return_value=None), \
             patch.object(GeneratedLocalSession, '_abort', return_value=None), \
             patch.object(GeneratedLocalSession, 'end_case', return_value=None):
            session.begin_case('case')
            session._abort()
            session.end_case()
        self.assertEqual(['revoke'] * 3, calls)

    def test_step_services_the_observers_original_accepted_key(self):
        for session_type in (GeneratedNativeMemorySession, DeferredNativeMemorySession):
            with self.subTest(session_type=session_type.__name__):
                self._assert_step_services_original_key(session_type)

    def test_deferred_services_expected_key_without_observer(self):
        self._assert_step_services_original_key(DeferredNativeMemorySession,
                                                observer_enabled=False)

    def _assert_step_services_original_key(self, session_type, *, observer_enabled=True):
        session = object.__new__(session_type)
        key = TransactionKey('local-execution', 'testcase', 'cpu', 0, 'memory', 1)
        accepted = []
        backend = dict(m_req_valid=1, m_req_ready=1, m_req_addr=0x80000040,
            m_req_write=0, m_req_be=15, m_req_wdata=0,
            m_rsp_valid=0, m_rsp_ready=0, m_rsp_rdata=0, m_rsp_error=0)
        sample = dict(pre=dict(backend=backend, physical={'instr': 1}),
                      post=dict(backend=backend, physical={'instr': 1}))
        receipt = SimpleNamespace(status='result', new_ticks=1,
            payload=dict(pre_backend=backend, samples=[sample],
                         observations=dict(physical={})))
        session.command = lambda operation, controls: receipt
        session._native_request_ready = lambda available: 1
        session._observe_verified_memory_edge = lambda result: None
        session._native_bus_observer = (
            SimpleNamespace(observe=lambda *args: key) if observer_enabled else None)
        session._service_accepted_request = lambda actual, *args: (
            accepted.append(actual) or 0x13)
        session.memory = SimpleNamespace(advance_step=lambda: None)
        session.artifact = SimpleNamespace(plan=SimpleNamespace(
            request=SimpleNamespace(instance_id='cpu')))
        session._artifact_document = dict(physical_exports=[],
            instruction_identity_observation='instr')
        session._pending = None
        session._quiescing = False
        session._sequence_memory = 0
        session._case_id = 'testcase'
        session.reset_epoch = 0
        session.accepted_addresses = []
        session.native_instruction_fetch_count = 0
        session._online_instruction_slots = False
        session._queued_mmio = False
        session._check_native_online_acceptance = lambda *args: None
        session.last_samples = ()
        session.step_local({})
        self.assertEqual(1, len(accepted))
        if observer_enabled:
            self.assertIs(accepted[0], key)
        else:
            self.assertEqual(accepted[0], key)
