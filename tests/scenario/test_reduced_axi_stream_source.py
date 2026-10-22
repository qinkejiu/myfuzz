"""Software transport fixtures; these are not live native execution evidence."""
import copy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
import pytest
from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.local_harness.vexii_axi_session import GeneratedReducedAxiCpuSession
from myfuzz.local_harness.vexii_axi_fields import SHAPES, STEP_PORTS
from myfuzz.local_harness.wire import DriverReceipt


def cpu(monkeypatch):
    c = object.__new__(GeneratedReducedAxiCpuSession)
    c.source_component = 'renamed'
    c._artifact_document = {'artifact_digest': 'a'*64}
    c._execution = c._case_id = ''
    c._process = None
    c._sequence = c.local_ticks = c._tick_base = c.reset_epoch = 0
    c._native_reset_observation = None
    c._last_wire_reply = None
    c._clear()
    executions = iter(('e'*32, 'f'*32, '1'*32))
    def begin(self, case):
        self._execution = next(executions)
        self._case_id = case
        self._tick_base = self.local_ticks
        self._sequence = 0
        self._process = object()
    def end(self):
        self._process = None
        self._case_id = None
    monkeypatch.setattr(GeneratedLocalSession, 'begin_case', begin)
    monkeypatch.setattr(GeneratedLocalSession, 'end_case', end)
    c.calls = []
    def command(self, operation, fields):
        self.calls.append((operation, fields))
        before = self.local_ticks - self._tick_base
        row = {p+'_'+r: 0 for p, shape in SHAPES.items() for r in shape}
        row.update(zip(STEP_PORTS, fields))
        row.update(getattr(self, 'signals', {}))
        sample = {'local_tick': before+1, 'pre': {'backend': row},
                  'post': {'backend': copy.deepcopy(row)}}
        receipt = DriverReceipt('result', self._execution, self._sequence+1,
            before, before+1, 1, {'kind': self.artifact_kind, 'pre_backend': row,
              'samples': [sample], 'observations': {'physical': {}}})
        self._last_wire_reply = 'ORIGINAL WIRE REPLY\n'
        self.local_ticks += 1
        self._sequence += 1
        self.last_fixture_receipt = receipt
        return receipt
    monkeypatch.setattr(GeneratedLocalSession, 'command', command)
    return c


def admit(c, **limits):
    return c.admit_observation_stream(session_id='session', observer_stream_id='stream', **limits)


def records(s):
    return [s.lookup(t) for t in s.pending()]


def test_disabled_and_late_admission(monkeypatch):
    c = cpu(monkeypatch)
    assert c.observation_stream_source is None
    c.begin_case('case')
    with pytest.raises(ValueError, match='late'):
        admit(c)


def test_empty_lifecycle_and_no_reenable(monkeypatch):
    c = cpu(monkeypatch); s = admit(c)
    c.begin_case('case'); c.end_case(); c.end_case()
    assert [r['kind'] for r in records(s)] == ['begin_scope', 'end_scope', 'end_scope']
    assert [r['operation_index'] for r in records(s)] == [1, 2, 3]
    with pytest.raises(ValueError): admit(c)
    c.seal_observation_stream()
    assert s.state == 'sealed'
    assert records(s)[-1]['kind'] == 'seal'


def test_receipt_immutable_original_fields_and_tick_domains(monkeypatch):
    c = cpu(monkeypatch); s = admit(c)
    for i in range(2):
        c.begin_case('case')
        c.command('STEP_REDUCED_AXI', tuple(c._ready_inputs()[n] for n in STEP_PORTS))
        c.end_case()
    rs = [r for r in records(s) if r['kind'] == 'receipt']
    assert [r['payload']['receipt']['sequence'] for r in rs] == [1, 1]
    assert [r['payload']['receipt']['tick_after'] for r in rs] == [1, 1]
    assert [r['payload']['cumulative_after'] for r in rs] == [1, 2]
    assert rs[0]['payload']['receipt']['execution'] != rs[1]['payload']['receipt']['execution']
    assert rs[-1]['payload']['receipt'] == asdict(c.last_fixture_receipt)
    assert rs[-1]['payload']['wire_reply'] == 'ORIGINAL WIRE REPLY\n'
    assert rs[-1]['payload']['wire_command'].endswith('\n')
    c.runtime_events[0]['raw_sample']['local_tick'] = 900
    c.last_fixture_receipt.payload['samples'][0]['local_tick'] = 800
    assert [r for r in records(s) if r['kind']=='receipt'] == rs
    assert rs[0]['observations'][0]['raw_event_ref'] == rs[0]['first_record_index']


def test_observer_violation_issued_before_poison(monkeypatch):
    c = cpu(monkeypatch); s = admit(c); c.begin_case('case')
    c.signals = {'i_rvalid': 1, 'i_rlast': 1}
    c._state['i']['read'] = {'id':0, 'data':0}
    with pytest.raises(Exception, match='orphan_r'):
        c.command('STEP_REDUCED_AXI', tuple(c._ready_inputs()[n] for n in STEP_PORTS))
    assert s.state == 'active'
    r = records(s)[-1]
    assert r['kind']=='receipt' and r['payload']['receipt']['status']=='result'
    assert [e['kind'] for e in r['observations']] == ['reduced_axi_raw', 'reduced_axi_violation']
    with pytest.raises(Exception): c.command('STEP_REDUCED_AXI', ())
    assert len(c.calls)==1


def test_source_failure_blocks_next_transport(monkeypatch):
    c = cpu(monkeypatch); s = admit(c, max_pending_operations=1)
    c.begin_case('case')
    with pytest.raises(Exception):
        c.command('STEP_REDUCED_AXI', tuple(c._ready_inputs()[n] for n in STEP_PORTS))
    assert s.state == 'poisoned'
    assert c.observation_stream_failure_evidence['payload']['receipt']['sequence'] == 1
    with pytest.raises(Exception): c.command('STEP_REDUCED_AXI', ())
    assert len(c.calls)==1


@pytest.mark.parametrize('slot', ['read', 'aw', 'w', 'write'])
def test_reset_pending_slots_and_single_transition(monkeypatch, slot):
    c = cpu(monkeypatch); s = admit(c); c.begin_case('case')
    c._axi_observer._state['d'][slot] = {'refs':[1]}
    c._state['d']['read'] = {'id':0, 'data':0}
    c.reset_local()
    assert [r['kind'] for r in records(s)] == ['begin_scope','end_scope','begin_scope']
    end = records(s)[1]
    assert end['observations'][0]['cancelled']['d'][slot]
    assert not any(any(v.values()) for v in c._axi_observer.pending.values())
    assert c._axi_observer.scope['execution_id']=='f'*32


def test_clear_cannot_discard_active_pending(monkeypatch):
    c=cpu(monkeypatch); admit(c); c.begin_case('case')
    c._axi_observer._state['i']['read']={'refs':[1]}
    with pytest.raises(Exception, match='pending'): c._clear()


def test_seal_keeps_open_pending_and_does_not_cancel(monkeypatch):
    c=cpu(monkeypatch); s=admit(c); c.begin_case('case')
    c._axi_observer._state['i']['read']={'refs':[1]}
    c.seal_observation_stream()
    assert s.state=='sealed'
    assert records(s)[-1]['payload']['pending']['i']['read']
    assert not records(s)[-1]['observations']
    assert c._axi_observer.scope is not None


def test_source_modules_in_build_closure():
    from myfuzz.local_harness.build import _discover_host_sources
    closure = _discover_host_sources()
    for name in ('reduced_axi_stream_source', 'observation_stream'):
        path='src/myfuzz/scenario/'+name+'.py'
        assert path in closure


def test_protocol_failure_cannot_reopen_after_end(monkeypatch):
    c=cpu(monkeypatch); s=admit(c); c.begin_case('case')
    c.signals={'i_rvalid':1,'i_rlast':1}
    c._state['i']['read']={'id':0,'data':0}
    with pytest.raises(Exception):
        c.command('STEP_REDUCED_AXI', tuple(c._ready_inputs()[n] for n in STEP_PORTS))
    c.end_case()
    with pytest.raises(Exception): c.begin_case('again')
    c.seal_observation_stream()
    assert s.state=='sealed'
    assert records(s)[-1]['payload']['outcome']=='observed_protocol_failure'


def test_session_service_failure_blocks_transport(monkeypatch):
    c=cpu(monkeypatch); s=admit(c); c.begin_case('case')
    def failed_memory():
        raise RuntimeError('service failed')
    c.memory=SimpleNamespace(advance_step=failed_memory)
    with pytest.raises(Exception, match='service failed'): c.step_local({})
    assert s.state=='active'
    assert records(s)[-1]['kind']=='receipt'
    with pytest.raises(Exception): c.command('STEP_REDUCED_AXI', ())
    assert len(c.calls)==1


def test_parsed_error_retained_no_success_sample(monkeypatch):
    from myfuzz.local_harness.wire import parse_driver_receipt
    c=cpu(monkeypatch); s=admit(c); c.begin_case('case')
    line=f'ERROR {c._execution} 1 0 protocol_environment driver_fault\n'
    def error(self, operation, fields):
        self.calls.append((operation,fields)); self._last_wire_reply=line
        return parse_driver_receipt(line.strip(), execution=self._execution,
            sequence=1,current_tick=0,kind=self.artifact_kind)
    monkeypatch.setattr(GeneratedLocalSession,'command',error)
    with pytest.raises(Exception,match='driver_fault'):
        c.command('STEP_REDUCED_AXI', tuple(c._ready_inputs()[n] for n in STEP_PORTS))
    r=records(s)[-1]
    assert r['payload']['receipt']['status']=='error'
    assert r['payload']['wire_reply']==line and r['observations']==[]
    assert s.state=='poisoned'


def test_alias_is_distinct_from_source_component(monkeypatch):
    a=cpu(monkeypatch); b=cpu(monkeypatch)
    a.source_component=a._axi_observer.component_id='physical-a'
    b.source_component=b._axi_observer.component_id='physical-b'
    sa=admit(a); sb=b.admit_observation_stream(session_id='other',observer_stream_id='stream-b')
    sessions={'runner-alias-one':a,'runner-alias-two':b}
    assert sessions['runner-alias-one'].observation_stream_source is sa
    assert sa.identity_document()['source_component']=='physical-a'
    assert sb.identity_document()['source_component']=='physical-b'
    a.begin_case('case')
    a.command('STEP_REDUCED_AXI', tuple(a._ready_inputs()[n] for n in STEP_PORTS))
    receipt=records(sa)[-1]
    assert receipt['operation_index']==2 and receipt['payload']['receipt']['sequence']==1


def test_disabled_close_and_reset_keep_original_observer_prefix(monkeypatch):
    c=cpu(monkeypatch); c.begin_case('case'); c.end_case()
    assert c.runtime_events==[]
    c.begin_case('case')
    before=len(c.runtime_events)
    c.reset_local()
    assert len(c.runtime_events)==before+1
    assert c.runtime_events[-1]['kind']=='reduced_axi_reset'
    assert c.observation_stream_source is None


def test_scope_reuse_refused_after_end(monkeypatch):
    from myfuzz.scenario.reduced_axi_events import ReducedAxiObserver
    from myfuzz.scenario.reduced_axi_stream_source import ReducedAxiStreamExport
    o=ReducedAxiObserver(component_id='source')
    e=ReducedAxiStreamExport(o,session_id='s',observer_stream_id='o',
        artifact_digest='a'*64,source_component='source')
    scope=dict(execution_id='exec',testcase_id='c',reset_epoch=0)
    e.begin(scope); e.end()
    with pytest.raises(ValueError,match='reuse'): e.begin(scope)
    assert e.source.state=='poisoned'


def test_parser_result_and_physical_failure_retains_only_receipt(monkeypatch):
    import json
    from myfuzz.local_harness.wire import parse_driver_receipt
    c=cpu(monkeypatch); s=admit(c); c.begin_case('case')
    row={p+'_'+r:0 for p,shape in SHAPES.items() for r in shape}
    payload={'schema_version':'local_driver_result.v1','kind':c.artifact_kind,
        'pre_backend':row,'samples':[{'local_tick':1,'pre':{'backend':row},
        'post':{'backend':copy.deepcopy(row)}}], 'observations':{}, 'rdata':0,'error':0}
    raw=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
    line=f'RESULT {c._execution} 1 0 1 {raw.hex()}\n'
    r=parse_driver_receipt(line.strip(),execution=c._execution,sequence=1,
        current_tick=0,kind=c.artifact_kind)
    def parsed(self, operation, fields):
        self._last_wire_reply=line; self.local_ticks=1; self._sequence=1
        return r
    monkeypatch.setattr(GeneratedLocalSession,'command',parsed)
    # True wire receipt, but backend ARREADY differs from actual sent fields.
    with pytest.raises(Exception,match='physical'):
        c.command('STEP_REDUCED_AXI',tuple(c._ready_inputs()[n] for n in STEP_PORTS))
    assert records(s)[-1]['payload']['receipt']==asdict(r)
    assert records(s)[-1]['payload']['wire_reply']==line
    assert records(s)[-1]['observations']==[]
    assert s.state=='poisoned'


def test_irq_contract_uses_same_source_without_cpu_name_dispatch(monkeypatch):
    from myfuzz.local_harness.vexii_axi_session import GeneratedReducedAxiIrqCpuSession
    c=cpu(monkeypatch)
    c.__class__=GeneratedReducedAxiIrqCpuSession
    c.irq_level=0; c.irq_edges=[]
    s=admit(c); c.begin_case('case')
    # Software fixture maps trailing reduced-AXI input fields, preserving IRQ.
    original=GeneratedLocalSession.command
    def irq(self, operation, fields):
        return original(self,operation,fields[1:])
    monkeypatch.setattr(GeneratedLocalSession,'command',irq)
    fields=(1,)+tuple(c._ready_inputs()[n] for n in STEP_PORTS)
    c.command('STEP_REDUCED_AXI_IRQ',fields)
    assert records(s)[-1]['payload']['command_fields']==list(fields)
    assert s.identity_document()['observer_contract']==c._axi_observer.contract


def test_failed_begin_issued_as_lifecycle_failure(monkeypatch):
    c=cpu(monkeypatch); s=admit(c)
    def failed_begin(self, case):
        raise RuntimeError('software startup failure')
    monkeypatch.setattr(GeneratedLocalSession,'begin_case',failed_begin)
    with pytest.raises(RuntimeError,match='startup failure'): c.begin_case('case')
    assert s.state=='poisoned'
    assert records(s)[-1]['kind']=='begin_scope'
    assert records(s)[-1]['observations']==[]
    assert records(s)[-1]['payload']['failure']['detail']=='software startup failure'


def test_real_service_w_tuple_reset_is_strict_json(monkeypatch):
    c=cpu(monkeypatch); s=admit(c); c.begin_case('case')
    c._state['d']['w']=(0x1234,15)
    c._axi_observer._state['d']['w']={'strobe':15,'refs':[1],'tick':1}
    c.reset_local()
    end=records(s)[1]
    assert end['payload']['service_pending']['d']['w'] is True
    assert end['observations'][0]['pending_request_refs']['d']['w']['refs']==[1]
    assert s.state=='active'


@pytest.mark.parametrize('drift', ['listener','source','observer','export_observer',
                                   'export_removed','export_replaced','contract','component'])
@pytest.mark.parametrize('entry', ['command','seal','source_read'])
def test_admitted_owner_drift_poisons_original_before_transport(monkeypatch, drift, entry):
    from myfuzz.scenario.observation_stream import ObservationStreamSource
    from myfuzz.scenario.reduced_axi_events import ReducedAxiObserver
    c=cpu(monkeypatch); s=admit(c); c.begin_case('case')
    e=c._observation_export
    if drift=='listener': c._axi_observer._emit_listener=None
    elif drift=='source': e.source=ObservationStreamSource(binding=s.identity_document())
    elif drift in ('observer','export_observer'):
        replacement=ReducedAxiObserver(component_id=c.source_component)
        replacement.begin_scope(execution_id=c._execution,testcase_id='case',reset_epoch=0)
        if drift=='observer': c._axi_observer=replacement
        else: e.observer=replacement
    elif drift=='export_removed': del c._observation_export
    elif drift=='export_replaced': c._observation_export=None
    elif drift=='contract': c._axi_observer.contract['sampling']='tampered'
    else: c.source_component='other'
    with pytest.raises(Exception,match='integrity|ownership|binding'):
        if entry=='command': c.command('STEP_REDUCED_AXI',tuple(0 for _ in STEP_PORTS))
        elif entry=='seal': c.seal_observation_stream()
        else: _=c.observation_stream_source
    assert s.state=='poisoned'
    assert c.calls==[]
    assert records(s)[-1]['kind']=='begin_scope'


def test_capture_ordinal_error_cannot_be_hidden_by_protocol_failed(monkeypatch):
    c=cpu(monkeypatch); s=admit(c); c.begin_case('case')
    o=c._axi_observer; original=o._fail
    def corrupt(reason, raw_ref):
        o._record_count+=1
        return original(reason,raw_ref)
    o._fail=corrupt
    c.signals={'i_rvalid':1,'i_rlast':1}
    c._state['i']['read']={'id':0,'data':0}
    with pytest.raises(Exception,match='ordinal mismatch'):
        c.command('STEP_REDUCED_AXI',tuple(c._ready_inputs()[n] for n in STEP_PORTS))
    assert o._failed
    assert s.state=='poisoned'
    assert c.observation_stream_failure_evidence is not None
    with pytest.raises(Exception): c.seal_observation_stream()
    assert not [r for r in records(s) if r['kind']=='seal']


def test_guard_failure_still_tears_down_native_process(monkeypatch):
    c=cpu(monkeypatch); s=admit(c); c.begin_case('case')
    c._axi_observer._emit_listener=None
    with pytest.raises(Exception,match='integrity'): c.end_case()
    assert c._process is None
    assert s.state=='poisoned'


def test_terminal_seal_counts_and_chain_survive_ack_and_reset(monkeypatch):
    import hashlib
    import json
    c=cpu(monkeypatch); s=admit(c)
    encoded=json.dumps(s.identity_document(),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    chain=hashlib.sha256(encoded).hexdigest()
    issued=[]
    c.begin_case('case')
    c.command('STEP_REDUCED_AXI',tuple(c._ready_inputs()[n] for n in STEP_PORTS))
    issued.extend(records(s))
    for token in s.pending(): s.ack(token)
    c.reset_local()
    issued.extend(records(s))
    for row in issued:
        chain=hashlib.sha256((chain+':'+row['content_digest']).encode('ascii')).hexdigest()
    c.seal_observation_stream()
    seal=records(s)[-1]['payload']
    assert seal['prior_operation_count']==4
    assert seal['prior_record_count']==sum(r['record_count'] for r in issued)
    assert seal['prior_kind_counts']=={'begin_scope':2,'end_scope':1,'receipt':1,'seal':0}
    assert seal['prior_operation_chain_sha256']==chain


def test_contract_numeric_type_drift_is_not_equal_binding(monkeypatch):
    c=cpu(monkeypatch); s=admit(c); c.begin_case('case')
    c._axi_observer.contract['budgets']['read_per_face']=True
    with pytest.raises(Exception,match='integrity'): _=c.observation_stream_source
    assert s.state=='poisoned'


@pytest.mark.parametrize('replacement', [True, 1.0])
def test_export_limit_exact_type_drift_refused_before_begin(monkeypatch, replacement):
    c=cpu(monkeypatch); s=admit(c,max_pending_operations=1)
    c._observation_export.limits['max_pending_operations']=replacement
    with pytest.raises(RuntimeError,match='integrity'): c.begin_case('case')
    assert s.state=='poisoned'
    assert c._process is None
    assert s.pending()==()
