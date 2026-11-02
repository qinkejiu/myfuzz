"""Typed auxiliary pin actions, with no native proof claimed by these mocks."""
from types import SimpleNamespace
import pytest
from tests.integration.test_shared_f5_support_binding import all_six,ROOT


@pytest.fixture(scope='module')
def admitted(all_six):
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    return admit_compiled_f6_runtime_path(artifacts=dict(all_six.artifacts),compiled_inputs=all_six.compiled_inputs(),base_dir=ROOT)


@pytest.mark.parametrize('pin',[0,1])
def test_decoded_fifth_byte_is_a_real_typed_pin_action(all_six,admitted,pin):
    from myfuzz.integration.shared_slot_auxiliary import auxiliary_sources
    rows = auxiliary_sources(all_six.compiled_inputs()['compiled'],admitted,
        flow='F4',raw=bytes.fromhex('00010000')+bytes([pin]))
    assert len(rows)==1 and rows[0]['value']==pin
    assert rows[0]['component']=='peripheral' and rows[0]['bit_offset']==8 and rows[0]['width']==1
    assert rows[0]['path_id']==admitted['shared_flow_paths']['F5']['path_id']


def test_auxiliary_steps_preserve_CPU_and_separate_session_from_slot(all_six,admitted,monkeypatch):
    from myfuzz.integration import compiled_f6 as module,shared_f6_slots as slots,shared_slot_consumers
    class CPU: pass
    runtime = module.CompiledF6Runtime.__new__(module.CompiledF6Runtime)
    cpu = CPU();cpu._execution,cpu._case_id,cpu.reset_epoch='a'*32,'native',0
    cpu.process=SimpleNamespace(poll=lambda:None)
    runtime.cpu,runtime.memory,runtime.runner=cpu,object(),object()
    runtime.cpu_id,runtime.run_id,runtime.finished,runtime.cursor,runtime.max_cases='cpu','aux',False,0,4
    runtime.contract=admitted['execution_contract'];runtime.runtime_path_admission=admitted
    runtime.compiled_inputs=all_six.compiled_inputs()
    runtime.records,runtime.attempts,runtime.observer_view=[],[],[]
    runtime.layout=SimpleNamespace(decode=lambda raw:SimpleNamespace(raw=raw,words=(1,2,3,4)))
    runtime._verify_live_owner=lambda:True;runtime._drain_observer_view=lambda:None
    steps=[]
    class Session:
        def __init__(self):self._cases=[]
        def submit_case(self,case):
            assert tuple(case.advances[0].schedule)==('peripheral',)
            self._cases.append(case);steps.append(case.source.value)
            event=dict(event_id=len(steps),component='peripheral',inputs={case.source.port:case.source.value<<case.source.bit_offset},outputs={})
            return SimpleNamespace(status='running',violations=(),local_ticks_before={'cpu':11},local_ticks_after={'cpu':11},events=(event,))
    runtime.session=Session()
    monkeypatch.setattr(module,'advance_f6_dma_logical_scope',lambda *a,**k:None)
    declared_slots=[]
    def declare(*args,**kwargs):
        declared_slots.append(kwargs['slot_index'])
        return {}
    monkeypatch.setattr(shared_slot_consumers,'declare_slot',declare)
    def writer(owner,raw,mapping):
        evidence=slots.submit_auxiliary_sources(owner,mapping)
        owner.session._cases.append(SimpleNamespace(case_id=mapping['case_id']))
        result=dict(status='certified',auxiliary_sources=evidence)
        slots.seal_case(owner,mapping['case_id'],result,{'address':0})
        return result
    monkeypatch.setattr(slots,'submit_writer',writer)
    def execute(self,candidate,index,attempt):
        self.session._cases.append(SimpleNamespace(case_id=attempt['case_id']))
        event=dict(event_id=len(self.observer_view)+1,address=attempt['instruction_address']+256)
        self.observer_view.append(event);attempt['next_fetch']=event['event_id'];attempt['status_kind']='passed'
        return dict(status='passed',prefix_hex='00'*128,feedback=[1]*5)
    monkeypatch.setattr(module.CompiledF6Runtime,'_execute_case',execute)
    slots._RUNTIMES[runtime]=dict(cpu=cpu,memory=runtime.memory,runner=runtime.runner,session=runtime.session,scope=None,rows=[],
        pins=tuple((name,getattr(type(runtime),name),getattr(type(runtime),name).__code__) for name in ('submit','_execute_case')))
    monkeypatch.setattr(slots,'_HELPER_PINS',tuple((name,getattr(slots,name),getattr(slots,name).__code__) for name,_,_ in slots._HELPER_PINS))
    runtime.submit(bytes.fromhex('0001000001'),flow='F4')
    runtime.submit(bytes.fromhex('0110c00008000000'))
    runtime.submit(bytes.fromhex('0101000000'),flow='F4')
    runtime.submit(bytes.fromhex('0110c00008000000'))
    rows=slots.flow_records(runtime)
    assert steps==[1,0]
    assert declared_slots==[0,2]  # global main indices are 1 and 4
    assert [row['slot_index'] for row in rows]==[0,1,2,3]
    assert [row['session_case_index'] for row in rows]==[1,2,4,5]
    assert [row['f6_case_index'] for row in rows]==[None,0,None,1]
    assert len(runtime.session._cases)==6 and len(runtime.records)==len(runtime.attempts)==2
    assert [case.case_id for case in runtime.session._cases]==slots.session_case_ids(runtime)
    assert all(not row['CPU_advanced'] for item in rows for row in item.get('certificate',{}).get('auxiliary_sources',[]))


def test_partial_plan_keeps_auxiliary_and_excludes_only_unadmitted_reservation(monkeypatch):
    from myfuzz.integration import shared_f6_slots as slots
    rows=[dict(case_id='F4:1',status='passed',auxiliary_sources=[dict(case_id='F4:1:external:0')]),
          dict(case_id='F5:2',status='reserved')]
    runtime=SimpleNamespace(session=SimpleNamespace(_cases=[SimpleNamespace(case_id=value)
        for value in ('F4:1:external:0','F4:1')]))
    monkeypatch.setattr(slots,'flow_records',lambda owner:rows)
    assert slots.session_case_ids(runtime,admitted_only=True)==['F4:1:external:0','F4:1']
    assert slots.session_case_ids(runtime)==['F4:1:external:0','F4:1','F5:2']
    runtime.session._cases.pop()
    with pytest.raises(ValueError,match='only-current-reservation'):
        slots.session_case_ids(runtime,admitted_only=True)
    runtime.session._cases=[SimpleNamespace(case_id='wrong')]
    with pytest.raises(ValueError,match='admitted-session-prefix'):
        slots.session_case_ids(runtime,admitted_only=True)
