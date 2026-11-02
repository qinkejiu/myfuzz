"""Epoch rebind must use the image actually installed after a reset."""
from types import SimpleNamespace
import pytest

from myfuzz.integration import compiled_f6
from myfuzz.integration.compiled_f6_firmware import build_f6_firmware, render_epoch_program
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from tests.integration.test_compiled_f6_epoch_entry import contract


def runtime_with_image(*, installed=True):
    c = contract(4)
    original = build_f6_firmware(c)
    epoch = render_epoch_program(c, reset_epoch=1, slot=1)
    addr = c['program_contract']['boot_address']
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                              initialization_seed=0, max_initialized_bytes=0x20000)
    memory.preload(addr, original.initial_images[addr])
    barrier = {'event_id': 1, 'kind': 'reset_barrier', 'policy': 'warm_all'}
    image = {'event_id': 2, 'kind': 'reset_image', 'reset_event_id': 1,
             'component': 'cpu', 'address': addr,
             'data_hex': epoch['program'].initial_images[addr].hex()}
    if installed:
        memory.reinstall_image(addr, bytes.fromhex(image['data_hex']), event_id='reset-image:2')
    events = [barrier, image] if installed else [barrier]
    runner = SimpleNamespace(event_count=len(events),
        _event_ref_by_id=lambda n: next((e for e in events if e['event_id']==n), None),
        _event_refs_since=lambda cursor, stop=None: events[cursor:stop])
    return SimpleNamespace(contract=c, program=original, memory=memory, runner=runner,
                           cpu_id='cpu'), epoch


def test_epoch_binding_requires_the_measured_installed_boot_bytes():
    runtime, epoch = runtime_with_image()
    result = compiled_f6._validate_epoch_boot_image(runtime, reset_policy='warm_all',
                                        barrier_event_id=1, expected_epoch=1, next_slot=1)
    assert result['entry'] == epoch['entry']
    assert result['image_event_id'] == 2
    runtime, _ = runtime_with_image(installed=False)
    with pytest.raises(ValueError, match='epoch-program-unbound'):
        compiled_f6._validate_epoch_boot_image(runtime, reset_policy='warm_all',
                                   barrier_event_id=1, expected_epoch=1, next_slot=1)


def test_epoch_binding_refuses_modified_memory_after_install():
    runtime, _ = runtime_with_image()
    address = runtime.contract['program_contract']['boot_address']
    runtime.memory.write(address, 0, width_bytes=4, byte_enable=15, writer_event_id='overwrite')
    with pytest.raises(ValueError, match='epoch-program-unbound'):
        compiled_f6._validate_epoch_boot_image(runtime, reset_policy='warm_all',
                                   barrier_event_id=1, expected_epoch=1, next_slot=1)


@pytest.mark.parametrize('slot', [0, -1, 4, True])
def test_rebind_rejects_used_or_nonexistent_slot(slot):
    runtime = object.__new__(compiled_f6.CompiledF6Runtime)
    runtime.contract = {'program_contract': {'slot_count': 4}}
    with pytest.raises(ValueError, match='reset-rebind-slot'):
        runtime.rebind_reset_epoch(reset_policy='warm_all', barrier_event_id=1,
                                   expected_epoch=1, next_slot=slot)


@pytest.mark.parametrize('source_status', ['running','failure'])
def test_reset_bootstrap_samples_irq_sources_before_advancing_cpu(monkeypatch,source_status):
    from hashlib import sha256
    from myfuzz.integration import shared_f6_assembly,shared_f6_slots
    from myfuzz.scenario import f6_instruction_fetch_receipt
    class Process:
        pid=100
        def poll(self):return None
    cpu=SimpleNamespace(reset_epoch=1,_case_id='case',process=Process(),_execution='cpu-new')
    dma=SimpleNamespace(reset_epoch=1,process=Process(),_execution='dma-new')
    boot=b'boot'
    epoch=dict(boot_sha256=sha256(boot).hexdigest(),entry={'entry_address':0x11000})
    calls=[]
    def advance(schedule):
        calls.append(('advance',schedule))
        return SimpleNamespace(violations=(),status=source_status)
    runtime=SimpleNamespace(finished=False,_begin_state='begun',_terminal_error=None,
        cpu=cpu,dma=dma,cpu_id='cpu',_f6_original_cpu_reset_epoch=0,
        _f6_original_cpu_case_id='case',_f6_original_cpu_process=object(),
        _f6_original_dma_process=object(),contract={'program_contract':{
            'slot_count':4,'boot_address':0x10000,'gpio_irq':{}}},
        session=SimpleNamespace(_reset_operations=[dict(image=dict(address=0x10000,
            component='cpu',data_hex=boot.hex()))],advance_after_reset=advance),
        runner=SimpleNamespace(command_epoch=1),_epoch_launch=dict(reset_epoch=1,
            barrier_event_id=1,policy='warm_all'),_process_identities={'ok':True},
        _validated_build_process_identities=lambda:{'ok':True},artifacts={},base_dir='.',
        run_id='run',execution_binding_sha256='a'*64,max_cases=4,
        _bootstrap_to_first_slot=lambda **kw:calls.append(('bootstrap',kw['entry_address'])))
    monkeypatch.setattr(compiled_f6,'_validate_epoch_boot_image',lambda *a,**kw:epoch)
    monkeypatch.setattr(shared_f6_slots,'rebind_slot_scope',lambda *a,**kw:None)
    monkeypatch.setattr(f6_instruction_fetch_receipt,'install_f6_instruction_fetch',lambda *a,**kw:None)
    group=SimpleNamespace(members=(SimpleNamespace(source_component='dma'),
                                   SimpleNamespace(source_component='peripheral')))
    monkeypatch.setattr(shared_f6_assembly,'shared_irq_group',lambda *a,**kw:group)
    if source_status=='running':
        compiled_f6.CompiledF6Runtime.rebind_reset_epoch(runtime,reset_policy='warm_all',
            barrier_event_id=1,expected_epoch=1,next_slot=1)
        assert calls==[('advance',('dma','peripheral')),('bootstrap',0x11000)]
    else:
        with pytest.raises(RuntimeError,match='IRQ-source-sampling'):
            compiled_f6.CompiledF6Runtime.rebind_reset_epoch(runtime,reset_policy='warm_all',
                barrier_event_id=1,expected_epoch=1,next_slot=1)
        assert calls==[('advance',('dma','peripheral'))]


@pytest.mark.parametrize('with_reset', [False, True])
def test_export_projection_preserves_bound_plan_and_reset_timeline(with_reset, monkeypatch):
    import json
    from dataclasses import replace
    from myfuzz.scenario.genome import MemoryImage
    from tests.scenario.test_bound_instruction_session import Cpu, configured, candidate
    initial=MemoryImage('boot','cpu',0x1000,'13000000')
    monkeypatch.setattr(Cpu,'reset_local',lambda self:{'cancelled_responses':0},raising=False)
    session=configured();session.template=replace(session.template,initial_images=(initial,))
    session.begin();session.submit_case(candidate(session,0x1004))
    if with_reset:
        session.reset('warm_all',image=replace(initial,data_hex='93001000'))
        session.advance_after_reset(('cpu',))
    runtime=SimpleNamespace(session=session,runner=session.runner,
        contract={'program_contract':{}},artifacts={'cpu':object()},
        attempts=[{'case_id':'one'}])
    monkeypatch.setattr(compiled_f6,'_f6_runtime_case_advances',lambda runtime:session.cases[0].advances)
    actual=json.loads(session.encode_plan())
    projected=compiled_f6._f6_expected_online_plan(runtime)
    assert actual==projected
    assert actual['schema_version']==(26 if with_reset else 24)
    assert compiled_f6._f6_export_failure(runtime,'online_plan',actual) is None
    altered=dict(actual)
    if with_reset:
        altered['reset_operations']=[dict(actual['reset_operations'][0],policy='cold_all')]
    else:
        altered['instruction_image_bindings']=[]
    assert compiled_f6._f6_export_failure(runtime,'online_plan',altered)=='online-plan-shape-or-cases'
    session.finish()


def test_finish_case_gate_accepts_reset_plan_but_not_terminal_plan():
    runtime=SimpleNamespace(contract={'program_contract':{}},
        attempts=[{'case_id':'case','status_kind':'passed'}], records=[{}])
    def check(plan):
        return compiled_f6._f6_finish_state_failure(runtime,online_plan=plan,
            assertion_material={},feedback=[],final_dma_case_id='dma')
    assert check({'schema_version':26}) != 'case-terminal-online-plan-not-accepted'
    assert check({'schema_version':27,'terminal_failure':{}}) == 'case-terminal-online-plan-not-accepted'


def test_interrupted_diagnostic_preserves_failure_with_exportable_prefix(monkeypatch):
    from tests.integration.test_compiled_f6_runtime import _finish_gate_shell
    from myfuzz.runtime.flows.shared_slots import _finish_failed_runtime
    runtime = _finish_gate_shell(monkeypatch)
    monkeypatch.setattr(compiled_f6, '_f6_export_failure', lambda *a, **kw: None)
    monkeypatch.setattr(compiled_f6, '_f6_trace_failure', lambda *a: None)
    monkeypatch.setattr(compiled_f6, '_f6_finish_state_failure', lambda *a, **kw: None)
    interrupted = RuntimeError('diagnostic stopped')
    result = _finish_failed_runtime(runtime, interrupted)
    assert runtime._terminal_error is interrupted
    assert result['status'] == 'partial' and result['completed'] is False
    assert result['trace_status'] == 'complete'
    assert result['error']['error'] == 'diagnostic stopped'


def test_f6_replay_reapplies_saved_reset_at_case_boundary():
    from myfuzz.scenario.genome import MemoryImage
    from myfuzz.integration.compiled_f6 import _replay_f6_flow_timeline
    calls=[]
    class Session:
        def __init__(self):self.cases=[];self._reset_operations=[]
        def reset(self,policy,*,image):
            calls.append(('reset',policy,image.data_hex));runtime.runner.event_count+=1
            runtime.runner.command_epoch+=1
            self._reset_operations.append({'after_cases':len(self.cases),'policy':policy,'image':__import__('dataclasses').asdict(image)})
        def _encoded_reset_operations(self):
            return [dict(row,advances=[['dma','peripheral']]) for row in self._reset_operations]
    class Runtime:
        def __init__(self):
            self.session=Session();self.runner=SimpleNamespace(event_count=0,command_epoch=0,
                events_since=lambda n:({'kind':'reset_barrier','event_id':1,'policy':'warm_all'},))
        def submit(self,raw,*,flow):
            calls.append(('submit',flow,raw.hex()));self.session.cases.append(flow)
        def rebind_reset_epoch(self,**kwargs):calls.append(('rebind',kwargs))
    runtime=Runtime()
    image=MemoryImage('boot','cpu',0x1000,'93001000')
    operation={'after_cases':1,'policy':'warm_all','image':__import__('dataclasses').asdict(image),
               'advances':[['dma','peripheral']]}
    rows=[{'flow':'F3','raw_hex':'55000000'},{'flow':'F1','raw_hex':'03200000'}]
    _replay_f6_flow_timeline(runtime,rows,[operation])
    assert [row[0] for row in calls] == ['submit','reset','rebind','submit']
    assert calls[2][1] == {'reset_policy':'warm_all','barrier_event_id':1,'expected_epoch':1,'next_slot':1}

    calls.clear()
    runtime = Runtime()
    with pytest.raises(ValueError, match='reset-advance-mismatch'):
        _replay_f6_flow_timeline(runtime,rows,[dict(operation,advances=[['cpu']])])
    assert [row[0] for row in calls] == ['submit','reset','rebind']


def test_f6_replay_rejects_unreachable_or_uninstalled_reset():
    from myfuzz.integration.compiled_f6 import _replay_f6_flow_timeline
    runtime=SimpleNamespace(session=SimpleNamespace(cases=[]),runner=SimpleNamespace())
    with pytest.raises(ValueError,match='reset'):
        _replay_f6_flow_timeline(runtime,[],[{'after_cases':1,'policy':'warm_all'}])
