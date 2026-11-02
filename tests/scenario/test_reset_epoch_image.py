"""A reset can install a declared boot image and replay the same timeline."""
from dataclasses import replace
import json
import pytest

from myfuzz.scenario.genome import MemoryImage
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.session_runtime import ScenarioSession, replay_online_session
from myfuzz.scenario.native_reset_recovery import declare_reset_recovery
from myfuzz.integration.compiled_f6_firmware import build_f6_firmware, render_epoch_program
from tests.integration.test_compiled_f6_epoch_entry import contract
from tests.scenario.test_online_reset_replay import case, factory, _template


def memory_factory():
    runner = factory()
    runner.sessions['cpu'].memory = PersistentMemory(
        regions=(MemoryRegion('ram', 0, 4096),), initialization_seed=0,
        max_initialized_bytes=4096)
    return runner


@pytest.mark.parametrize('policy', ['warm_all', 'cold_all'])
def test_reset_reinstalls_declared_image_and_replays(policy):
    initial = MemoryImage('boot', 'cpu', 0x100, '11223344')
    changed = replace(initial, data_hex='55667788')
    template = replace(_template(), initial_images=(initial,))
    session = ScenarioSession(template, memory_factory())
    session.begin()
    before = session.runner.sessions['cpu'].memory.read(0x100, 4, transaction_id='before')
    session.submit_case(case(0))
    session.reset(policy, image=changed)
    session.advance_after_reset(('cpu',))
    read = session.runner.sessions['cpu'].memory.read(0x100, 4, transaction_id='boot')
    assert read.data == bytes.fromhex('55667788')
    assert read.versions != before.versions
    assert read.writer_kinds == ('RESET_IMAGE',) * 4
    session.submit_case(case(1))
    trace = session.finish()
    plan = session.encode_plan()
    assert json.loads(plan)['reset_operations'][0]['image']['data_hex'] == '55667788'
    assert json.loads(plan)['reset_operations'][0]['advances'] == [['cpu']]
    fresh_runners = []
    def fresh_factory():
        runner = memory_factory()
        fresh_runners.append(runner)
        return runner
    replay = replay_online_session(plan, fresh_factory, trace)
    assert replay.matches, replay.difference_context
    fresh_read = fresh_runners[0].sessions['cpu'].memory.read(0x100, 4, transaction_id='fresh')
    assert (fresh_read.data, fresh_read.versions, fresh_read.writer_event_ids) == (
        read.data, read.versions, read.writer_event_ids)
    original_events = [e for e in trace.events if e.get('kind') == 'reset_image']
    replay_events = [e for e in replay.actual_trace.events if e.get('kind') == 'reset_image']
    assert len(original_events) == 1 and replay_events == original_events


def test_reset_image_must_match_declared_image_location():
    initial = MemoryImage('boot', 'cpu', 0x100, '11223344')
    session = ScenarioSession(replace(_template(), initial_images=(initial,)), memory_factory())
    session.begin()
    session.submit_case(case(0))
    with pytest.raises(ValueError, match='declared image'):
        session.reset('warm_all', image=replace(initial, address=0x200))
    assert session.runner.command_epoch == 0
    session.finish()


def test_declared_f6_resume_entry_is_installed_during_session_reset():
    from types import SimpleNamespace
    program_contract = contract(4)
    firmware = build_f6_firmware(program_contract)
    images = tuple(MemoryImage(f'boot-{i}', 'cpu', address, data.hex())
                   for i, (address, data) in enumerate(sorted(firmware.initial_images.items())))
    def f6_factory():
        runner = factory()
        cpu = runner.sessions['cpu']
        cpu.memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                                      initialization_seed=0, max_initialized_bytes=0x20000)
        cpu.reset_epoch = 0
        cpu._execution = 'original'
        cpu.process = None
        def reset():
            cpu.reset_epoch += 1
            cpu._execution = 'fresh'
            return {'cancelled_responses': 0}
        cpu.reset_local = reset
        return runner
    session = ScenarioSession(replace(_template(), initial_images=images), f6_factory())
    session.begin(); session.submit_case(case(0))
    carrier = SimpleNamespace(session=session, submit=lambda *a, **kw: None)
    recovery = declare_reset_recovery(session.runner, policy='warm_all',
                                      sources=dict(session.runner.sessions), carrier=carrier,
                                      providers={'ram': SimpleNamespace(current_state=lambda: {})})
    recovery.declare_epoch_program(contract=program_contract, next_slot=1)
    recovery.reset_with_declared_program()
    expected = render_epoch_program(program_contract, reset_epoch=1, slot=1)
    boot_address = program_contract['program_contract']['boot_address']
    boot = expected['program'].initial_images[boot_address]
    actual = session.runner.sessions['cpu'].memory.read(boot_address + len(boot) - 4, 4, transaction_id='boot')
    assert actual.data == boot[-4:]
    assert any(e.get('kind') == 'reset_image' for e in session.runner.events_since(0))
    assert session._reset_operations[0]['image']['address'] == boot_address
    session.finish()


def test_f6_reset_probe_uses_declared_program_reset():
    from types import SimpleNamespace
    from scripts.run_reset_recovery_native import ResetRecoverySelector
    calls = []
    selector = object.__new__(ResetRecoverySelector)
    selector.recovery = SimpleNamespace(reset_with_declared_program=lambda: calls.append('reset'))
    selector._apply_reset()
    assert calls == ['reset']


@pytest.mark.parametrize('install_image', [True, False])
def test_recovery_calls_epoch_rebind_only_after_session_installs_image(install_image):
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6 import _validate_epoch_boot_image
    from myfuzz.scenario.ownership import InputField,InputOwner,compile_ownership
    from myfuzz.scenario.runner import ScenarioRunner
    from tests.scenario.test_reset_continuation_chain import _AuditedSession,_EpochCarrier
    program_contract=contract(4)
    program=build_f6_firmware(program_contract)
    memory=PersistentMemory(regions=(MemoryRegion('ram',0x10000,0x20000),),
        initialization_seed=0,max_initialized_bytes=0x20000)
    cpu=_AuditedSession(memory,'cpu')
    ownership=compile_ownership((InputField('cpu','source',8),),
        (InputOwner('cpu','source',0,8,'source','program'),))
    runner=ScenarioRunner(sessions={'cpu':cpu},ownership=ownership,bindings=())
    images=tuple(MemoryImage(f'image-{i}','cpu',address,data.hex())
        for i,(address,data) in enumerate(sorted(program.initial_images.items())))
    session=ScenarioSession(replace(_template(),initial_images=images),runner)
    session.begin();session.submit_case(case(0))
    class Carrier(_EpochCarrier):
        def __init__(self):
            super().__init__(runner,next_slot=1,slot_count=4)
            self.session=session;self.memory=memory;self.contract=program_contract
            self.program=program;self.rebind_calls=[]
        def rebind_reset_epoch(self,**kwargs):
            assert self._native_processes['cpu'] is cpu.process
            result=_validate_epoch_boot_image(self,**kwargs)
            self.rebind_calls.append(kwargs)
            return result
    carrier=Carrier()
    provider_calls=[]
    provider=SimpleNamespace(current_state=lambda:{'status':'unknown'},
        rebind_after_reset=lambda **kw:provider_calls.append(kw))
    recovery=declare_reset_recovery(runner,policy='warm_all',sources=dict(runner.sessions),
                                    providers={'RAM':provider},carrier=carrier)
    recovery.declare_epoch_program(contract=program_contract,next_slot=1)
    if install_image:recovery.reset_with_declared_program()
    else:session.reset('warm_all')
    observed=recovery.observe()
    if install_image:
        assert len(carrier.rebind_calls)==1
        assert observed['carrier_rebind']['status']=='reinstalled'
        assert observed['carrier_rebind']['execution']=='unverified'
        assert provider_calls==[{'barrier_event_id':observed['barrier']['event_id']}]
        # A rebind receipt alone is not proof that the new program executed.
        from myfuzz.scenario.native_reset_recovery import ResetRecoveryRefused
        with pytest.raises(ResetRecoveryRefused):
            recovery.continue_slot(bytes.fromhex('0110c00008000000'),flow='F6')
        assert recovery.document()['slot_continuation']['code']=='carrier-epoch-program-unverified'
    else:
        assert carrier.rebind_calls==[]
        assert provider_calls==[]
        assert observed['carrier_rebind']['status']=='unavailable'
        from myfuzz.scenario.native_reset_recovery import ResetRecoveryRefused
        with pytest.raises(ResetRecoveryRefused):
            recovery.continue_slot(bytes.fromhex('0110c00008000000'),flow='F6')
        assert carrier.submissions==[]
    session.finish()

@pytest.mark.parametrize('policy', ['warm_all', 'cold_all'])
def test_reset_image_updates_real_dependency_history(policy):
    from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
    from myfuzz.scenario.memory_service import MemoryService
    initial = MemoryImage('boot', 'cpu', 0x100, '11223344')
    session = ScenarioSession(replace(_template(), initial_images=(initial,)), memory_factory())
    session.begin()
    memory = session.runner.sessions['cpu'].memory
    service = MemoryService(memory, TransactionLedger())
    def key(epoch, seq):
        return TransactionKey('exec', 'case', 'cpu', epoch, 'data', seq)
    service.read(key(0, 1), 0x100, width_bytes=4)
    service.write(key(0, 2), 0x200, 0x5a, width_bytes=1, byte_enable=1)
    session.runner.state_dependencies.ingest(service.events)
    session.submit_case(case(0))
    session.reset(policy, image=replace(initial, data_hex='55667788'))
    image_event = next(e for e in session.runner.events_since(0) if e.get('kind') == 'reset_image')
    post = service.read(key(1, 1), 0x100, width_bytes=4)
    session.runner.state_dependencies.ingest(service.events)
    edges = session.runner.state_dependencies.edges
    assert post.value == 0x88776655
    assert {e.source for e in edges if e.kind == 'RAW' and e.target == str(key(1, 1))} == {f"reset-image:{image_event['event_id']}"}
    if policy == 'warm_all':
        service.read(key(1, 2), 0x200, width_bytes=1)
        session.runner.state_dependencies.ingest(service.events)
        assert any(e.kind == 'RAW' and e.source == str(key(0, 2)) and e.target == str(key(1, 2)) for e in edges)
        assert {e.byte_offset for e in edges if e.kind == 'WAR' and e.target == f"reset-image:{image_event['event_id']}"} == set(range(0x100, 0x104))
    session.finish()
