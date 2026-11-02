"""Real six-flow construction and ledger installation, no native clocking."""
import pytest
from tests.integration.test_shared_f5_support_binding import all_six
from tests.integration.test_compiled_f6_contract import ROOT


def test_actual_shared_runtime_installs_pin_provider_on_same_GPIO_authority(all_six,tmp_path,monkeypatch):
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime,_f6_runner_ownership
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly,shared_irq_ownership
    from tests.integration.test_compiled_f6_runtime import _install_software_process_boundary
    from myfuzz.search.shared_slot_pin_read import install_shared_slot_pin_consumer,_INSTALLATIONS,authenticated_report
    inputs=all_six.compiled_inputs();artifacts=dict(all_six.artifacts)
    admission=admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    contract=admission['execution_contract']
    ownership=shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],cpu_id='cpu',dma_id='dma'),contract,artifacts,base_dir=ROOT)
    assembly=build_f6_assembly(contract=contract,artifacts=artifacts,request=inputs['request'],ownership=ownership,base_dir=ROOT,cache_dir=tmp_path)
    _install_software_process_boundary(monkeypatch)
    runtime=CompiledF6Runtime(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT,cache_dir=tmp_path,
        max_cases=8,defer_begin=True,shared_assembly=assembly)
    from myfuzz.search.shared_slot_ram_adapter import SharedSlotSelector
    records=['F3:55000000','F1:03200000','F4:0001000000','F5:0000000100000000',
        'F2:08100040','F6:0110c00008000000','F5:0000000000000000']
    selector=SharedSlotSelector(None,flow='mixed',records=records,policy='state',seed=1,cases=8)
    selector.attach_runtime(runtime)
    handle=selector._pin_handle
    from myfuzz.search.shared_slot_ram import _INSTALLATIONS as RAM_INSTALLATIONS
    ram=RAM_INSTALLATIONS[selector._handle]
    assert ram['runtime'] is runtime and ram['cpu'] is runtime.cpu and ram['memory'] is runtime.memory
    assert ram['session'] is runtime.session and ram['provider'] is runtime.runner._memory_dependency_consumer
    assert selector.pin_credit.policy is selector.credit.policy is selector.scheduler
    state=_INSTALLATIONS[handle]
    assert state['authority'] is assembly.companion_authorities['peripheral']
    assert state['cpu'] is runtime.cpu and state['session'] is runtime.session
    assert state['registry'] is runtime.runner._provenance.registry
    assert state['paths']['F5']['pin']['bit_offset']==8
    assert state['f2_row']['execution_contract']['register']=='PADIN'
    assert state['writers']=={} and handle.audit()==[]
    assert handle.current_state()['status']=='unknown'  # no fabricated live sample before begin
    with pytest.raises(ValueError,match='actual_shared_slot_runtime_required'):
        install_shared_slot_pin_consumer(runtime)
    with pytest.raises(ValueError):authenticated_report(handle,{'relations':[{'status':'verified'}]})
    # Exercise the observation-only exception inside the original executing
    # ScenarioSession frame, after its real MemoryService support acceptance.
    from types import SimpleNamespace
    from myfuzz.scenario import native_f6_isr_return as native_return
    monkeypatch.setattr(runtime.session,'advance_initial',lambda schedule: SimpleNamespace(violations=(),status='running'))
    monkeypatch.setattr(runtime,'_bootstrap_to_first_slot',lambda:None)
    runtime.begin()
    issuer=runtime.cpu._f6_isr_return
    live=native_return._issuer_state(issuer)
    gpio=live['dispatch']['stages']['gpio']
    physical=dict(rvfi_valid=1,rvfi_insn=0x30200073,rvfi_pc_rdata=gpio['mret_addresses'][0],
        rvfi_trap=0,rvfi_intr=0,rvfi_mode=3,rvfi_ext_debug_mode=0,rvfi_ext_debug_req=0,rvfi_halt=0)
    class StopAfterSupport(Exception):pass
    checked=[]
    def stop(*args,**kwargs):
        assert native_return._allow_shared_gpio_mret(runtime.cpu,live,physical) is True
        checked.append(True)
        assert issuer.events==()
        with pytest.raises(ValueError,match='fixed native retirement'):
            native_return._allow_shared_gpio_mret(runtime.cpu,live,dict(physical,rvfi_pc_rdata=live['isr']['mret_addresses'][0]))
        with pytest.raises(ValueError,match='declared fixed support'):
            native_return._allow_shared_gpio_mret(runtime.cpu,dict(live,active={'F6':'active'}),physical)
        # Equal-looking instruction bytes rewritten by another source must not
        # qualify as the fixed initial ISR image.
        address=gpio['address'];word=int.from_bytes(runtime.memory.read(address,4,transaction_id='check').data,'little')
        runtime.memory.write(address,word,width_bytes=4,byte_enable=15,writer_event_id='foreign-writer')
        with pytest.raises(ValueError,match='fixed stage bytes changed'):
            native_return._allow_shared_gpio_mret(runtime.cpu,live,physical)
        raise StopAfterSupport()
    monkeypatch.setattr(runtime.runner,'inject_source',stop)
    with pytest.raises(StopAfterSupport):runtime.submit(bytes.fromhex('0000000100000000'),flow='F5')
    assert checked==[True] and issuer.events==()
    with pytest.raises(ValueError,match='actual executing case'):
        native_return._allow_shared_gpio_mret(runtime.cpu,live,physical)
