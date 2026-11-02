"""Source-backed partial E40 retirement observations, never IRQ authority."""
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2]


def test_source_backed_profile_exports_only_assigned_monitor_fields():
    from myfuzz.local_harness.cv32e40p_rvfi_contract import observation_fields
    from myfuzz.composition.component_profile import load_component_profile
    fields=observation_fields()
    assert {k:fields[k] for k in ('rvfi_valid','rvfi_order','rvfi_insn','rvfi_pc_rdata')}==dict(rvfi_valid=1,rvfi_order=64,rvfi_insn=32,rvfi_pc_rdata=32)
    assert len(fields)==4
    assert not set(fields)&{'rvfi_intr','rvfi_pc_wdata','rvfi_halt','rvfi_mode','rvfi_ixl','rvfi_nmip'}
    profile=load_component_profile(ROOT/'configs/cpus/cv32e40p_rvfi_local/component_profile.json')
    assert profile.capabilities['verilator_timing_mode']=='timing'
    assert {a.port for a in profile.port_actions if a.action=='observe' and a.port.startswith('rvfi_')}==set(fields)


def test_actual_source_elaboration_and_session_use_partial_real_RVFI(tmp_path):
    from myfuzz.local_harness import load_local_harness_request,plan_local_harness,render_local_harness,render_local_runtime,verify_local_source_lock
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.cv32e40p_rvfi_contract import observation_fields
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session,rvfi_observation_contract
    from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
    from myfuzz.scenario.router import DataflowRouter
    request=load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/cpus/cv32e40p_rvfi_local/component_profile.json',instance_id='cpu',
        reset_assert_ticks=8,reset_release_ticks=8,max_wait_cycles=16))
    plan=plan_local_harness(request,base_dir=ROOT)
    verified=verify_local_source_lock(plan.profile,base_dir=ROOT)
    artifact=render_local_driver(render_local_runtime(plan,render_local_harness(plan),verified,base_dir=ROOT),base_dir=ROOT)
    contract=rvfi_observation_contract(artifact)
    assert contract['fields']==observation_fields()
    assert contract['schema_version']=='rvfi_observation.v1'
    cpu=GeneratedCve2Session(artifact,base_dir=ROOT,cache_dir=tmp_path,
        memory=PersistentMemory(regions=(MemoryRegion('ram',0,0x30000),),initialization_seed=0,max_initialized_bytes=0x30000),router=DataflowRouter(()))
    assert cpu.process is None and cpu._rvfi_enabled and not cpu.native_irq_receipts_enabled
    # Pure capture semantics only: these supplied observations are not a DUT run.
    from myfuzz.scenario.contracts import ProtocolEnvironmentError
    cpu._retire(dict(rvfi_valid=1,rvfi_order=1,rvfi_insn=0x13,rvfi_pc_rdata=0x10000))
    retired=cpu.cpu_events[-1]
    assert retired['order']==1 and retired['pc_rdata']==0x10000
    assert not set(retired)&{'intr','pc_wdata','halt','mode','irq_serial_observation','take_key'}
    with pytest.raises(ProtocolEnvironmentError,match='incomplete declared POST'):
        cpu._retire(dict(rvfi_valid=1,rvfi_order=2,rvfi_insn=0x13))
    # The RVFI stream alone still confers no IRQ source authority. The
    # registered E40 authority comes only from the real controller ack/id and
    # exception-entry-PC probes, never from an RVFI field.
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract
    from myfuzz.local_harness.cv32e40p_irq_receipt_contract import cv32e40p_irq_receipt_contract
    contract=native_irq_receipt_contract(artifact)
    assert contract==cv32e40p_irq_receipt_contract()
    assert 'rvfi_intr' not in contract['notification_widths']
    assert 'serial_observation' not in contract


def test_changed_local_wrapper_is_rejected_before_observation_claim(tmp_path):
    import shutil
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.cv32e40p_rvfi_contract import verify_cv32e40p_rvfi_source_contract
    relative=Path('configs/cpus/cv32e40p_rvfi_local')
    (tmp_path/relative).mkdir(parents=True)
    for name in ('component_profile.json','cv32e40p_rvfi_local_top.sv'):
        shutil.copyfile(ROOT/relative/name,tmp_path/relative/name)
    wrapper=tmp_path/relative/'cv32e40p_rvfi_local_top.sv'
    wrapper.write_text(wrapper.read_text()+'\n// changed passive wiring\n')
    with pytest.raises(ValueError,match='cv32e40p-rvfi-source-changed'):
        verify_cv32e40p_rvfi_source_contract(load_component_profile(ROOT/relative/'component_profile.json'),base_dir=tmp_path)
