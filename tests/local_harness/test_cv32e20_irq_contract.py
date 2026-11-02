"""Source-backed external cause selection; RVFI alone grants no IRQ lineage."""
from pathlib import Path
import pytest
from myfuzz.local_harness.cv32e20_irq_receipt_contract import (
    cv32e20_irq_receipt_contract,verify_cv32e20_irq_source_contract,cv32e20_irq_sideband)
ROOT=Path(__file__).resolve().parents[2]

def test_real_source_contract_and_distinct_notification_shape():
    from myfuzz.composition.component_profile import load_component_profile
    profile=load_component_profile(ROOT/'configs/cpus/cv32e20/component_profile.json')
    verified=verify_cv32e20_irq_source_contract(profile,base_dir=ROOT)
    assert verified['source_status']=='source_verified'
    contract=cv32e20_irq_receipt_contract()
    assert 'EXC_CAUSE_IRQ_EXTERNAL_M' in contract['decision_probes']['irq_taken_pre']
    assert 'rvfi_ext_irq_valid' not in contract['notification_widths']
    assert contract['profile_id']=='cv32e20'

def test_other_cpu_and_rvfi_only_cannot_claim_E20_source():
    from myfuzz.composition.component_profile import load_component_profile
    profile=load_component_profile(ROOT/'configs/cpus/cv32e40p/component_profile.json')
    with pytest.raises(ValueError):verify_cv32e20_irq_source_contract(profile,base_dir=ROOT)

def test_serial_lineage_is_passive_and_nonexternal_trap_clears_source():
    body=cv32e20_irq_sideband()
    assert 'irq_sequence_q' in body and "64'd1" in body
    assert 'pc_mux_id == cve2_pkg::PC_EXC' in body
    assert 'irq_pending_q <= probe_irq_decision_serial' in body
    assert 'rvfi_id_done' in body and 'instr_first_cycle_id' in body
    assert 'rvfi_valid' in body and 'rvfi_intr' in body


def test_registered_serial_builder_has_own_schema_and_keeps_Ibex_compatibility():
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_serial_observation
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract,ibex_irq_serial_observation
    fields=dict(sampling='pre_post_rising',decision_value=3,retirement_value=3,decision_phase='pre',retirement_phase='post')
    assert native_irq_serial_observation(ibex_irq_receipt_contract(),**fields)==ibex_irq_serial_observation(**fields)
    observed=native_irq_serial_observation(cv32e20_irq_receipt_contract(),**fields)
    assert observed['schema_version']=='cpu_irq_serial_observation.v1'
    assert observed['decision']['value']==observed['retirement']['value']==3
    with pytest.raises(ValueError):native_irq_serial_observation({'schema_version':'rvfi_observation.v1'},**fields)


def test_actual_E20_render_has_source_verified_passive_IRQ_exports():
    from tests.local_harness.test_renderer import real_plan
    from myfuzz.local_harness import render_local_harness,verify_local_source_lock,render_local_runtime
    from myfuzz.local_harness.cv32e20_irq_receipt_contract import verify_cv32e20_irq_receipt_artifact
    plan=real_plan('configs/cpus/cv32e20/component_profile.json','processor')
    artifact=render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
    runtime_name=verify_cv32e20_irq_receipt_artifact(artifact,base_dir=ROOT)
    assert runtime_name and cv32e20_irq_sideband() in artifact.runtime_sv
    exports={row['physical_port']:row for row in artifact.runtime_document['physical_exports']}
    assert exports['irq_decision_serial']['width']==exports['irq_retirement_serial']['width']==64


def test_generated_passive_sideband_elaborates_without_running_DUT(tmp_path):
    import shutil,subprocess
    if shutil.which('verilator') is None:pytest.skip('Verilator unavailable')
    from tests.local_harness.test_renderer import real_plan
    from myfuzz.local_harness import render_local_harness,verify_local_source_lock,render_local_runtime
    plan=real_plan('configs/cpus/cv32e20/component_profile.json','processor')
    artifact=render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
    wrapper=tmp_path/'structural.sv';runtime=tmp_path/'runtime.sv'
    wrapper.write_text(artifact.structural.wrapper_sv);runtime.write_text(artifact.runtime_sv)
    source=plan.profile.source_document;source_root=ROOT/source['root']
    argv=['verilator','--lint-only','-Wno-fatal','--top-module',artifact.runtime_document['module_name']]
    argv += ['-I'+str(source_root/p) for p in source['include_roots']]
    argv += ['-D'+row['name']+'='+row['value'] for row in source['elaboration'].get('defines',[])]
    argv += [str(source_root/p) for p in source['files']]+[str(ROOT/'src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv'),str(wrapper),str(runtime)]
    result=subprocess.run(argv,capture_output=True,text=True,timeout=60)
    assert result.returncode==0,result.stdout+result.stderr


def test_service_identity_allows_declared_E20_observation_but_not_borrowed_Ibex_contract(tmp_path):
    from copy import deepcopy
    from tests.local_harness.test_renderer import real_plan
    from myfuzz.local_harness import render_local_harness,verify_local_source_lock,render_local_runtime,render_local_driver
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
    from myfuzz.scenario.router import DataflowRouter
    from myfuzz.scenario.contracts import _verify_generated_session
    plan=real_plan('configs/cpus/cv32e20/component_profile.json','processor')
    artifact=render_local_driver(render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
    memory=PersistentMemory(regions=(MemoryRegion('ram',0x10000,0x20000),),initialization_seed=0,max_initialized_bytes=0x20000)
    from tests.local_harness.test_cpu_session import Target
    from myfuzz.scenario.router import DeviceWindow
    cpu=GeneratedCve2Session(artifact,base_dir=ROOT,cache_dir=tmp_path,memory=memory,router=DataflowRouter((DeviceWindow('target',0x40000000,0x1000,Target()),)))
    identity=cpu.identity_document()
    assert identity['cpu_observation_schema_version']=='rvfi_observation.v1'
    _verify_generated_session(identity)
    wrong=deepcopy(identity);wrong['cpu_observation_schema_version']='ibex_rvfi_observation.v1'
    with pytest.raises(ValueError,match='observation identity mismatch'):_verify_generated_session(wrong)
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    wrong=deepcopy(identity);wrong['cpu_native_irq_receipt_contract']=ibex_irq_receipt_contract()
    with pytest.raises(ValueError,match='native IRQ provider identity mismatch'):_verify_generated_session(wrong)


def test_harness_timing_extension_preserves_irq_source_contract():
    from dataclasses import replace
    from myfuzz.composition.component_profile import load_component_profile
    profile=load_component_profile(ROOT/'configs/cpus/cv32e20/component_profile.json')
    timing={'reset_assert_ticks':12,'reset_release_ticks':0,'max_wait_cycles':64}
    extended=replace(profile,evidence={**profile.evidence,'local_harness':timing})
    assert verify_cv32e20_irq_source_contract(extended,base_dir=ROOT)['source_status']=='source_verified'


def test_irq_contract_rejects_behavior_or_invalid_timing_extensions():
    from dataclasses import replace
    from myfuzz.composition.component_profile import load_component_profile
    profile=load_component_profile(ROOT/'configs/cpus/cv32e20/component_profile.json')
    for evidence in ({**profile.evidence,'local_harness':{'reset_assert_ticks':0,'reset_release_ticks':0,'max_wait_cycles':64}},
                     {**profile.evidence,'local_harness':{'reset_assert_ticks':1,'reset_release_ticks':0,'max_wait_cycles':64,'custom_signal':'forged'}},
                     {**profile.evidence,'native_irq_observation':{}}):
        with pytest.raises(ValueError,match='profile-mismatch'):
            verify_cv32e20_irq_source_contract(replace(profile,evidence=evidence),base_dir=ROOT)
    changed=replace(profile,cpu=replace(profile.cpu,irq_entry_role='forged'))
    with pytest.raises(ValueError,match='profile-mismatch'):
        verify_cv32e20_irq_source_contract(changed,base_dir=ROOT)


def test_irq_contract_rejects_null_timing_and_changed_raw_source_document():
    from dataclasses import replace
    from myfuzz.composition.component_profile import load_component_profile
    profile=load_component_profile(ROOT/'configs/cpus/cv32e20/component_profile.json')
    for changed in (replace(profile,evidence={**profile.evidence,'local_harness':None}),
                    replace(profile,source_document={**profile.source_document,'top_module':'forged'})):
        with pytest.raises(ValueError,match='profile-mismatch'):
            verify_cv32e20_irq_source_contract(changed,base_dir=ROOT)


def test_parsed_profile_with_harness_timing_is_accepted(tmp_path):
    import json
    from myfuzz.composition.component_profile import load_component_profile
    document=json.loads((ROOT/'configs/cpus/cv32e20/component_profile.json').read_text())
    document['evidence']['local_harness']={'reset_assert_ticks':8,'reset_release_ticks':8,'max_wait_cycles':16}
    path=tmp_path/'component_profile.json'
    path.write_text(json.dumps(document))
    parsed=load_component_profile(path)
    assert verify_cv32e20_irq_source_contract(parsed,base_dir=ROOT)['source_status']=='source_verified'
