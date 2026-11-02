"""Profile timing selects the real CV32E40P limited-RVFI IRQ adapter."""
import json
from dataclasses import replace
from pathlib import Path
import tempfile
import pytest
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness.cv32e40p_irq_receipt_contract import (
    verify_cv32e40p_irq_source_contract, verify_cv32e40p_irq_receipt_artifact)
from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract_for_profile
from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from tests.local_harness.test_renderer import real_plan

ROOT=Path(__file__).resolve().parents[2]
PROFILE='configs/cpus/cv32e40p_profile/component_profile.json'


def test_timing_profile_keeps_pinned_irq_and_limited_real_probes():
    profile=load_component_profile(ROOT/PROFILE)
    assert verify_cv32e40p_irq_source_contract(profile,base_dir=ROOT)['source_status']=='source_verified'
    plan=real_plan(PROFILE,'processor')
    art=render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
    assert verify_cv32e40p_irq_receipt_artifact(art,base_dir=ROOT)
    contract=native_irq_receipt_contract_for_profile(profile)
    assert contract['input_bit_offset']==11 and 'serial_observation' not in contract
    assert {'irq_ack_pre','irq_id_pre','irq_entry_pc'} <= set(contract['decision_probe_widths'])


def test_timing_extension_rejects_changed_semantics_or_invalid_shape():
    profile=load_component_profile(ROOT/PROFILE)
    variants=[replace(profile,cpu=replace(profile.cpu,irq_entry_role='forged')),
              replace(profile,source_document={**profile.source_document,'top_module':'forged'}),
              replace(profile,evidence={**profile.evidence,'local_harness':None}),
              replace(profile,evidence={**profile.evidence,'local_harness':{'reset_assert_ticks':1,'reset_release_ticks':0,'max_wait_cycles':3,'extra':1}})]
    for changed in variants:
        with pytest.raises(ValueError):verify_cv32e40p_irq_source_contract(changed,base_dir=ROOT)


def test_profile_generated_scenario_admits_shared_f6_assembly(tmp_path):
    from scripts.generate_shared_dma_scenario import generate_scenario
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly, shared_irq_ownership
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    config=json.loads((ROOT/'configs/scenarios/shared-dma-profile-examples/cv32e40p-profile-embedded-zipdma-i2c.json').read_text())
    with tempfile.TemporaryDirectory(dir=ROOT/'runs') as tmp:
        descriptor=load_descriptor(generate_scenario(config,base_dir=ROOT,output=Path(tmp)/'scenario'),base_dir=ROOT)
        with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
            prep=create_preparation(base_dir=ROOT,compose_path=descriptor.compose,
                capability_paths=descriptor.capability,supplement_path=descriptor.supplement,
                generated_dir=Path(tmp)/'generated',flow_ids=descriptor.flow_ids)
            try:
                artifacts=dict(prep.artifacts);inputs=prep.compiled_inputs()
                assert artifacts['cpu'].plan.profile.component_id=='cv32e40p_rvfi_local'
                contract=admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)['execution_contract']
                ownership=shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],cpu_id='cpu',dma_id='dma'),
                    contract,artifacts,base_dir=ROOT)
                assembly=build_f6_assembly(contract=contract,artifacts=artifacts,request=inputs['request'],
                    ownership=ownership,base_dir=ROOT,cache_dir=tmp_path)
                assert assembly.companion_document()['target']['cross_case_origin']=='unknown'
            finally:prep.close()
