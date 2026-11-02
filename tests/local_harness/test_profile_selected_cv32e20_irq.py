"""New CPU ID may explicitly reuse a source-verified IRQ adapter."""
from dataclasses import replace
from pathlib import Path
import pytest
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness.native_irq_receipt_contract import (native_irq_receipt_contract_for_profile,
    verify_native_irq_cpu_source, verify_native_irq_receipt_artifact)
from tests.local_harness.test_renderer import real_plan
from myfuzz.local_harness import render_local_harness, verify_local_source_lock, render_local_runtime

ROOT=Path(__file__).resolve().parents[2]
PROFILE='configs/cpus/cv32e20_profile_irq_adapter/component_profile.json'


def test_new_id_selects_locked_controller_decision_and_rendered_probes():
    profile=load_component_profile(ROOT/PROFILE)
    assert profile.component_id == 'cv32e20_profile_irq_adapter'
    assert native_irq_receipt_contract_for_profile(profile)['schema_version']=='cv32e20_native_irq_receipts.v1'
    assert verify_native_irq_cpu_source(profile,base_dir=ROOT)['source_status']=='source_verified'
    plan=real_plan(PROFILE,'processor')
    artifact=render_local_runtime(plan,render_local_harness(plan),
        verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
    assert verify_native_irq_receipt_artifact(artifact,base_dir=ROOT)
    assert 'EXC_CAUSE_IRQ_EXTERNAL_M' in artifact.runtime_sv
    assert 'probe_irq_decision_serial' in artifact.runtime_sv


def test_explicit_adapter_cannot_change_cpu_semantics_or_port():
    profile=load_component_profile(ROOT/PROFILE)
    with pytest.raises(ValueError):
        verify_native_irq_cpu_source(replace(profile,cpu=replace(profile.cpu,irq_entry_role='forged')),base_dir=ROOT)
    with pytest.raises(ValueError):
        native_irq_receipt_contract_for_profile(replace(profile,evidence={**profile.evidence,
            'native_irq_adapter':'unknown'}))


def test_adapter_declaration_cannot_be_null_or_use_unverified_source():
    from copy import deepcopy
    profile=load_component_profile(ROOT/PROFILE)
    with pytest.raises(ValueError):
        native_irq_receipt_contract_for_profile(replace(profile,evidence={**profile.evidence,'native_irq_adapter':None}))
    evidence=deepcopy(profile.evidence)
    evidence['local_source_manifest']['components'][0]['source']['revision']='git:'+'0'*40
    with pytest.raises(ValueError):
        verify_native_irq_cpu_source(replace(profile,evidence=evidence),base_dir=ROOT)


def test_new_id_profile_admits_shared_f1_f6_assembly(tmp_path):
    import json, tempfile
    from scripts.generate_shared_dma_scenario import generate_scenario
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly, shared_irq_ownership
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    config=json.loads((ROOT/'configs/scenarios/shared-dma-profile-examples/cv32e20-newid-irq-adapter-zipdma-i2c.json').read_text())
    with tempfile.TemporaryDirectory(dir=ROOT/'runs') as tmp:
        descriptor=load_descriptor(generate_scenario(config,base_dir=ROOT,output=Path(tmp)/'scenario'),base_dir=ROOT)
        with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
            prepared=create_preparation(base_dir=ROOT,compose_path=descriptor.compose,
                capability_paths=descriptor.capability,supplement_path=descriptor.supplement,
                generated_dir=Path(tmp)/'generated',flow_ids=descriptor.flow_ids)
            try:
                artifacts=dict(prepared.artifacts);inputs=prepared.compiled_inputs()
                assert artifacts['cpu'].plan.profile.component_id == 'cv32e20_profile_irq_adapter'
                contract=admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)['execution_contract']
                ownership=shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],cpu_id='cpu',dma_id='dma'),
                    contract,artifacts,base_dir=ROOT)
                assembly=build_f6_assembly(contract=contract,artifacts=artifacts,request=inputs['request'],
                    ownership=ownership,base_dir=ROOT,cache_dir=tmp_path)
                assert assembly.companion_document()['target']['cross_case_origin']=='unknown'
            finally:
                prepared.close()


def test_rejects_conflicting_explicit_adapters():
    profile=load_component_profile(ROOT/PROFILE)
    with pytest.raises(ValueError):
        native_irq_receipt_contract_for_profile(replace(profile,evidence={**profile.evidence,
            'native_irq_observation':{}}))
