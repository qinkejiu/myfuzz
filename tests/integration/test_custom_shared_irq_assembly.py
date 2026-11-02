"""Observation-only custom IRQ must not attach unused reset history."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.generate_shared_dma_scenario import generate_scenario
from myfuzz.runtime.generic_campaign import load_descriptor
from myfuzz.runtime.preparation import create_preparation
from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
from myfuzz.integration.shared_f6_assembly import build_f6_assembly
from myfuzz.local_harness.build import host_source_discovery_scope
from myfuzz.local_harness.execution_validation import execution_validation_scope
from myfuzz.scenario.ownership import InputField,InputOwner,compile_ownership

ROOT=Path(__file__).resolve().parents[2]


def test_custom_six_path_assembly_does_not_record_unneeded_resets():
    config=json.loads((ROOT/'configs/scenarios/shared-dma-profile-examples/picorv32-custom-zipdma-i2c-gpio.json').read_text())
    with TemporaryDirectory(dir=ROOT/'runs') as temp:
        root=Path(temp)
        descriptor=load_descriptor(generate_scenario(config,base_dir=ROOT,output=root/'scenario'),base_dir=ROOT)
        with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
            preparation=create_preparation(base_dir=ROOT,compose_path=descriptor.compose,
                capability_paths=descriptor.capability,supplement_path=descriptor.supplement,
                generated_dir=root/'generated',flow_ids=descriptor.flow_ids)
            try:
                inputs=preparation.compiled_inputs(); artifacts=dict(preparation.artifacts)
                admitted=admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
                contract=admitted['execution_contract']; doc=inputs['ownership'].document()
                fields=[InputField(**row) for row in doc['fields']]+[InputField('cpu','irq',32)]
                sources={3:'dma.irq',4:'peripheral.interrupt'}
                owners=[InputOwner(**row) for row in doc['owners']]+[
                    InputOwner('cpu','irq',i,1,'bound' if i in sources else 'fixed',sources.get(i,'inactive'))
                    for i in range(32)]
                assembly=build_f6_assembly(contract=contract,artifacts=artifacts,
                    ownership=compile_ownership(tuple(fields),tuple(owners)),request=inputs['request'],
                    base_dir=ROOT,cache_dir=root/'cache')
                assert assembly.runner.sessions['peripheral']._native_reset_observation is None
                assert not assembly.companion_authorities
                assert {binding.target_bit_offset for binding in assembly.runner.bindings}=={3,4}
                assert all(session.process is None for session in assembly.runner.sessions.values())
            finally:
                preparation.close()
