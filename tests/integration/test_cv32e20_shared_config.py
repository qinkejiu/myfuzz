"""Configuration-only CPU substitution; no native process is started."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OLD=ROOT/'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared'
NEW=ROOT/'configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared'


def read(path):return json.loads(path.read_text())


def test_E20_shared_configuration_reuses_IP_contracts_and_source_backed_boot():
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.integration.shared_irq_firmware import irq_firmware_register_count
    old,new=read(OLD/'compose.json'),read(NEW/'compose.json')
    new['cpu']['request']=old['cpu']['request']
    assert new==old
    old,new=read(OLD/'execution_supplement.json'),read(NEW/'execution_supplement.json')
    assert new['request_supplements']['f6_execution']['program']['boot_address']==0x10000
    new['request_supplements']['f6_execution']['program']['boot_address']=old['request_supplements']['f6_execution']['program']['boot_address']
    assert new==old
    descriptor=load_descriptor(NEW/'generic_scenario.json',base_dir=ROOT)
    original=load_descriptor(OLD/'generic_scenario.json',base_dir=ROOT)
    assert descriptor.capability==original.capability
    assert descriptor.flow_ids==original.flow_ids
    request=read(NEW/'requests/cpu.json')
    profile=load_component_profile(ROOT/request['profile_path'])
    assert irq_firmware_register_count(profile)==32
    assert source_backed_boot_fetch(profile,base_dir=ROOT,configured_boot_base=0x10000)==0x10000


def test_E20_shared_real_preparation_and_admission(tmp_path):
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    descriptor=load_descriptor(NEW/'generic_scenario.json',base_dir=ROOT)
    preparation=create_preparation(base_dir=ROOT,compose_path=descriptor.compose,
        capability_paths=descriptor.capability,supplement_path=descriptor.supplement,
        generated_dir=tmp_path/'generated',flow_ids=descriptor.flow_ids)
    try:
        admission=admit_compiled_f6_runtime_path(artifacts=dict(preparation.artifacts),
            compiled_inputs=preparation.compiled_inputs(),base_dir=ROOT)
        assert set(preparation.artifacts)=={'cpu','dma','peripheral'}
        assert preparation.artifacts['cpu'].plan.profile.component_id=='cv32e20'
        assert set(admission['shared_flow_paths'])==set(descriptor.flow_ids)
        contract=admission['execution_contract']
        assert contract['program_contract']['boot_address']==0x10000
        assert build_f6_firmware(contract).document()['irq_dispatch']['stages']['dma']
    finally:preparation.close()
