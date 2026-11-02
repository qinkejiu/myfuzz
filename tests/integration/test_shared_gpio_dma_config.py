"""Checked-in shared composition must compile real owners without starting RTL."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def test_checked_in_gpio_dma_configuration_has_real_shared_contract(tmp_path):
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    descriptor=load_descriptor(ROOT/'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json',base_dir=ROOT)
    preparation=create_preparation(base_dir=ROOT,compose_path=descriptor.compose,
        capability_paths=descriptor.capability,supplement_path=descriptor.supplement,
        generated_dir=tmp_path/'generated',flow_ids=descriptor.flow_ids)
    try:
        admission=admit_compiled_f6_runtime_path(artifacts=dict(preparation.artifacts),
            compiled_inputs=preparation.compiled_inputs(),base_dir=ROOT)
        contract=admission['execution_contract']
        assert set(preparation.artifacts)=={'cpu','dma','peripheral'}
        assert set(admission['shared_flow_paths'])==set(descriptor.flow_ids)
        assert contract['program_contract']['gpio_irq']['component']=='peripheral'
        firmware=build_f6_firmware(contract).document()
        stages=firmware['irq_dispatch']['stages']
        assert firmware['isr']['mret_addresses']==stages['dma']['mret_addresses']
        assert set(stages['gpio']['mret_addresses']).isdisjoint(firmware['isr']['mret_addresses'])
    finally:
        preparation.close()
