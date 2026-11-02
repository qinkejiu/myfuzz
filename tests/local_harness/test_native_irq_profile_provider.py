from pathlib import Path
from types import SimpleNamespace
import pytest
from myfuzz.composition.component_profile import load_component_profile

ROOT=Path(__file__).resolve().parents[2]


def test_registered_profiles_have_distinct_actual_native_contracts():
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract_for_profile
    from myfuzz.local_harness.cv32e20_irq_receipt_contract import cv32e20_irq_receipt_contract
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    assert native_irq_receipt_contract_for_profile(load_component_profile(ROOT/'configs/cpus/cv32e20/component_profile.json'))==cv32e20_irq_receipt_contract()
    assert native_irq_receipt_contract_for_profile(load_component_profile(ROOT/'configs/cpus/ibex_rvfi_local/component_profile.json'))==ibex_irq_receipt_contract()
    for name in ('cv32e40p','cv32e20_rv32e','unknown'):
        # A real component profile always carries the ``evidence`` mapping
        # (defaulting to {}), so the fake must too: the provider inspects it to
        # pick the code-owned adapter before falling back to the component id.
        with pytest.raises(ValueError):native_irq_receipt_contract_for_profile(SimpleNamespace(component_id=name,evidence={}))


def test_E20_source_provider_is_verified_independently_of_RVFI_names():
    from myfuzz.local_harness.native_irq_receipt_contract import verify_native_irq_cpu_source
    profile=load_component_profile(ROOT/'configs/cpus/cv32e20/component_profile.json')
    result=verify_native_irq_cpu_source(profile,base_dir=ROOT)
    assert result['source_status']=='source_verified'


def test_F6_marker_uses_registered_source_boot_instead_of_Ibex_formula():
    from myfuzz.scenario.f6_execution_contract import _marker,F6ContractRefused
    import json
    from copy import deepcopy
    profile=load_component_profile(ROOT/'configs/cpus/cv32e20/component_profile.json')
    declaration=json.loads((ROOT/'configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared/execution_supplement.json').read_text())['request_supplements']['f6_execution']
    request=SimpleNamespace(document={'f6_execution':declaration},cpu=SimpleNamespace(profile=profile))
    assert _marker(request,base_dir=ROOT)['program']['boot_address']==0x10000
    bad=deepcopy(declaration);bad['program']['boot_address']=0x10080
    with pytest.raises(F6ContractRefused,match='native-reset-entry'):
        _marker(SimpleNamespace(document={'f6_execution':bad},cpu=request.cpu),base_dir=ROOT)


def test_retirement_diversion_uses_actual_registered_fields_without_fake_Ibex_ports():
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_retirement_diverted
    from myfuzz.local_harness.cv32e20_irq_receipt_contract import cv32e20_irq_receipt_contract
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    fields=dict(rvfi_ext_debug_req=0,rvfi_ext_nmi=0,rvfi_halt=0)
    assert native_irq_retirement_diverted(cv32e20_irq_receipt_contract(),fields) is False
    assert native_irq_retirement_diverted(ibex_irq_receipt_contract(),fields) is True
    assert native_irq_retirement_diverted(cv32e20_irq_receipt_contract(),dict(fields,rvfi_ext_nmi=1)) is True
    del fields['rvfi_ext_debug_req']
    assert native_irq_retirement_diverted(cv32e20_irq_receipt_contract(),fields) is True
