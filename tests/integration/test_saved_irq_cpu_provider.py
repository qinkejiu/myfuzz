from types import SimpleNamespace as NS
import pytest
from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract_for_profile


@pytest.mark.parametrize('name', ['ibex_rvfi_local', 'cv32e20'])
def test_saved_provider_requires_registered_contract_and_same_actual_cpu(name):
    from myfuzz.integration.compiled_f6_saved_semantics import _registered_saved_irq_provider, _EvidenceIssue
    artifact = NS(plan=NS(profile=NS(component_id=name)))
    provider = native_irq_receipt_contract_for_profile(artifact.plan.profile)
    contract = {'cpu': {'native_irq_provider': provider}}
    assert _registered_saved_irq_provider(contract, artifact) == provider
    assert _registered_saved_irq_provider(contract, None) == provider
    other = 'cv32e20' if name == 'ibex_rvfi_local' else 'ibex_rvfi_local'
    with pytest.raises(_EvidenceIssue, match='provider'):
        _registered_saved_irq_provider(contract, NS(plan=NS(profile=NS(component_id=other))))


def test_saved_provider_does_not_infer_capability_from_unknown_contract():
    from myfuzz.integration.compiled_f6_saved_semantics import _registered_saved_irq_provider
    with pytest.raises(ValueError):
        _registered_saved_irq_provider({'cpu': {'native_irq_provider': {'profile_id': 'unknown'}}}, None)
