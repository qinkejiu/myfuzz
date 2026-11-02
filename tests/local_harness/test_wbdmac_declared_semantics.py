"""The wbdmac CSR units/clear facts come from the profile, checked by the source.

The pinned RTL is unchanged: these tests prove the *declaration* decides what the
F6 host is allowed to assume, and that the pinned readback facts still refuse every
declaration the bytes do not implement.
"""
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness.wishbone_dma_fields import (
    dma_profile_edge_contract, declared_master_address_shift)
from myfuzz.local_harness.wbdmac_source_contract import (
    declared_csr_semantics, verify_wbdmac_source_contract)

ROOT = Path(__file__).resolve().parents[2]
#: The declared variant: same pinned bytes, same component id, four declaration
#: fields added to the capability block.
PROFILE = ROOT / 'configs/peripherals/inprocess_generality_wbdmac/component_profile.json'
#: The shared profile, which declares none of them.
UNDECLARED = ROOT / 'configs/peripherals/zipcpu_wbdmac/component_profile.json'


def document():
    return json.loads(PROFILE.read_text())


def profile(**capabilities):
    payload = document()
    payload['capabilities'].update(capabilities)
    return load_component_profile(payload)


def test_the_profile_declares_the_csr_units_and_the_source_admits_them():
    declared = declared_csr_semantics(profile())
    assert declared == {
        'source_destination_units': 'byte_address_shift_right_2',
        'master_address_units': 'word', 'master_address_shift': 2,
        'length_unit': 'words', 'irq_clear': 'none'}
    contract = verify_wbdmac_source_contract(profile(), base_dir=ROOT)
    # The host writes a byte address either way; the shift is the RTL's own and is
    # declared separately as the master's word addressing.
    assert contract['csr']['source_destination_units'] == 'byte_address'
    assert contract['csr']['master_address_units'] == 'word'
    assert contract['declared']['source_destination_units'] == 'byte_address_shift_right_2'
    assert contract['declared']['host_source_destination_units'] == 'byte_address'


def test_the_f6_provider_consumes_the_declared_units_without_a_code_change():
    from myfuzz.scenario.f6_dma_source_provider import select_f6_dma_source_provider
    provider = select_f6_dma_source_provider(profile(), base_dir=ROOT)
    # This is the exact predicate the F1-F6 entry applies to a DMA declaration.
    assert provider.csr['source_destination_units'] == 'byte_address'
    assert provider.behavior['length_unit'] == 'words'
    assert provider.behavior['irq_clear'] == {'method': 'none'}
    assert provider.irq_trigger == 'pulse'


@pytest.mark.parametrize('capabilities,drifed', [
    ({'irq_clear': 'write'}, 'irq_clear'),
    ({'length_unit': 'bytes'}, 'length_unit'),
    ({'master_address_shift': 1}, 'master_address_shift'),
    ({'source_destination_units': 'word_address'}, 'source_destination_units'),
    ({'length_unit': True}, 'length_unit'),
])
def test_a_declaration_the_pinned_source_does_not_implement_is_refused(capabilities,
                                                                      drifed):
    with pytest.raises(ValueError, match='wbdmac-declaration-source-drift:' + drifed):
        verify_wbdmac_source_contract(profile(**capabilities), base_dir=ROOT)


def test_the_f6_provider_refuses_the_same_drift_instead_of_shifting_the_guest():
    from myfuzz.scenario.f6_dma_source_provider import select_f6_dma_source_provider
    for capabilities, drifed in (({'length_unit': 'bytes'}, 'length_unit'),
                                 ({'irq_clear': 'write'}, 'irq_clear')):
        with pytest.raises(ValueError, match='wbdmac-declaration-source-drift:' + drifed):
            select_f6_dma_source_provider(profile(**capabilities), base_dir=ROOT)


def test_an_undeclared_profile_keeps_the_pinned_values():
    shared = json.loads(UNDECLARED.read_text())
    for name in ('source_destination_units', 'master_address_shift', 'length_unit',
                 'irq_clear'):
        assert name not in shared['capabilities']
    contract = verify_wbdmac_source_contract(load_component_profile(shared),
                                             base_dir=ROOT)
    assert contract['declared']['master_address_shift'] == 2
    assert contract['declared']['length_unit'] == 'words'
    assert contract['declared']['irq_clear'] == 'none'
    assert contract['csr']['source_destination_units'] == 'byte_address'


def test_the_master_address_shift_is_the_declared_capability():
    contract = dma_profile_edge_contract(profile().capabilities)
    assert (contract['master_address_units'], contract['master_address_shift']) == ('word', 2)
    assert declared_master_address_shift({}) == 2
    for value in (1, 4, True, '2'):
        with pytest.raises(ValueError, match='dma-master-address-shift-unsupported'):
            declared_master_address_shift({'master_address_shift': value})
