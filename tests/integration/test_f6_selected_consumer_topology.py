from types import SimpleNamespace
from myfuzz.integration import compiled_f6_consumer as consumer
from myfuzz.integration import compiled_f6_runtime_path as topology
from myfuzz.local_harness.dma_artifact_endpoint_links import _PROVIDER_CONTRACT, _SELECTED_PROVIDER_CONTRACT, _sha


def test_configuration_values_follow_dma_length_unit_and_start_word():
    contract = {'program_contract': {'source_address': 0x11000, 'destination_address': 0x12000},
                'dma': {'csr': {'length_words': 4, 'start_word': 0},
                        'behavior': {'length_unit': 'bytes'}}}
    assert consumer._configuration_values(contract) == [0x11000, 0x12000, 16, 0]
    contract['dma']['csr']['start_word'] = 0x0fed0004
    contract['dma']['behavior']['length_unit'] = 'words'
    assert consumer._configuration_values(contract) == [0x11000, 0x12000, 4, 0x0fed0004]


def test_selected_provider_and_endpoint_identity_match_actual_session(monkeypatch):
    monkeypatch.setattr(topology, '_artifact_link', lambda artifact: {'test': True})
    profile = SimpleNamespace(capabilities={'local_runtime_variant': 'wishbone_dma_selected_edge_v1','address_width':2})
    artifact = SimpleNamespace(plan=SimpleNamespace(profile=profile), runtime_document={}, runtime_sv='rtl', cpp_text='cpp')
    assert topology._artifact_link_document(artifact)['provider_contract_sha256'] == _sha(_SELECTED_PROVIDER_CONTRACT)
    assert topology._dma_endpoint_identity(artifact, 'dma')['byte_enable'] == 'mwb_sel'
    profile.capabilities['local_runtime_variant'] = 'wishbone_dma_edge_v1'
    assert topology._artifact_link_document(artifact)['provider_contract_sha256'] == _sha(_PROVIDER_CONTRACT)
    assert topology._dma_endpoint_identity(artifact, 'dma')['byte_enable'] == 15


def test_wide_provider_identity_uses_actual_control_abi(monkeypatch):
    from myfuzz.local_harness.dma_artifact_endpoint_links import dma_link_provider_contract
    monkeypatch.setattr(topology,'_artifact_link',lambda artifact:{'test':True})
    profile=SimpleNamespace(capabilities={'local_runtime_variant':'wishbone_dma_selected_edge_v1','address_width':4})
    artifact=SimpleNamespace(plan=SimpleNamespace(profile=profile),runtime_document={},runtime_sv='rtl',cpp_text='cpp')
    expected=dma_link_provider_contract(control_address_width=4,selected=True)
    assert topology._artifact_link_document(artifact)['provider_contract_sha256']==_sha(expected)
    assert topology._dma_endpoint_identity(artifact,'dma')['byte_enable']=='mwb_sel'


def test_level_irq_boundary_reuses_observed_low_reference():
    import pytest
    assert consumer._irq_low_reference(True, {'low_cpu_sample_event_id': 34}, None) == 34
    assert consumer._irq_low_reference(False, None, 19) == 19
    with pytest.raises(consumer._Missing):
        consumer._irq_low_reference(True, {}, None)
