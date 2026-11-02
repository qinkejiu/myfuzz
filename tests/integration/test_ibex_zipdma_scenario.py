"""Static configuration checks; no DUT execution is implied."""
from pathlib import Path
import json
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability
from myfuzz.runtime.generic_campaign import load_descriptor
from myfuzz.local_harness.harness_set import load_compose
from myfuzz.scenario.f6_dma_source_provider import select_f6_dma_source_provider
from myfuzz.integration.compiled_f6_saved_semantics import _saved_dma_configuration_values

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT/'configs/scenarios/compiled-f1-f6-ibex-gpio-zipdma-shared'


def test_descriptor_selects_actual_zipdma_profile_and_routes():
    d = load_descriptor(SCENARIO/'generic_scenario.json', base_dir=ROOT)
    compose = load_compose(d.compose, base_dir=ROOT)
    profile = load_component_profile(ROOT/'configs/peripherals/zipdma_smoke/component_profile.json')
    cap = load_ip_test_capability(d.capability[0], profile=profile)
    provider = select_f6_dma_source_provider(profile, base_dir=ROOT)
    assert d.flow_ids == ('F1','F2','F3','F4','F5','F6')
    for row in [compose, *compose['devices']]:
        assert (d.compose.parent/row['request']).resolve().is_file()
    request = json.loads((d.compose.parent/compose['devices'][0]['request']).read_text())
    assert ROOT/request['profile_path'] == ROOT/'configs/peripherals/zipdma_smoke/component_profile.json'
    supplement = json.loads(d.supplement.read_text())
    irq = supplement['request_supplements']['deliveries'][0]
    assert (irq['producer_endpoint_id'], irq['producer_signal'], irq['trigger']) == (provider.irq_endpoint_id,provider.irq_port,provider.irq_trigger)
    assert cap.component_id == profile.component_id
    assert provider.irq_trigger == 'level' and provider.behavior['length_unit'] == 'bytes'
    assert compose['devices'][0]['template']['variant_id'] == 'dma-selected'
    assert all(row['initiator_template']['variant_id'] == 'dma-selected' for row in compose['dma_master_route_bindings'])
    assert all(row['initiator_endpoint_id'] == provider.master_endpoint_id for row in compose['dma_master_routes']['routes'])


def test_saved_configuration_uses_actual_source_csr_and_length_units():
    program = {'source_address': 0x22000, 'destination_address': 0x23000}
    for name, expected in [('zipcpu_wbdmac',(4,0x0fed0004)),('zipdma_smoke',(16,0))]:
        profile = load_component_profile(ROOT/'configs/peripherals'/name/'component_profile.json')
        provider = select_f6_dma_source_provider(profile, base_dir=ROOT)
        values = _saved_dma_configuration_values(program, provider.csr, provider.behavior)
        assert values == (0x22000, 0x23000, *expected)
