"""Contract checks for the real, unstarted Ibex/DMA/Caliptra assembly."""
import importlib
import importlib.util

import pytest

from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.dma_artifact_endpoint_links import (
    validate_dma_artifact_endpoint_links,
)
from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
from myfuzz.scenario.ibex_dma_example import SOURCE
from myfuzz.scenario.runner import Binding


@pytest.fixture(scope='module')
def fixture(tmp_path_factory):
    module_name = 'myfuzz.scenario.ibex_dma_caliptra_sha_runner'
    assert importlib.util.find_spec(module_name) is not None, 'Caliptra runner fixture is missing'
    factory = importlib.import_module(module_name)
    result = factory.make_ibex_dma_caliptra_sha_runner(
        cache_dir=tmp_path_factory.mktemp('ibex-caliptra-runner'))
    yield result
    for session in result.runner.sessions.values():
        session.end_case()


def test_factory_uses_real_unstarted_sessions_and_shared_ram(fixture):
    runner = fixture.runner
    assert set(runner.sessions) == {'cpu', 'dma', 'sha'}
    cpu, dma, sha = (runner.sessions[name] for name in ('cpu', 'dma', 'sha'))
    assert type(cpu) is GeneratedCve2Session
    assert type(dma) is GeneratedWishboneDmaScenarioSession
    assert type(sha) is GeneratedAhbLiteRegisterSession
    assert cpu.artifact.plan.profile.component_id == 'ibex_rvfi_local'
    assert cpu.memory is dma.memory_service.memory
    assert cpu.memory.read(SOURCE, 4, transaction_id='test-source').value == 5
    assert cpu.defer_mmio
    assert cpu.native_irq_receipts_enabled
    assert all(session.process is None and session.local_ticks == 0
        for session in runner.sessions.values())


def test_cpu_routes_dma_controls_and_full_sha_aperture(fixture):
    cpu, dma, sha = (fixture.runner.sessions[name] for name in ('cpu', 'dma', 'sha'))
    assert [(row.device_id, row.base, row.size, row.target)
        for row in cpu.router.windows] == [
            ('dma', 0x40000000, 16, dma), ('sha', 0x40002000, 0x1000, sha)]


def test_dma_target_admits_only_full_word_ctrl_start(fixture):
    dma, sha = (fixture.runner.sessions[name] for name in ('dma', 'sha'))
    window, = dma.master_targets
    assert (window.component, window.base, window.size, window.endpoint) == (
        'sha', 0x40002000, 0x1000, sha)
    assert window.writable_offsets == (0x10,)
    assert window.accepted_write_values == (5,)
    assert window.byte_enable == 15
    assert window.readable_offsets == ()
    provider = sha.dma_master_target_provider_identity_document()
    assert (provider['offset'], provider['value'], provider['byte_enable']) == (0x10, 5, 15)


def test_dma_irq_has_exact_ownership_and_sixteen_tick_pulse(fixture):
    runner = fixture.runner
    binding = Binding('dma', 'irq', 'cpu', 'irq', 1)
    assert runner.bindings == (binding,)
    assert set(runner._irq_pulses) == {binding}
    assert runner._irq_pulses[binding].width_ticks == 16
    assert runner.ownership.document() == {
        'fields': [{'component_id': 'cpu', 'port': 'irq', 'width': 1}],
        'owners': [{'component_id': 'cpu', 'port': 'irq', 'bit_offset': 0,
            'width': 1, 'kind': 'bound', 'producer_ref': 'dma.irq'}]}


def test_dma_links_match_the_exact_generated_session_artifact(fixture):
    dma = fixture.runner.sessions['dma']
    assert set(fixture.dma_endpoint_links) == {'dma'}
    links = validate_dma_artifact_endpoint_links(
        fixture.dma_endpoint_links['dma'], dma.artifact)
    assert links.document() == fixture.dma_endpoint_links['dma']


def test_firmware_arguments_do_not_widen_dma_target_policy(tmp_path):
    module_name = 'myfuzz.scenario.ibex_dma_caliptra_sha_runner'
    assert importlib.util.find_spec(module_name) is not None, 'Caliptra runner fixture is missing'
    factory = importlib.import_module(module_name)
    from myfuzz.scenario.ibex_dma_caliptra_sha_example import ibex_dma_caliptra_sha_images
    destination = 0x40002014
    result = factory.make_ibex_dma_caliptra_sha_runner(cache_dir=tmp_path,
        source_value=7, destination_address=destination)
    try:
        cpu, dma = (result.runner.sessions[name] for name in ('cpu', 'dma'))
        images = ibex_dma_caliptra_sha_images(source_value=7, destination_address=destination)
        for address, image in images.items():
            for offset in range(0, len(image), 4):
                assert cpu.memory.read(address + offset, 4,
                    transaction_id=f'test-image-{address}-{offset}').data == image[offset:offset + 4]
        assert dma.master_targets[0].writable_offsets == (0x10,)
        assert dma.master_targets[0].accepted_write_values == (5,)
    finally:
        for session in result.runner.sessions.values():
            session.end_case()
