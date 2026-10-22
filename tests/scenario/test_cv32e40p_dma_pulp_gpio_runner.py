"""Contract checks for the unstarted CV32E40P/DMA/PULP fixture."""
import importlib

import pytest

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.dma_artifact_endpoint_links import validate_dma_artifact_endpoint_links
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
from myfuzz.scenario.cv32e40p_dma_pulp_gpio_example import (
    MAIN, cv32e40p_dma_pulp_gpio_images,
)
from myfuzz.scenario.cv32e40p_dma_pulp_gpio_example import SOURCE
from myfuzz.scenario.ibex_dma_pulp_gpio_example import GPIO_BASE, PADOUT_ADDRESS
from myfuzz.scenario.pulp_gpio_dma_paths import GPIO_PADOUT_OFFSET
from myfuzz.scenario.runner import Binding

DMA_BASE = 0x40002000


def _factory():
    return importlib.import_module('myfuzz.scenario.cv32e40p_dma_pulp_gpio_runner')


def test_fixture_uses_cv32e40p_shared_ram_exact_padout_and_linked_dma(tmp_path):
    factory = _factory()
    fixture = factory.make_cv32e40p_dma_pulp_gpio_runner(cache_dir=tmp_path)
    try:
        runner = fixture.runner
        assert set(runner.sessions) == {'cpu', 'dma', 'gpio'}
        cpu, dma, gpio = (runner.sessions[key] for key in ('cpu', 'dma', 'gpio'))
        assert type(cpu) is GeneratedCve2Session
        assert type(dma) is GeneratedWishboneDmaScenarioSession
        assert type(gpio) is GeneratedPulpGpioSession
        assert cpu.artifact.plan.profile.component_id == 'cv32e40p'
        assert gpio.artifact.plan.profile.component_id == 'pulp_gpio_causal_local'
        assert cpu.memory is dma.memory_service.memory
        assert cpu.memory.identity_document()['regions'] == [
            {'memory_id': 'rom0', 'base': 0x10000, 'size': 0x8000,
                'aliases': (), 'readable': True, 'writable': False},
            {'memory_id': 'ram', 'base': 0x20000, 'size': 0x20000,
                'aliases': (), 'readable': True, 'writable': True}]
        assert cpu.memory.read(SOURCE, 4, transaction_id='fixture-source').value == 0x5AA55AA5
        assert cpu.defer_mmio
        assert not cpu.native_irq_receipts_enabled
        assert all(s.process is None and s.local_ticks == 0 for s in runner.sessions.values())

        assert [(w.device_id, w.base, w.size, w.target) for w in cpu.router.windows] == [
            ('dma', DMA_BASE, 16, dma), ('gpio', GPIO_BASE, 0x1000, gpio)]
        target, = dma.master_targets
        assert (target.component, target.base, target.size, target.endpoint) == (
            'gpio', GPIO_BASE, 0x1000, gpio)
        assert target.writable_offsets == (GPIO_PADOUT_OFFSET,)
        assert target.accepted_write_values == (0x5AA55AA5,)
        assert target.byte_enable == 15 and target.readable_offsets == ()
        assert target.accepts(PADOUT_ADDRESS, True, 0x5AA55AA5, 15)
        assert not target.accepts(PADOUT_ADDRESS + 4, True, 0x5AA55AA5, 15)

        binding = Binding('dma', 'irq', 'cpu', 'irq', 1)
        assert runner.bindings == (binding,)
        assert set(runner._irq_pulses) == {binding}
        assert runner._irq_pulses[binding].width_ticks == 16
        assert runner.ownership.document() == {
            'fields': [{'component_id': 'cpu', 'port': 'irq', 'width': 1},
                {'component_id': 'gpio', 'port': 'gpio_in', 'width': 32}],
            'owners': [{'component_id': 'cpu', 'port': 'irq', 'bit_offset': 0,
                'width': 1, 'kind': 'bound', 'producer_ref': 'dma.irq'},
                {'component_id': 'gpio', 'port': 'gpio_in', 'bit_offset': 0,
                'width': 32, 'kind': 'fixed', 'producer_ref': 'constant_zero'}]}
        assert set(fixture.dma_endpoint_links) == {'dma'}
        assert validate_dma_artifact_endpoint_links(
            fixture.dma_endpoint_links['dma'], dma.artifact).document() == fixture.dma_endpoint_links['dma']
    finally:
        for session in fixture.runner.sessions.values():
            session.end_case()


def test_wrong_offset_firmware_does_not_widen_target_and_partial_sessions_close(tmp_path,
        monkeypatch):
    factory = _factory()
    fixture = factory.make_cv32e40p_dma_pulp_gpio_runner(cache_dir=tmp_path,
        destination_address=PADOUT_ADDRESS + 4)
    try:
        cpu, dma = (fixture.runner.sessions[key] for key in ('cpu', 'dma'))
        assert cpu.memory.read(SOURCE, 4, transaction_id='wrong-offset-source').value == 0x5AA55AA5
        expected = cv32e40p_dma_pulp_gpio_images(
            destination_address=PADOUT_ADDRESS + 4)[MAIN]
        assert b''.join(cpu.memory.read(MAIN + offset, 4,
            transaction_id=f'wrong-offset-firmware-{offset}').data
            for offset in range(0, len(expected), 4)) == expected
        assert dma.master_targets[0].writable_offsets == (GPIO_PADOUT_OFFSET,)
    finally:
        for session in fixture.runner.sessions.values():
            session.end_case()

    created = []
    closed = []
    real_gpio = factory.GeneratedPulpGpioSession
    real_dma = factory.GeneratedWishboneDmaScenarioSession

    def record_gpio(*args, **kwargs):
        session = real_gpio(*args, **kwargs)
        created.append(session)
        original_end = session.end_case

        def end_case():
            closed.append(session)
            return original_end()

        session.end_case = end_case
        return session

    def record_dma(*args, **kwargs):
        session = real_dma(*args, **kwargs)
        created.append(session)
        original_end = session.end_case

        def end_case():
            closed.append(session)
            return original_end()

        session.end_case = end_case
        return session

    def fail_cpu(*args, **kwargs):
        raise RuntimeError('injected CPU construction failure')

    monkeypatch.setattr(factory, 'GeneratedPulpGpioSession', record_gpio)
    monkeypatch.setattr(factory, 'GeneratedWishboneDmaScenarioSession', record_dma)
    monkeypatch.setattr(factory, 'GeneratedCve2Session', fail_cpu)
    with pytest.raises(RuntimeError, match='injected CPU construction failure'):
        factory.make_cv32e40p_dma_pulp_gpio_runner(cache_dir=tmp_path)
    assert len(created) == 2
    assert closed == list(reversed(created))
