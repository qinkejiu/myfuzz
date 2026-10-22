from pathlib import Path
from types import SimpleNamespace

import pytest

import myfuzz.scenario.ibex_dma_pulp_gpio_runner as factory
from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract
from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.pulp_gpio_dma_paths import GPIO_PADOUT_OFFSET


GPIO_BASE = factory.GPIO_BASE
PADOUT = factory.PADOUT_ADDRESS


class _GPIO:
    def __init__(self, artifact, **kwargs):
        self.artifact = artifact
        self.max_local_ticks_per_register_access = 37
        self.started = 0
        self.ended = 0

    @property
    def routed_register_access_enabled(self):
        return True

    def identity_document(self):
        return {'component': 'gpio', 'runtime': 'test'}

    def dma_master_target_provider_identity_document(self):
        return {
            'schema_version': 'pulp_gpio_dma_target_provider.v1',
            'api_schema_version': 'dma_master_target_access.v1',
            'implementation_profile': 'pulp_gpio_padout_apb3.v1',
            'observation_contract': pulp_gpio_observation_contract(),
            'operations': [{'operation': 'write', 'register': 'PADOUT',
                'offset': GPIO_PADOUT_OFFSET, 'byte_enable': 15}],
        }

    def dma_master_target_access(self, *args, **kwargs):
        raise AssertionError('route compilation must not execute the provider')

    def write_register(self, offset, value, *, be=15):
        raise AssertionError('route compilation must not access GPIO')

    def end_case(self):
        self.ended += 1


class _DMA:
    def __init__(self, artifact, *, memory, master_targets, **kwargs):
        self.memory_service = MemoryService(memory, TransactionLedger())
        self.master_targets = master_targets
        self.route_admission = None
        self.route_validator = None
        self.started = 0
        self.ended = 0

    def dma_route_endpoint_identity_document(self):
        return {'schema_version': 'test_dma_endpoint.v1'}

    def configure_dma_route_validator(self, validator):
        self.route_validator = validator

    def configure_dma_route_admission(self, admission):
        self.route_admission = admission

    def indirect_step_tick_bounds(self):
        endpoint = self.master_targets[0].endpoint
        return {'gpio': (endpoint, endpoint.max_local_ticks_per_register_access)}

    def end_case(self):
        self.ended += 1


class _CPU:
    def __init__(self, artifact, *, memory, router, **kwargs):
        self.memory = memory
        self.router = router
        self.started = 0
        self.ended = 0

    def end_case(self):
        self.ended += 1


def _install(monkeypatch, *, shadow_dma_memory=False):
    created = []

    class GPIO(_GPIO):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

    class DMA(_DMA):
        def __init__(self, artifact, *, memory, master_targets, **kwargs):
            if shadow_dma_memory:
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', factory.RAM_BASE,
                        factory.RAM_SIZE),), initialization_seed=17,
                    max_initialized_bytes=factory.RAM_SIZE)
            super().__init__(artifact, memory=memory,
                master_targets=master_targets, **kwargs)
            created.append(self)

    class CPU(_CPU):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

    gpio_artifact = SimpleNamespace(runtime_document={
        'kind': 'apb_gpio',
        'gpio_observation_contract': pulp_gpio_observation_contract()})
    monkeypatch.setattr(factory, 'GeneratedPulpGpioSession', GPIO)
    monkeypatch.setattr(factory, 'GeneratedWishboneDmaScenarioSession', DMA)
    monkeypatch.setattr(factory, 'GeneratedCve2Session', CPU)
    monkeypatch.setattr(factory, '_gpio_artifact', lambda _root: gpio_artifact)
    monkeypatch.setattr(factory, '_artifact', lambda *args, **kwargs: object())
    return created


def test_factory_binds_one_shared_ram_word_to_real_pulp_window_and_irq(monkeypatch,
        tmp_path):
    _install(monkeypatch)

    runner, paths = factory.make_ibex_dma_pulp_gpio_runner(cache_dir=tmp_path)

    assert set(runner.sessions) == {'cpu', 'dma', 'gpio'}
    cpu, dma, gpio = (runner.sessions[name] for name in ('cpu', 'dma', 'gpio'))
    assert cpu.memory is dma.memory_service.memory
    assert cpu.memory.read(factory.SOURCE, 4,
        transaction_id='test-source-image').value == 0x5AA55AA5
    assert len(dma.master_targets) == 1
    window = dma.master_targets[0]
    assert type(window) is MasterTargetWindow
    assert (window.component, window.base, window.size, window.endpoint) == (
        'gpio', GPIO_BASE, 0x1000, gpio)
    assert window.writable_offsets == (GPIO_PADOUT_OFFSET,)
    assert window.accepted_write_values == range(0, 1 << 32)
    assert [(row.device_id, row.base, row.size, row.target) for row in
        cpu.router.windows] == [
            ('dma', factory.DMA_BASE, 16, dma),
            ('gpio', GPIO_BASE, 0x1000, gpio)]
    binding, = runner.bindings
    assert (binding.source_component, binding.source_port,
        binding.target_component, binding.target_port, binding.width) == (
            'dma', 'irq', 'cpu', 'irq', 1)
    assert runner._irq_pulses[binding].width_ticks == 16
    owners = runner.ownership.document()['owners']
    assert any(row['component_id'] == 'cpu' and row['port'] == 'irq'
        and row['kind'] == 'bound' and row['producer_ref'] == 'dma.irq'
        for row in owners)
    assert any(row['component_id'] == 'gpio' and row['port'] == 'gpio_in'
        and row['kind'] == 'fixed' and row['producer_ref'] == 'constant_zero'
        for row in owners)
    assert paths.image_address == factory.SOURCE
    assert paths.admission.gpio_window is window
    assert dma.route_admission is paths.admission
    assert dma.route_validator is not None
    paths.compiled.validate_topology()


@pytest.mark.parametrize('failure', ['wrong_offset', 'split_memory'])
def test_factory_refuses_invalid_route_before_any_session_starts(monkeypatch,
        tmp_path, failure):
    created = _install(monkeypatch,
        shadow_dma_memory=(failure == 'split_memory'))
    if failure == 'wrong_offset':
        actual_window = factory.MasterTargetWindow

        def wrong_offset(component, base, size, endpoint, writable_offsets,
                accepted_write_values, byte_enable=15, readable_offsets=()):
            return actual_window(component, base, size, endpoint,
                (GPIO_PADOUT_OFFSET + 4,), accepted_write_values,
                byte_enable, readable_offsets)

        monkeypatch.setattr(factory, 'MasterTargetWindow', wrong_offset)

    with pytest.raises(ValueError):
        factory.make_ibex_dma_pulp_gpio_runner(cache_dir=tmp_path)

    assert created
    assert all(session.started == 0 for session in created)
