"""ScenarioRunner interface for an actual dual-role Wishbone DMA process."""
from collections.abc import Mapping
from copy import deepcopy

from .wishbone_dma_session import GeneratedWishboneDmaSession


class GeneratedWishboneDmaScenarioSession(GeneratedWishboneDmaSession):
    """Expose measured DMA edges, RAM facts and native IRQ to the scheduler.

    Keyword control steps retain the direct driver's receipt API. A mapping
    step is a scheduler-owned idle control edge, with no fuzzable DUT inputs.
    Both paths retain samples, including edges advanced by CPU MMIO accesses.
    """

    artifact_kind = 'wishbone_dma'
    max_local_ticks_per_step = 1
    max_transaction_events_per_step = 1
    max_mmio_target_accesses_per_step = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.master_targets:
            raise ValueError('scenario DMA IP master targets require explicit scheduler bounds')
        exports = [p for p in self.artifact.runtime_document['physical_exports']
            if p['direction'] == 'output' and p['role'] == 'irq'
            and p['width'] == 1 and p['disposition'] == 'functional']
        if len(exports) != 1:
            raise ValueError('scenario DMA requires one declared native IRQ output')
        self._irq_runtime_name = exports[0]['runtime_name']
        self.service = self.memory_service
        self.memory = self.service.memory
        self.max_local_ticks_per_register_access = self.max_control_edges
        self._scenario_samples = []

    @property
    def runtime_events(self):
        return self.events

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._scenario_samples.clear()

    def drain_tick_samples(self):
        samples = tuple(self._scenario_samples)
        self._scenario_samples.clear()
        return samples

    def step_local(self, inputs=None, **control):
        scheduler_step = inputs is not None
        if scheduler_step and (not isinstance(inputs, Mapping) or inputs or control):
            raise ValueError('scenario DMA has no external input')
        receipt = super().step_local(**control)
        samples = receipt.payload.get('samples')
        if not isinstance(samples, list) or len(samples) != 1:
            raise RuntimeError('scenario DMA requires one measured native sample')
        sample = deepcopy(samples[0])
        if sample.get('local_tick') != receipt.tick_after:
            raise RuntimeError('scenario DMA sample tick mismatch')
        sample['native_local_tick'] = sample['local_tick']
        sample['local_tick'] += self._tick_base
        event = self.events[-1]
        event.update(native_local_tick=event['tick'],
            tick=self._tick_base + receipt.tick_after, reset_epoch=self.reset_epoch)
        for phase in ('pre', 'post'):
            level = sample[phase]['physical'][self._irq_runtime_name]
            if type(level) is not int or level not in (0, 1):
                raise RuntimeError('scenario DMA native IRQ is not one bit')
            sample[phase]['irq'] = level
        self._scenario_samples.append(sample)
        if not scheduler_step:
            return receipt
        return dict(irq=sample['post']['irq'])

    def identity_document(self):
        return {**super().identity_document(), 'scenario_dma_interface': dict(
            schema_version='scenario_dma_interface.v1',
            master_targets='RAM_only', irq_runtime_name=self._irq_runtime_name,
            max_control_edges=self.max_control_edges,
            raw_samples='all_control_and_scheduler_edges_pre_post')}
