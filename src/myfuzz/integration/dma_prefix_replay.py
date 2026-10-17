"""Unified fresh prefix replay for recorded DMA descriptor runs (S4).

One implementation for every direction: the recorded ``ScenarioBatchPlan`` is
executed again on brand-new native processes, then *every* real event, local
tick and per-case certificate of the requested prefix is compared through the
typed normalizer.  A divergence raises :class:`PrefixDivergence` carrying the
first difference (path and both values); no comparison here rewrites whole
documents or replaces arbitrary strings.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.replay_normalize import (PrefixDivergence,
    first_difference_normalized, first_replay_difference,
    normalize_execution_identities, normalized_digest)


@dataclass(frozen=True)
class DmaPrefixReference:
    """The recorded run reduced to what a prefix replay must reproduce."""

    direction: str
    plan: object
    cases: tuple[dict, ...]
    local_ticks: dict
    events: tuple[dict, ...]
    uncertain_status: dict
    identities: dict
    execution_ids: dict
    source_pins: dict
    budget: ResourceBudget
    phase: str
    case_index: int
    error: dict | None
    trace: object | None

    def __post_init__(self):
        if self.direction not in ('RX_TO_RAM', 'RAM_TO_RAM', 'RAM_TO_TX',
                                  'DMA_DESCRIPTOR'):
            raise ValueError('unknown DMA prefix replay direction')
        if not isinstance(self.budget, ResourceBudget):
            raise ValueError('prefix replay reference requires its budget')
        if not isinstance(self.cases, tuple) or not self.cases:
            raise ValueError('prefix replay reference requires recorded cases')

    @property
    def case_count(self) -> int:
        return len(self.cases)

    def command_documents(self, case_count=None):
        limit = (len(self.plan.commands) if case_count is None
                 else self.cases[case_count - 1]['command_end'])
        return tuple(_command_document(command)
                     for command in self.plan.commands[:limit])

    def prefix_document(self, case_count):
        if type(case_count) is not int or not 1 <= case_count <= len(self.cases):
            raise ValueError('case_count must select a recorded case')
        case = self.cases[case_count - 1]
        return dict(schema_version='dma_prefix_reference.v1',
            direction=self.direction,
            plan=[_command_document(command)
                  for command in self.plan.commands[:case['command_end']]],
            events=self.events[:case['event_end']],
            cases=list(self.cases[:case_count]),
            ticks=dict(case['ticks_after']))

    def prefix_digest(self, case_count):
        return normalized_digest(self.prefix_document(case_count),
            self.execution_ids)


@dataclass(frozen=True)
class DmaPrefixReplayResult:
    """Outcome of one successful typed prefix replay (differences raise)."""

    direction: str
    case_count: int
    command_count: int
    event_count: int
    ticks: dict
    prefix_sha256: str
    fresh_execution_ids: dict

    @property
    def equal(self) -> bool:
        return True


def _command_document(command):
    if isinstance(command, BatchSourceEvent):
        return dict(kind='source_event', action_id=command.action_id,
            component=command.component, port=command.port, value=command.value,
            bit_offset=command.bit_offset, width=command.width)
    if isinstance(command, BatchAdvance):
        return dict(kind='advance', schedule=list(command.schedule))
    raise ValueError('unknown batch command')


def prefix_reference(result, *, direction='DMA_DESCRIPTOR') -> DmaPrefixReference:
    """Derive the replay reference from one recorded descriptor ``DescriptorResult``."""
    if not isinstance(getattr(result, 'cases', None), tuple) or not result.cases:
        raise ValueError('recorded descriptor cases are required')
    return DmaPrefixReference(direction=direction, plan=result.plan,
        cases=tuple(result.cases), local_ticks=dict(result.local_ticks),
        events=tuple(result.events), uncertain_status=dict(result.uncertain_status),
        identities=dict(result.identities),
        execution_ids=dict(result.execution_ids), source_pins=dict(result.source_pins),
        budget=result.budget, phase=result.phase, case_index=result.case_index,
        error=result.error, trace=result.trace)


def _as_descriptor_result(reference):
    from myfuzz.integration.dma_uart_descriptor_runtime import DescriptorResult
    return DescriptorResult(reference.plan, reference.trace, reference.cases,
        reference.identities, reference.execution_ids, reference.budget,
        reference.phase, reference.case_index, reference.error, reference.events,
        reference.local_ticks, reference.uncertain_status, reference.source_pins)


def compare_dma_prefix(reference, fresh, *, case_count):
    """Compare every real event/tick/case of the prefix through typed rules.

    ``reference`` is the recorded run and ``fresh`` the new one.  Raises
    :class:`PrefixDivergence` at the first difference with its path instead of
    collapsing the comparison to a boolean.
    """
    if not isinstance(reference, DmaPrefixReference):
        raise ValueError('DmaPrefixReference is required')
    if type(case_count) is not int or not 1 <= case_count <= len(reference.cases):
        raise ValueError('case_count must select a recorded case')
    if len(fresh.cases) < case_count:
        raise RuntimeError('fresh replay did not reach every requested case')
    if dict(fresh.identities) != dict(reference.identities):
        raise RuntimeError('fresh replay native identity documents differ')
    if dict(fresh.execution_ids) == dict(reference.execution_ids):
        raise RuntimeError('fresh replay must use new native executions')
    case = reference.cases[case_count - 1]
    if case['command_end'] > len(reference.plan.commands):
        raise ValueError('recorded case command boundary exceeds the plan')
    commands = reference.command_documents(case_count)
    fresh_commands = tuple(_command_document(command)
        for command in fresh.plan.commands[:case['command_end']])
    difference = first_difference_normalized(list(commands),
        list(fresh_commands))
    if difference is not None:
        raise PrefixDivergence('plan', difference)
    event_end = case['event_end']
    if len(fresh.events) < event_end:
        raise RuntimeError('fresh replay produced a shorter event prefix')
    difference = first_replay_difference(list(reference.events[:event_end]),
        list(fresh.events[:event_end]),
        reference_execution_ids=reference.execution_ids,
        actual_execution_ids=fresh.execution_ids)
    if difference is not None:
        raise PrefixDivergence('event', difference)
    for position in range(case_count):
        difference = first_replay_difference(reference.cases[position],
            fresh.cases[position],
            reference_execution_ids=reference.execution_ids,
            actual_execution_ids=fresh.execution_ids)
        if difference is not None:
            difference = dict(difference,
                path=['cases', position, *difference.get('path', [])])
            raise PrefixDivergence('case', difference)
    ticks = reference.cases[case_count - 1]['ticks_after']
    difference = first_difference_normalized(ticks,
        fresh.cases[case_count - 1]['ticks_after'])
    if difference is not None:
        raise PrefixDivergence('tick', difference)
    return DmaPrefixReplayResult(direction=reference.direction,
        case_count=case_count, command_count=len(commands),
        event_count=event_end, ticks=dict(ticks),
        prefix_sha256=reference.prefix_digest(case_count),
        fresh_execution_ids=dict(fresh.execution_ids))


def replay_dma_prefix(reference, *, case_count, cache_dir: Path,
        budget: ResourceBudget | None = None,
        factory: Callable[[], object] | None = None):
    """Fresh full replay plus typed comparison of the requested prefix.

    The descriptor runtime replays the entire recorded command plan on fresh
    native processes (the strictest fresh form); this function then compares
    exactly the requested prefix and reports the first real difference.  A
    direction with its own fresh replay can pass its own ``replay`` callable
    through the factory boundary in a later increment.
    """
    from myfuzz.integration.dma_uart_descriptor_runtime import (
        replay_descriptor_cases)
    fresh = replay_descriptor_cases(_as_descriptor_result(reference),
        cache_dir=cache_dir, budget=budget, factory=factory)
    return compare_dma_prefix(reference, fresh, case_count=case_count)


__all__ = ['DmaPrefixReference', 'DmaPrefixReplayResult', 'prefix_reference',
           'compare_dma_prefix', 'replay_dma_prefix']
