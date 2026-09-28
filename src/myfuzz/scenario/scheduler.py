"""Fair local stepping and causally triggered source actions for one testcase."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .genome import ScenarioGenome
from .runner import QuiesceResult, ScenarioRunner


@dataclass(frozen=True)
class ConsumptionCursor:
    """Identity of the observed source edge that selected one action."""

    kind: str
    event_id: int | None
    epoch: int
    occurrence: int
    source_component: str = ""
    source_port: str = ""


@dataclass(frozen=True)
class SchedulerResult:
    status: str
    steps: int
    fired_actions: tuple[str, ...]
    pending_actions: tuple[str, ...]
    fired_resets: tuple[str, ...] = ()
    pending_resets: tuple[str, ...] = ()
    quiesce: QuiesceResult | None = None
    consumption_cursor_records: tuple[tuple[str, ConsumptionCursor], ...] = ()

    @property
    def consumption_cursors(self) -> Mapping[str, ConsumptionCursor]:
        """Read-only lookup of fired action IDs to their source identities."""
        return MappingProxyType(dict(self.consumption_cursor_records))


class DependencyScheduler:
    """Permit future source input changes; never predict DUT outputs.

    AFTER_OUTPUT detects a transition into a predicate. A held IRQ is one
    occurrence until the actual observed signal leaves and re-enters it.
    """

    def run(self, runner: ScenarioRunner, genome: ScenarioGenome, *,
            batch_sizes: tuple[int, ...] | None = None) -> SchedulerResult:
        if not isinstance(runner, ScenarioRunner) or not isinstance(genome, ScenarioGenome):
            raise ValueError("runner and genome are required")
        if batch_sizes is not None and (not isinstance(batch_sizes, tuple)
                                        or not batch_sizes
                                        or any(isinstance(size, bool)
                                               or not isinstance(size, int)
                                               or size <= 0
                                               for size in batch_sizes)):
            raise ValueError("batch_sizes must be a nonempty tuple of positive integers")
        if set(genome.schedule_order) != set(runner.sessions):
            raise ValueError("schedule_order must contain every local harness")
        for action in genome.actions:
            if action.direction != genome.direction:
                raise ValueError("action direction disagrees with genome")
            field_width = runner.ownership.field_width(action.component, action.port)
            width = action.width if action.width is not None else field_width
            runner.ownership.mutation_source(action.component, action.port,
                                             action.bit_offset, width,
                                             direction=action.direction)
            if action.value >= 1 << width:
                raise ValueError("action value exceeds selected source width")
        if genome.reset_actions:
            for component, session in runner.sessions.items():
                if not callable(getattr(session, "reset_local", None)):
                    raise ValueError(f"local harness {component} cannot reset")
        for image in genome.initial_images:
            runner.preload_image(image)

        pending: dict[str, int] = {}
        fired: set[str] = set()
        counts = {action.action_id: 0 for action in genome.actions}
        previous_match = {action.action_id: False for action in genome.actions}
        reset_pending: dict[str, int] = {}
        reset_fired: set[str] = set()
        reset_counts = {action.action_id: 0 for action in genome.reset_actions}
        reset_previous_match = {action.action_id: False for action in genome.reset_actions}
        selected_cursors: dict[str, ConsumptionCursor] = {}
        consumed_cursors: dict[str, ConsumptionCursor] = {}
        for action in genome.actions:
            if action.trigger.kind == "START":
                clock = action.delay_component or action.component
                pending[action.action_id] = runner.local_ticks[clock] + action.delay_ticks
                selected_cursors[action.action_id] = ConsumptionCursor(
                    "START", None, runner.command_epoch, 0)
        for action in genome.reset_actions:
            if action.trigger.kind == "START":
                clock = action.delay_component or genome.schedule_order[0]
                reset_pending[action.action_id] = runner.local_ticks[clock] + action.delay_ticks
                selected_cursors[action.action_id] = ConsumptionCursor(
                    "START", None, runner.command_epoch, 0)

        def release_due() -> None:
            for action in genome.reset_actions:
                if action.action_id not in reset_pending:
                    continue
                clock = action.delay_component or genome.schedule_order[0]
                if runner.local_ticks[clock] < reset_pending[action.action_id]:
                    continue
                runner.reset_all(action.policy)
                reset_fired.add(action.action_id)
                consumed_cursors[action.action_id] = selected_cursors[action.action_id]
                del reset_pending[action.action_id]
                for identity in previous_match:
                    previous_match[identity] = False
                for identity in reset_previous_match:
                    reset_previous_match[identity] = False
            for action in genome.actions:
                if action.action_id not in pending:
                    continue
                clock = action.delay_component or action.component
                if runner.local_ticks[clock] < pending[action.action_id]:
                    continue
                runner.inject_source(action.component, action.port, action.value,
                                     direction=action.direction,
                                     bit_offset=action.bit_offset,
                                     width=action.width,
                                     action_id=action.action_id)
                fired.add(action.action_id)
                consumed_cursors[action.action_id] = selected_cursors[action.action_id]
                del pending[action.action_id]

        steps = 0
        quiesce_result: QuiesceResult | None = None
        failure_status: str | None = None
        last_event_count = 0

        def observed_cursor(component: str, source_event_id: int,
                            source_epoch: int,
                            source_port: str, occurrence: int) -> ConsumptionCursor:
            return ConsumptionCursor("AFTER_OUTPUT", source_event_id,
                                     source_epoch, occurrence,
                                     component, source_port)

        def observe_step(component: str, outputs: Mapping[str, int]) -> None:
            nonlocal steps, last_event_count
            source_events = tuple(event for event in runner.events_since(last_event_count)
                                  if event.get("component") == component
                                  and "outputs" in event)
            if (len(source_events) != 1
                    or source_events[0]["outputs"] != dict(outputs)):
                raise RuntimeError("observed output has no unique source step event")
            source_event_id = source_events[0]["event_id"]
            source_epoch = runner.command_epoch
            steps += 1
            for action in genome.actions:
                if (action.action_id in fired or action.action_id in pending
                        or action.trigger.kind != "AFTER_OUTPUT"
                        or action.trigger.source_component != component):
                    continue
                trigger = action.trigger
                observed = outputs.get(trigger.source_port)
                matched = (isinstance(observed, int) and not isinstance(observed, bool)
                           and observed >= 0
                           and observed & trigger.mask == trigger.value)
                if matched and not previous_match[action.action_id]:
                    counts[action.action_id] += 1
                    if counts[action.action_id] == trigger.occurrence:
                        clock = action.delay_component or action.component
                        pending[action.action_id] = (
                            runner.local_ticks[clock] + action.delay_ticks)
                        selected_cursors[action.action_id] = observed_cursor(
                            component, source_event_id, source_epoch,
                            trigger.source_port,
                            counts[action.action_id])
                previous_match[action.action_id] = matched
            for action in genome.reset_actions:
                if (action.action_id in reset_fired or action.action_id in reset_pending
                        or action.trigger.kind != "AFTER_OUTPUT"
                        or action.trigger.source_component != component):
                    continue
                trigger = action.trigger
                observed = outputs.get(trigger.source_port)
                matched = (isinstance(observed, int) and not isinstance(observed, bool)
                           and observed >= 0
                           and observed & trigger.mask == trigger.value)
                if matched and not reset_previous_match[action.action_id]:
                    reset_counts[action.action_id] += 1
                    if reset_counts[action.action_id] == trigger.occurrence:
                        clock = action.delay_component or component
                        reset_pending[action.action_id] = (
                            runner.local_ticks[clock] + action.delay_ticks)
                        selected_cursors[action.action_id] = observed_cursor(
                            component, source_event_id, source_epoch,
                            trigger.source_port,
                            reset_counts[action.action_id])
                reset_previous_match[action.action_id] = matched
            release_due()
            last_event_count = runner.event_count

        try:
            runner.begin_test(genome.testcase_id)
            release_due()
            last_event_count = runner.event_count
            if batch_sizes is None:
                for index in range(genome.max_steps):
                    component = genome.schedule_order[index % len(genome.schedule_order)]
                    observe_step(component, runner.step(component))
            else:
                offset = batch_index = 0
                while offset < genome.max_steps:
                    size = min(batch_sizes[batch_index % len(batch_sizes)],
                               genome.max_steps - offset)
                    schedule = tuple(genome.schedule_order[
                        (offset + index) % len(genome.schedule_order)]
                        for index in range(size))
                    runner.step_batch(schedule, on_step=observe_step)
                    offset += size
                    batch_index += 1
            if genome.quiesce_steps:
                quiesce_result = runner.quiesce(genome.quiesce_steps)
        except Exception:
            failure_status = runner.failure_status or "environment_error"
        finally:
            runner.finalize()
        failure_status = runner.failure_status or failure_status
        path_complete = (len(fired) == len(genome.actions)
                         and len(reset_fired) == len(genome.reset_actions))
        status = "complete" if path_complete else "path_incomplete"
        if quiesce_result is not None and quiesce_result.status != "drained":
            status = quiesce_result.status
        if failure_status is not None:
            status = failure_status
        return SchedulerResult(
            status,
            steps, tuple(action.action_id for action in genome.actions
                         if action.action_id in fired),
            tuple(action.action_id for action in genome.actions
                  if action.action_id not in fired),
            tuple(action.action_id for action in genome.reset_actions
                  if action.action_id in reset_fired),
            tuple(action.action_id for action in genome.reset_actions
                  if action.action_id not in reset_fired),
            quiesce_result,
            tuple((action.action_id, consumed_cursors[action.action_id])
                  for action in (*genome.actions, *genome.reset_actions)
                  if action.action_id in consumed_cursors))
