"""Full event-trace replay from a fresh scenario runtime."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from typing import Callable

from .batch import (BatchAdvance, BatchSourceEvent, ScenarioBatchCodec,
                    ScenarioBatchPlan, ScenarioBatchRecorder)
from .genome import GenomeCodec, ScenarioGenome
from .protocol_io import LocalCommandDeadlineExceeded
from .runner import ScenarioBudgetExhausted, ScenarioRunner
from .scheduler import DependencyScheduler


@dataclass(frozen=True)
class ScenarioTrace:
    genome_sha256: str
    status: str
    events: tuple[dict, ...]
    local_ticks: dict[str, int]
    semantic_sha256: str
    manifest_sha256: str = ""


@dataclass(frozen=True)
class ReplayComparison:
    matches: bool
    first_difference: int | None
    expected_event: dict | None
    actual_event: dict | None
    actual_trace: ScenarioTrace
    difference_context: dict | None = None
    verification_scope: str = "full"


def _difference_context(expected: dict | None, actual: dict | None,
                        index: int) -> dict:
    event = actual if actual is not None else expected or {}
    context = {"event_index": index,
               "event_id": event.get("event_id"),
               "component": event.get("component"),
               "local_tick": event.get("local_tick", event.get("local_tick_after")),
               "transaction": event.get("transaction"),
               "memory_id": event.get("memory_id"),
               "generation": event.get("generation"),
               "byte_offset": event.get("byte_offset"),
               "version": event.get("version", event.get("versions")),
               "writer_event_id": event.get("writer_event_id",
                                            event.get("writer_event_ids")),
               "expected": deepcopy(expected), "actual": deepcopy(actual)}
    return context


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def record_scenario(genome: ScenarioGenome,
                    factory: Callable[[], ScenarioRunner]) -> ScenarioTrace:
    """Run fresh RTL; the recorded observations are never fed back as inputs."""
    if not isinstance(genome, ScenarioGenome):
        raise ValueError("ScenarioGenome is required")
    runner = factory()
    if not isinstance(runner, ScenarioRunner):
        raise ValueError("factory must return a fresh ScenarioRunner")
    return _record_with_runner(genome, runner)


def _record_with_runner(genome: ScenarioGenome,
                        runner: ScenarioRunner) -> ScenarioTrace:
    manifest_sha256 = hashlib.sha256(_canonical(runner.identity_document())).hexdigest()
    result = DependencyScheduler().run(runner, genome)
    events = deepcopy(runner.events)
    ticks = dict(runner.local_ticks)
    status = runner.failure_status or result.status
    payload = {"status": status, "events": events, "local_ticks": ticks}
    return ScenarioTrace(hashlib.sha256(GenomeCodec.encode(genome)).hexdigest(),
                         status, events, ticks,
                         hashlib.sha256(_canonical(payload)).hexdigest(),
                         manifest_sha256)


def replay_scenario(genome: ScenarioGenome,
                    factory: Callable[[], ScenarioRunner],
                    reference: ScenarioTrace) -> ReplayComparison:
    if not isinstance(reference, ScenarioTrace):
        raise ValueError("reference trace is required")
    expected_genome = hashlib.sha256(GenomeCodec.encode(genome)).hexdigest()
    if reference.genome_sha256 != expected_genome:
        raise ValueError("replay genome identity mismatch")
    if not reference.manifest_sha256:
        raise ValueError("replay manifest identity missing")
    runner = factory()
    if not isinstance(runner, ScenarioRunner):
        raise ValueError("factory must return a fresh ScenarioRunner")
    actual_manifest = hashlib.sha256(_canonical(runner.identity_document())).hexdigest()
    if reference.manifest_sha256 != actual_manifest:
        raise ValueError("replay manifest identity mismatch")
    actual = _record_with_runner(genome, runner)
    for index in range(max(len(reference.events), len(actual.events))):
        expected_event = reference.events[index] if index < len(reference.events) else None
        actual_event = actual.events[index] if index < len(actual.events) else None
        if expected_event != actual_event:
            return ReplayComparison(False, index, expected_event, actual_event,
                                    actual, _difference_context(expected_event,
                                                                actual_event, index))
    if (reference.status != actual.status
            or reference.local_ticks != actual.local_ticks
            or reference.semantic_sha256 != actual.semantic_sha256):
        index = len(reference.events)
        return ReplayComparison(
            False, index, None, None, actual,
            {"event_index": index, "expected_status": reference.status,
             "actual_status": actual.status,
             "expected_local_ticks": reference.local_ticks,
             "actual_local_ticks": actual.local_ticks,
             "expected_semantic_sha256": reference.semantic_sha256,
             "actual_semantic_sha256": actual.semantic_sha256})
    return ReplayComparison(True, None, None, None, actual)


def record_scenario_batch(plan: ScenarioBatchPlan,
                          factory: Callable[[], ScenarioRunner]) -> ScenarioTrace:
    """Record a live command stream in one fresh, continuous runtime."""
    if not isinstance(plan, ScenarioBatchPlan):
        raise ValueError("ScenarioBatchPlan is required")
    runner = factory()
    if not isinstance(runner, ScenarioRunner):
        raise ValueError("factory must return a fresh ScenarioRunner")
    return _record_batch_with_runner(plan, runner)


def _record_batch_with_runner(plan: ScenarioBatchPlan,
                              runner: ScenarioRunner) -> ScenarioTrace:
    recorder = ScenarioBatchRecorder(plan.template, runner)
    try:
        recorder.begin()
        for command in plan.commands:
            if isinstance(command, BatchSourceEvent):
                recorder.submit_source_event(command)
            elif isinstance(command, BatchAdvance):
                recorder.advance(command.schedule)
            else:  # Plan validation makes this unreachable; keep replay strict.
                raise ValueError("unknown batch command")
    except (ScenarioBudgetExhausted, LocalCommandDeadlineExceeded):
        # Budget exhaustion is a deterministic terminal testcase result. The
        # recorder already retains the command attempt that reached the limit.
        if runner.failure_status != "budget_exhausted":
            raise
    finally:
        if (not recorder._finished and recorder._begin_attempted
                and getattr(runner, "_status", None) in
                ("running", "quiescing", "failed")):
            recorder.finish()
    return recorder.trace


def _install_batch_wall_cut(runner: ScenarioRunner,
                            reference: ScenarioTrace) -> None:
    """Restore a saved wall-clock cutoff at its semantic command boundary."""
    cuts = [event for event in reference.events
            if event.get("kind") == "budget_exhausted"
            and event.get("limit") == "max_wall_time_ms"]
    if not cuts:
        return
    if len(cuts) != 1:
        raise ValueError("batch replay has multiple wall-time budget markers")
    marker = cuts[0]
    phase = marker.get("phase")
    prefix_ticks = marker.get("prefix_local_ticks", marker.get("local_ticks"))
    prefix_event_count = marker.get("prefix_event_count")
    if (not isinstance(prefix_ticks, dict)
            or any(type(value) is not int or value < 0
                   for value in prefix_ticks.values())
            or type(prefix_event_count) is not int or prefix_event_count < 0):
        raise ValueError("batch replay wall-time marker is incomplete")
    options = {"prefix_event_count": prefix_event_count}
    if phase == "inflight_step" and "step_timeout_us" in marker:
        value = marker["step_timeout_us"]
        if type(value) is not int or value < 0:
            raise ValueError("batch replay step wall-time marker is invalid")
        options["step_timeout_us"] = value
    if phase == "inflight_finalize":
        if "finalize_timeout_us" not in marker:
            raise ValueError(
                "batch replay finalize wall-time marker is incomplete")
        value = marker["finalize_timeout_us"]
        if type(value) is not int or value < 0:
            raise ValueError("batch replay finalize wall-time marker is invalid")
        options["finalize_timeout_us"] = value
    if phase in ("before_begin", "inflight_begin"):
        failed_component = marker.get("failed_component")
        started_components = marker.get("started_components")
        if (not isinstance(failed_component, str)
                or not isinstance(started_components, (tuple, list))
                or any(not isinstance(name, str) for name in started_components)):
            raise ValueError("batch replay begin wall-time marker is incomplete")
        options.update({"failed_component": failed_component,
                        "started_components": tuple(started_components)})
    runner.set_replay_wall_cut(sum(prefix_ticks.values()), phase, **options)


def replay_scenario_batch(plan: ScenarioBatchPlan,
                          factory: Callable[[], ScenarioRunner],
                          reference: ScenarioTrace) -> ReplayComparison:
    """Replay all live admissions and local-step boundaries from fresh RTL."""
    if not isinstance(plan, ScenarioBatchPlan):
        raise ValueError("ScenarioBatchPlan is required")
    if not isinstance(reference, ScenarioTrace):
        raise ValueError("reference trace is required")
    expected_plan = hashlib.sha256(ScenarioBatchCodec.encode(plan)).hexdigest()
    if reference.genome_sha256 != expected_plan:
        raise ValueError("replay batch identity mismatch")
    if not reference.manifest_sha256:
        raise ValueError("replay manifest identity missing")
    runner = factory()
    if not isinstance(runner, ScenarioRunner):
        raise ValueError("factory must return a fresh ScenarioRunner")
    actual_manifest = hashlib.sha256(_canonical(runner.identity_document())).hexdigest()
    if reference.manifest_sha256 != actual_manifest:
        raise ValueError("replay manifest identity mismatch")
    _install_batch_wall_cut(runner, reference)
    actual = _record_batch_with_runner(plan, runner)
    for index in range(max(len(reference.events), len(actual.events))):
        expected_event = reference.events[index] if index < len(reference.events) else None
        actual_event = actual.events[index] if index < len(actual.events) else None
        if expected_event != actual_event:
            return ReplayComparison(
                False, index, expected_event, actual_event, actual,
                _difference_context(expected_event, actual_event, index))
    if (reference.status != actual.status
            or reference.local_ticks != actual.local_ticks
            or reference.semantic_sha256 != actual.semantic_sha256):
        index = len(reference.events)
        return ReplayComparison(
            False, index, None, None, actual,
            {"event_index": index, "expected_status": reference.status,
             "actual_status": actual.status,
             "expected_local_ticks": reference.local_ticks,
             "actual_local_ticks": actual.local_ticks,
             "expected_semantic_sha256": reference.semantic_sha256,
             "actual_semantic_sha256": actual.semantic_sha256})
    return ReplayComparison(True, None, None, None, actual)
