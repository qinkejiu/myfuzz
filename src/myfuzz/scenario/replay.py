"""Full event-trace replay from a fresh scenario runtime."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from typing import Callable

from .genome import GenomeCodec, ScenarioGenome
from .runner import ScenarioRunner
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
