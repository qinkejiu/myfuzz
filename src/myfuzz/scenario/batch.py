"""Online command scripts for one reset-free, stateful scenario testcase.

The batch layer records when an environment source was admitted and which
independent harnesses advanced. It deliberately delegates ownership checks,
dataflow delivery, component timing, and persistent state to ``ScenarioRunner``.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import TYPE_CHECKING, Mapping

from .genome import GenomeCodec, ScenarioGenome
from .runner import ScenarioRunner

if TYPE_CHECKING:
    from .replay import ScenarioTrace


def _natural(value: int, name: str, *, minimum: int = 0) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")


@dataclass(frozen=True)
class BatchSourceEvent:
    """One mutation of an unbound Fuzzable Source input."""

    action_id: str
    component: str
    port: str
    value: int
    bit_offset: int = 0
    width: int | None = None

    def __post_init__(self) -> None:
        if not all(isinstance(item, str) and item
                   for item in (self.action_id, self.component, self.port)):
            raise ValueError("source event identity and endpoint are required")
        _natural(self.value, "source event value")
        _natural(self.bit_offset, "source event bit_offset")
        if self.width is not None:
            _natural(self.width, "source event width", minimum=1)
            if self.value >= 1 << self.width:
                raise ValueError("source event value exceeds width")


@dataclass(frozen=True)
class BatchAdvance:
    """Advance the named local harnesses once each in the supplied order."""

    schedule: tuple[str, ...]

    def __post_init__(self) -> None:
        if (not isinstance(self.schedule, tuple) or not self.schedule
                or any(not isinstance(item, str) or not item
                       for item in self.schedule)):
            raise ValueError("advance schedule must be a nonempty component tuple")


BatchCommand = BatchSourceEvent | BatchAdvance


@dataclass(frozen=True)
class ScenarioBatchPlan:
    """A reset-free template plus the ordered live command history."""

    template: ScenarioGenome
    commands: tuple[BatchCommand, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.template, ScenarioGenome):
            raise ValueError("ScenarioGenome template is required")
        if (self.template.actions != () or self.template.reset_actions != ()
                or self.template.quiesce_steps != 0):
            raise ValueError("batch template actions, resets, and quiesce must be empty")
        if not isinstance(self.commands, tuple) or any(
                not isinstance(command, (BatchSourceEvent, BatchAdvance))
                for command in self.commands):
            raise ValueError("commands must be an immutable tuple of batch commands")
        source_ids = [command.action_id for command in self.commands
                      if isinstance(command, BatchSourceEvent)]
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("source event action_id values must be unique")
        local_steps = 0
        components = set(self.template.schedule_order)
        for command in self.commands:
            if isinstance(command, BatchAdvance):
                if any(component not in components for component in command.schedule):
                    raise ValueError("advance schedule references an unknown component")
                local_steps += len(command.schedule)
            elif command.component not in components:
                raise ValueError("source event references an unknown component")
        if local_steps > self.template.max_steps:
            raise ValueError("batch commands exceed template max_steps")


class ScenarioBatchCodec:
    """Strict, versioned JSON encoding for an online command transcript."""

    VERSION = 1

    @staticmethod
    def encode(plan: ScenarioBatchPlan) -> bytes:
        if not isinstance(plan, ScenarioBatchPlan):
            raise ValueError("ScenarioBatchPlan is required")
        commands = []
        for command in plan.commands:
            if isinstance(command, BatchSourceEvent):
                commands.append({"kind": "source_event", **{
                    "action_id": command.action_id,
                    "component": command.component,
                    "port": command.port,
                    "value": command.value,
                    "bit_offset": command.bit_offset,
                    "width": command.width,
                }})
            else:
                commands.append({"kind": "advance",
                                 "schedule": list(command.schedule)})
        document = {"schema_version": ScenarioBatchCodec.VERSION,
                    "template": json.loads(GenomeCodec.encode(plan.template)),
                    "commands": commands}
        return json.dumps(document, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")

    @staticmethod
    def decode(raw: bytes) -> ScenarioBatchPlan:
        if not isinstance(raw, bytes):
            raise ValueError("batch plan must be bytes")

        def object_without_duplicate_keys(pairs):
            record = {}
            for key, value in pairs:
                if key in record:
                    raise ValueError("duplicate JSON object key")
                record[key] = value
            return record

        try:
            document = json.loads(raw.decode("utf-8"),
                                  object_pairs_hook=object_without_duplicate_keys)
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("invalid batch plan JSON") from exc
        if (not isinstance(document, dict)
                or set(document) != {"schema_version", "template", "commands"}
                or type(document.get("schema_version")) is not int
                or document["schema_version"] != ScenarioBatchCodec.VERSION):
            raise ValueError("unknown or missing batch plan fields/version")
        try:
            template_raw = json.dumps(
                document["template"], sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False).encode("utf-8")
            template = GenomeCodec.decode(template_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid batch template") from exc
        if not isinstance(document["commands"], list):
            raise ValueError("commands must be a list")
        commands: list[BatchCommand] = []
        source_fields = {"kind", "action_id", "component", "port", "value",
                         "bit_offset", "width"}
        advance_fields = {"kind", "schedule"}
        for record in document["commands"]:
            if not isinstance(record, dict):
                raise ValueError("batch command must be an object")
            kind = record.get("kind")
            if kind == "source_event":
                if set(record) != source_fields:
                    raise ValueError("unknown or missing source event fields")
                commands.append(BatchSourceEvent(
                    action_id=record["action_id"], component=record["component"],
                    port=record["port"], value=record["value"],
                    bit_offset=record["bit_offset"], width=record["width"]))
            elif kind == "advance":
                if set(record) != advance_fields:
                    raise ValueError("unknown or missing advance fields")
                schedule = record["schedule"]
                if not isinstance(schedule, list):
                    raise ValueError("advance schedule must be a list")
                commands.append(BatchAdvance(tuple(schedule)))
            else:
                raise ValueError("unknown batch command kind")
        return ScenarioBatchPlan(template, tuple(commands))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class ScenarioBatchRecorder:
    """Apply an online command stream to one supplied fresh ScenarioRunner."""

    def __init__(self, template: ScenarioGenome, runner: ScenarioRunner) -> None:
        if not isinstance(template, ScenarioGenome):
            raise ValueError("ScenarioGenome template is required")
        if not isinstance(runner, ScenarioRunner):
            raise ValueError("ScenarioRunner is required")
        if (template.actions != () or template.reset_actions != ()
                or template.quiesce_steps != 0):
            raise ValueError("batch template actions, resets, and quiesce must be empty")
        if set(template.schedule_order) != set(runner.sessions):
            raise ValueError("template schedule_order must contain every harness")
        if getattr(runner, "_status", None) != "created":
            raise ValueError("batch recorder requires a fresh ScenarioRunner")
        self.template = template
        self.runner = runner
        self._commands: list[BatchCommand] = []
        self._source_ids: set[str] = set()
        self._step_count = 0
        self._begin_attempted = False
        self._begun = False
        self._finished = False
        self._plan: ScenarioBatchPlan | None = None
        self._manifest_sha256 = ""
        self._trace = None

    @property
    def commands(self) -> tuple[BatchCommand, ...]:
        """Snapshot of successfully admitted commands so far."""
        return tuple(self._commands)

    @property
    def plan(self) -> ScenarioBatchPlan:
        if self._plan is None:
            raise RuntimeError("batch plan is available only after finish")
        return self._plan

    @property
    def trace(self) -> ScenarioTrace:
        if self._trace is None:
            raise RuntimeError("batch trace is available only after finish")
        return self._trace

    def begin(self) -> None:
        if self._begin_attempted or self._finished:
            raise RuntimeError("batch begin may be called exactly once")
        self._begin_attempted = True
        # Validate image destinations before writing any image into persistent
        # memory; the runner remains the sole owner of actual image loading.
        for image in self.template.initial_images:
            if image.component not in self.runner.sessions:
                raise ValueError("memory image references unknown local harness")
            if getattr(self.runner.sessions[image.component], "memory", None) is None:
                raise ValueError("local harness has no persistent memory")
        self._manifest_sha256 = hashlib.sha256(
            _canonical(self.runner.identity_document())).hexdigest()
        for image in self.template.initial_images:
            self.runner.preload_image(image)
        self.runner.begin_test(self.template.testcase_id)
        self._begun = True

    def _require_running(self) -> None:
        if not self._begun or self._finished:
            raise RuntimeError("batch command requires an active testcase")
        if getattr(self.runner, "_status", None) != "running":
            raise RuntimeError("batch testcase is not running")

    def submit_source_event(self, event: BatchSourceEvent) -> None:
        self._require_running()
        if not isinstance(event, BatchSourceEvent):
            raise ValueError("BatchSourceEvent is required")
        if event.action_id in self._source_ids:
            raise ValueError("source event action_id values must be unique")
        field_width = self.runner.ownership.field_width(event.component, event.port)
        selected_width = event.width if event.width is not None else field_width
        # Do all semantic checks before changing the runner or transcript.
        self.runner.ownership.mutation_source(
            event.component, event.port, event.bit_offset, selected_width,
            direction=self.template.direction)
        if event.value >= 1 << selected_width:
            raise ValueError("source event value exceeds selected source width")
        if event.component not in self.template.schedule_order:
            raise ValueError("source event component is absent from template")
        self._commands.append(event)
        self._source_ids.add(event.action_id)
        self.runner.inject_source(
            event.component, event.port, event.value,
            direction=self.template.direction, bit_offset=event.bit_offset,
            width=event.width, action_id=event.action_id)

    def advance(self, schedule: tuple[str, ...]) -> tuple[Mapping[str, int], ...]:
        self._require_running()
        command = BatchAdvance(schedule)
        if any(component not in self.template.schedule_order
               for component in command.schedule):
            raise ValueError("advance schedule references an unknown component")
        if self._step_count + len(command.schedule) > self.template.max_steps:
            raise ValueError("batch advance exceeds template max_steps")
        # Save the requested call boundary before stepping, so an exceptional
        # partial step can still be diagnosed and replayed from the same input.
        self._commands.append(command)
        self._step_count += len(command.schedule)
        return self.runner.step_batch(command.schedule)

    def finish(self) -> ScenarioTrace:
        if not self._begin_attempted or self._finished:
            raise RuntimeError("batch finish may be called exactly once after begin")
        status_before_finish = getattr(self.runner, "_status", None)
        if status_before_finish not in ("running", "quiescing", "failed"):
            raise RuntimeError("batch testcase was not started")
        self.runner.finalize()
        from .replay import ScenarioTrace

        self._plan = ScenarioBatchPlan(self.template, tuple(self._commands))
        encoded_plan = ScenarioBatchCodec.encode(self._plan)
        events = self.runner.events
        local_ticks = dict(self.runner.local_ticks)
        status = self.runner.failure_status or "complete"
        semantic_payload = {"status": status, "events": events,
                            "local_ticks": local_ticks}
        self._trace = ScenarioTrace(
            hashlib.sha256(encoded_plan).hexdigest(), status, events, local_ticks,
            hashlib.sha256(_canonical(semantic_payload)).hexdigest(),
            self._manifest_sha256)
        self._finished = True
        return self._trace
