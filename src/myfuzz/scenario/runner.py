"""Minimal continuous runner for independently stepped local harnesses.

Sessions own RTL and local protocol time. The runner keeps scenario inputs
between calls and routes only values actually observed from a session.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, is_dataclass
import json
from typing import Callable, Mapping, Protocol
import time
import uuid

from .ownership import OwnershipMap
from .contracts import ResourceBudget
from .protocol_io import (LocalCommandDeadlineExceeded, command_deadline)
from .host_identity import host_source_identity
from .state_dependency import StateDependencyTracker
from .genome import MemoryImage
from .irq import IrqPulseDelivery
from .memory import PersistentMemory


class LocalHarnessSession(Protocol):
    def begin_case(self, testcase_id: str) -> None: ...
    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]: ...
    def end_case(self) -> None: ...


@dataclass(frozen=True)
class Binding:
    source_component: str
    source_port: str
    target_component: str
    target_port: str
    width: int
    source_bit_offset: int = 0
    target_bit_offset: int = 0

    def __post_init__(self) -> None:
        if not all((self.source_component, self.source_port,
                    self.target_component, self.target_port)):
            raise ValueError("binding endpoints must be nonempty")
        for name in ("width", "source_bit_offset", "target_bit_offset"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) \
                    or value < (1 if name == "width" else 0):
                    raise ValueError("invalid binding bit range")


@dataclass(frozen=True)
class ResetResult:
    policy: str
    memory_generations: dict[str, int]
    cancelled_responses: dict[str, int]


@dataclass(frozen=True)
class QuiesceResult:
    status: str
    steps: int
    pending_responses: dict[str, int]
    uncertain_transactions: tuple[str, ...]


@dataclass(frozen=True)
class StepReceipt:
    execution_id: str
    command_sequence: int
    epoch: int
    component: str
    inputs: dict[str, int]
    outputs: dict[str, int]
    events: tuple[dict, ...]
    local_tick: int


class ScenarioBudgetExhausted(ValueError):
    """A bounded semantic trace cannot accept another ordinary event."""


class ScenarioFinalStateGrowthViolation(RuntimeError):
    """A local harness exceeded its declared evidence state growth bound."""


class ScenarioEvidenceRecordViolation(RuntimeError):
    """A local harness produced an event above its declared byte bound."""


class _EventLog(list):
    def __init__(self, runner: ScenarioRunner) -> None:
        super().__init__()
        self.runner = runner

    def append(self, record: dict) -> None:
        self.runner._ensure_semantic_capacity("append_event")
        super().append(record)
        if record.get("kind") in ("memory_read", "memory_write", "mmio_delivery",
                                  "local_register_transaction"):
            self.runner._transaction_count += 1
        self.runner._count_evidence_record(record)


class ScenarioRunner:
    def __init__(self, *, sessions: Mapping[str, LocalHarnessSession],
                 ownership: OwnershipMap, bindings: tuple[Binding, ...],
                 irq_pulses: Mapping[Binding, int] | None = None,
                 independent_baseline: bool = False) -> None:
        if not sessions:
            raise ValueError("at least one local harness is required")
        if not isinstance(independent_baseline, bool):
            raise ValueError("independent_baseline must be boolean")
        if independent_baseline and (bindings or irq_pulses):
            raise ValueError("independent baseline cannot have cross-component bindings")
        if independent_baseline and any(
                owner["kind"] == "bound" for owner in ownership.document()["owners"]):
            raise ValueError("independent baseline cannot own bound inputs")
        self.sessions = dict(sessions)
        self.ownership = ownership
        self.bindings = bindings
        self.independent_baseline = independent_baseline
        self._irq_pulses: dict[Binding, IrqPulseDelivery] = {}
        for binding, width in (irq_pulses or {}).items():
            if binding not in bindings or binding.width != 1:
                raise ValueError("IRQ pulse must select a declared one-bit binding")
            self._irq_pulses[binding] = IrqPulseDelivery(width_ticks=width)
        self._irq_event_offsets = {binding: 0 for binding in self._irq_pulses}
        for binding in bindings:
            if binding.source_component not in self.sessions \
                    or binding.target_component not in self.sessions:
                raise ValueError("binding references unknown local harness")
            expected = f"{binding.source_component}.{binding.source_port}"
            actual = ownership.binding_producer(
                binding.target_component, binding.target_port,
                binding.target_bit_offset, binding.width)
            if actual != expected:
                raise ValueError("binding producer does not match input ownership")
        target_routers: dict[str, object] = {}
        for session in self.sessions.values():
            router = getattr(session, "router", None)
            if router is None:
                continue
            for window in getattr(router, "windows", ()):
                if (independent_baseline and window.device_id.endswith("_local")
                        and window.device_id not in self.sessions
                        and not getattr(session, "defer_mmio", True)):
                    # Comparison-only CPU responses come from a declared local
                    # shadow, never from a second component's RTL output.
                    continue
                if (window.device_id not in self.sessions
                        or window.target is not self.sessions[window.device_id]):
                    raise ValueError("MMIO target must be a registered local harness")
                previous = target_routers.setdefault(window.device_id, router)
                if previous is not router:
                    raise ValueError("all sources for one MMIO target need a shared target router")
        self.local_ticks = {component: 0 for component in self.sessions}
        self._last_sample_ticks: dict[str, int] = {}
        self._inputs: dict[str, dict[str, int]] = {component: {} for component in self.sessions}
        self._pending_bound_targets: set[str] = set()
        self._events: list[dict] = _EventLog(self)
        self._transaction_count = 0
        self._resource_budget: ResourceBudget | None = None
        self._evidence_projected_bytes: int | None = None
        self._evidence_final_state_bytes = 0
        self._evidence_final_state_growth_bound: int | None = None
        self._evidence_record_bound: int | None = None
        self._evidence_copy_counts: dict[str, int] = {}
        self._evidence_gpio_checker_devices: frozenset[str] = frozenset()
        self._evidence_gpio_expected: dict[str, int] = {}
        self._evidence_gpio_reported: set[str] = set()
        self._wall_started_at: float | None = None
        self._replay_wall_cut: tuple[int, str] | None = None
        self._replay_wall_cut_prefix_event_count: int | None = None
        self._replay_begin_component: str | None = None
        self._replay_begin_started: tuple[str, ...] = ()
        self._step_in_flight = False
        self._external_offsets: dict[int, int] = {}
        self.state_dependencies = StateDependencyTracker()
        self._status = "created"
        self._begin_cleanup_done = False
        self.failure_status: str | None = None
        self.execution_id = ""
        self.command_epoch = 0
        self._next_command_sequence = 1
        self._step_commands: dict[tuple[int, int], tuple[str, dict[str, int],
                                                        StepReceipt | None]] = {}

    @property
    def events(self) -> tuple[dict, ...]:
        return deepcopy(tuple(self._events))

    @property
    def event_count(self) -> int:
        """Number of recorded events, usable as a cursor for ``events_since``."""
        return len(self._events)

    def events_since(self, index: int) -> tuple[dict, ...]:
        """Return a detached copy of events starting at zero-based ``index``."""
        if type(index) is not int or not 0 <= index <= len(self._events):
            raise ValueError("event index is outside the recorded prefix")
        return deepcopy(tuple(self._events[index:]))

    def set_resource_budget(self, budget: ResourceBudget) -> None:
        """Arm an opt-in trace limit before images or RTL have been touched."""
        if not isinstance(budget, ResourceBudget):
            raise ValueError("ResourceBudget is required")
        if self._status != "created" or self._events or self._resource_budget is not None:
            raise ValueError("resource budget must be set once before testcase work")
        self._resource_budget = budget

    def arm_evidence_meter(self, base_bytes: int,
                           copy_counts: Mapping[str, int], *,
                           max_final_state_growth_bytes_per_operation: int | None = None,
                           max_evidence_record_bytes: int | None = None,
                           gpio_checker_devices: tuple[str, ...] = ()) -> None:
        """Reserve immutable material before RTL starts and meter event growth."""
        budget = self._resource_budget
        if (self._status != "created" or self._events or budget is None
                or self._evidence_projected_bytes is not None
                or type(base_bytes) is not int or base_bytes < 0
                or (max_final_state_growth_bytes_per_operation is not None
                    and (type(max_final_state_growth_bytes_per_operation) is not int
                         or max_final_state_growth_bytes_per_operation < 0))
                or (max_evidence_record_bytes is not None
                    and (type(max_evidence_record_bytes) is not int
                         or max_evidence_record_bytes < 1))
                or any(not isinstance(kind, str) or type(count) is not int
                       or count < 0 for kind, count in copy_counts.items())
                or not isinstance(gpio_checker_devices, tuple)
                or any(not isinstance(device, str) or not device
                       for device in gpio_checker_devices)
                or len(set(gpio_checker_devices)) != len(gpio_checker_devices)):
            raise ValueError("invalid evidence meter setup")
        final_state_bytes = self._evidence_final_state_size()
        if base_bytes > (budget.max_evidence_bytes
                         - budget.evidence_termination_reserve_bytes):
            raise ValueError("max_evidence_bytes immutable material exceeds normal capacity")
        # The initial final-state document belongs to the termination floor.
        # Charge only its growth to normal execution capacity.
        self._evidence_projected_bytes = base_bytes
        self._evidence_final_state_bytes = final_state_bytes
        self._evidence_final_state_growth_bound = (
            max_final_state_growth_bytes_per_operation)
        self._evidence_record_bound = max_evidence_record_bytes
        self._evidence_copy_counts = dict(copy_counts)
        self._evidence_gpio_checker_devices = frozenset(gpio_checker_devices)

    def _count_evidence_record(self, record: dict) -> None:
        if self._evidence_projected_bytes is None:
            return
        size = len(json.dumps(record, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode("utf-8")) + 1
        if self._evidence_record_bound is not None and size > self._evidence_record_bound:
            raise ScenarioEvidenceRecordViolation("evidence record bound exceeded")
        copies = 1 + self._evidence_copy_counts.get(record.get("kind", ""), 0)
        if ("outputs" in record
                or record.get("kind") in ("harness_failure", "begin_failure")):
            copies += 1
        self._evidence_projected_bytes += size * copies
        self._count_final_state_growth()
        if record.get("kind") == "reset_barrier":
            self._evidence_gpio_expected.clear()
            self._evidence_gpio_reported.clear()
        elif record.get("kind") == "mmio_delivery" and record.get("write"):
            device = record.get("device_id")
            if (device in self._evidence_gpio_checker_devices
                    and record.get("offset") in (0x14, 0x18, 0x1c)):
                self._evidence_gpio_expected.pop(device, None)
                self._evidence_gpio_reported.discard(device)
                value = record.get("write_value")
                if (record.get("offset") == 0x14
                        and record.get("byte_enable") == 15
                        and type(value) is int and 0 <= value < 1 << 32):
                    self._evidence_gpio_expected[device] = value
        device = record.get("component")
        if (device in self._evidence_gpio_expected
                and device not in self._evidence_gpio_reported):
            outputs = record.get("outputs")
            observed = outputs.get("gpio_out") if isinstance(outputs, Mapping) else None
            expected = self._evidence_gpio_expected[device]
            if type(observed) is int and observed != expected:
                finding = {"finding_id": f"gpio_direct_out_mismatch:{device}",
                           "event_id": record["event_id"],
                           "expected": expected, "observed": observed}
                self._evidence_projected_bytes += len(json.dumps(
                    finding, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False, allow_nan=False).encode("utf-8")) + 1
                self._evidence_gpio_reported.add(device)
        self._check_evidence_capacity("append_event")

    def _count_final_state_growth(self) -> None:
        if self._evidence_projected_bytes is None:
            return
        final_state_bytes = self._evidence_final_state_size()
        growth = final_state_bytes - self._evidence_final_state_bytes
        self._evidence_projected_bytes += growth
        self._evidence_final_state_bytes = final_state_bytes
        if (self._evidence_final_state_growth_bound is not None
                and growth > self._evidence_final_state_growth_bound):
            raise ScenarioFinalStateGrowthViolation(
                "final state growth bound exceeded")

    def _check_evidence_capacity(self, phase: str) -> None:
        budget = self._resource_budget
        if (budget is not None and self._evidence_projected_bytes is not None
                and self._evidence_projected_bytes >
                budget.max_evidence_bytes - budget.evidence_termination_reserve_bytes):
            # The record may describe an effect that already happened. Keep it
            # in the reserved tail and stop before another local operation.
            self._exhaust_budget("max_evidence_bytes", phase)

    def set_replay_wall_cut(self, scheduler_steps: int, phase: str, *,
                            prefix_event_count: int | None = None,
                            failed_component: str | None = None,
                            started_components: tuple[str, ...] = ()) -> None:
        """Reproduce a saved watchdog prefix at its semantic boundary."""
        if (self._status != "created" or self._resource_budget is None
                or self._replay_wall_cut is not None
                or isinstance(scheduler_steps, bool)
                or not isinstance(scheduler_steps, int) or scheduler_steps < 0
                or (prefix_event_count is not None and
                    (type(prefix_event_count) is not int
                     or prefix_event_count < 0))
                or phase not in ("before_begin", "inflight_begin",
                                 "before_step", "inflight_step", "before_reset",
                                 "inflight_reset", "before_source_injection",
                                 "before_quiesce", "inflight_finalize")):
            raise ValueError("invalid replay wall cutoff")
        if phase in ("before_begin", "inflight_begin"):
            names = tuple(sorted(self.sessions))
            if (scheduler_steps != 0 or failed_component not in names
                    or started_components != names[:names.index(failed_component)]):
                raise ValueError("invalid replay begin cutoff")
            self._replay_begin_component = failed_component
            self._replay_begin_started = started_components
        elif failed_component is not None or started_components:
            raise ValueError("begin cutoff metadata is only valid for begin")
        self._replay_wall_cut = (scheduler_steps, phase)
        self._replay_wall_cut_prefix_event_count = prefix_event_count

    def _ensure_semantic_capacity(self, phase: str) -> None:
        budget = self._resource_budget
        if budget is None:
            return
        if self.failure_status == "budget_exhausted":
            raise ScenarioBudgetExhausted("max_semantic_records budget exhausted")
        if len(self._events) < budget.max_semantic_records - 1:
            return
        self._exhaust_budget("max_semantic_records", phase)

    def _ensure_wall_capacity(self, phase: str) -> None:
        budget = self._resource_budget
        if budget is None or self._wall_started_at is None:
            return
        if self._replay_wall_cut is not None:
            steps, cut_phase = self._replay_wall_cut
            prefix = self._replay_wall_cut_prefix_event_count
            at_boundary = (sum(self.local_ticks.values()) >= steps
                           if prefix is None else
                           sum(self.local_ticks.values()) == steps
                           and len(self._events) == prefix)
            if (phase == "before_step" and cut_phase == "inflight_step"
                    and at_boundary):
                self._exhaust_budget(
                    "max_wall_time_ms", "inflight_step",
                    effect_may_have_occurred=True,
                    prefix_event_count=len(self._events))
            if (phase == "before_reset" and cut_phase == "inflight_reset"
                    and at_boundary):
                self._exhaust_budget(
                    "max_wall_time_ms", "inflight_reset",
                    effect_may_have_occurred=True,
                    prefix_event_count=len(self._events))
            if phase == cut_phase and at_boundary:
                self._exhaust_budget("max_wall_time_ms", phase)
            return
        if (time.monotonic() - self._wall_started_at) * 1000 > budget.max_wall_time_ms:
            self._exhaust_budget("max_wall_time_ms", phase)

    def _testcase_wall_deadline_reached(self) -> bool:
        budget = self._resource_budget
        return (budget is not None and self._wall_started_at is not None
                and self._replay_wall_cut is None
                and time.monotonic() >=
                self._wall_started_at + budget.max_wall_time_ms / 1000)

    def _exhaust_budget(self, limit: str, phase: str, *,
                        effect_may_have_occurred: bool | None = None,
                        prefix_event_count: int | None = None) -> None:
        self.failure_status = "budget_exhausted"
        self._status = "failed"
        if limit == "max_wall_time_ms" and prefix_event_count is None:
            prefix_event_count = len(self._events)
        event = {
            "event_id": len(self._events) + 1,
            "kind": "budget_exhausted",
            "limit": limit,
            "phase": phase,
            "effect_may_have_occurred": (
                self._step_in_flight if effect_may_have_occurred is None
                else effect_may_have_occurred),
            "local_ticks": dict(self.local_ticks),
        }
        if prefix_event_count is not None:
            event["prefix_event_count"] = prefix_event_count
            event["prefix_local_ticks"] = dict(self.local_ticks)
        list.append(self._events, event)
        raise ScenarioBudgetExhausted(f"{limit} budget exhausted")

    def _evidence_final_state_size(self) -> int:
        document = self.final_state_document(_size_only=True)
        return len(json.dumps(document, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode("utf-8")) + 1

    def final_state_document(self, *, _size_only: bool = False) -> dict:
        """Known host state at testcase end; RTL state is verified by replay."""
        memories = {}
        for component, session in sorted(self.sessions.items()):
            memory = getattr(session, "memory", None)
            if memory is not None:
                if _size_only and type(memory) is PersistentMemory:
                    # The SHA-256 text is always 64 ASCII bytes. Its contents
                    # do not affect serialized size; avoid hashing every RAM
                    # byte for every semantic event in a budgeted run.
                    memories[component] = {
                        "generation": memory.generation,
                        "step_count": memory.step_count,
                        "initialized_bytes": memory.initialized_bytes,
                        "commit_sequences": dict(memory._commit_sequences),
                        "cells_sha256": "0" * 64,
                    }
                else:
                    memories[component] = memory.state_summary()
        document = {"local_ticks": dict(self.local_ticks),
                    "inputs": deepcopy(self._inputs),
                    "pending_dataflow_targets": tuple(sorted(self._pending_bound_targets)),
                    "pending_target_requests": self._pending_target_requests(),
                    "memories": memories,
                    "pending_responses": self._pending_responses(),
                    "pending_events": self._pending_events(),
                    "pending_irq_pulses": self._pending_irq_pulses(),
                    "uncertain_transactions": self._uncertain_transactions()}
        if self._irq_pulses:
            document["irq_delivery"] = [
                {"binding": asdict(binding), **policy.state_document()}
                for binding, policy in self._irq_pulses.items()]
        return document

    def identity_document(self) -> dict:
        """All declared dataflow and local harness identities before RTL start."""
        component_by_object = {id(session): component
                               for component, session in self.sessions.items()}
        sessions = {}
        memories = {}
        windows = {}
        for component, session in sorted(self.sessions.items()):
            identity = getattr(session, "identity_document", None)
            sessions[component] = {
                "type": f"{type(session).__module__}.{type(session).__qualname__}",
                "identity": identity() if callable(identity) else {}}
            memory = getattr(session, "memory", None)
            if memory is not None:
                memories[component] = memory.identity_document()
            router = getattr(session, "router", None)
            if router is not None:
                windows[component] = [
                    {"device_id": window.device_id, "base": window.base,
                     "size": window.size,
                     "target_component": component_by_object.get(id(window.target), ""),
                     "target_type": (f"{type(window.target).__module__}."
                                     f"{type(window.target).__qualname__}")}
                    for window in router.windows]
        generated = tuple(record['identity'] for record in sessions.values()
                          if record['identity'].get('schema_version') == 'generated_local_session_identity.v1')
        document = {"schema_version": ("scenario_manifest_identity.v2" if generated else "scenario_manifest_identity.v1"),
                    "sessions": sessions, "memories": memories, "windows": windows,
                    "ownership": self.ownership.document(),
                    "bindings": [asdict(binding) for binding in self.bindings],
                    "host_sources": host_source_identity(harness_identities=generated)}
        if self.independent_baseline:
            document["independent_baseline"] = True
        if self._irq_pulses:
            document["irq_pulses"] = [
                {"binding": asdict(binding),
                 "width_cpu_ticks": policy.width_ticks,
                 "overrun_policy": "terminate_unsupported"}
                for binding, policy in self._irq_pulses.items()]
        return document

    def begin_test(self, testcase_id: str) -> None:
        if self._status != "created" or not testcase_id:
            raise ValueError("testcase can begin exactly once")
        self.testcase_id = testcase_id
        self.execution_id = uuid.uuid4().hex
        started: list[str] = []
        attempted: str | None = None
        begin_in_flight = False
        try:
            # The local RTL build is a separately bounded setup phase. It must
            # complete before the testcase's shared wall clock starts.
            for component in sorted(self.sessions):
                attempted = component
                prepare = getattr(self.sessions[component], "prepare_local", None)
                if callable(prepare):
                    prepare()
            self._wall_started_at = time.monotonic()
            if (self._replay_wall_cut is not None
                    and self._replay_wall_cut[1] in
                    ("before_begin", "inflight_begin")):
                self._record_begin_wall_cut(
                    self._replay_wall_cut[1],
                    self._replay_begin_component,
                    self._replay_begin_started)
            budget = self._resource_budget
            deadline = (self._wall_started_at + budget.max_wall_time_ms / 1000
                        if budget is not None else None)
            for component in sorted(self.sessions):
                attempted = component
                if deadline is not None and time.monotonic() >= deadline:
                    raise LocalCommandDeadlineExceeded(
                        "max_wall_time_ms: before local begin")
                begin_in_flight = True
                with command_deadline(deadline):
                    self.sessions[component].begin_case(testcase_id)
                begin_in_flight = False
                started.append(component)
        except BaseException as exc:
            self._status = "failed"
            cleanup = [*started]
            if attempted is not None and attempted not in cleanup:
                cleanup.append(attempted)
            for component in reversed(cleanup):
                try:
                    with command_deadline(
                            self._wall_started_at + self._resource_budget.max_wall_time_ms / 1000
                            if self._resource_budget is not None
                            and self._wall_started_at is not None else None):
                        self.sessions[component].end_case()
                except BaseException:
                    pass
            self._begin_cleanup_done = True
            if isinstance(exc, ScenarioBudgetExhausted):
                raise
            if (isinstance(exc, LocalCommandDeadlineExceeded)
                    and self._testcase_wall_deadline_reached()):
                self._record_begin_wall_cut(
                    "inflight_begin" if begin_in_flight else "before_begin",
                    attempted, tuple(started))
            self._events.append({"event_id": len(self._events) + 1,
                                 "kind": "begin_failure",
                                 "failed_component": attempted,
                                 "error_type": type(exc).__name__,
                                 "started_components": tuple(started)})
            raise
        self._status = "running"
        self._count_final_state_growth()
        self._check_evidence_capacity("after_begin")

    def _record_begin_wall_cut(self, phase: str, component: str | None,
                               started: tuple[str, ...]) -> None:
        self.failure_status = "budget_exhausted"
        self._status = "failed"
        list.append(self._events, {
            "event_id": len(self._events) + 1,
            "kind": "budget_exhausted", "limit": "max_wall_time_ms",
            "phase": phase, "effect_may_have_occurred":
                phase == "inflight_begin",
            "local_ticks": dict(self.local_ticks),
            "prefix_event_count": len(self._events),
            "prefix_local_ticks": dict(self.local_ticks),
            "failed_component": component,
            "started_components": started,
        })
        raise ScenarioBudgetExhausted("max_wall_time_ms budget exhausted")

    def preload_image(self, image: MemoryImage) -> None:
        """Install declared program/data bytes before any RTL step or reset."""
        if self._status != "created":
            raise RuntimeError("memory image can only be loaded before testcase start")
        if not isinstance(image, MemoryImage) or image.component not in self.sessions:
            raise ValueError("memory image references unknown local harness")
        memory = getattr(self.sessions[image.component], "memory", None)
        if memory is None:
            raise ValueError("local harness has no persistent memory")
        self._ensure_semantic_capacity("before_image")
        memory.preload(image.address, image.data)
        self._events.append({"event_id": len(self._events) + 1,
                             "kind": "initial_image", "image_id": image.image_id,
                             "component": image.component, "address": image.address,
                             "data_hex": image.data_hex})

    def reset_all(self, policy: str) -> ResetResult:
        """Apply an explicit whole-scenario RTL reset and memory resource policy."""
        if self._status != "running":
            raise RuntimeError("scenario is not running")
        if policy not in ("warm_all", "cold_all"):
            raise ValueError("unsupported reset policy; only warm_all/cold_all")
        for component, session in self.sessions.items():
            if not callable(getattr(session, "reset_local", None)):
                raise ValueError(f"local harness {component} cannot reset")
        self._ensure_wall_capacity("before_reset")
        self._ensure_semantic_capacity("before_reset")
        pending_responses_before = self._pending_responses()
        pending_events_before = self._pending_events()
        pending_bound_before = tuple(sorted(self._pending_bound_targets))
        pending_irq_before = self._pending_irq_pulses()
        memories = {}
        for session in self.sessions.values():
            memory = getattr(session, "memory", None)
            if memory is not None:
                memories[id(memory)] = memory
        memory_owners: dict[str, int] = {}
        for object_id, memory in memories.items():
            for memory_id in memory.memory_ids:
                if memory_id in memory_owners and memory_owners[memory_id] != object_id:
                    raise ValueError(f"ambiguous memory identity: {memory_id}")
                memory_owners[memory_id] = object_id
        cancelled: dict[str, int] = {}
        cancelled_targets: dict[str, tuple[str, ...]] = {}
        resetting_component = ""
        budget = self._resource_budget
        deadline = (self._wall_started_at + budget.max_wall_time_ms / 1000
                    if budget is not None and self._wall_started_at is not None
                    and self._replay_wall_cut is None else None)
        try:
            for component in sorted(self.sessions):
                resetting_component = component
                with command_deadline(deadline):
                    outcome = self.sessions[component].reset_local()
                count = (outcome or {}).get("cancelled_responses", 0)
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    raise ValueError("invalid reset cancellation receipt")
                cancelled[component] = count
                target_requests = (outcome or {}).get("cancelled_target_requests", ())
                if (not isinstance(target_requests, tuple)
                        or any(not isinstance(value, str) or not value
                               for value in target_requests)):
                    raise ValueError("invalid target cancellation receipt")
                if target_requests:
                    cancelled_targets[component] = target_requests
            generations: dict[str, int] = {}
            old_generations: dict[str, int] = {}
            for memory in memories.values():
                for memory_id in memory.memory_ids:
                    old_generations[memory_id] = memory.generation
                if policy == "cold_all":
                    memory.cold_reset()
                else:
                    memory.warm_reset()
                for memory_id in memory.memory_ids:
                    generations[memory_id] = memory.generation
        except BaseException as exc:
            if (isinstance(exc, LocalCommandDeadlineExceeded)
                    and deadline is not None and time.monotonic() >= deadline):
                self._exhaust_budget(
                    "max_wall_time_ms", "inflight_reset",
                    effect_may_have_occurred=True,
                    prefix_event_count=len(self._events))
            self._status = "failed"
            if self.failure_status == "budget_exhausted":
                raise
            self._events.append({"event_id": len(self._events) + 1,
                                 "kind": "reset_failure", "policy": policy,
                                 "active_component": resetting_component,
                                 "completed_components": tuple(cancelled),
                                 "error_type": type(exc).__name__})
            raise
        self._inputs = {component: {} for component in self.sessions}
        self._pending_bound_targets.clear()
        for binding, pulse in self._irq_pulses.items():
            pulse.reset(cpu_tick=self.local_ticks[binding.target_component])
            self._append_irq_events(binding)
        self.command_epoch += 1
        self._next_command_sequence = 1
        pending_events_after = self._pending_events()
        self._events.append({"event_id": len(self._events) + 1,
                             "kind": "reset_barrier", "policy": policy,
                             "memory_generations": dict(generations),
                             "cancelled_responses": dict(cancelled),
                             "cancelled_target_requests": dict(cancelled_targets),
                             "pending_responses_before_reset":
                                 dict(pending_responses_before),
                             "pending_events_before_reset":
                                 dict(pending_events_before),
                             "pending_events_after_reset":
                                 dict(pending_events_after),
                             "cancelled_dataflow_targets": pending_bound_before,
                             "cancelled_irq_pulses": dict(pending_irq_before)})
        if policy == "cold_all":
            barrier_id = self._events[-1]["event_id"]
            for memory_id, generation in old_generations.items():
                edges = self.state_dependencies.invalidate_generation(
                    memory_id, generation, f"reset:{barrier_id}")
                for edge in edges:
                    record = asdict(edge)
                    record["edge_kind"] = record.pop("kind")
                    record.update({"event_id": len(self._events) + 1,
                                   "producer_event_id": barrier_id,
                                   "kind": "state_dependency"})
                    self._events.append(record)
        return ResetResult(policy, generations, cancelled)

    def inject_source(self, component: str, port: str, value: int, *,
                      direction: str, bit_offset: int = 0,
                      width: int | None = None,
                      action_id: str = "") -> None:
        if self._status != "running":
            raise RuntimeError("scenario is not running")
        if component not in self.sessions:
            raise ValueError("unknown local harness")
        field_width = self.ownership.field_width(component, port)
        selected_width = width if width is not None else field_width
        source_ref = self.ownership.mutation_source(
            component, port, bit_offset, selected_width, direction=direction)
        if isinstance(value, bool) or not isinstance(value, int) \
                or not 0 <= value < 1 << selected_width:
            raise ValueError("source value exceeds declared segment")
        mask = ((1 << selected_width) - 1) << bit_offset
        self._ensure_wall_capacity("before_source_injection")
        self._ensure_semantic_capacity("before_source_injection")
        old = self._inputs[component].get(port, 0)
        self._inputs[component][port] = (old & ~mask) | (value << bit_offset)
        self._events.append({"event_id": len(self._events) + 1,
                             "kind": "source_injection", "action_id": action_id,
                             "component": component, "port": port,
                             "source_ref": source_ref, "direction": direction,
                             "bit_offset": bit_offset, "width": selected_width,
                             "value": value})

    def step(self, component: str) -> Mapping[str, int]:
        """Advance through the same idempotent command path as transport retries."""
        if component not in self.sessions:
            raise ValueError("unknown local harness")
        if self._resource_budget is not None:
            self._sync_session_ticks()
        receipt = self.execute_step(
            component, execution_id=self.execution_id,
            command_sequence=self._next_command_sequence,
            epoch=self.command_epoch,
            expected_inputs=self._effective_inputs(component))
        return receipt.outputs

    def step_batch(
            self, schedule: tuple[str, ...], *,
            on_step: Callable[[str, Mapping[str, int]], None] | None = None
            ) -> tuple[Mapping[str, int], ...]:
        """Execute a declared sequence without changing testcase lifecycle.

        A batch is a transport convenience. Each local step still uses the
        ordinary command ledger and the supplied component order. ``on_step``
        observes each completed step before the next one starts, so a caller
        may react to an output within the batch. If a step or callback fails,
        the already executed prefix remains committed.
        """
        if not isinstance(schedule, tuple) or not schedule:
            raise ValueError("step_batch requires a nonempty component tuple")
        if any(component not in self.sessions for component in schedule):
            raise ValueError("step_batch references unknown local harness")
        if on_step is not None and not callable(on_step):
            raise ValueError("step_batch callback must be callable")
        outputs = []
        for component in schedule:
            observed = self.step(component)
            outputs.append(observed)
            if on_step is not None:
                on_step(component, observed)
        return tuple(outputs)

    def _effective_inputs(self, component: str) -> dict[str, int]:
        inputs = dict(self._inputs[component])
        for binding, policy in self._irq_pulses.items():
            if binding.target_component != component:
                continue
            value = policy.input_at(self.local_ticks[component] + 1)
            mask = 1 << binding.target_bit_offset
            inputs[binding.target_port] = (
                (inputs.get(binding.target_port, 0) & ~mask)
                | (value << binding.target_bit_offset))
        return inputs

    def _sync_session_ticks(self) -> None:
        """Include target MMIO clocks advanced by another local harness."""
        for component, session in self.sessions.items():
            observed = getattr(session, "local_ticks", None)
            if observed is None:
                continue
            if (type(observed) is not int or observed < self.local_ticks[component]):
                raise ValueError("local harness tick count is invalid or moved backwards")
            self.local_ticks[component] = observed

    def _unique_routers(self) -> tuple[tuple[str, object], ...]:
        seen: set[int] = set()
        routers = []
        for component, session in sorted(self.sessions.items()):
            router = getattr(session, "router", None)
            if router is not None and id(router) not in seen:
                seen.add(id(router))
                routers.append((component, router))
        return tuple(routers)

    def _step_tick_bounds(self, component: str) -> dict[str, int]:
        """Worst local clock advances from one selected harness step."""
        session = self.sessions[component]
        own = getattr(session, "max_local_ticks_per_step", 1)
        if type(own) is not int or own < 1:
            raise ValueError("invalid maximum local ticks per step")
        bounds = {component: own}
        router = getattr(session, "router", None)
        windows = getattr(router, "windows", ())
        targets = {id(target): name for name, target in self.sessions.items()}
        for window in windows:
            target = window.target
            name = targets.get(id(target))
            if name is None:
                continue
            accesses = getattr(session, "max_mmio_target_accesses_per_step", None)
            ticks = getattr(target, "max_local_ticks_per_register_access", None)
            if (type(accesses) is not int or accesses < 0
                    or type(ticks) is not int or ticks < 1):
                raise ValueError("budgeted MMIO route needs local tick bounds")
            bounds[name] = max(bounds.get(name, 0), accesses * ticks)
        for _, queued_router in self._unique_routers():
            if component not in getattr(queued_router, "ready_targets", ()):
                continue
            ticks = getattr(session, "max_local_ticks_per_register_access", None)
            if type(ticks) is not int or ticks < 1:
                raise ValueError("budgeted queued MMIO needs target tick bound")
            bounds[component] += ticks
        return bounds

    def _append_irq_events(self, binding: Binding) -> None:
        policy = self._irq_pulses[binding]
        offset = self._irq_event_offsets[binding]
        for event in policy.events[offset:]:
            self._events.append({"event_id": len(self._events) + 1,
                                 "source": (binding.source_component, binding.source_port),
                                 "target": (binding.target_component, binding.target_port),
                                 **event})
        self._irq_event_offsets[binding] = len(policy.events)

    def _step_once(self, component: str) -> Mapping[str, int]:
        if self._status not in ("running", "quiescing"):
            raise RuntimeError("scenario is not running")
        if component not in self.sessions:
            raise ValueError("unknown local harness")
        inputs = self._effective_inputs(component)
        tick_before_step = self.local_ticks[component]
        event_count_before_step = len(self._events)
        ticks_before_step = dict(self.local_ticks)
        try:
            outputs = dict(self.sessions[component].step_local(inputs))
        except BaseException as exc:
            self._status = "failed"
            uncertain = self._uncertain_transactions()
            # The local command was issued but no complete reply was accepted.
            # A harness may have ticked or performed an effect without a ledger
            # entry, so absence of an unresolved transaction proves nothing.
            timed_out = (isinstance(exc, LocalCommandDeadlineExceeded)
                         and self._testcase_wall_deadline_reached())
            self.failure_status = "uncertain_effect"
            tick_before = self.local_ticks[component]
            for session_id, session in self.sessions.items():
                observed_ticks = getattr(session, "local_ticks", None)
                if (type(observed_ticks) is int
                        and observed_ticks >= self.local_ticks[session_id]):
                    self.local_ticks[session_id] = observed_ticks
            self._events.append({"event_id": len(self._events) + 1,
                                 "kind": "harness_failure", "component": component,
                                 "local_tick_before": tick_before,
                                 "local_tick_after": self.local_ticks[component],
                                 "error_type": type(exc).__name__,
                                 "status": ("budget_exhausted" if timed_out
                                            else self.failure_status),
                                 "uncertain_transactions": uncertain})
            self._append_external_events(component, self._events[-1]["event_id"])
            self._drain_tick_samples(self._events[-1]["event_id"])
            if timed_out:
                self.failure_status = "budget_exhausted"
                list.append(self._events, {
                    "event_id": len(self._events) + 1,
                    "kind": "budget_exhausted", "limit": "max_wall_time_ms",
                    "phase": "inflight_step", "effect_may_have_occurred": True,
                    "local_ticks": dict(self.local_ticks),
                    "prefix_event_count": event_count_before_step,
                    "prefix_local_ticks": ticks_before_step,
                })
            raise
        if getattr(self.sessions[component], "local_ticks", None) is None:
            self.local_ticks[component] += 1
        self._sync_session_ticks()
        # This local step consumed the bound inputs present at its start.
        # New outputs routed below may schedule this target again.
        self._pending_bound_targets.discard(component)
        event_id = len(self._events) + 1
        self._events.append({"event_id": event_id, "component": component,
                             "local_tick": self.local_ticks[component],
                             "inputs": inputs, "outputs": dict(outputs)})
        self._append_external_events(component, event_id)
        for binding, policy in self._irq_pulses.items():
            if binding.target_component != component:
                continue
            if self.local_ticks[component] != tick_before_step + 1:
                raise ValueError("IRQ pulse target must advance one local tick per step")
            mask_observed = outputs.get("irq_masked_pre")
            taken_observed = outputs.get("irq_taken_pre")
            for name, observed in (("irq_masked_pre", mask_observed),
                                   ("irq_taken_pre", taken_observed)):
                if observed is not None and (isinstance(observed, bool)
                                             or observed not in (0, 1)):
                    raise ValueError(f"invalid RTL {name} observation")
            policy.sample_cpu(self.local_ticks[component],
                              masked=None if mask_observed is None else bool(mask_observed),
                              accepted=None if taken_observed is None else bool(taken_observed))
            self._append_irq_events(binding)
        if not callable(getattr(self.sessions[component], "drain_tick_samples", None)):
            self._route_observed_outputs(component, outputs, event_id,
                                         self.local_ticks[component])
        self._drain_tick_samples(event_id)
        for source_component, router in self._unique_routers():
            if (router is None or
                    component not in getattr(router, "pending_targets", ())):
                continue
            try:
                router.drain_one(component)
            finally:
                self._sync_session_ticks()
                self._append_external_events(source_component, event_id)
                self._drain_tick_samples(event_id)
        return outputs

    def _route_observed_outputs(self, component: str, outputs: Mapping[str, int],
                                event_id: int, source_tick: int) -> None:
        for binding in self.bindings:
            if binding.source_component != component \
                    or binding.source_port not in outputs:
                continue
            value = outputs[binding.source_port]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("observed RTL output must be a nonnegative integer")
            fragment = value >> binding.source_bit_offset & ((1 << binding.width) - 1)
            if binding in self._irq_pulses:
                policy = self._irq_pulses[binding]
                policy.observe_source(fragment, source_tick=source_tick,
                                      cpu_tick=self.local_ticks[binding.target_component])
                self._append_irq_events(binding)
                if policy.status != "active":
                    self.failure_status = policy.status
                    self._status = "failed"
                continue
            target = self._inputs[binding.target_component]
            mask = ((1 << binding.width) - 1) << binding.target_bit_offset
            prior = target.get(binding.target_port, 0)
            updated = (prior & ~mask) | (fragment << binding.target_bit_offset)
            target[binding.target_port] = updated
            if updated != prior:
                self._pending_bound_targets.add(binding.target_component)
            self._events.append({"event_id": len(self._events) + 1,
                                 "kind": "dataflow_delivery",
                                 "producer_event_id": event_id,
                                 "source": (component, binding.source_port),
                                 "target": (binding.target_component, binding.target_port),
                                 "value": fragment})

    def _drain_tick_samples(self, producer_event_id: int) -> None:
        """Route every real receipt phase, including indirectly clocked targets.

        Pre and post are distinct observations of one local tick. A post-only
        summary cannot establish whether a native interrupt pulsed during an
        APB command. Legacy sessions without this API keep their output path.
        """
        for component, session in self.sessions.items():
            drain = getattr(session, "drain_tick_samples", None)
            if not callable(drain):
                continue
            for sample in drain():
                tick = sample.get("local_tick")
                if (type(tick) is not int
                        or not self._last_sample_ticks.get(component, 0) < tick
                        <= self.local_ticks[component]):
                    raise ValueError("invalid local tick sample receipt")
                for phase in ("pre", "post"):
                    observed = sample.get(phase)
                    if not isinstance(observed, Mapping):
                        raise ValueError("invalid local tick sample observations")
                    outputs = dict(observed)
                    # The generated GPIO receipt names the native signal;
                    # irq is the session's existing public semantic alias.
                    if "interrupt" in outputs:
                        outputs["irq"] = outputs["interrupt"]
                    if isinstance(outputs.get("gpio_padcfg"), str):
                        outputs["gpio_padcfg"] = int(outputs["gpio_padcfg"], 16)
                    event_id = len(self._events) + 1
                    self._events.append({"event_id": event_id,
                                         "kind": "local_tick_sample",
                                         "producer_event_id": producer_event_id,
                                         "component": component, "local_tick": tick,
                                         "phase": phase, "outputs": dict(observed)})
                    self._route_observed_outputs(component, outputs, event_id, tick)
                self._last_sample_ticks[component] = tick

    def _append_external_events(self, component: str, event_id: int) -> None:
        """Keep facts logged by local services even when the step reply is lost."""
        session = self.sessions[component]
        for owner, attribute, kind in ((getattr(session, "service", None),
                                        "events", "memory_commit"),
                                       (getattr(session, "router", None),
                                        "acceptances", "mmio_acceptance"),
                                       (getattr(session, "router", None),
                                        "deliveries", "mmio_delivery"),
                                       (session, "local_transactions",
                                        "local_register_transaction")):
            stream = getattr(owner, attribute, None)
            if stream is None:
                continue
            stream_id = id(stream)
            offset = self._external_offsets.get(stream_id, 0)
            for item in stream[offset:]:
                record = dict(item)
                for key, value in tuple(record.items()):
                    if is_dataclass(value):
                        record[key] = asdict(value)
                if kind in ("mmio_acceptance", "mmio_delivery",
                            "local_register_transaction"):
                    record["kind"] = kind
                event_component = component
                if kind in ("mmio_acceptance", "mmio_delivery"):
                    transaction = record.get("source_transaction")
                    source_name = (transaction.get("source_component")
                                   if isinstance(transaction, dict) else None)
                    if source_name in self.sessions:
                        event_component = source_name
                record.update({"event_id": len(self._events) + 1,
                               "producer_event_id": event_id,
                               "component": event_component})
                self._events.append(record)
                if kind == "memory_commit":
                    old_edges = len(self.state_dependencies.edges)
                    self.state_dependencies.ingest((record,))
                    for edge in self.state_dependencies.edges[old_edges:]:
                        edge_record = asdict(edge)
                        edge_record["edge_kind"] = edge_record.pop("kind")
                        edge_record.update({"event_id": len(self._events) + 1,
                                            "producer_event_id": record["event_id"],
                                            "kind": "state_dependency"})
                        self._events.append(edge_record)
            self._external_offsets[stream_id] = len(stream)

    def execute_step(self, component: str, *, execution_id: str,
                     command_sequence: int, epoch: int,
                     expected_inputs: Mapping[str, int]) -> StepReceipt:
        """Execute one host command, or return its complete cached observation."""
        if not self.execution_id or execution_id != self.execution_id:
            raise ValueError("stale_execution: STEP belongs to another testcase run")
        if (isinstance(command_sequence, bool) or not isinstance(command_sequence, int)
                or command_sequence < 1 or isinstance(epoch, bool)
                or not isinstance(epoch, int) or epoch < 0
                or not isinstance(expected_inputs, Mapping)):
            raise ValueError("invalid STEP command identity or payload")
        payload = dict(expected_inputs)
        identity = (epoch, command_sequence)
        previous = self._step_commands.get(identity)
        if previous is not None:
            old_component, old_payload, receipt = previous
            if old_component != component or old_payload != payload:
                raise ValueError("identity_conflict: STEP payload changed")
            if receipt is None:
                raise RuntimeError("uncertain_effect: STEP outcome is not known")
            return deepcopy(receipt)
        if self._status not in ("running", "quiescing"):
            raise RuntimeError("scenario is not running")
        if epoch != self.command_epoch:
            raise ValueError("stale_epoch: STEP belongs to an old reset epoch")
        if command_sequence != self._next_command_sequence:
            raise ValueError("out_of_order_command: STEP sequence is not next")
        if component not in self.sessions:
            raise ValueError("unknown local harness")
        if self._resource_budget is not None:
            self._sync_session_ticks()
        if payload != self._effective_inputs(component):
            raise ValueError("STEP payload disagrees with scenario input state")
        self._ensure_wall_capacity("before_step")
        self._ensure_semantic_capacity("before_step")
        budget = self._resource_budget
        tick_bounds = None
        if budget is not None:
            tick_bounds = self._step_tick_bounds(component)
            if any(self.local_ticks[target] + advance >
                   budget.max_local_cycles_per_component
                   for target, advance in tick_bounds.items()):
                self._exhaust_budget("max_local_cycles_per_component", "before_step")
            if (sum(self.local_ticks.values()) + sum(tick_bounds.values()) >
                    budget.max_scheduler_steps):
                self._exhaust_budget("max_scheduler_steps", "before_step")
            session = self.sessions[component]
            dynamic_maximum = getattr(session, "max_transaction_events_for_step", None)
            maximum = (dynamic_maximum(payload) if callable(dynamic_maximum)
                       else getattr(session, "max_transaction_events_per_step", 0))
            if type(maximum) is not int or maximum < 0:
                raise ValueError("invalid maximum transaction events per step")
            maximum += sum(component in getattr(router, "ready_targets", ())
                           for _, router in self._unique_routers())
            if self._transaction_count + maximum > budget.max_transactions:
                self._exhaust_budget("max_transactions", "before_step")
        self._step_commands[identity] = (component, payload, None)
        self._next_command_sequence += 1
        start = len(self._events)
        ticks_before_step = dict(self.local_ticks)
        transaction_count_before = self._transaction_count
        self._step_in_flight = True
        deadline = (self._wall_started_at + budget.max_wall_time_ms / 1000
                    if budget is not None and self._wall_started_at is not None
                    and self._replay_wall_cut is None else None)
        try:
            with command_deadline(deadline):
                outputs = dict(self._step_once(component))
            if tick_bounds is not None and any(
                    self.local_ticks[target] - ticks_before_step[target] >
                    tick_bounds.get(target, 0) for target in self.sessions):
                raise RuntimeError("local harness exceeded declared tick bound")
            if (budget is not None and
                    self._transaction_count - transaction_count_before > maximum):
                raise RuntimeError("local harness exceeded transaction event bound")
        except BaseException as exc:
            if self._status != "failed":
                # The local step returned, but its observation failed host
                # validation or routing after the DUT may have advanced.
                self._status = "failed"
                timed_out = (isinstance(exc, LocalCommandDeadlineExceeded)
                             and deadline is not None
                             and time.monotonic() >= deadline)
                self.failure_status = (
                    "environment_error" if isinstance(
                        exc, (ScenarioFinalStateGrowthViolation,
                              ScenarioEvidenceRecordViolation))
                    else "uncertain_effect")
                self._events.append({"event_id": len(self._events) + 1,
                                     "kind": "harness_failure",
                                     "component": component,
                                     "phase": "post_step_processing",
                                     "local_tick_after": self.local_ticks[component],
                                     "error_type": type(exc).__name__,
                                     "status": ("budget_exhausted" if timed_out
                                                else self.failure_status),
                                     "uncertain_transactions":
                                         self._uncertain_transactions()})
                if timed_out:
                    self.failure_status = "budget_exhausted"
                    list.append(self._events, {
                        "event_id": len(self._events) + 1,
                        "kind": "budget_exhausted",
                        "limit": "max_wall_time_ms",
                        "phase": "inflight_step",
                        "effect_may_have_occurred": True,
                        "local_ticks": dict(self.local_ticks),
                        "prefix_event_count": start,
                        "prefix_local_ticks": ticks_before_step,
                    })
            raise
        finally:
            self._step_in_flight = False
        receipt = StepReceipt(execution_id, command_sequence, epoch, component,
                              deepcopy(payload), deepcopy(outputs),
                              deepcopy(tuple(self._events[start:])),
                              self.local_ticks[component])
        self._step_commands[identity] = (component, payload, receipt)
        return deepcopy(receipt)

    def _pending_responses(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for component, session in self.sessions.items():
            count = getattr(session, "pending_responses", 0)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError(f"invalid pending response count for {component}")
            counts[component] = count
        return counts

    def _pending_irq_pulses(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for binding, policy in self._irq_pulses.items():
            if policy.pending:
                target = binding.target_component
                counts[target] = counts.get(target, 0) + 1
        return counts

    def _pending_events(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for component, session in self.sessions.items():
            count = getattr(session, "pending_events", 0)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError(f"invalid pending event count for {component}")
            if count:
                counts[component] = count
        return counts

    def _pending_target_requests(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, router in self._unique_routers():
            for target, count in getattr(router, "pending_target_counts", {}).items():
                counts[target] = counts.get(target, 0) + count
        return counts

    def _uncertain_transactions(self) -> tuple[str, ...]:
        keys = set()
        for session in self.sessions.values():
            ledger = getattr(getattr(session, "service", None), "ledger", None)
            if ledger is not None:
                keys.update(str(key) for key in ledger.uncertain_keys)
        return tuple(sorted(keys))

    def quiesce(self, max_scheduler_steps: int = 4096) -> QuiesceResult:
        """Stop accepting roots and drain already accepted local responses."""
        if self._status != "running":
            raise RuntimeError("scenario is not running")
        if (isinstance(max_scheduler_steps, bool)
                or not isinstance(max_scheduler_steps, int)
                or not 0 <= max_scheduler_steps <= 4096):
            raise ValueError("max_scheduler_steps exceeds first-stage budget")
        if (self._resource_budget is not None
                and max_scheduler_steps > self._resource_budget.max_quiesce_steps):
            raise ValueError("max_quiesce_steps budget exceeded")
        initial_pending = self._pending_responses()
        initial_irq = self._pending_irq_pulses()
        initial_events = self._pending_events()
        initial_targets = self._pending_target_requests()
        initial_bound = tuple(sorted(self._pending_bound_targets))
        for component, session in self.sessions.items():
            if (initial_pending[component] or initial_irq.get(component, 0)
                    or initial_events.get(component, 0)
                    or initial_targets.get(component, 0)
                    or component in self._pending_bound_targets) and not callable(
                    getattr(session, "begin_quiesce", None)):
                raise ValueError(f"local harness {component} cannot quiesce pending work")
        self._ensure_wall_capacity("before_quiesce")
        self._ensure_semantic_capacity("before_quiesce")
        self._status = "quiescing"
        start_event = {"event_id": len(self._events) + 1,
                       "kind": "quiesce_start",
                       "pending_responses": dict(initial_pending)}
        if initial_irq:
            start_event["pending_irq_pulses"] = dict(initial_irq)
        if initial_events:
            start_event["pending_events"] = dict(initial_events)
        if initial_targets:
            start_event["pending_target_requests"] = dict(initial_targets)
        if initial_bound:
            start_event["pending_dataflow_targets"] = initial_bound
        self._events.append(start_event)
        try:
            for component in sorted(self.sessions):
                begin = getattr(self.sessions[component], "begin_quiesce", None)
                if callable(begin):
                    begin()
            steps = 0
            pending = self._pending_responses()
            pending_irq = self._pending_irq_pulses()
            pending_events = self._pending_events()
            pending_targets = self._pending_target_requests()
            pending_bound = tuple(sorted(self._pending_bound_targets))
            while (any(pending.values()) or pending_irq or pending_events
                   or pending_targets
                   or pending_bound) \
                    and steps < max_scheduler_steps:
                for component in sorted(self.sessions):
                    if (not pending[component] and not pending_irq.get(component, 0)
                            and not pending_events.get(component, 0)
                            and not pending_targets.get(component, 0)
                            and component not in self._pending_bound_targets) \
                            or steps >= max_scheduler_steps:
                        continue
                    self.step(component)
                    steps += 1
                pending = self._pending_responses()
                pending_irq = self._pending_irq_pulses()
                pending_events = self._pending_events()
                pending_targets = self._pending_target_requests()
                pending_bound = tuple(sorted(self._pending_bound_targets))
            uncertain = self._uncertain_transactions()
            status = ("uncertain_effect" if uncertain else
                      "incomplete" if any(pending.values()) or pending_irq
                      or pending_events or pending_targets or pending_bound
                      else "drained")
            end_event = {"event_id": len(self._events) + 1,
                         "kind": "quiesce_end", "status": status,
                         "steps": steps, "pending_responses": dict(pending),
                         "uncertain_transactions": uncertain}
            if initial_irq:
                end_event["pending_irq_pulses"] = dict(pending_irq)
            if initial_events:
                end_event["pending_events"] = dict(pending_events)
            if initial_targets:
                end_event["pending_target_requests"] = dict(pending_targets)
            if initial_bound or pending_bound:
                end_event["pending_dataflow_targets"] = pending_bound
            self._events.append(end_event)
            return QuiesceResult(status, steps, pending, uncertain)
        except BaseException as exc:
            self._status = "failed"
            if self.failure_status == "budget_exhausted":
                raise
            self._events.append({"event_id": len(self._events) + 1,
                                 "kind": "quiesce_failure",
                                 "error_type": type(exc).__name__,
                                 "initial_pending_responses": dict(initial_pending)})
            raise

    def finalize(self) -> None:
        if self._status == "finalized":
            return
        if self._status not in ("running", "quiescing", "failed"):
            raise RuntimeError("scenario was not started")
        if self._begin_cleanup_done:
            self._status = "finalized"
            return
        budget = self._resource_budget
        deadline = (self._wall_started_at + budget.max_wall_time_ms / 1000
                    if budget is not None and self._wall_started_at is not None
                    and self._replay_wall_cut is None else None)
        cleanup_errors: list[dict[str, str]] = []
        for component in sorted(self.sessions):
            try:
                with command_deadline(deadline):
                    self.sessions[component].end_case()
            except BaseException as exc:
                cleanup_errors.append({"component": component,
                                       "error_type": type(exc).__name__})
        if self._evidence_projected_bytes is not None:
            try:
                self._count_final_state_growth()
                if self.failure_status is None:
                    self._check_evidence_capacity("after_finalize")
            except ScenarioBudgetExhausted:
                pass
            except ScenarioFinalStateGrowthViolation:
                self.failure_status = "environment_error"
                list.append(self._events, {
                    "event_id": len(self._events) + 1,
                    "kind": "harness_failure",
                    "phase": "finalize",
                    "error_type": "ScenarioFinalStateGrowthViolation",
                    "status": "environment_error",
                })
        self._status = "finalized"
        replay_cut = (self._replay_wall_cut is not None
                      and self._replay_wall_cut[1] == "inflight_finalize")
        wall_expired = (deadline is not None and time.monotonic() >= deadline)
        already_has_wall_cut = any(
            event.get("kind") == "budget_exhausted"
            and event.get("limit") == "max_wall_time_ms"
            for event in self._events)
        if (replay_cut or wall_expired) and not already_has_wall_cut:
            prior_failure_status = self.failure_status
            if prior_failure_status is None:
                self.failure_status = "budget_exhausted"
            marker = {
                "event_id": len(self._events) + 1,
                "kind": "budget_exhausted", "limit": "max_wall_time_ms",
                "phase": "inflight_finalize", "effect_may_have_occurred": True,
                "local_ticks": dict(self.local_ticks),
                "prefix_event_count": len(self._events),
                "prefix_local_ticks": dict(self.local_ticks),
            }
            if cleanup_errors:
                marker["cleanup_errors"] = cleanup_errors
            if prior_failure_status is not None:
                marker["status_before_finalize"] = prior_failure_status
            list.append(self._events, marker)
        elif cleanup_errors and self.failure_status is None:
            self.failure_status = "environment_error"
            list.append(self._events, {
                "event_id": len(self._events) + 1,
                "kind": "harness_failure", "phase": "finalize",
                "status": "environment_error", "cleanup_errors": cleanup_errors,
            })
