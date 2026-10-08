"""Minimal continuous runner for independently stepped local harnesses.

Sessions own RTL and local protocol time. The runner keeps scenario inputs
between calls and routes only values actually observed from a session.
"""

from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, is_dataclass
from functools import wraps
import json
from typing import Callable, Mapping, Protocol
import time
import uuid
import weakref

from .ownership import OwnershipMap
from .contracts import ResourceBudget
from .protocol_io import (LocalCommandDeadlineExceeded, command_deadline)
from .host_identity import host_source_identity
from .state_dependency import StateDependencyTracker
from .genome import MemoryImage
from .irq import IrqPulseDelivery
from .memory import PersistentMemory
from .event_journal import EventJournal


_runtime_timing_observer: ContextVar[Callable[[str, float], None] | None] = (
    ContextVar("runtime_timing_observer", default=None))


@contextmanager
def observe_runtime_timings(observer: Callable[[str, float], None]):
    """Observe inclusive call time within one active online case."""
    token = _runtime_timing_observer.set(observer)
    try:
        yield
    finally:
        _runtime_timing_observer.reset(token)


def timed_runtime_call(name: str):
    """Add an optional timer without changing the wrapped operation."""
    def decorate(function):
        @wraps(function)
        def measured(*args, **kwargs):
            observer = _runtime_timing_observer.get()
            if observer is None:
                return function(*args, **kwargs)
            started = time.monotonic()
            try:
                return function(*args, **kwargs)
            finally:
                observer(name, time.monotonic() - started)
        return measured
    return decorate


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


class _EventLog:
    def __init__(self, runner: ScenarioRunner) -> None:
        self._runner_ref = weakref.ref(runner)
        self._records: list[dict] | EventJournal = []

    @property
    def runner(self) -> ScenarioRunner:
        runner = self._runner_ref()
        if runner is None:
            raise RuntimeError("event log owner no longer exists")
        return runner

    def enable_journal(self, *, chunk_size: int = 2048) -> None:
        if self._records:
            raise ValueError("event journal must be enabled before the first event")
        self._records = EventJournal(chunk_size=chunk_size)

    def __len__(self) -> int:
        return len(self._records)

    def __getitem__(self, index):
        return self._records[index]

    def __iter__(self):
        return iter(self._records)

    def snapshot(self):
        if isinstance(self._records, EventJournal):
            return self._records.snapshot()
        return deepcopy(tuple(self._records))

    def append_unchecked(self, record: dict) -> None:
        self._records.append(self.runner._decorate_provenance(record))

    def append(self, record: dict) -> None:
        self.runner._ensure_semantic_capacity("append_event")
        record = self.runner._decorate_provenance(record)
        self._records.append(record)
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
        for component, session in self.sessions.items():
            validate = getattr(session, 'validate_scenario_ownership', None)
            if callable(validate):
                validate(component, ownership)
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
        for component, session in self.sessions.items():
            validate = getattr(session, 'validate_scenario_bindings', None)
            if callable(validate):
                validate(component, bindings)
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
        self._events = _EventLog(self)
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
        self._replay_wall_cut_step_timeout_us: int | None = None
        self._replay_wall_cut_finalize_timeout_us: int | None = None
        self._replay_wall_cut_step_armed = False
        self._active_step_deadline: float | None = None
        self._active_step_timeout_us: int | None = None
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
        self._retired_step_floor: dict[int, int] = {}
        self._provenance = None
        self._retirement_delivery_linker = None
        self._gpio_consumption_tracker = None
        self._uart_consumption_tracker = None
        self._native_irq_join = None
        self._uart_retired_read_linker = None
        self._uart_operand_seed_tracker = None
        self._uart_operand_use_tracker = None
        self._uart_ram_commit_join = None
        self._memory_commit_authority = None
        self._uart_store_memory_join = None
        self._memory_read_authority = None
        self._uart_memory_readback_join = None
        self._controlled_irq_bootstrap = None
        self._controlled_irq_configuration = None
        self._controlled_irq_entry_join = None
        self._controlled_irq_images: dict[str, dict] = {}
        self._native_irq_inputs: dict[str, dict] = {}
        self._native_cpu_samples: dict[str, tuple[dict, int]] = {}
        self._uart_command_ticks: dict[str, tuple[dict, dict[int, int | None]]] = {}
        self._gpio_input_origins: dict[str, list[dict | None]] = {}
        self._gpio_irq_trigger_refs: dict[tuple[str, int, int, str], dict | None] = {}
        self._source_transport_scopes: dict[str, dict[str, str]] = {}

    def configure_provenance(self, edge_index) -> None:
        if self._status != 'created' or self._events or self._provenance is not None:
            raise ValueError('provenance must be configured once before startup')
        from .event_provenance import EventProvenance
        from .memory_service import MemoryService
        self._provenance = EventProvenance(edge_index)
        from .cpu_retirement import CpuRetirementMatcher
        # A persistent online CPU can fetch beyond one case before an older
        # response retires. Keep the raw matcher and the independent UART
        # retired-read reconstruction on the same finite instruction budget.
        self._cpu_retirement_matcher = CpuRetirementMatcher(max_pending=2048)
        if any(getattr(session, 'routed_register_access_enabled', False)
               and not getattr(session, 'uart_fifo_observation_enabled', False)
               for session in self.sessions.values()):
            from .retirement_delivery import RetirementRouterLinker
            self._retirement_delivery_linker = RetirementRouterLinker(
                admission_registry=self._provenance.registry)
            from .gpio_consumption import GpioConsumptionTracker
            self._gpio_consumption_tracker = GpioConsumptionTracker(
                admission_registry=self._provenance.registry, ownership=self.ownership,
                max_completed_accesses=8192, edge_index=self._provenance.edge_index)
        if any(getattr(session, 'uart_fifo_observation_enabled', False)
               for session in self.sessions.values()):
            from .uart_consumption import UartConsumptionTracker
            self._uart_consumption_tracker = UartConsumptionTracker(
                admission_registry=self._provenance.registry, ownership=self.ownership,
                edge_index=self._provenance.edge_index)
            if any(getattr(session, 'native_irq_receipts_enabled', False)
                   for session in self.sessions.values()):
                from .uart_irq_consumption import UartNativeIrqJoin
                self._native_irq_join = UartNativeIrqJoin(
                    admission_registry=self._provenance.registry, ownership=self.ownership,
                    edge_index=self._provenance.edge_index)
                from .uart_retired_read import UartRetiredReadLinker
                self._uart_retired_read_linker = UartRetiredReadLinker(
                    admission_registry=self._provenance.registry, ownership=self.ownership,
                    edge_index=self._provenance.edge_index,
                    max_instruction_witnesses=2048)
                from .uart_operand_seed import UartOperandSeedTracker
                self._uart_operand_seed_tracker = UartOperandSeedTracker(
                    admission_registry=self._provenance.registry, ownership=self.ownership,
                    edge_index=self._provenance.edge_index,
                    max_instruction_witnesses=2048)
                from .uart_operand_use import UartOperandUseTracker
                self._uart_operand_use_tracker = UartOperandUseTracker(
                    admission_registry=self._provenance.registry, ownership=self.ownership,
                    edge_index=self._provenance.edge_index,
                    max_instruction_witnesses=2048)
                commit_services = {component: session.service
                    for component, session in self.sessions.items()
                    if isinstance(getattr(session, 'service', None), MemoryService)
                    and session.service.commit_stream_enabled}
                if commit_services:
                    from .memory_commit_authority import MemoryCommitAuthority
                    from .uart_store_memory import UartStoreMemoryJoin
                    self._memory_commit_authority = MemoryCommitAuthority(
                        services=commit_services)
                    self._uart_store_memory_join = UartStoreMemoryJoin(
                        memory_commit_authority=self._memory_commit_authority,
                        admission_registry=self._provenance.registry,
                        ownership=self.ownership, edge_index=self._provenance.edge_index,
                        max_instruction_witnesses=2048)
        for session in self.sessions.values():
            enable = getattr(session, 'enable_source_provenance', None)
            if callable(enable):
                enable()
            service = getattr(session, 'service', None)
            if isinstance(service, MemoryService):
                service.include_writer_kinds = True
        read_sessions = {component: session for component, session in self.sessions.items()
            if getattr(session, 'memory_readback_receipts_enabled', False)}
        if read_sessions:
            if (self._memory_commit_authority is None
                    or any(not isinstance(getattr(session, 'service', None), MemoryService)
                           or not session.service.commit_stream_enabled
                           for session in read_sessions.values())):
                raise ValueError('UART RAM readback requires live write commits and provenance')
            from .memory_read_authority import MemoryReadAuthority
            from .uart_memory_readback import UartMemoryReadbackJoin
            self._memory_read_authority = MemoryReadAuthority(
                services={component: session.service
                          for component, session in read_sessions.items()})
            for session in read_sessions.values():
                session.memory_read_authority = self._memory_read_authority
            self._uart_memory_readback_join = UartMemoryReadbackJoin(
                memory_commit_authority=self._memory_commit_authority,
                memory_read_authority=self._memory_read_authority,
                admission_registry=self._provenance.registry,
                ownership=self.ownership, edge_index=self._provenance.edge_index,
                max_instruction_witnesses=2048)
            self._uart_store_memory_join = None

    @property
    def provenance_configuration(self) -> dict | None:
        return deepcopy(self._provenance.configuration) if self._provenance is not None else None

    @property
    def provenance_enabled(self) -> bool:
        return self._provenance is not None

    @property
    def source_admissions(self) -> dict | None:
        return self._provenance.registry.document() if self._provenance is not None else None

    def set_observation_case(self, case_id: str, case_index: int) -> None:
        if self._provenance is None:
            return
        if type(case_id) is not str or not case_id.strip() or type(case_index) is not int or case_index < 0:
            raise ValueError('invalid provenance observation case')
        self._provenance.observed_case = {'case_id': case_id, 'case_index': case_index}

    def clear_observation_case(self) -> None:
        if self._provenance is not None:
            self._provenance.observed_case = None

    def register_source_admission(self, admission) -> None:
        from .source_provenance import SourceAdmission
        if self._provenance is None or not isinstance(admission, SourceAdmission):
            raise ValueError('configured provenance and SourceAdmission are required')
        if (admission.component not in self.sessions
                or admission.path_id not in self._provenance.configuration['edge_index']['path_ids']):
            raise ValueError('source admission component/path is outside configured provenance')
        existing = self._provenance.registry.get(admission.action_id)
        if existing is not None:
            self._provenance.registry.register(admission)
            return
        self._ensure_semantic_capacity('source_admission')
        self._provenance.registry.register(admission)
        self._events.append({'event_id': len(self._events) + 1,
                             'kind': 'source_admission', 'admission': admission.document()})

    def _decorate_provenance(self, record: dict) -> dict:
        return self._provenance.decorate(record) if self._provenance is not None else record

    @property
    def events(self) -> tuple[dict, ...]:
        return self._events.snapshot()

    def enable_event_journal(self, *, chunk_size: int = 2048) -> None:
        """Bound online event memory before any testcase input is admitted."""
        if self._status != "created" or self._events:
            raise ValueError("event journal requires a fresh runner")
        self._events.enable_journal(chunk_size=chunk_size)

    @property
    def event_count(self) -> int:
        """Number of recorded events, usable as a cursor for ``events_since``."""
        return len(self._events)

    def events_since(self, index: int) -> tuple[dict, ...]:
        """Return a detached copy of events starting at zero-based ``index``."""
        if type(index) is not int or not 0 <= index <= len(self._events):
            raise ValueError("event index is outside the recorded prefix")
        return deepcopy(tuple(self._events[index:]))

    def event_by_id(self, event_id: int) -> dict | None:
        """Read one detached event from the authoritative indexed log."""
        event = self._event_ref_by_id(event_id)
        return deepcopy(event) if event is not None else None

    def _event_ref_by_id(self, event_id: int) -> dict | None:
        """Borrow a journal event for trusted synchronous readers only.

        The returned record must never be mutated or retained as mutable
        state. Public callers use ``event_by_id`` for a detached copy.
        """
        if type(event_id) is not int or not 1 <= event_id <= len(self._events):
            return None
        event = self._events[event_id - 1]
        if event.get("event_id") != event_id:
            raise ValueError("event journal ID/order mismatch")
        return event

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
                            step_timeout_us: int | None = None,
                            finalize_timeout_us: int | None = None,
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
        for name, value in (("step_timeout_us", step_timeout_us),
                            ("finalize_timeout_us", finalize_timeout_us)):
            if (value is not None and
                    (type(value) is not int or value < 0)):
                raise ValueError(f"invalid replay {name}")
            if (value is not None and self._resource_budget is not None
                    and value > self._resource_budget.max_wall_time_ms * 1000):
                raise ValueError(f"replay {name} exceeds testcase wall budget")
        if (step_timeout_us is not None and phase != "inflight_step"):
            raise ValueError("step timeout is only valid for an inflight step")
        if (finalize_timeout_us is not None and phase != "inflight_finalize"):
            raise ValueError("finalize timeout is only valid for inflight finalize")
        if phase == "inflight_finalize" and finalize_timeout_us is None:
            raise ValueError(
                "finalize_timeout_us is required for inflight finalize replay")
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
        self._replay_wall_cut_step_timeout_us = step_timeout_us
        self._replay_wall_cut_finalize_timeout_us = finalize_timeout_us

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
                if self._replay_wall_cut_step_timeout_us is None:
                    # Legacy markers lack a command-local remaining deadline.
                    # Keep their historical prefix-only replay behavior.
                    self._exhaust_budget(
                        "max_wall_time_ms", "inflight_step",
                        effect_may_have_occurred=True,
                        prefix_event_count=len(self._events))
                self._replay_wall_cut_step_armed = True
                return
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
        self._events.append_unchecked(event)
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

    def configure_controlled_irq_bootstrap(self, bootstrap, *, component: str = 'cpu') -> None:
        if self._status != 'created' or self._events or self._controlled_irq_bootstrap is not None:
            raise ValueError('controlled bootstrap must be configured once before installation')
        session = self.sessions.get(component)
        if not getattr(session, 'native_irq_receipts_enabled', False):
            raise ValueError('controlled bootstrap requires native CPU receipts')
        from .uart_irq_entry import controlled_uart_bootstrap_configuration
        from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
        self._controlled_irq_configuration = controlled_uart_bootstrap_configuration(
            bootstrap, component=component, runtime_artifact=session.artifact.runtime_document,
            observation_contract=ibex_irq_receipt_contract())
        self._controlled_irq_bootstrap = deepcopy(bootstrap)

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
        if self._controlled_irq_configuration is not None:
            document['controlled_uart_bootstrap_configuration'] = deepcopy(
                self._controlled_irq_configuration)
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
        if self._controlled_irq_configuration is not None and self._controlled_irq_entry_join is None:
            raise ValueError('controlled bootstrap images must be installed before startup')
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
        self._events.append_unchecked({
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
        configuration = self._controlled_irq_configuration
        controlled_image = False
        if configuration is not None and image.component == configuration['component']:
            expected = {row['image_id']: row for row in configuration['images']}
            if image.image_id in expected:
                if image.image_id in self._controlled_irq_images:
                    raise ValueError('controlled image cannot be installed twice')
                row = expected[image.image_id]
                if image.address != row['address'] or image.data_hex != row['data_hex']:
                    raise ValueError('controlled image differs from configured bootstrap')
                controlled_image = True
        self._ensure_semantic_capacity("before_image")
        memory.preload(image.address, image.data)
        record = {"event_id": len(self._events) + 1,
                             "kind": "initial_image", "image_id": image.image_id,
                             "component": image.component, "address": image.address,
                             "data_hex": image.data_hex}
        if controlled_image:
            memory_id, generation, byte_offset = memory.resolve_span(image.address, 1)
            record.update(memory_id=memory_id, generation=generation, byte_offset=byte_offset)
            self._controlled_irq_images[image.image_id] = deepcopy({key: value
                for key, value in record.items() if key != 'kind'})
        self._events.append(record)
        if (configuration is not None and self._controlled_irq_entry_join is None
                and len(self._controlled_irq_images) == len(configuration['images'])):
            from .uart_irq_entry import ControlledUartBootstrapRegistry, UartControlledIrqEntryJoin
            from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
            component = configuration['component']
            registry = ControlledUartBootstrapRegistry.from_bootstrap(
                self._controlled_irq_bootstrap, component=component,
                memory_metadata={'images': list(self._controlled_irq_images.values())},
                runtime_artifact=self.sessions[component].artifact.runtime_document,
                observation_contract=ibex_irq_receipt_contract())
            self._controlled_irq_entry_join = UartControlledIrqEntryJoin(bootstrap_registry=registry)
            self._events.append({'event_id': len(self._events) + 1,
                'kind': 'controlled_uart_bootstrap_registration', 'component': component,
                'registry': registry.document()})

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
            if self._gpio_consumption_tracker is not None or self._uart_consumption_tracker is not None:
                self._drain_causal_gpio_events(self._events[-1]['event_id'])
            raise
        self._inputs = {component: {} for component in self.sessions}
        self._gpio_input_origins.clear()
        self._gpio_irq_trigger_refs.clear()
        self._native_irq_inputs.clear()
        self._native_cpu_samples.clear()
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
        reset_event_id = self._events[-1]['event_id']
        if self._gpio_consumption_tracker is not None or self._uart_consumption_tracker is not None:
            for component in sorted(self.sessions):
                self._append_external_events(component, reset_event_id)
        if policy == "cold_all":
            barrier_id = reset_event_id
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
                      action_id: str = "") -> int | None:
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
        admit = getattr(self.sessions[component], 'admit_source_event', None)
        scheduled_tick = None
        if callable(admit):
            scheduled_tick = admit(port, value, bit_offset=bit_offset,
                                   width=selected_width, action_id=action_id)
            if (scheduled_tick is not None and
                    (type(scheduled_tick) is not int or scheduled_tick < 0)):
                raise ValueError('source admission returned invalid local tick')
        old = self._inputs[component].get(port, 0)
        self._inputs[component][port] = (old & ~mask) | (value << bit_offset)
        if self._gpio_consumption_tracker is not None and port == 'gpio_in':
            origins = self._gpio_input_origins.setdefault(component, [None] * 32)
            for bit in range(bit_offset, bit_offset + selected_width):
                origins[bit] = {'kind': 'source_admission', 'action_id': action_id}
        event = {"event_id": len(self._events) + 1,
                 "kind": "source_injection", "action_id": action_id,
                 "component": component, "port": port,
                 "source_ref": source_ref, "direction": direction,
                 "bit_offset": bit_offset, "width": selected_width,
                 "value": value}
        if scheduled_tick is not None:
            event["scheduled_local_tick"] = scheduled_tick
        self._events.append(event)
        return scheduled_tick

    @timed_runtime_call("runner_step")
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

    @timed_runtime_call("scheduler_batch")
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
            if type(accesses) is not int or accesses < 0:
                raise ValueError("budgeted MMIO route needs local tick bounds")
            if accesses == 0:
                continue
            ticks = getattr(target, "max_local_ticks_per_register_access", None)
            if type(ticks) is not int or ticks < 1:
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
            bits = ({'source_bit_offset': binding.source_bit_offset,
                     'target_bit_offset': binding.target_bit_offset,
                     'width': binding.width} if self._provenance is not None else {})
            self._events.append({"event_id": len(self._events) + 1,
                                 "source": (binding.source_component, binding.source_port),
                                 "target": (binding.target_component, binding.target_port),
                                 **event, **bits})
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
            session = self.sessions[component]
            stage_irq = getattr(session, 'set_next_irq_input_context', None)
            if self._native_irq_join is not None and callable(stage_irq):
                stage_irq(self._native_irq_input_context(component, inputs.get('irq', 0)))
            stage_gpio = getattr(session, 'set_next_gpio_input_context', None)
            if (self._gpio_consumption_tracker is not None and callable(stage_gpio)
                    and getattr(session, 'routed_register_access_enabled', False)):
                value = inputs.get('gpio_in', 0)
                segments = []
                for bit, origin in enumerate(self._gpio_input_origins.get(component, ())):
                    if origin is None:
                        continue
                    origin = deepcopy(origin)
                    if origin.get('kind') == 'binding':
                        resources = self._gpio_consumption_tracker.output_resources_at(
                            origin['source_component'], origin['producer_reset_epoch'],
                            origin['producer_local_tick'], phase=origin['producer_phase'])
                        source_bit = origin['source_bit_lo']
                        origin['producer_resource_refs'] = resources[source_bit:source_bit + 1]
                    segments.append({'bit_lo': bit, 'width': 1,
                                     'value': (value >> bit) & 1, 'origin': origin})
                stage_gpio({'segments': segments})
            routed_step = getattr(session, 'step_local_routed', None)
            if callable(routed_step):
                names = getattr(session, 'routed_input_names', None)
                if not isinstance(names, frozenset):
                    raise ValueError('routed session must declare bound input names')
                source_inputs = {name: value for name, value in inputs.items()
                                 if name not in names}
                bound_inputs = {name: value for name, value in inputs.items()
                                if name in names}
                outputs = dict(routed_step(source_inputs, bound_inputs))
            else:
                outputs = dict(session.step_local(inputs))
        except BaseException as exc:
            self._status = "failed"
            uncertain = self._uncertain_transactions()
            # The local command was issued but no complete reply was accepted.
            # A harness may have ticked or performed an effect without a ledger
            # entry, so absence of an unresolved transaction proves nothing.
            replay_step_expired = (
                self._replay_wall_cut_step_armed
                and self._active_step_deadline is not None
                and time.monotonic() >= self._active_step_deadline)
            timed_out = (isinstance(exc, LocalCommandDeadlineExceeded)
                         and (self._testcase_wall_deadline_reached()
                              or replay_step_expired))
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
            failure_event_id = self._events[-1]['event_id']
            self._drain_causal_gpio_events(failure_event_id, exclude=component)
            self._append_external_events(component, failure_event_id)
            self._drain_tick_samples(failure_event_id)
            if timed_out:
                self.failure_status = "budget_exhausted"
                marker = {
                    "event_id": len(self._events) + 1,
                    "kind": "budget_exhausted", "limit": "max_wall_time_ms",
                    "phase": "inflight_step", "effect_may_have_occurred": True,
                    "local_ticks": dict(self.local_ticks),
                    "prefix_event_count": event_count_before_step,
                    "prefix_local_ticks": ticks_before_step,
                }
                if self._active_step_timeout_us is not None:
                    marker["step_timeout_us"] = self._active_step_timeout_us
                self._events.append_unchecked(marker)
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
        self._drain_causal_gpio_events(event_id, exclude=component)
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
                              accepted=None if taken_observed is None else bool(taken_observed),
                              cpu_step_event_id=event_id)
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
                self._drain_causal_gpio_events(event_id)
                self._append_external_events(source_component, event_id)
                self._drain_tick_samples(event_id)
        return outputs

    @timed_runtime_call("observed_output_route")
    def _route_observed_outputs(self, component: str, outputs: Mapping[str, int],
                                event_id: int, source_tick: int,
                                source_phase: str = 'post') -> None:
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
                source_trigger = None
                if fragment == 1 and policy.source_level == 0:
                    source_trigger = self._gpio_irq_source_trigger(
                        binding, event_id, source_tick, source_phase)
                policy.observe_source(fragment, source_tick=source_tick,
                                      cpu_tick=self.local_ticks[binding.target_component],
                                      source_trigger=source_trigger)
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
            delivery_id = len(self._events) + 1
            self._events.append({"event_id": delivery_id,
                                 "kind": "dataflow_delivery",
                                 "producer_event_id": event_id,
                                 "source": (component, binding.source_port),
                                 "target": (binding.target_component, binding.target_port),
                                 "value": fragment,
                                 "source_bit_offset": binding.source_bit_offset,
                                 "target_bit_offset": binding.target_bit_offset,
                                 "width": binding.width,
                                 "target_value": updated})
            self._route_native_irq_binding(binding, fragment, updated, delivery_id,
                event_id, source_tick, source_phase)
            if self._gpio_consumption_tracker is not None and binding.target_port == 'gpio_in':
                origins = self._gpio_input_origins.setdefault(binding.target_component, [None] * 32)
                for offset in range(binding.width):
                    origins[binding.target_bit_offset + offset] = {
                        'kind': 'binding', 'source_component': component,
                        'source_port': binding.source_port,
                        'source_bit_lo': binding.source_bit_offset + offset,
                        'producer_reset_epoch': getattr(self.sessions[component], 'reset_epoch', 0),
                        'producer_local_tick': source_tick, 'producer_phase': source_phase,
                        'delivery_event_id': delivery_id}

    def _native_irq_input_context(self, component: str, value: int) -> dict | None:
        record = self._native_irq_inputs.get(component)
        if (record is None or type(value) is not int or record['value'] != value
                or record['target_epoch'] != getattr(self.sessions[component], 'reset_epoch', 0)):
            return None
        return {'schema_version': 'native_irq_input_context.v1',
                'binding_delivery_event_id': record['event_id'], 'expected_input': value,
                'source_output_key': deepcopy(record['source_output_key']),
                'target_component': component, 'target_epoch': record['target_epoch']}

    def _route_native_irq_binding(self, binding: Binding, value: int, target_value: int,
                                  delivery_id: int, producer_id: int,
                                  tick: int, phase: str) -> None:
        if self._native_irq_join is None or binding.target_port != 'irq':
            return
        target = binding.target_component
        # Every applied write replaces prior proof metadata, including equal values.
        self._native_irq_inputs.pop(target, None)
        if (binding.source_port != 'uart_rx_watermark' or binding.width != 1
                or binding.source_bit_offset != 0 or binding.target_bit_offset != 0
                or not getattr(self.sessions[target], 'native_irq_receipts_enabled', False)
                or not getattr(self.sessions[binding.source_component], 'uart_fifo_observation_enabled', False)):
            return
        epoch = getattr(self.sessions[binding.source_component], 'reset_epoch', 0)
        source = self._native_irq_join.output_at(binding.source_component, epoch,
                                                 tick, phase, 'rx_watermark')
        if not isinstance(source, dict) or type(source.get('value')) is not int or source['value'] != value:
            return
        record = {'kind': 'native_irq_binding_delivery',
            'schema_version': 'native_irq_binding_delivery.v1',
            'event_id': len(self._events) + 1, 'producer_event_id': producer_id,
            'dataflow_delivery_event_id': delivery_id,
            'source_component': binding.source_component, 'source_epoch': epoch,
            'source_local_tick': tick, 'source_phase': phase, 'irq_class': 'rx_watermark',
            'source_port': binding.source_port, 'source_output_key': deepcopy(source['source_output_key']),
            'source_observation_event_id': source['source_observation_event_id'],
            'source_receipt_ref': deepcopy(source['source_receipt_ref']),
            'target_component': target, 'target_epoch': getattr(self.sessions[target], 'reset_epoch', 0),
            'target_port': binding.target_port, 'width': 1,
            'source_bit_offset': 0, 'target_bit_offset': 0,
            'value': value, 'target_value': target_value}
        self._events.append(record)
        self._native_irq_inputs[target] = deepcopy(record)
        self._append_native_irq(record)

    def _append_native_irq(self, record: dict) -> None:
        if self._native_irq_join is None:
            return
        for report in self._native_irq_join.consume(record):
            logged = {**report, 'event_id': len(self._events) + 1,
                'producer_event_id': record['event_id']}
            self._events.append(logged)
            self._append_controlled_irq_entry(logged)

    def _append_controlled_irq_entry(self, record: dict) -> None:
        if self._controlled_irq_entry_join is None:
            return
        for report in self._controlled_irq_entry_join.consume(record):
            self._events.append({**report, 'event_id': len(self._events) + 1,
                'producer_event_id': record['event_id']})

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
                    self._route_observed_outputs(component, outputs, event_id, tick, phase)
                    epoch = getattr(session, 'reset_epoch', 0)
                    if type(epoch) is int:
                        self._gpio_irq_trigger_refs.pop((component, epoch, tick, phase), None)
                self._last_sample_ticks[component] = tick

    def _drain_causal_gpio_events(self, event_id: int, *, exclude: str = '') -> None:
        if self._gpio_consumption_tracker is None and self._uart_consumption_tracker is None:
            return
        for component, session in self.sessions.items():
            if component != exclude and (
                    getattr(session, 'uart_fifo_observation_enabled', False)
                    or getattr(session, 'routed_register_access_enabled', False)):
                self._append_external_events(component, event_id)

    def _append_external_events(self, component: str, event_id: int) -> None:
        """Keep facts logged by local services even when the step reply is lost."""
        session = self.sessions[component]
        drained_streams = []
        for owner, attribute, kind in ((getattr(session, "service", None),
                                        "events", "memory_commit"),
                                       (getattr(session, "router", None),
                                        "acceptances", "mmio_acceptance"),
                                       (getattr(session, "router", None),
                                        "deliveries", "mmio_delivery"),
                                       (session, "local_transactions",
                                        "local_register_transaction"),
                                       (session, "source_events", "source_observation"),
                                       (session, "gpio_events", "gpio_observation"),
                                       (session, "uart_events", "uart_observation"),
                                       (session, "cpu_events", "cpu_observation")):
            stream = getattr(owner, attribute, None)
            if stream is None:
                continue
            stream_id = id(stream)
            offset = self._external_offsets.get(stream_id, 0)
            pending_gpio_tick = None
            for stream_offset, item in enumerate(stream[offset:], start=offset + 1):
                record = deepcopy(dict(item))
                if kind == 'uart_observation':
                    self._prepare_uart_observation(component, record)
                if kind == 'cpu_observation' and record.get('kind') in (
                        'cpu_external_irq_sample', 'cpu_external_irq_taken', 'cpu_irq_notification',
                        'cpu_retire', 'cpu_native_startup', 'cpu_reset'):
                    self._prepare_native_cpu_observation(component, record)
                if kind == 'source_observation' and record.get('kind') in (
                        'uart_source_frame_end', 'uart_source_frame_cancel'):
                    # The command parser already binds every raw receipt to the
                    # current driver nonce. Preserve that distinct process scope
                    # in replay without comparing random wire UUIDs. Raw session
                    # evidence remains untouched; sequence numbers stay measured.
                    witnesses = record.get('bit_witness')
                    for witness in witnesses if isinstance(witnesses, (list, tuple)) else ():
                        receipt = witness.get('receipt') if isinstance(witness, dict) else None
                        if not isinstance(receipt, dict) or receipt.get('execution_scope') == 'parsed_driver_execution':
                            continue
                        nonce = receipt.get('execution')
                        if type(nonce) is str and nonce.strip():
                            scopes = self._source_transport_scopes.setdefault(component, {})
                            if nonce not in scopes:
                                scopes[nonce] = f'local-driver:{component}:{len(scopes) + 1}'
                            receipt['execution'] = scopes[nonce]
                            receipt['execution_scope'] = 'parsed_driver_execution'
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
                if kind not in ('cpu_observation', 'uart_observation'):
                    self._append_uart_ram_commit_join(record)
                    self._append_uart_store_memory_join(record)
                self._external_offsets[stream_id] = stream_offset
                if kind == 'cpu_observation':
                    if record.get('kind') == 'cpu_external_irq_sample':
                        self._native_cpu_samples[component] = (
                            {key: deepcopy(record.get(key)) for key in
                                ('command_scope', 'receipt_id', 'local_tick', 'reset_epoch')},
                            record['event_id'])
                    if record.get('kind') == 'cpu_reset':
                        self._native_irq_inputs.pop(component, None)
                        self._native_cpu_samples.pop(component, None)
                    self._append_controlled_irq_entry(record)
                    self._append_native_irq(record)
                    self._append_uart_retired_read(record)
                if kind == 'uart_observation' and self._uart_consumption_tracker is not None:
                    self._append_uart_consumption(record)
                if kind == 'gpio_observation' and self._gpio_consumption_tracker is not None:
                    if record.get('kind') == 'gpio_input_applied':
                        self._apply_gpio_receipt_segments(record, pending_gpio_tick)
                    if pending_gpio_tick is not None:
                        self._append_gpio_consumption(pending_gpio_tick)
                        pending_gpio_tick = None
                    if record.get('kind') == 'gpio_tick_observation':
                        pending_gpio_tick = record
                    elif record.get('kind') != 'gpio_input_applied':
                        self._append_gpio_consumption(record)
                if kind == 'mmio_delivery' and self._retirement_delivery_linker is not None:
                    self._append_retirement_deliveries(
                        self._retirement_delivery_linker.consume_delivery(record), record)
                if kind == 'cpu_observation' and self._provenance is not None:
                    if record.get('kind') == 'cpu_reset' and self._retirement_delivery_linker is not None:
                        self._append_retirement_deliveries(
                            self._retirement_delivery_linker.consume_reset({name: record.get(name)
                                for name in ('execution_id', 'source_component', 'source_epoch')}), record)
                    for match in self._cpu_retirement_matcher.consume(record):
                        logged_match = {**match, 'kind': 'cpu_retirement_match',
                            'event_id': len(self._events) + 1,
                            'producer_event_id': record['event_id'], 'component': component,
                            'origin_relation': 'retired_instruction_bytes'}
                        self._events.append(logged_match)
                        self._append_uart_retired_read(logged_match)
                        if self._retirement_delivery_linker is not None and match.get('transaction_keys'):
                            origins = [self._provenance.registry.get(ref)
                                       for ref in match.get('source_refs', ()) if type(ref) is str]
                            self._append_retirement_deliveries(
                                self._retirement_delivery_linker.consume_match(
                                    self.event_by_id(logged_match['event_id']),
                                    registered_origins=[origin.document() for origin in origins
                                                        if origin is not None]), logged_match)
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
            if (kind in ('memory_commit', 'cpu_observation', 'uart_observation')
                    and isinstance(self._events._records, EventJournal)
                    and type(stream) is list):
                drained_streams.append((stream_id, stream, len(stream)))
            if kind == 'memory_commit' and (self._uart_memory_readback_join is not None
                                            or self._uart_store_memory_join is not None
                                            or self._uart_ram_commit_join is not None):
                for issued in owner.drain_commit_events():
                    commit_id = issued['commit_id']
                    receipt, actual = owner.lookup_pending_commit(commit_id)
                    try:
                        same_issued = (type(actual) is dict and type(issued) is dict
                            and json.dumps(actual, sort_keys=True, separators=(',', ':'),
                                           allow_nan=False)
                            == json.dumps(issued, sort_keys=True, separators=(',', ':'),
                                          allow_nan=False))
                    except (TypeError, ValueError):
                        same_issued = False
                    if not same_issued:
                        raise RuntimeError('live memory commit changed during drain')
                    token = None
                    if (self._uart_memory_readback_join is not None
                            or self._uart_store_memory_join is not None):
                        token = self._memory_commit_authority.stage(
                            component, owner, owner.ledger, receipt.transaction_id, receipt)
                    elif not self._uart_ram_commit_join.stage_commit(
                            component, owner, owner.ledger, receipt.transaction_id, receipt):
                        raise RuntimeError('live memory commit could not be authenticated')
                    logged = {**issued, 'event_id': len(self._events) + 1,
                              'producer_event_id': event_id, 'component': component}
                    self._events.append(logged)
                    self._append_uart_store_memory_join(logged, commit_token=token)
                    owner.ack_commit_events((commit_id,))
            if (kind == 'memory_commit' and self._uart_memory_readback_join is not None
                    and self._memory_read_authority is not None):
                for token, issued in self._memory_read_authority.drain():
                    if issued['fullkey']['source_component'] != component:
                        continue
                    logged = {**issued, 'kind': 'memory_read_issuance',
                              'status': 'accepted', 'event_id': len(self._events) + 1,
                              'producer_event_id': event_id, 'component': component}
                    self._events.append(logged)
                    self._append_uart_store_memory_join(logged, read_token=token)
            if pending_gpio_tick is not None:
                self._append_gpio_consumption(pending_gpio_tick)
        # The journal owns detached copies of every drained fact. Releasing the
        # memory/CPU/UART producer lists prevents a long online session from
        # retaining a second event history alongside the on-disk journal.
        # Router lists retain len()-based acceptance order and cannot shrink.
        for stream_id, stream, count in drained_streams:
            if len(stream) == count:
                stream.clear()
                self._external_offsets[stream_id] = 0

    def _prepare_native_cpu_observation(self, component: str, record: dict) -> None:
        self._normalize_observation_receipts(component, record)
        if record.get('kind') != 'cpu_external_irq_taken':
            return
        record.pop('sample_event_id', None)
        sample = self._native_cpu_samples.get(component)
        reference = record.get('sample_ref')
        if sample is None or not isinstance(reference, dict):
            return
        measured, event_id = sample
        scope, receipt = measured['command_scope'], measured['receipt_id']
        if (type(scope) is not dict or set(scope) != {'component', 'reset_epoch', 'command_sequence'}
                or type(scope['component']) is not str or scope['component'] != component
                or type(scope['reset_epoch']) is not int or scope['reset_epoch'] < 0
                or type(measured['reset_epoch']) is not int or measured['reset_epoch'] != scope['reset_epoch']
                or type(scope['command_sequence']) is not int or scope['command_sequence'] <= 0
                or type(measured['local_tick']) is not int or measured['local_tick'] < 0
                or type(receipt) is not dict or set(receipt) != {'execution', 'sequence'}
                or type(receipt['execution']) is not str or not receipt['execution']
                or type(receipt['sequence']) is not int or receipt['sequence'] != scope['command_sequence']):
            return
        expected = {key: record.get(key) for key in measured}
        expected_ref = {'command_scope': measured['command_scope'],
                        'local_tick': measured['local_tick']}
        try:
            matches = (json.dumps(measured, sort_keys=True, allow_nan=False)
                       == json.dumps(expected, sort_keys=True, allow_nan=False)
                       and json.dumps(reference, sort_keys=True, allow_nan=False)
                       == json.dumps(expected_ref, sort_keys=True, allow_nan=False))
        except (TypeError, ValueError):
            matches = False
        if matches:
            record['sample_event_id'] = event_id

    def _normalize_observation_receipts(self, component: str, record: dict) -> None:
        """Preserve parsed process distinctions with deterministic replay scopes."""
        scopes = self._source_transport_scopes.setdefault(component, {})
        visited = set()

        def visit(value):
            if isinstance(value, (dict, list)):
                if id(value) in visited:
                    return
                visited.add(id(value))
            if isinstance(value, list):
                for child in value:
                    visit(child)
            elif isinstance(value, dict):
                receipt = value.get('receipt_id')
                if isinstance(receipt, dict):
                    nonce = receipt.get('execution')
                    if type(nonce) is str and nonce.strip() and nonce not in scopes.values():
                        if nonce not in scopes:
                            scopes[nonce] = f'local-driver:{component}:{len(scopes) + 1}'
                        receipt['execution'] = scopes[nonce]
                action = value.get('action_id')
                if 'admission_id' in value:
                    admission = (self._provenance.registry.get(action)
                        if self._provenance is not None and type(action) is str and action.strip()
                        else None)
                    value['admission_id'] = (admission.admission_id if admission is not None
                        and admission.component == component and admission.input_kind == 'source_event'
                        else None)
                for child in value.values():
                    visit(child)

        visit(record)

    def _prepare_uart_observation(self, component: str, record: dict) -> None:
        """Bridge measured command receipts without modifying session evidence."""
        self._normalize_observation_receipts(component, record)
        if record.get('kind') == 'uart_rdata_access':
            record.pop('actual_request_event_id', None)
            record.pop('actual_response_event_id', None)
        scope = record.get('command_scope')
        valid = (type(scope) is dict
            and set(scope) == {'component', 'reset_epoch', 'command_sequence'}
            and scope['component'] == component
            and type(scope['reset_epoch']) is int and scope['reset_epoch'] >= 0
            and scope['reset_epoch'] == record.get('reset_epoch')
            and type(scope['command_sequence']) is int and scope['command_sequence'] > 0)
        if not valid:
            return
        active = self._uart_command_ticks.get(component)
        if active is None or active[0] != scope:
            # A closed command cannot regain a receipt mapping by arriving late.
            if active is not None and (scope['reset_epoch'], scope['command_sequence']) <= (
                    active[0]['reset_epoch'], active[0]['command_sequence']):
                return
            active = (deepcopy(scope), {})
            self._uart_command_ticks[component] = active
        ticks = active[1]
        if record.get('kind') == 'uart_tick_observation':
            tick = record.get('local_tick')
            if type(tick) is int and tick >= 0:
                if tick in ticks:
                    ticks[tick] = None
                elif len(ticks) < 8192:
                    ticks[tick] = len(self._events) + 1
        elif record.get('kind') == 'uart_rdata_access':
            for role, capture in (('request', 'read_capture'), ('response', 'response_capture')):
                measured = record.get(capture)
                tick = record.get(role + '_tick')
                reference = measured.get('actual_receipt_ref') if isinstance(measured, dict) else None
                reference_scope = reference.get('command_scope') if isinstance(reference, dict) else None
                if (type(tick) is int and isinstance(measured, dict)
                    and type(reference) is dict and set(reference) == {'command_scope', 'local_tick'}
                    and type(reference.get('local_tick')) is int and reference['local_tick'] == tick
                    and type(reference_scope) is dict and set(reference_scope) == set(scope)
                    and all(type(reference_scope[key]) is type(scope[key])
                            and reference_scope[key] == scope[key] for key in scope)
                    and ticks.get(tick) is not None):
                    record['actual_' + role + '_event_id'] = ticks[tick]

    def _append_uart_consumption(self, record: dict) -> None:
        self._append_native_irq(record)
        self._append_uart_retired_read(record)
        for report in self._uart_consumption_tracker.consume(record):
            logged = {**report, 'event_id': len(self._events) + 1,
                'producer_event_id': record['event_id']}
            self._events.append(logged)
            self._append_native_irq(logged)
            self._append_uart_retired_read(logged)

    def _append_uart_retired_read(self, record: dict) -> None:
        if self._uart_retired_read_linker is None:
            return
        self._append_uart_ram_commit_join(record)
        self._append_uart_store_memory_join(record)
        if record.get('kind') in ('uart_retired_read_match', 'uart_operand_seed',
                                  'uart_operand_use'):
            return
        for report in self._uart_retired_read_linker.consume(record):
            self._events.append({**report, 'event_id': len(self._events) + 1,
                'producer_event_id': record['event_id']})
        if self._uart_operand_seed_tracker is not None:
            for report in self._uart_operand_seed_tracker.consume(record):
                self._events.append({**report, 'event_id': len(self._events) + 1,
                    'producer_event_id': record['event_id']})
        if self._uart_operand_use_tracker is not None:
            for report in self._uart_operand_use_tracker.consume(record):
                self._events.append({**report, 'event_id': len(self._events) + 1,
                    'producer_event_id': record['event_id']})

    def _append_uart_ram_commit_join(self, record: dict) -> None:
        if self._uart_ram_commit_join is None:
            return
        for report in self._uart_ram_commit_join.consume(record):
            self._events.append({**report, 'event_id': len(self._events) + 1,
                'producer_event_id': record['event_id']})

    def _append_uart_store_memory_join(self, record: dict, *, commit_token=None,
                                       read_token=None) -> None:
        if self._uart_memory_readback_join is not None:
            reports = self._uart_memory_readback_join.consume(
                record, commit_token=commit_token, read_token=read_token)
        elif self._uart_store_memory_join is not None:
            reports = self._uart_store_memory_join.consume(record, commit_token=commit_token)
        else:
            return
        for report in reports:
            if report.get('kind') == 'uart_memory_readback':
                report = {**report,
                    'load_observed_case': deepcopy(self._provenance.observed_case)}
            self._events.append({**report, 'event_id': len(self._events) + 1,
                'producer_event_id': record['event_id']})

    def _append_gpio_consumption(self, record: dict) -> None:
        if self._gpio_consumption_tracker is None:
            return
        for report in self._gpio_consumption_tracker.consume(record):
            logged = {**report, 'event_id': len(self._events) + 1,
                'producer_event_id': record['event_id']}
            self._events.append(logged)
            self._remember_gpio_irq_trigger(logged)

    def _remember_gpio_irq_trigger(self, report: dict) -> None:
        """Retain a native rise only with its exact authenticated tick receipt."""
        if report.get('kind') != 'gpio_irq_trigger':
            return
        from .gpio_consumption import is_authenticated_gpio_tick
        component = report.get('component')
        epoch = report.get('reset_epoch')
        tick = report.get('local_tick')
        phase = report.get('phase')
        observation_id = report.get('observation_event_id')
        if (type(component) is not str or type(epoch) is not int
                or type(tick) is not int or phase not in ('pre', 'post')
                or type(observation_id) is not int):
            return
        key = (component, epoch, tick, phase)
        raw = self._event_ref_by_id(observation_id)
        measured = raw.get(phase) if isinstance(raw, dict) else None
        valid = (report.get('status') == 'observed'
            and type(report.get('trigger_id')) is str and bool(report['trigger_id'])
            and type(report.get('mask')) is int and report['mask'] > 0
            and is_authenticated_gpio_tick(raw)
            and raw['component'] == component and raw['reset_epoch'] == epoch
            and raw['local_tick'] == tick and isinstance(measured, dict)
            and measured.get('gpio_probe_native_irq') == 1
            and measured.get('gpio_probe_irq_trigger_mask') == report['mask'])
        if key in self._gpio_irq_trigger_refs:
            # Duplicate identities cannot nominate either trigger.
            self._gpio_irq_trigger_refs[key] = None
        elif valid:
            if len(self._gpio_irq_trigger_refs) >= 8192:
                self._gpio_irq_trigger_refs.clear()
            self._gpio_irq_trigger_refs[key] = {
                'trigger_id': report['trigger_id'],
                'trigger_event_id': report['event_id'],
                'observation_event_id': observation_id}

    def _gpio_irq_source_trigger(self, binding: Binding, sample_event_id: int,
                                 tick: int, phase: str) -> dict | None:
        """Join only one matching RTL sample phase to a proven native rise."""
        from .gpio_consumption import is_authenticated_gpio_tick
        if (binding.source_port != 'irq' or binding.source_bit_offset != 0
                or binding.width != 1 or phase not in ('pre', 'post')):
            return None
        component = binding.source_component
        epoch = getattr(self.sessions[component], 'reset_epoch', 0)
        if type(epoch) is not int:
            return None
        key = (component, epoch, tick, phase)
        ref = self._gpio_irq_trigger_refs.get(key)
        sample = self._event_ref_by_id(sample_event_id)
        raw = (self._event_ref_by_id(ref['observation_event_id'])
               if isinstance(ref, dict) else None)
        if (not isinstance(ref, dict) or not is_authenticated_gpio_tick(raw)
                or not isinstance(sample, dict)
                or sample.get('kind') != 'local_tick_sample'
                or sample.get('component') != component
                or sample.get('local_tick') != tick or sample.get('phase') != phase
                or not isinstance(sample.get('outputs'), dict)
                or sample['outputs'].get('interrupt') != 1
                or raw[phase].get('gpio_probe_native_irq') != 1):
            return None
        return {**deepcopy(ref), 'sample_event_id': sample_event_id}

    def _apply_gpio_receipt_segments(self, record: dict, tick: dict | None) -> None:
        from .gpio_consumption import is_authenticated_gpio_tick
        reference = record.get('actual_receipt_ref')
        command_scope = record.get('command_scope')
        valid_scope = (isinstance(command_scope, dict)
            and set(command_scope) == {'component', 'reset_epoch', 'command_sequence'}
            and command_scope['component'] == record.get('component')
            and type(command_scope['reset_epoch']) is int
            and command_scope['reset_epoch'] >= 0
            and command_scope['reset_epoch'] == record.get('reset_epoch')
            and type(command_scope['command_sequence']) is int
            and command_scope['command_sequence'] > 0)
        valid = (isinstance(tick, dict) and isinstance(reference, dict)
            and is_authenticated_gpio_tick(tick)
            and valid_scope
            and reference == {'command_scope': tick.get('command_scope'),
                              'local_tick': tick.get('local_tick')}
            and record.get('command_scope') == tick.get('command_scope')
            and record.get('component') == tick.get('component')
            and record.get('reset_epoch') == tick.get('reset_epoch')
            and record.get('local_tick') == tick.get('local_tick')
            and type(record.get('actual_input_value')) is int
            and all(isinstance(tick.get(phase), dict)
                    and tick[phase].get('gpio_in') == record['actual_input_value']
                    for phase in ('pre', 'post'))
            and isinstance(record.get('segments'), list))
        if not valid:
            self._reject_gpio_input_receipt(record)
            return
        for segment in record['segments']:
            if not isinstance(segment, dict) or set(segment) != {'bit_lo', 'width', 'value', 'origin'}:
                self._reject_gpio_input_receipt(record)
                return
        used = 0
        for segment in record['segments']:
            lo, width, value = (segment[name] for name in ('bit_lo', 'width', 'value'))
            if (type(lo) is not int or type(width) is not int or type(value) is not int
                    or lo < 0 or width < 1 or lo + width > 32
                    or not 0 <= value < 1 << width or not isinstance(segment['origin'], dict)):
                self._reject_gpio_input_receipt(record)
                return
            mask = ((1 << width) - 1) << lo
            if used & mask or (record['actual_input_value'] >> lo) & ((1 << width) - 1) != value:
                self._reject_gpio_input_receipt(record)
                return
            used |= mask
        for segment in record['segments']:
            fragment = {**record, **deepcopy(segment), 'port': 'gpio_in',
                'kind': 'gpio_input_applied', 'actual_receipt_event_id': tick['event_id'],
                'event_id': len(self._events) + 1, 'producer_event_id': record['event_id']}
            self._events.append({**fragment, 'kind': 'gpio_input_segment_applied'})
            self._append_gpio_consumption(fragment)

    def _reject_gpio_input_receipt(self, record: dict) -> None:
        rejected = {key: record.get(key) for key in
                    ('event_id', 'component', 'reset_epoch', 'local_tick')}
        rejected.update(kind='gpio_input_applied')
        self._append_gpio_consumption(rejected)

    def _append_retirement_deliveries(self, reports, producer: dict) -> None:
        for report in reports:
            logged = {**report, 'event_id': len(self._events) + 1,
                'producer_event_id': producer['event_id'],
                'component': report.get('component') or producer['component']}
            self._events.append(logged)
            self._append_gpio_consumption(logged)

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
        if command_sequence <= self._retired_step_floor.get(epoch, 0):
            raise ValueError("retired_command: STEP receipt was acknowledged and retired")
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
        if (self._replay_wall_cut_step_armed
                and self._replay_wall_cut_step_timeout_us is not None):
            self._active_step_timeout_us = self._replay_wall_cut_step_timeout_us
            deadline = (time.monotonic()
                        + self._active_step_timeout_us / 1_000_000)
        else:
            deadline = (self._wall_started_at + budget.max_wall_time_ms / 1000
                        if budget is not None and self._wall_started_at is not None
                        and self._replay_wall_cut is None else None)
            self._active_step_timeout_us = (
                max(0, int((deadline - time.monotonic()) * 1_000_000))
                if deadline is not None else None)
        self._active_step_deadline = deadline
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
                    marker = {
                        "event_id": len(self._events) + 1,
                        "kind": "budget_exhausted",
                        "limit": "max_wall_time_ms",
                        "phase": "inflight_step",
                        "effect_may_have_occurred": True,
                        "local_ticks": dict(self.local_ticks),
                        "prefix_event_count": start,
                        "prefix_local_ticks": ticks_before_step,
                    }
                    if self._active_step_timeout_us is not None:
                        marker["step_timeout_us"] = self._active_step_timeout_us
                    self._events.append_unchecked(marker)
            raise
        finally:
            self._step_in_flight = False
            self._active_step_deadline = None
            self._active_step_timeout_us = None
            self._replay_wall_cut_step_armed = False
        receipt = StepReceipt(execution_id, command_sequence, epoch, component,
                              deepcopy(payload), deepcopy(outputs),
                              deepcopy(tuple(self._events[start:])),
                              self.local_ticks[component])
        self._step_commands[identity] = (component, payload, receipt)
        return deepcopy(receipt)

    def retire_step_receipts_through(self, epoch: int, command_sequence: int) -> None:
        """Release acknowledged online STEP payloads without permitting reexecution."""
        if (type(epoch) is not int or epoch < 0
                or type(command_sequence) is not int or command_sequence < 0
                or epoch > self.command_epoch or self._step_in_flight):
            raise ValueError("invalid STEP receipt retirement boundary")
        if epoch == self.command_epoch and command_sequence >= self._next_command_sequence:
            raise ValueError("cannot retire an unissued STEP command")
        previous = self._retired_step_floor.get(epoch, 0)
        if command_sequence < previous:
            raise ValueError("STEP receipt retirement cannot move backwards")
        for identity in tuple(self._step_commands):
            if identity[0] == epoch and previous < identity[1] <= command_sequence:
                if self._step_commands[identity][2] is None:
                    raise ValueError("cannot retire an uncertain STEP command")
                del self._step_commands[identity]
        self._retired_step_floor[epoch] = command_sequence

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
            ledgers = (getattr(getattr(session, "service", None), "ledger", None),
                       getattr(session, "mmio_ledger", None))
            for ledger in ledgers:
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
        replay_cut = (self._replay_wall_cut is not None
                      and self._replay_wall_cut[1] == "inflight_finalize")
        if (replay_cut
                and self._replay_wall_cut_finalize_timeout_us is not None):
            finalize_timeout_us = self._replay_wall_cut_finalize_timeout_us
            deadline = time.monotonic() + finalize_timeout_us / 1_000_000
        else:
            deadline = (self._wall_started_at + budget.max_wall_time_ms / 1000
                        if budget is not None and self._wall_started_at is not None
                        and self._replay_wall_cut is None else None)
            finalize_timeout_us = (
                max(0, int((deadline - time.monotonic()) * 1_000_000))
                if deadline is not None else None)
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
                self._events.append_unchecked({
                    "event_id": len(self._events) + 1,
                    "kind": "harness_failure",
                    "phase": "finalize",
                    "error_type": "ScenarioFinalStateGrowthViolation",
                    "status": "environment_error",
                })
        self._status = "finalized"
        wall_expired = (deadline is not None and time.monotonic() >= deadline)
        already_has_wall_cut = any(
            event.get("kind") == "budget_exhausted"
            and event.get("limit") == "max_wall_time_ms"
            for event in self._events)
        if wall_expired and not already_has_wall_cut:
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
            if finalize_timeout_us is not None:
                marker["finalize_timeout_us"] = finalize_timeout_us
            if prior_failure_status is not None:
                marker["status_before_finalize"] = prior_failure_status
            self._events.append_unchecked(marker)
        elif cleanup_errors and self.failure_status is None:
            self.failure_status = "environment_error"
            self._events.append_unchecked({
                "event_id": len(self._events) + 1,
                "kind": "harness_failure", "phase": "finalize",
                "status": "environment_error", "cleanup_errors": cleanup_errors,
            })
