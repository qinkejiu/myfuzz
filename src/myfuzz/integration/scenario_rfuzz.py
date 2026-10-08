"""RFuzz shared-buffer adapter for complete, persistent scenario testcases.

One RFuzz test (possibly several fixed records) is decoded before any RTL is
started. Its records are mutation decisions, not DUT cycles. Existing RFuzz
wire framing remains unchanged; this adapter is opt-in for scenario mode.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Callable, Protocol
from collections import Counter, OrderedDict
from collections.abc import Iterable, Mapping
from copy import deepcopy

from myfuzz.scenario.chain_certificates import ChainCertificates
from myfuzz.scenario.closed_loop_feedback import (
    CERTIFICATE_SCHEMA_VERSION as CERTIFICATE_PRODUCER_SCHEMA_VERSION,
    CLOSED_LOOP,
    DEFAULT_GAINS,
    FEEDBACK_SCHEMA_VERSION,
    PARTIAL_PROPAGATION,
    STAGE_REACHED,
    ClosedLoopFeedback,
    EnergyGains,
    edge_feature,
    energy_weights,
    failure_feature,
    hit_feature,
    producer_identity,
    transition_feature,
)
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.feedback import CoverageTarget, observed_targets
from myfuzz.scenario.event_journal import canonical_json_chunks
from myfuzz.scenario.genome import GenomeCodec, ScenarioGenome
from myfuzz.scenario.interaction_feedback import InteractionFeedback
from myfuzz.scenario.online_case_decoder import (OnlineCaseDecoder,
                                                 OnlineSourceActionRefusal,
                                                 PathSwitchRequest)
from myfuzz.scenario.rejection_codes import (RejectionError, description_of,
                                             rejection_of)
from myfuzz.scenario.session_runtime import OnlineCase, OnlineInstruction, ScenarioSession
from myfuzz.scenario.replay import ScenarioTrace, record_scenario
from myfuzz.scenario.rfuzz_decoder import GenomeRecordDecoder, RECORD_BYTES
from myfuzz.scenario.runner import ScenarioBudgetExhausted, ScenarioRunner
from myfuzz.scenario.source_actions import (SourceAction, SourceActionError,
                                            SourceActionPrerequisiteError)

from .rfuzz_shmem import OwnedSegment
from .rfuzz_wire import InputBatch, encode_coverage_buffer, parse_input_buffer


class ScenarioRecordingSession(Protocol):
    """Keep RTL alive and return a cumulative event prefix and local tick counts."""

    def record(self, genome: ScenarioGenome) -> ScenarioTrace: ...


class _InstructionEvidence:
    """Bounded fetch and transaction witness for one admitted CPU fragment."""

    def __init__(self, source: OnlineInstruction) -> None:
        self.source = source
        self.seen = 0
        self.fetched_at: int | None = None
        self.downstream = False
        self.downstream_event_id: int | None = None
        self.reported = False
        self.superseded = False
        self.expected_mmio = self._mmio_access(source.data)

    @staticmethod
    def _mmio_access(data: bytes) -> tuple[int, bool, int | None] | None:
        words = [int.from_bytes(data[pos:pos + 4], "little")
                 for pos in range(0, len(data), 4)]
        access = words[-1]
        opcode = access & 0x7f
        if opcode not in (0x03, 0x23) or ((access >> 12) & 7) != 2:
            return None
        base = (access >> 15) & 31
        value = None
        if opcode == 0x23:
            data_register = (access >> 20) & 31
            # Only a complete LUI + ADDI setup proves the value later sent
            # by this SW. Other register state belongs to prior CPU execution.
            if len(words) != 4 or data_register == base:
                return None
            lui, addi = words[:2]
            if (lui & 0x7f != 0x37 or (lui >> 7) & 31 != data_register
                    or addi & 0x707f != 0x13
                    or (addi >> 7) & 31 != data_register
                    or (addi >> 15) & 31 != data_register):
                return None
            low = (addi >> 20) & 0xfff
            if low & 0x800:
                low -= 0x1000
            value = ((lui & 0xfffff000) + low) & 0xffffffff
        for word in reversed(words[:-1]):
            if word & 0x7f == 0x37 and (word >> 7) & 31 == base:
                immediate = ((access >> 20) & 0xfff) if opcode == 0x03 else (
                    ((access >> 25) << 5) | ((access >> 7) & 31))
                if immediate & 0x800:
                    immediate -= 0x1000
                return (((word & 0xfffff000) + immediate) & 0xffffffff,
                        opcode == 0x23, value)
        return None

    def ingest(self, events: tuple[dict, ...]) -> tuple[bool, bool]:
        for event in events:
            event_id = event.get("event_id")
            if type(event_id) is not int:
                continue
            if (event.get("kind") == "memory_read"
                    and event.get("component") == self.source.component
                    and isinstance(event.get("transaction"), dict)
                    and event["transaction"].get("channel_id") == "instr"):
                address = event.get("address")
                writers = event.get("writer_event_ids")
                data_hex = event.get("data_hex")
                if (type(address) is int and isinstance(writers, (list, tuple))
                        and isinstance(data_hex, str)):
                    try:
                        actual = bytes.fromhex(data_hex)
                    except ValueError:
                        actual = b""
                    if len(actual) == len(writers):
                        for lane, writer in enumerate(writers):
                            offset = address + lane - self.source.address
                            if (0 <= offset < len(self.source.data)
                                    and writer == self.source.action_id
                                    and actual[lane] == self.source.data[offset]):
                                self.seen |= 1 << offset
                        if (self.fetched_at is None
                                and self.seen == (1 << len(self.source.data)) - 1):
                            self.fetched_at = event_id
            if (self.fetched_at is not None and self.expected_mmio is not None
                    and event_id > self.fetched_at
                    and event.get("kind") == "mmio_acceptance"
                    and event.get("component") == self.source.component
                    and (event.get("address"), event.get("write"),
                         event.get("write_value") if self.expected_mmio[1] else None)
                    == self.expected_mmio):
                self.downstream = True
                self.downstream_event_id = event_id
        return self.fetched_at is not None, self.downstream


class _GpioPinIrqEvidence:
    """Observed pin sample, synchronized edge, and real GPIO IRQ start.

    This is a pilot-specific temporal witness, not proof of RTL internal
    causality. It requires the mutated pin's synchronized bit to change in
    the same local step that raises IRQ, then matches that step to the router's
    IRQ source event. Cross-case delay is allowed.
    """

    def __init__(self, source) -> None:
        self.source = source
        self.injection_event_id: int | None = None
        self.sampled_event_id: int | None = None
        self.irq_tick: int | None = None
        self.start_event_id: int | None = None
        self.reported = False

    def ingest(self, event: dict, previous: dict | None) -> None:
        event_id = event.get("event_id")
        if type(event_id) is not int:
            return
        if event.get("kind") == "source_injection":
            if event.get("action_id") == self.source.action_id:
                self.injection_event_id = event_id
            return
        if self.injection_event_id is None or event_id <= self.injection_event_id:
            return
        if (event.get("kind") is None
                and event.get("component") == self.source.component
                and isinstance(event.get("inputs"), dict)
                and isinstance(event.get("outputs"), dict)):
            pin = self.source.bit_offset
            mask = 1 << pin
            value = (self.source.value & 1) << pin
            inputs, outputs = event["inputs"], event["outputs"]
            if type(inputs.get(self.source.port)) is not int or (
                    inputs[self.source.port] & mask) != value:
                return
            if self.sampled_event_id is None:
                self.sampled_event_id = event_id
            before = previous.get("outputs", {}) if previous is not None else {}
            if (self.irq_tick is None and self.sampled_event_id is not None
                    and type(before.get("gpio_in_sync")) is int
                    and type(outputs.get("gpio_in_sync")) is int
                    and before["gpio_in_sync"] & mask != value
                    and outputs["gpio_in_sync"] & mask == value
                    and before.get("irq") == 0 and outputs.get("irq") == 1
                    and type(event.get("local_tick")) is int):
                self.irq_tick = event["local_tick"]
        elif (self.irq_tick is not None and self.start_event_id is None
              and event.get("kind") == "source_start"
              and event.get("source") in ([self.source.component, "irq"],
                                            (self.source.component, "irq"))
              and event.get("source_tick") == self.irq_tick):
            self.start_event_id = event_id


@dataclass(frozen=True)
class ScenarioRfuzzReceipt:
    run_id: str
    buffer_id: int
    slot: int
    raw_sha256: str
    genome_sha256: str | None
    semantic_sha256: str | None
    status: str
    total_local_ticks: int
    coverage_hex: str
    violations: tuple[str, ...]
    error: str | None
    trace: ScenarioTrace | None
    manifest_sha256: str | None = None
    local_ticks: dict[str, int] | None = None
    path_id: str | None = None
    applied_sources: tuple[str, ...] = ()
    applied_template: int | None = None
    applied_path: int | None = None
    applied_hint_sequence: int | None = None
    effective_genome_sha256: str | None = None
    wall_cut: dict | None = None
    # Raw selection is applied_sources; this is trace-proven consumption.
    applied_source_ids: tuple[str, ...] = ()
    interaction_feedback: dict | None = None
    online_case: dict | None = None
    online_weights: dict[str, int] | None = None
    online_plan_hex: str | None = None
    #: Structured ``candidate_rejection.v1`` refusal of the online candidate.
    #: None for an admitted case, for an unclassified refusal without a code,
    #: and for any post-submit uncertainty; uncertainty is never a rejection.
    rejection: dict | None = None
    #: Versioned ``online_source_action.v1`` record of the gate decision for
    #: this candidate: the declared source action, its prerequisite evaluation
    #: document and, for a refusal, the stable reason and detail.  None when no
    #: source-action gate is configured (the legacy online behaviour).
    source_action: dict | None = None
    #: Bounded ``online_closed_loop_feedback.v1`` record of the closed-loop
    #: certificate energy this case produced and the switch state.  Always set
    #: on the online path, including when the switch is disabled, so every
    #: receipt states which search behaviour produced it.
    closed_loop_feedback: dict | None = None


#: Receipt vocabulary of one online source-action gate decision.
ONLINE_SOURCE_ACTION_RECEIPT_VERSION = "online_source_action.v1"

#: Receipt vocabulary of one online closed-loop energy observation.
CLOSED_LOOP_FEEDBACK_VERSION = "online_closed_loop_feedback.v1"
#: Run-level vocabulary of the same switch and its bounded retained state.
CLOSED_LOOP_STATE_VERSION = "online_closed_loop_state.v1"
#: Opt-in environment bridge.  The constructor argument always wins; this lets
#: a serial A/B gate change exactly one variable without touching the caller's
#: command line.  Only consulted on the online decoder path.
CLOSED_LOOP_ENERGY_ENV = "MYFUZZ_CLOSED_LOOP_ENERGY"
#: Opt-in live path-switch operator.  Off by default so the shipped decode
#: distribution is byte-identical; when on, each admitted candidate may be
#: retargeted inside the declared switch pool from one raw byte.
PATH_SWITCH_ENV = "MYFUZZ_PATH_SWITCH"
#: Run-level state of the live path switch, reported even when it is off so a
#: run always states which search behaviour produced it.
PATH_SWITCH_STATE_VERSION = "online_path_switch_state.v1"
#: One refused switch attempt: the declared target it asked for and the shipped
#: rejection code that refused it.  A refusal consumes nothing.
PATH_SWITCH_REFUSAL_VERSION = "online_path_switch_refusal.v1"
#: Domain separator of the raw-derived declared-target draw.  It is disjoint
#: from the shipped decode domains, so an operator choice can never alias the
#: drawn path of the unswitched decode, and a replay draws the same target.
_PATH_SWITCH_DOMAIN = b"myfuzz.online.path_switch.v1\0"
_ENV_TRUE = ("1", "true", "yes", "on")
_ENV_FALSE = ("0", "false", "no", "off", "")
#: Bounded retention of refusal evidence in the run-level document.
_CLOSED_LOOP_REFUSAL_LIMIT = 32
#: Bounded detail per document; counts stay complete, and a truncated list is
#: always flagged so an auditor recomputes from the journal.
_CLOSED_LOOP_DETAIL_LIMIT = 64
_CLOSED_LOOP_HIT_KIND_COUNT = {CLOSED_LOOP: "closed_loop_count",
                              PARTIAL_PROPAGATION: "partial_propagation_count",
                              STAGE_REACHED: "stage_reached_count"}
_CLOSED_LOOP_HIT_KIND_GAIN = {CLOSED_LOOP: "closed_loop",
                             PARTIAL_PROPAGATION: "partial_propagation",
                             STAGE_REACHED: "stage_reached"}


def _zero_closed_loop_counts() -> dict:
    return {"certificate_count": 0, "closed_loop_count": 0,
            "partial_propagation_count": 0, "stage_reached_count": 0}


def _path_switch_switch(requested: bool | None, *, online: bool
                        ) -> tuple[bool, str]:
    """Resolve the opt-in live path-switch operator and name its source.

    Mirrors :func:`_closed_loop_switch`: ``None`` defers to
    :data:`PATH_SWITCH_ENV`, the environment is only consulted on the online
    decoder path, and any other value is refused instead of guessed.
    """
    if requested is not None:
        if type(requested) is not bool:
            raise ValueError("path_switch must be boolean or None")
        return requested, "constructor"
    if not online:
        return False, "default"
    value = os.environ.get(PATH_SWITCH_ENV)
    if value is None:
        return False, "default"
    text = value.strip().lower()
    if text in _ENV_TRUE:
        return True, "environment"
    if text in _ENV_FALSE:
        return False, "environment"
    raise ValueError(
        f"{PATH_SWITCH_ENV} must be one of "
        f"{', '.join(sorted(_ENV_TRUE + _ENV_FALSE))}, got {value!r}")


def _closed_loop_switch(requested: bool | None, *, online: bool
                        ) -> tuple[bool, str]:
    """Resolve the opt-in switch and name the source of the decision.

    ``None`` defers to :data:`CLOSED_LOOP_ENERGY_ENV`; the environment is only
    consulted when the caller actually runs the online decoder path, so an
    unrelated run can never change behaviour.  Any other environment value is
    refused instead of guessed.
    """
    if requested is not None:
        if type(requested) is not bool:
            raise ValueError("closed_loop_energy must be boolean or None")
        return requested, "constructor"
    if not online:
        return False, "default"
    value = os.environ.get(CLOSED_LOOP_ENERGY_ENV)
    if value is None:
        return False, "default"
    text = value.strip().lower()
    if text in _ENV_TRUE:
        return True, "environment"
    if text in _ENV_FALSE:
        return False, "environment"
    raise ValueError(
        f"{CLOSED_LOOP_ENERGY_ENV} must be one of "
        f"{', '.join(sorted(_ENV_TRUE + _ENV_FALSE))}, got {value!r}")


def _closed_loop_attribution_map(attribution):
    """Validate and freeze caller attribution of non-certificate evidence."""
    if attribution is None:
        return None
    if not isinstance(attribution, Mapping):
        raise ValueError("closed_loop_attribution must be a mapping of features "
                         "to weight keys")
    frozen = {}
    for feature, keys in attribution.items():
        if not isinstance(feature, str) or not feature:
            raise ValueError("closed_loop_attribution needs nonempty feature keys")
        if isinstance(keys, (str, bytes)) or not isinstance(keys, Iterable):
            raise ValueError(f"closed_loop_attribution for {feature!r} must be an "
                             "iterable of weight keys")
        materialised = tuple(keys)
        if not materialised or any(not isinstance(key, str) or not key
                                   for key in materialised):
            raise ValueError(f"closed_loop_attribution for {feature!r} must name "
                             "nonempty weight keys")
        frozen[feature] = materialised
    return frozen


def _resolve_closed_loop_producer(factory, *, max_pending: int,
                                  max_event_gap: int):
    """Instantiate the injected producer or the frozen default one."""
    if factory is None:
        return (ChainCertificates(max_pending=max_pending,
                                  max_event_gap=max_event_gap), "default")
    if isinstance(factory, type) or not hasattr(factory, "ingest"):
        try:
            producer = factory(max_pending=max_pending,
                               max_event_gap=max_event_gap)
        except TypeError as exc:
            raise ValueError(
                "closed-loop certificate producer factory rejected the frozen "
                f"keyword arguments max_pending/max_event_gap: {exc}") from exc
    else:
        producer = factory
    if not callable(getattr(producer, "ingest", None)):
        raise ValueError("closed-loop certificate producer must implement "
                         "ingest(events)")
    return producer, "injected"



def _effective_genome_sha256(genome: ScenarioGenome) -> str:
    """Hash executable scenario content, excluding RFuzz identity labels."""
    document = json.loads(GenomeCodec.encode(genome))
    document.pop("testcase_id")
    document.pop("path_id")
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _trace_protocol_environment_error(trace: ScenarioTrace) -> bool:
    """Classify only a typed harness failure, never an arbitrary DUT symptom."""
    return trace.status == "uncertain_effect" and any(
        event.get("kind") == "harness_failure"
        and event.get("error_type") == "ProtocolEnvironmentError"
        for event in trace.events)


def _trace_wall_cut(trace: ScenarioTrace) -> dict | None:
    """Retain the real wall-budget cut for deterministic corpus replay."""
    cut = next((dict(event) for event in trace.events
                if event.get("kind") == "budget_exhausted"
                and event.get("limit") == "max_wall_time_ms"), None)
    if cut is None:
        return None
    prefix_count = cut.get("prefix_event_count", len(trace.events) - 1)
    if type(prefix_count) is not int or not 0 <= prefix_count < len(trace.events):
        raise ValueError("invalid wall-cut event prefix")
    encoded = json.dumps(trace.events[:prefix_count], sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    cut["semantic_prefix_sha256"] = hashlib.sha256(encoded).hexdigest()
    return cut


class ScenarioRfuzzExecutor:
    def __init__(self, *, run_id: str, decoder: GenomeRecordDecoder | None = None,
                 factory: Callable[[], ScenarioRunner],
                 targets: tuple[CoverageTarget, ...],
                 checker: Callable[[ScenarioTrace], tuple[str, ...]] | None = None,
                 evidence_dir: Path | None = None,
                 replay_only: bool = False,
                 allow_legacy_search: bool = False,
                 session: ScenarioRecordingSession | ScenarioSession | None = None,
                 online_decoder: OnlineCaseDecoder | None = None,
                 feedback_interval: int = 16,
                 checker_config: dict | None = None,
                 checker_identity_target: Callable | None = None,
                 source_action_gate=None,
                 case_witness_recorder=None,
                 path_switch: bool | None = None,
                 closed_loop_energy: bool | None = None,
                 closed_loop_gains: EnergyGains | None = None,
                 closed_loop_attribution: Mapping[str, Iterable[str]] | None = None,
                 closed_loop_max_pending: int = 128,
                 closed_loop_max_event_gap: int = 4096,
                 closed_loop_producer=None) -> None:
        if type(feedback_interval) is not int or feedback_interval < 1:
            raise ValueError("feedback_interval must be a positive integer")
        self.feedback_interval = feedback_interval
        # The live path-switch operator is opt-in and off by default, so the
        # shipped decode distribution stays byte-identical.
        self.path_switch, self.path_switch_source = (
            _path_switch_switch(path_switch, online=online_decoder is not None))
        if self.path_switch and online_decoder is None:
            raise ValueError("live path switch requires the online decoder path")
        self._path_switch_records: Counter[str] = Counter()
        # The operator's own counters: attempts are granted or refused, granted
        # switches may or may not change the candidate identity, and every
        # refusal keeps the shipped rejection code that refused it.
        self._path_switch_attempts = 0
        self._path_switch_granted = 0
        self._path_switch_changed = 0
        self._path_switch_refusals: Counter[str] = Counter()
        self._path_switch_codes: Counter[str] = Counter()
        # Closed-loop certificate energy is opt-in and off by default; with the
        # switch off no journal is consumed and no feedback state exists.
        self.closed_loop_energy, self.closed_loop_energy_source = (
            _closed_loop_switch(closed_loop_energy,
                                online=online_decoder is not None))
        if self.closed_loop_energy and online_decoder is None:
            raise ValueError("closed-loop certificate energy requires the online "
                             "decoder path")
        if closed_loop_gains is not None and not isinstance(closed_loop_gains,
                                                            EnergyGains):
            raise ValueError("closed_loop_gains must be an EnergyGains instance")
        if (type(closed_loop_max_pending) is not int or closed_loop_max_pending < 1
                or type(closed_loop_max_event_gap) is not int
                or closed_loop_max_event_gap < 1):
            raise ValueError("closed-loop certificate bounds must be positive "
                             "integers")
        self._closed_loop_gains = (DEFAULT_GAINS if closed_loop_gains is None
                                   else closed_loop_gains)
        self._closed_loop_attribution = _closed_loop_attribution_map(
            closed_loop_attribution)
        self._closed_loop_max_pending = closed_loop_max_pending
        self._closed_loop_max_event_gap = closed_loop_max_event_gap
        self._closed_loop_producer = None
        self._closed_loop_producer_kind: str | None = None
        self._closed_loop_producer_identity: dict | None = None
        # Bounded scoring state: one signed delta per legal source key, plus at
        # most ``max_pending`` retained certificate identities.
        self._closed_loop_energy_delta: Counter[str] = Counter()
        self._closed_loop_credit_guard: OrderedDict[str, str] = OrderedDict()
        self._closed_loop_counts: Counter[str] = Counter()
        self._closed_loop_refusals: list[dict] = []
        self._closed_loop_refusal_count = 0
        self._closed_loop_duplicate_count = 0
        self._closed_loop_event_cursor = 0
        self._closed_loop_desync: str | None = None
        self._closed_loop_initial: dict | None = None
        self._closed_loop_terminal: dict | None = None
        self._closed_loop_transitions: dict[str, int] = {}
        # Bounded feature identity set: ``energy_weights`` scores a feature once.
        self._closed_loop_scored_features: set[str] = set()
        self.online_decisions: list[dict] = []
        self._online_decisions_by_slot: dict[tuple[int, int], dict] = {}
        self._online_finish_attempted = False
        self._online_terminal_evidence_saved = False
        self._online_feedback_event_end = 0
        # Only a source's witnessed transaction may earn interaction novelty.
        # A port injection alone does not prove that a later RTL output was
        # caused by that injection.
        self._online_interval_witnesses: dict[tuple[int, int, str], set[int]] = {}
        self._online_final_trace: ScenarioTrace | None = None
        self._online_final_plan_hex: str | None = None
        if not run_id:
            raise ValueError("run_id is required")
        if not targets or len(targets) > 4096:
            raise ValueError("RFuzz requires 1..4096 coverage targets")
        if len({target.target_id for target in targets}) != len(targets):
            raise ValueError("coverage target IDs must be unique")
        if (decoder is None) == (online_decoder is None):
            raise ValueError("choose exactly one genome decoder or online decoder")
        if online_decoder is not None and (
                not isinstance(online_decoder, OnlineCaseDecoder)
                or not isinstance(session, ScenarioSession) or replay_only):
            raise ValueError("online RFuzz requires OnlineCaseDecoder and live ScenarioSession")
        if online_decoder is not None:
            if online_decoder.from_document_replay_only:
                raise ValueError("online decoder documents are replay-only")
            if online_decoder.runtime_contract is not None and not online_decoder.trusted_for_search:
                raise ValueError("online contract search requires trusted source bindings")
        if not replay_only and decoder is not None:
            if decoder.from_document_replay_only:
                raise ValueError("decoder documents are replay-only")
            if not decoder.trusted_for_search and not (
                    allow_legacy_search and decoder.source_bindings is None):
                raise ValueError("search requires trusted source bindings; "
                                 "legacy search needs explicit compatibility")
        if session is not None and decoder is not None:
            if replay_only:
                raise ValueError("continuous session is unavailable in replay-only mode")
            if any(source.kind == "memory_image" for source in decoder.graph.sources.values()):
                raise ValueError("continuous RFuzz cannot mutate preloaded images; use fresh execution")
            images = {tuple(template.genome.initial_images) for template in decoder.templates}
            if len(images) > 1:
                raise ValueError("continuous RFuzz templates must share one immutable preload")
        if online_decoder is not None and online_decoder.max_input_bytes != RECORD_BYTES:
            raise ValueError("online RFuzz currently requires one eight-byte record")
        if online_decoder is not None:
            target_ids = {target.target_id for target in targets}
            for source in online_decoder.sources:
                unknown = set(source.coverage_target_ids) - target_ids
                if unknown:
                    raise ValueError("online source names unknown coverage targets: "
                                     + ", ".join(sorted(unknown)))
        # An opt-in source-action gate binds every online candidate to its
        # declared action before any RTL command.  Without one the online path
        # behaves exactly as before: no action, no query, no receipt field.
        session_gate = getattr(session, "prerequisite_gate", None)
        if (source_action_gate is not None and session_gate is not None
                and session_gate is not source_action_gate):
            raise ValueError(
                "online RFuzz source-action gate must be the session prerequisite gate")
        gate = session_gate if source_action_gate is None else source_action_gate
        if gate is not None:
            if online_decoder is None:
                raise ValueError(
                    "source-action gate requires the online decoder path")
            for name in ("register", "require_case", "observe"):
                if not callable(getattr(gate, name, None)):
                    raise ValueError(
                        f"online RFuzz source-action gate must expose {name}")
        self.source_action_gate = gate
        # The session already feeds admitted receipts into its own gate.
        self._source_action_gate_observes_itself = (
            gate is not None and session_gate is gate)
        self._online_pending_sources: dict[str, tuple[OnlineCase, tuple[int, int, str]]] = {}
        self._online_instruction_evidence: dict[str, _InstructionEvidence] = {}
        self._online_pin_evidence: dict[str, _GpioPinIrqEvidence] = {}
        self._online_last_gpio_step: dict[str, dict] = {}
        self._online_evidence_limit = 256
        self.online_decoder = online_decoder
        self.session = session
        # An opt-in per-case evidence recorder: the executor hands it each
        # admitted case's own event slice, so routing/consumption witnesses are
        # read from the case that really produced them instead of a global
        # stream.  Without one nothing is collected and no report key appears.
        if (case_witness_recorder is not None
                and not callable(getattr(case_witness_recorder, "observe_case",
                                         None))):
            raise ValueError(
                "case_witness_recorder must expose observe_case()")
        self.case_witness_recorder = case_witness_recorder
        self._session_stop_reason: str | None = None
        self._interaction = InteractionFeedback(
            event_lookup=session.runner._event_ref_by_id
            if online_decoder is not None else None,
            starting_event_id=session.runner.event_count
            if online_decoder is not None else 0)
        self._interaction_counts: Counter[str] = Counter()
        self._selection_uses: Counter[tuple[int, int, str]] = Counter()
        self._selection_gains: Counter[tuple[int, int, str]] = Counter()
        self._session_ticks: dict[str, int] = {}
        self._session_event_count = 0
        self.run_id = run_id
        self.decoder = decoder
        self.replay_only = replay_only
        self.factory = factory
        self.targets = targets
        self.checker = checker
        self.checker_config = checker_config
        self.checker_identity_target = checker_identity_target
        self.fresh_manifest_document: dict | None = None
        self.fresh_manifest_sha256: str | None = None
        self.fresh_runtime_path_documents: dict[str, dict] = {}
        runtime_decoder = decoder if decoder is not None else online_decoder
        self.runtime_contract = getattr(runtime_decoder, "runtime_contract", None)
        self.runtime_path_status = ("contract_preflight" if self.runtime_contract is not None
                                    else "legacy_unchecked")
        self._prepared_runtime_paths = None
        self._runtime_declaration_document = None
        self._runtime_source_owners = {}
        if self.runtime_contract is not None:
            from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
            self._prepared_runtime_paths = PreparedRuntimePathContract(
                runtime_decoder.graph, self.runtime_contract, runtime_decoder.runtime_paths)
            self._runtime_declaration_document = self._prepared_runtime_paths.document()
            for direction, path in runtime_decoder.runtime_paths:
                for source_id in path.source_ids:
                    source = runtime_decoder.graph.sources[source_id]
                    if source.kind == "source":
                        self._runtime_source_owners[(direction, source_id)] = (
                            runtime_decoder.ownership.mutation_source(
                                source.component, source.port, source.bit_offset,
                                source.width, direction=direction))
            if session is not None:
                session_document = getattr(session, "runtime_path_document", None)
                session_contract = getattr(session, "runtime_contract", None)
                if (session_document is None or session_contract != self.runtime_contract
                        or session_document.get("graph_sha256") != self.runtime_contract.graph_sha256
                        or session_document.get("contract_sha256") != self.runtime_contract.identity_sha256
                        or set(getattr(session, "runtime_path_ids", ()))
                        != set(self._prepared_runtime_paths.path_ids)):
                    raise ValueError("runtime paths must be configured on the session before begin")
                for path_id in self._prepared_runtime_paths.path_ids:
                    self._validate_runtime_source_owners(path_id, session.runner, runtime_decoder)
        self.evidence_dir = Path(evidence_dir) if evidence_dir is not None else None
        if self.evidence_dir is not None:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.receipts: list[ScenarioRfuzzReceipt] = []
        self.first_receipt_completed_at: float | None = None
        self._completed: dict[tuple[int, int], tuple[str, bytes, ScenarioRfuzzReceipt | None]] = {}
        self._target_hits: set[str] = set()
        self._hint_source_uses = {source_id: 0 for source_id in (
            decoder.graph.sources if decoder is not None else
            (source.source_id for source in online_decoder.sources))}
        self._hint_sequence = 0
        self._published_hints: list[dict] = []
        self._latest_completed_batch: tuple[ScenarioRfuzzReceipt, ...] = ()
        self._max_completed_buffer_id: int | None = None
        # The live transport may contain more slots than its requested test
        # budget. Such slots still need neutral RFuzz replies, but must never
        # advance the persistent RTL session.
        self._online_live_max_tests: int | None = None
        # A live FIFO buffer can carry many slots. Check the wall budget at
        # each slot boundary instead of waiting for the whole buffer reply.
        self._online_live_duration_seconds: float | None = None
        if self.closed_loop_energy:
            self._closed_loop_initialize(closed_loop_producer)

    def _closed_loop_initialize(self, producer_factory) -> None:
        """Create the producer and align it with the session's journal origin.

        ``ChainCertificates`` joins hops by exact identity over one contiguous
        journal that must start at ``event_id`` 1.  An online session may
        already have executed its fixed bootstrap, so the whole recorded prefix
        is ingested here and the first case slice then continues exactly where
        the session began.  A journal that does not start at 1 cannot be
        aligned: it is refused loudly instead of silently shifting every hop
        identity by a constant offset.
        """
        self._closed_loop_producer, self._closed_loop_producer_kind = (
            _resolve_closed_loop_producer(
                producer_factory, max_pending=self._closed_loop_max_pending,
                max_event_gap=self._closed_loop_max_event_gap))
        self._closed_loop_producer_identity = producer_identity()
        self._closed_loop_weight_keys = frozenset(
            source.source_id for source in self.online_decoder.sources)
        prefix = self.session.runner.events_since(0)
        if not prefix:
            return
        first = prefix[0].get("event_id")
        if first != 1:
            raise ValueError(
                "closed-loop certificate energy requires the online session "
                "journal to start at event_id 1, got "
                f"{first!r}")
        self._closed_loop_event_cursor = len(prefix)
        document = self._closed_loop_document(status="ok")
        document["journal"] = {"start": 0, "end": len(prefix)}
        certificates = self._closed_loop_producer.ingest(prefix)
        if certificates:
            self._closed_loop_observe(document, tuple(certificates))
            document["status"] = "initial_prefix"
        self._closed_loop_initial = document

    @property
    def _closed_loop_enabled(self) -> bool:
        """Switch state that also holds for partially constructed test doubles."""
        return bool(getattr(self, "closed_loop_energy", False))

    @staticmethod
    def _closed_loop_signed_totals(counter: Mapping[str, int], *,
                                   positive: bool) -> dict:
        if positive:
            return {key: value for key, value in sorted(counter.items())
                    if value > 0}
        return {key: -value for key, value in sorted(counter.items())
                if value < 0}

    @property
    def counter_count(self) -> int:
        return len(self.targets)

    def _observe_fresh_identity(self, identity: dict) -> None:
        """Freeze the identity already computed by record_scenario, before RTL."""
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        if self.fresh_manifest_sha256 is not None and digest != self.fresh_manifest_sha256:
            if self._prepared_runtime_paths is not None:
                self._session_stop_reason = "runtime_identity_environment_error"
            raise ValueError("fresh RFuzz runner identity changed during run")
        if self.fresh_manifest_document is None:
            self.fresh_manifest_document = json.loads(encoded)
            self.fresh_manifest_sha256 = digest

    def _runtime_preflight(self, path_id: str):
        """Use prepared metadata on the one actual factory-created runner."""
        if self._prepared_runtime_paths is None:
            return None

        def inspect(runner):
            try:
                self._validate_runtime_source_owners(path_id, runner, self.decoder)
                compiled = self._prepared_runtime_paths.bind(runner, path_ids=(path_id,))
                document = compiled.document()
                document["declaration"] = self._runtime_declaration_document
                previous = self.fresh_runtime_path_documents.get(path_id)
                if previous is not None and previous != document:
                    raise ValueError("fresh runtime path topology changed during run")
                self.fresh_runtime_path_documents[path_id] = document
            except Exception:
                self._session_stop_reason = "runtime_path_environment_error"
                raise

        return inspect

    def _validate_runtime_source_owners(self, path_id, runner, decoder) -> None:
        direction, path = self._prepared_runtime_paths.resolve_path_id(path_id)
        for source_id in path.source_ids:
            expected = self._runtime_source_owners.get((direction, source_id))
            if expected is None:
                continue
            source = decoder.graph.sources[source_id]
            actual = runner.ownership.mutation_source(source.component, source.port,
                source.bit_offset, source.width, direction=direction)
            if actual != expected:
                raise ValueError("runtime path source ownership producer mismatch")

    def _install_runtime_replay_identity(self, record: dict | None) -> None:
        """Validate saved declarations before a replay factory is called."""
        if self._prepared_runtime_paths is None:
            if record is not None and record != {"status": "legacy_unchecked",
                                                 "declaration": None, "compiled": {}}:
                raise ValueError("legacy decoder cannot claim runtime path preflight")
            return
        if (not isinstance(record, dict) or set(record) != {"status", "declaration", "compiled"}
                or record["status"] != "contract_preflight"
                or record["declaration"] != self._runtime_declaration_document
                or not isinstance(record["compiled"], dict)):
            raise ValueError("fresh replay runtime path declaration mismatch")
        for path_id, document in record["compiled"].items():
            direction, path = self._prepared_runtime_paths.resolve_path_id(path_id)
            if (not isinstance(document, dict)
                    or document.get("schema_version") != "runtime_path_compilation.v1"
                    or document.get("graph_sha256") != self.runtime_contract.graph_sha256
                    or document.get("contract_sha256") != self.runtime_contract.identity_sha256
                    or document.get("declaration") != self._runtime_declaration_document
                    or document.get("paths") != [{"direction": direction,
                        "path_id": path_id, "target": path.target}]
                    or document.get("topology_sha256") != hashlib.sha256(json.dumps(
                        document.get("topology"), sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False, allow_nan=False).encode()).hexdigest()):
                raise ValueError("fresh replay compiled runtime path identity mismatch")
        self.fresh_runtime_path_documents = json.loads(json.dumps(record["compiled"]))

    def _validate_online_runtime_selection(self, case, selected) -> None:
        if self._prepared_runtime_paths is None:
            return
        direction, path = self.online_decoder.resolve_path_id(case.path_id)
        if (case.direction != direction or selected.source_id not in path.source_ids
                or self.online_decoder.path_target(case.path_id) != selected.path_id):
            self._session_stop_reason = "runtime_path_environment_error"
            raise ValueError("online selected source differs from cached runtime path")
        self._validate_runtime_source_owners(case.path_id, self.session.runner,
                                             self.online_decoder)

    @property
    def applied_source_uses(self) -> dict[str, int]:
        return dict(self._hint_source_uses)

    def note_published_hint(self, hint: dict) -> None:
        """Record a successfully published sideband; publication is not use."""
        self._published_hints.append(dict(hint))

    def _raw_mutation_provenance(self, records: tuple[bytes, ...]):
        """Recover sources exercised by actual submitted records.

        The wire format does not carry the Rust hint sequence. Associate a
        sequence only when the observed selector uniquely identifies one
        published hint; otherwise leave it unknown rather than inventing it.
        """
        template_index = records[0][0] % len(self.decoder.templates)
        template = self.decoder.templates[template_index]
        paths = self.decoder.paths_for(
            template.target_id, direction=template.genome.direction)
        path_index = records[0][1] % len(paths)
        path = paths[path_index]
        source_indices = []
        selected_targets: dict[str, set[int | tuple[str, int, str]]] = {}
        for record in records:
            operation = record[5] % 3
            if operation == 0 or (operation == 2 and record[6] == 0):
                continue
            source_index = record[2] % len(path.source_ids)
            source = self.decoder.graph.sources[path.source_ids[source_index]]
            if operation == 1 or source.kind == "source":
                source_indices.append(source_index)
                choices = self.decoder._choices(template.genome, source)
                if not choices:
                    continue
                bit_selector = record[3] | record[7] << 8
                bit_index, action_ids = choices[bit_selector % len(choices)]
                absolute_bit = source.bit_offset + bit_index
                target = (absolute_bit // 8 if source.kind == "memory_image" else
                          (action_ids[record[4] % len(action_ids)],
                           absolute_bit,
                           "value" if operation == 1 else "delay")
                          if action_ids else ("", absolute_bit, "value"))
                selected_targets.setdefault(source.source_id, set()).add(target)
        sources = tuple(dict.fromkeys(path.source_ids[index]
                                      for index in source_indices))
        matching = [hint["sequence"] for hint in self._published_hints
                    if hint.get("template") == template_index
                    and hint.get("path") == path_index
                    and hint.get("source") in source_indices]
        sequence = matching[0] if len(matching) == 1 else None
        return sources, template_index, path_index, sequence, selected_targets

    def _consumed_source_ids(self, selected_targets: dict,
                             template_index: int, genome: ScenarioGenome,
                             trace: ScenarioTrace) -> tuple[str, ...]:
        """Count only mutated source bytes/ports observed by an accepted local step.

        A source injection alone is insufficient: a later successful step must
        record the same input segment. An image preload alone is insufficient:
        an accepted memory read must return the selected initial-image byte.
        Address aliases without a directly matching read are conservatively
        excluded. Neither condition proves a downstream causal effect.
        """
        template = self.decoder.templates[template_index].genome
        template_images = {(item.component, item.image_id): item
                           for item in template.initial_images}
        template_actions = {item.action_id: item for item in template.actions}
        final_actions = {item.action_id: item for item in genome.actions}
        used = []
        events = trace.events
        for source_id, targets in selected_targets.items():
            source = self.decoder.graph.sources[source_id]
            if source.kind == "memory_image":
                image = next((item for item in genome.initial_images
                              if item.component == source.component
                              and item.image_id == source.port), None)
                original = template_images.get((source.component, source.port))
                if image is None or original is None:
                    continue
                changed_bytes = {byte for byte in targets if type(byte) is int
                                 and byte < len(image.data)
                                 and image.data[byte] != original.data[byte]}
                if not changed_bytes:
                    continue
                preload = next((event for event in events
                                if event.get("kind") == "initial_image"
                                and event.get("component") == source.component
                                and event.get("image_id") == source.port
                                and event.get("address") == image.address
                                and event.get("data_hex") == image.data_hex), None)
                if preload is None:
                    continue
                for event in events:
                    if (event.get("kind") != "memory_read"
                            or event.get("component") != source.component
                            or event.get("event_id", 0) <= preload.get("event_id", 0)):
                        continue
                    transaction = event.get("transaction")
                    # Ibex exposes an instruction channel; CVA6's local
                    # harness has one unified instruction/data port.
                    if (source.component == "cpu"
                            and (not isinstance(transaction, dict)
                                 or transaction.get("channel_id")
                                 not in ("instr", "unified"))):
                        continue
                    address = event.get("address")
                    data_hex = event.get("data_hex")
                    writers = event.get("writer_event_ids")
                    if (type(address) is not int or not isinstance(data_hex, str)
                            or not isinstance(writers, (tuple, list))):
                        continue
                    try:
                        data = bytes.fromhex(data_hex)
                    except ValueError:
                        continue
                    if len(data) != len(writers):
                        continue
                    if any(address <= image.address + byte < address + len(data)
                           and 0 <= byte < len(image.data)
                           and data[image.address + byte - address] == image.data[byte]
                           and writers[image.address + byte - address] == "initial-image"
                           for byte in changed_bytes):
                        used.append(source_id)
                        break
                continue
            changed_actions = set()
            for action_id, absolute_bit, kind in targets:
                original = template_actions.get(action_id)
                actual = final_actions.get(action_id)
                if original is None or actual is None:
                    continue
                if kind == "delay":
                    changed = actual.delay_ticks != original.delay_ticks
                else:
                    local_bit = absolute_bit - actual.bit_offset
                    changed = (local_bit >= 0
                               and bool((actual.value ^ original.value)
                                        & (1 << local_bit)))
                if changed:
                    changed_actions.add(action_id)
            if not changed_actions:
                continue
            mask = ((1 << source.width) - 1) << source.bit_offset
            owner_ref = self.decoder.ownership.mutation_source(
                source.component, source.port, source.bit_offset,
                source.width, direction=genome.direction)
            for index, event in enumerate(events):
                event_action = event.get("action_id")
                action_matches = event_action in changed_actions
                if self.session is not None:
                    action_matches = isinstance(event_action, str) and any(
                        event_action.startswith(f"{genome.testcase_id}:{action_id}:")
                        and event_action[len(f"{genome.testcase_id}:{action_id}:"):].isascii()
                        and event_action[len(f"{genome.testcase_id}:{action_id}:"):].isdecimal()
                        for action_id in changed_actions)
                if (event.get("kind") != "source_injection"
                        or event.get("component") != source.component
                        or event.get("port") != source.port
                        or event.get("source_ref") != owner_ref
                        or event.get("direction") != genome.direction
                        or not action_matches):
                    continue
                offset, width, value = (event.get("bit_offset"),
                                        event.get("width"), event.get("value"))
                if (type(offset) is not int or type(width) is not int or width < 1
                        or type(value) is not int
                        or not (mask & (((1 << width) - 1) << offset))):
                    continue
                observed_mask = mask & (((1 << width) - 1) << offset)
                expected = (value << offset) & observed_mask
                for later in events[index + 1:]:
                    if (later.get("kind") == "source_injection"
                            and later.get("component") == source.component
                            and later.get("port") == source.port
                            and type(later.get("bit_offset")) is int
                            and type(later.get("width")) is int
                            and later["width"] > 0
                            and observed_mask & (((1 << later["width"]) - 1)
                                        << later["bit_offset"])):
                        break
                    inputs = later.get("inputs")
                    if (later.get("component") == source.component
                            and isinstance(inputs, dict)
                            and type(inputs.get(source.port)) is int
                            and inputs[source.port] & observed_mask == expected):
                        used.append(source_id)
                        break
                if source_id in used:
                    break
        return tuple(used)

    def _feedback_hint_fields(self) -> dict:
        """The completed batch identity is shared by every mutation policy."""
        return {
            "feedback_scope": "cumulative_run_feedback",
            "max_completed_buffer_id": self._max_completed_buffer_id,
            "latest_completed_batch": [
                {"run_id": receipt.run_id,
                 "buffer_id": receipt.buffer_id, "slot": receipt.slot,
                 "raw_sha256": receipt.raw_sha256,
                 "genome_sha256": receipt.genome_sha256,
                 "path_id": receipt.path_id,
                 "status": receipt.status}
                for receipt in self._latest_completed_batch],
        }

    def mutation_hint(self) -> dict:
        """Jointly score coverage gaps, observed interaction gain, and exploration."""
        if self.replay_only:
            raise ValueError("replay-only executor cannot provide mutation hints")
        if self.online_decoder is not None:
            weights = self._online_weights()
            available = ((index, source) for index, source in
                         enumerate(self.online_decoder.sources)
                         if source.kind != "instruction" or
                         self.online_decoder.instruction_cursor + 4
                         <= self.online_decoder.instruction_end)
            index, source = max(
                available,
                key=lambda item: (
                    weights[item[1].source_id],
                    -self._selection_uses[(0, item[0], item[1].source_id)],
                    -item[0]))
            self._hint_sequence += 1
            return {"schema_version": "scenario_mutation_hint.v1",
                    "run_id": self.run_id, "sequence": self._hint_sequence,
                    **self._feedback_hint_fields(), "target_id": source.path_id,
                    "template": 0, "path": index, "source": index,
                    "source_id": source.source_id, "energy": min(255, weights[source.source_id]),
                    "online_weights": weights}
        target_ids = {target.target_id for target in self.targets}
        candidates = [(index, template) for index, template
                      in enumerate(self.decoder.templates)
                      if template.target_id in target_ids]
        if not candidates:
            raise ValueError("no RFuzz template maps to a coverage target")
        choices = []
        for template_index, template in candidates:
            paths = self.decoder.paths_for(
                template.target_id, direction=template.genome.direction)
            for path_index, path in enumerate(paths):
                for source_index, source_id in enumerate(path.source_ids):
                    key = (template_index, path_index, source_id)
                    uses = self._selection_uses[key]
                    # Shrinking exploration and observed yield allow both
                    # component sides to compete without fixed alternation.
                    score = ((64 if template.target_id not in self._target_hits else 8)
                             + 32 / (uses + 1)
                             + 16 * self._selection_gains[key] / (uses + 1))
                    choices.append((score, template_index, path_index,
                                    source_index, template, path))
        if not choices:
            raise ValueError("no RFuzz dependency path has a mutable source")
        score, template_index, path_index, source_index, template, path = max(
            choices, key=lambda item: (item[0], -item[1], -item[2], -item[3]))
        source_id = path.source_ids[source_index]
        self._hint_sequence += 1
        return {"schema_version": "scenario_mutation_hint.v1",
                "run_id": self.run_id, "sequence": self._hint_sequence,
                **self._feedback_hint_fields(),
                "target_id": template.target_id,
                "template": template_index, "path": path_index,
                "source": source_index,
                "energy": max(8, min(255, round(score))),
                "source_id": source_id,
                "interaction_feature_count": len(self._interaction_counts)}

    def _save_evidence(self, *, receipt: ScenarioRfuzzReceipt,
                       records: tuple[bytes, ...], genome: ScenarioGenome) -> None:
        if self.evidence_dir is None:
            return
        run_hash = hashlib.sha256(self.run_id.encode("utf-8")).hexdigest()[:8]
        name = (f"{receipt.status}_{run_hash}_{receipt.buffer_id}_{receipt.slot}_"
                f"{receipt.raw_sha256[:16]}.json")
        document = {"run_id": self.run_id, "buffer_id": receipt.buffer_id,
                    "slot": receipt.slot, "raw_records_hex": [r.hex() for r in records],
                    "raw_sha256": receipt.raw_sha256,
                    "path_id": receipt.path_id,
                    "genome": json.loads(GenomeCodec.encode(genome)),
                    "genome_sha256": receipt.genome_sha256,
                    "status": receipt.status,
                    "violations": list(receipt.violations),
                    "trace": asdict(receipt.trace)}
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False)
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False,
                                             dir=self.evidence_dir,
                                             prefix=".violation-") as handle:
                temporary_path = Path(handle.name)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.evidence_dir / name)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def execute_batch(self, batch: InputBatch, *,
                      on_receipt: Callable[[ScenarioRfuzzReceipt], None] | None = None
                      ) -> tuple[bytes, ...]:
        if not isinstance(batch, InputBatch) or batch.input_bytes != RECORD_BYTES:
            raise ValueError("scenario RFuzz input must use eight bytes records")
        if self.online_decoder is not None:
            return self._execute_online_batch(batch, on_receipt=on_receipt)
        coverages: list[bytes] = []
        before_batch = len(self.receipts)
        for slot, records in enumerate(batch.tests):
            raw_hash = hashlib.sha256(b"".join(records)).hexdigest()
            identity = (batch.buffer_id, slot)
            old = self._completed.get(identity)
            if old is not None:
                if old[0] != raw_hash:
                    raise ValueError("RFuzz slot identity reused with different input")
                coverages.append(old[1])
                if on_receipt is not None and old[2] is not None:
                    on_receipt(old[2])
                continue
            empty_coverage = bytes(self.counter_count)
            try:
                genome = self.decoder.decode(records)
            except ValueError as exc:
                receipt = ScenarioRfuzzReceipt(
                    self.run_id, batch.buffer_id, slot, raw_hash, None,
                    None, "input_invalid", 0, empty_coverage.hex(),
                    (), str(exc), None)
                coverage = empty_coverage
            else:
                try:
                    (applied_sources, applied_template, applied_path,
                     applied_hint_sequence, selected_targets) = self._raw_mutation_provenance(records)
                    for source_id in applied_sources:
                        self._selection_uses[(applied_template, applied_path, source_id)] += 1
                    effective_genome_sha256 = _effective_genome_sha256(genome)
                    if self._session_stop_reason is not None and (self.session is not None
                            or self._prepared_runtime_paths is not None):
                        raise RuntimeError("continuous RFuzz session stopped: " + self._session_stop_reason)
                    if self.session is not None and self._prepared_runtime_paths is not None:
                        self._validate_runtime_source_owners(genome.path_id,
                                                             self.session.runner, self.decoder)
                    trace = (self.session.record(genome) if self.session is not None
                             else record_scenario(
                                 genome, self.factory,
                                 identity_observer=self._observe_fresh_identity,
                                 **({"runner_preflight": self._runtime_preflight(genome.path_id)}
                                    if self._prepared_runtime_paths is not None else {})))
                    if not isinstance(trace, ScenarioTrace):
                        raise ValueError("session must return ScenarioTrace")
                    if self.session is not None and len(trace.events) < self._session_event_count:
                        raise ValueError("continuous session event prefix regressed")
                    slot_trace = (replace(trace, events=trace.events[self._session_event_count:])
                                  if self.session is not None else trace)
                    if self.session is not None:
                        self._session_event_count = len(trace.events)
                    collector = self._interaction if self.session is not None else InteractionFeedback()
                    collector.ingest(slot_trace.events)
                    interaction = collector.incremental_summary()
                    feature_deltas = interaction["feature_deltas"]
                    interaction["new_run_features"] = sorted(
                        set(feature_deltas) - set(self._interaction_counts))
                    interaction_gain = len(interaction["new_run_features"])
                    self._interaction_counts.update(feature_deltas)
                    consumed_sources = self._consumed_source_ids(
                        selected_targets, applied_template, genome, slot_trace)
                    wall_cut = _trace_wall_cut(trace)
                    protocol_environment_error = _trace_protocol_environment_error(trace)
                    checks_allowed = trace.status not in (
                        "uncertain_effect", "environment_error") and not protocol_environment_error
                    violations = (tuple(self.checker(trace))
                                  if self.checker and checks_allowed else ())
                    if any(not isinstance(item, str) or not item
                           for item in violations):
                        raise ValueError("checker returned invalid violation IDs")
                    hits = observed_targets(slot_trace.events, self.targets)
                    coverage_gain = len(set(hits) - self._target_hits)
                    self._target_hits.update(hits)
                    for source_id in applied_sources:
                        key = (applied_template, applied_path, source_id)
                        if source_id in consumed_sources:
                            self._selection_gains[key] += coverage_gain + interaction_gain
                    local_ticks = dict(trace.local_ticks)
                    if self.session is not None:
                        local_ticks = {component: ticks - self._session_ticks.get(component, 0)
                                       for component, ticks in trace.local_ticks.items()}
                        if any(ticks < 0 for ticks in local_ticks.values()):
                            raise ValueError("continuous session local ticks regressed")
                        self._session_ticks = dict(trace.local_ticks)
                    coverage = bytes(int(target.target_id in hits)
                                     for target in self.targets)
                    status = ("environment_error" if protocol_environment_error else
                              "dut_violation" if violations else trace.status)
                    receipt = ScenarioRfuzzReceipt(
                        self.run_id, batch.buffer_id, slot, raw_hash,
                        trace.genome_sha256, trace.semantic_sha256, status,
                        sum(local_ticks.values()), coverage.hex(),
                        violations, None,
                        trace if violations or not checks_allowed or wall_cut else None,
                        trace.manifest_sha256, local_ticks,
                        genome.path_id, applied_sources, applied_template,
                        applied_path, applied_hint_sequence,
                        effective_genome_sha256, wall_cut, consumed_sources, interaction)
                except Exception as exc:
                    receipt = ScenarioRfuzzReceipt(
                        self.run_id, batch.buffer_id, slot, raw_hash, None,
                        None, "environment_error", 0, empty_coverage.hex(), (),
                        f"{type(exc).__name__}: {exc}", None)
                    coverage = empty_coverage
            if self.session is not None and receipt.status in (
                    "dut_violation", "uncertain_effect", "environment_error", "budget_exhausted"):
                if self._session_stop_reason is None:
                    self._session_stop_reason = receipt.status
            if receipt.status in ("dut_violation", "uncertain_effect"):
                self._save_evidence(receipt=receipt, records=records,
                                    genome=genome)
            self.receipts.append(receipt)
            if receipt.genome_sha256 is not None:
                for source_id in receipt.applied_source_ids:
                    self._hint_source_uses[source_id] += 1
            self._max_completed_buffer_id = (batch.buffer_id if self._max_completed_buffer_id is None
                                             else max(self._max_completed_buffer_id,
                                                      batch.buffer_id))
            if self.first_receipt_completed_at is None:
                self.first_receipt_completed_at = time.monotonic()
            self._completed[identity] = (raw_hash, coverage, receipt)
            coverages.append(coverage)
            if on_receipt is not None:
                on_receipt(receipt)
        if len(self.receipts) > before_batch:
            self._latest_completed_batch = tuple(self.receipts[before_batch:])
        return tuple(coverages)

    def _online_baseline_weights(self) -> dict[str, int]:
        """Frozen pre-closed-loop weights: coverage gaps, use counts, yield."""
        return {source.source_id: max(1, min(65536, round(
            source.weight * (8 + (64 if any(target not in self._target_hits
                                           for target in source.coverage_target_ids) else 0)
                             + 32 / (self._selection_uses[(0, index, source.source_id)] + 1)
                             + 16 * self._selection_gains[(0, index, source.source_id)]
                             / (self._selection_uses[(0, index, source.source_id)] + 1)))))
            for index, source in enumerate(self.online_decoder.sources)}

    def _online_weights(self) -> dict[str, int]:
        """Bias legal online sources by actual coverage and interaction yield.

        With the closed-loop switch off this is the frozen baseline verbatim.
        With it on, the certificate energy accumulated so far is added to the
        credited source and subtracted from the penalised one; the result is
        still the mapping handed to ``decode_candidate``, so the energy really
        decides the next legal source.
        """
        weights = self._online_baseline_weights()
        energy = getattr(self, "_closed_loop_energy_delta", None)
        if not energy:
            return weights
        return {key: max(1, min(65536, value + energy.get(key, 0)))
                for key, value in weights.items()}

    # ------------------------------------------- closed-loop certificate energy

    def _closed_loop_document(self, *, status: str) -> dict:
        """The one bounded document shape shared by every online slot."""
        enabled = self._closed_loop_enabled
        document = {
            "schema_version": CLOSED_LOOP_FEEDBACK_VERSION,
            "enabled": enabled,
            "source": getattr(self, "closed_loop_energy_source", "default"),
            "status": status,
            "feedback_schema_version": FEEDBACK_SCHEMA_VERSION,
            "certificate_schema_version": CERTIFICATE_PRODUCER_SCHEMA_VERSION,
            "counts": _zero_closed_loop_counts(),
            "certificates": [],
            "hit_ids": [],
            "certificates_truncated": 0,
            "duplicates": [],
            "deduplicated": [],
            "deduplicated_truncated": 0,
            "credited": {},
            "penalized": {},
            "credit_totals": {},
            "penalty_totals": {},
            "source_weights": {},
            "evidence": [],
            "refusals": [],
            "desynchronized": None,
            "pending_count": None,
        }
        if not enabled:
            return document
        document.update(
            producer=deepcopy(self._closed_loop_producer_identity),
            producer_kind=self._closed_loop_producer_kind,
            energy_gains=asdict(self._closed_loop_gains),
            bounds={"max_pending": self._closed_loop_max_pending,
                    "max_event_gap": self._closed_loop_max_event_gap},
            journal={"start": self._closed_loop_event_cursor,
                     "end": self._closed_loop_event_cursor},
            credit_totals=self._closed_loop_signed_totals(
                self._closed_loop_energy_delta, positive=True),
            penalty_totals=self._closed_loop_signed_totals(
                self._closed_loop_energy_delta, positive=False),
            desynchronized=self._closed_loop_desync,
            pending_count=self._closed_loop_pending_count(),
        )
        return document

    def _closed_loop_pending_count(self) -> int | None:
        pending = getattr(self._closed_loop_producer, "pending_count", None)
        return pending if type(pending) is int else None

    def _closed_loop_refuse(self, document: dict, reason: str, detail: dict) -> None:
        """Record one refusal without letting it escape into the search loop."""
        refusal = {"reason": reason, "detail": detail}
        document["refusals"].append(refusal)
        self._closed_loop_refusal_count += 1
        self._closed_loop_refusals.append(refusal)
        del self._closed_loop_refusals[:-_CLOSED_LOOP_REFUSAL_LIMIT]

    def _closed_loop_desynchronize(self, document: dict, reason: str,
                                   error: Exception) -> dict:
        """A journal that cannot be aligned stops feedback, never the session."""
        detail = {"error_type": type(error).__name__, "error": str(error),
                  "cursor": self._closed_loop_event_cursor}
        self._closed_loop_desync = f"{reason}: {error}"
        document["status"] = "desynchronized"
        document["desynchronized"] = self._closed_loop_desync
        self._closed_loop_refuse(document, reason, detail)
        return document

    def _closed_loop_attributed(self, document: dict, identity: str, *,
                                default_keys: tuple[str, ...] | None,
                                attribution: str) -> tuple[str, ...] | None:
        """Resolve one evidence identity to legal weight keys or refuse it.

        Nothing is ever scored from an ambiguous or unknown key: an unknown key
        and an identity with no attribution at all both leave the weights
        untouched and are recorded on the receipt.
        """
        keys = None
        if (self._closed_loop_attribution is not None
                and identity in self._closed_loop_attribution):
            keys = self._closed_loop_attribution[identity]
            attribution = "explicit"
        elif default_keys is not None:
            keys = default_keys
        if keys is None:
            self._closed_loop_refuse(document, "unattributable_evidence",
                                     {"feature": identity,
                                      "attribution": attribution})
            return None
        unknown = sorted(key for key in keys
                         if key not in self._closed_loop_weight_keys)
        if unknown:
            self._closed_loop_refuse(document, "unknown_weight_key",
                                     {"feature": identity,
                                      "attribution": attribution,
                                      "unknown_keys": unknown})
            return None
        return tuple(keys)

    def _closed_loop_observe(self, document: dict, certificates: tuple, *,
                             credit: bool = True) -> tuple:
        """Validate new certificates and return the hits that may be scored.

        One forged document or one reused certificate identity is recorded and
        dropped; a valid sibling in the same batch is never invented, and the
        caller keeps the weights it already had.
        """
        try:
            consumer = ClosedLoopFeedback()
            recorded = consumer.ingest(certificates)
        except Exception as error:  # fail closed: one forged document is not fatal
            self._closed_loop_refuse(document, "certificate_refused",
                                     {"error_type": type(error).__name__,
                                      "error": str(error)})
            return ()
        slot_counts = Counter()
        hits = []
        for hit in recorded:
            certificate_id = hit["certificate_id"]
            if credit:
                previous = self._closed_loop_credit_guard.get(certificate_id)
                if previous is not None:
                    if previous == hit["hit_id"]:
                        # The same settled admission cannot be counted twice.
                        document["duplicates"].append(certificate_id)
                        self._closed_loop_duplicate_count += 1
                        continue
                    self._closed_loop_refuse(
                        document, "certificate_id_reused_with_different_evidence",
                        {"certificate_id": certificate_id,
                         "hit_id": hit["hit_id"], "recorded_hit_id": previous})
                    continue
                self._closed_loop_credit_guard[certificate_id] = hit["hit_id"]
                while (len(self._closed_loop_credit_guard)
                       > self._closed_loop_max_pending):
                    self._closed_loop_credit_guard.popitem(last=False)
            if len(document["certificates"]) < _CLOSED_LOOP_DETAIL_LIMIT:
                document["certificates"].append({
                    "certificate_id": certificate_id,
                    "status": hit["status"],
                    "direction": hit["direction"],
                    "source_id": hit["source_id"],
                    "source_admission_id": hit["source_admission_id"],
                    "kind": hit["kind"],
                    "hit_id": hit["hit_id"],
                    "hops": [[hop["hop_id"], hop["event_id"]]
                             for hop in hit["hops"]],
                })
                document["hit_ids"].append(hit["hit_id"])
            else:
                document["certificates_truncated"] += 1
            slot_counts["certificate_count"] += 1
            slot_counts[_CLOSED_LOOP_HIT_KIND_COUNT[hit["kind"]]] += 1
            hits.append(hit)
        document["counts"] = {name: slot_counts.get(name, 0)
                              for name in _zero_closed_loop_counts()}
        for name, value in document["counts"].items():
            self._closed_loop_counts[name] += value
        return tuple(hits)

    def _closed_loop_slot_evidence(self, interaction: dict | None,
                                   failures: tuple):
        """Collect this slot's non-certificate evidence with its attribution.

        New interaction edges and state transitions only count when the run has
        not observed them before, and they are scored only through an explicit
        caller attribution: no weight is invented from an adjacent event.
        """
        edges: list[dict] = []
        transitions: list[str] = []
        if interaction:
            novelty = set(interaction.get("new_run_features", ()))
            for edge in interaction.get("delta_edges", ()):
                if edge_feature(edge) in novelty:
                    edges.append(edge)
            current = interaction.get("state_transitions") or {}
            growing = {key for key, count in current.items()
                       if count > self._closed_loop_transitions.get(key, 0)}
            transitions = sorted(key for key in growing if key in novelty)
            self._closed_loop_transitions = dict(current)
        return edges, transitions, tuple(failures)

    def _closed_loop_apply_energy(self, document: dict, *, hits: tuple,
                                  edges: tuple = (), transitions: tuple = (),
                                  failures: tuple = ()) -> None:
        """Translate every attributable evidence item through ``energy_weights``."""
        attribution: dict[str, tuple[str, ...]] = {}
        evidence: list[dict] = []

        scored_here: set[str] = set()

        def attribute(identity: str, *,
                      default_keys: tuple[str, ...] | None,
                      origin: str, gain: int, penalty: bool) -> bool:
            """Score one feature identity once per run, or record the repeat."""
            if (identity in self._closed_loop_scored_features
                    or identity in scored_here):
                if len(document["deduplicated"]) < _CLOSED_LOOP_DETAIL_LIMIT:
                    document["deduplicated"].append(identity)
                else:
                    document["deduplicated_truncated"] += 1
                return False
            keys = self._closed_loop_attributed(document, identity,
                                                default_keys=default_keys,
                                                attribution=origin)
            if keys is None:
                return False
            attribution[identity] = keys
            scored_here.add(identity)
            evidence.append({"feature": identity, "keys": list(keys),
                             "gain": gain, "penalty": penalty})
            return True

        closed_loops: list = []
        partial: list = []
        stages: list = []
        for hit in hits:
            gain = getattr(self._closed_loop_gains,
                           _CLOSED_LOOP_HIT_KIND_GAIN[hit["kind"]])
            if not attribute(hit_feature(hit), default_keys=(hit["source_id"],),
                             origin="declared_source_id", gain=gain,
                             penalty=False):
                continue
            {CLOSED_LOOP: closed_loops, PARTIAL_PROPAGATION: partial,
             STAGE_REACHED: stages}[hit["kind"]].append(hit)
        new_edges = []
        for edge in edges:
            if attribute(edge_feature(edge), default_keys=None, origin="explicit",
                         gain=self._closed_loop_gains.new_edge, penalty=False):
                new_edges.append(edge)
        new_transitions = []
        for transition in transitions:
            if attribute(transition_feature(transition), default_keys=None,
                         origin="explicit",
                         gain=self._closed_loop_gains.new_state_transition,
                         penalty=False):
                new_transitions.append(transition)
        failure_evidence = []
        for family in failures:
            if attribute(failure_feature(family), default_keys=None,
                         origin="explicit",
                         gain=self._closed_loop_gains.failure_penalty,
                         penalty=True):
                failure_evidence.append(family)
        if not (closed_loops or partial or stages or new_edges or new_transitions
                or failure_evidence):
            return
        # ``energy_weights`` needs the current weights as its base: its floor
        # then bounds the next weight instead of hiding a penalty behind zero.
        base = self._online_baseline_weights()
        try:
            weights = energy_weights(
                base, closed_loops=closed_loops, partial_propagation=partial,
                stage_reached=stages, new_edges=new_edges,
                new_state_transitions=new_transitions,
                failures=failure_evidence, attribution=attribution,
                gains=self._closed_loop_gains)
        except Exception as error:  # fail closed: a refused conversion scores nothing
            self._closed_loop_refuse(document, "energy_conversion_refused",
                                     {"error_type": type(error).__name__,
                                      "error": str(error)})
            return
        document["evidence"] = evidence
        delta = {key: weights[key] - base[key] for key in base
                 if weights[key] != base[key]}
        # Committed only after a successful conversion, so a refused one can
        # never mark evidence as scored without having moved a weight.
        self._closed_loop_scored_features.update(scored_here)
        if not delta:
            return
        self._closed_loop_energy_delta.update(delta)
        for key, value in sorted(delta.items()):
            bucket = document["credited"] if value > 0 else document["penalized"]
            bucket[key] = bucket.get(key, 0) + abs(value)
        document["credit_totals"] = self._closed_loop_signed_totals(
            self._closed_loop_energy_delta, positive=True)
        document["penalty_totals"] = self._closed_loop_signed_totals(
            self._closed_loop_energy_delta, positive=False)
        weights_now = self._online_weights()
        document["source_weights"] = {
            **document["source_weights"],
            **{key: weights_now[key] for key in sorted(delta)
               if key in self._closed_loop_weight_keys}}

    def _closed_loop_step(self, *, interaction: dict | None = None,
                          failures: tuple = ()) -> dict:
        """Observe the new journal suffix and credit what it proves.

        This is the only place the online search touches certificate feedback.
        It never raises: a refused certificate, an unattributable identity or a
        journal that cannot be aligned is recorded on the returned document and
        the session keeps running with the weights it already had.
        """
        if not self._closed_loop_enabled:
            return self._closed_loop_document(status="disabled")
        document = self._closed_loop_document(status="ok")
        if self._closed_loop_desync is not None:
            document["status"] = "desynchronized"
            return document
        started = self._closed_loop_event_cursor
        try:
            events = self.session.runner.events_since(started)
        except Exception as error:
            return self._closed_loop_desynchronize(
                document, "certificate_journal_unreadable", error)
        if events:
            try:
                certificates = tuple(self._closed_loop_producer.ingest(events))
            except Exception as error:
                return self._closed_loop_desynchronize(
                    document, "certificate_journal_not_contiguous", error)
            self._closed_loop_event_cursor = started + len(events)
            document["journal"] = {"start": started,
                                   "end": self._closed_loop_event_cursor}
        # One last fail-closed boundary: whatever a single slot's evidence
        # looks like, it can never raise into the search loop.
        try:
            hits = (self._closed_loop_observe(document, certificates)
                    if events and certificates else ())
            edges, transitions, families = self._closed_loop_slot_evidence(
                interaction, failures)
            self._closed_loop_apply_energy(document, hits=hits, edges=edges,
                                           transitions=transitions,
                                           failures=families)
        except Exception as error:
            self._closed_loop_refuse(document, "closed_loop_observation_refused",
                                     {"error_type": type(error).__name__,
                                      "error": str(error)})
        document["pending_count"] = self._closed_loop_pending_count()
        if document["status"] == "ok" and document["refusals"]:
            document["status"] = "refused"
        return document

    def closed_loop_state(self) -> dict:
        """Run-level report of the switch and its bounded retained state."""
        enabled = self._closed_loop_enabled
        document = self._closed_loop_document(
            status=("disabled" if not enabled else
                    "desynchronized" if self._closed_loop_desync is not None
                    else "active"))
        document["schema_version"] = CLOSED_LOOP_STATE_VERSION
        if not enabled:
            return document
        document.update(
            counts={name: self._closed_loop_counts.get(name, 0)
                    for name in _zero_closed_loop_counts()},
            credit_totals=self._closed_loop_signed_totals(
                self._closed_loop_energy_delta, positive=True),
            penalty_totals=self._closed_loop_signed_totals(
                self._closed_loop_energy_delta, positive=False),
            refusal_count=self._closed_loop_refusal_count,
            duplicate_count=self._closed_loop_duplicate_count,
            refusals=deepcopy(self._closed_loop_refusals),
            retained_certificates=len(self._closed_loop_credit_guard),
            scored_features=len(self._closed_loop_scored_features),
            journal_cursor=self._closed_loop_event_cursor,
            initial=deepcopy(self._closed_loop_initial),
            terminal=deepcopy(self._closed_loop_terminal),
        )
        return document

    def _closed_loop_finalize(self) -> None:
        """Settle chains still open at the session end as reported evidence.

        A terminal settlement can no longer influence any slot, so those
        certificates are counted and retained as evidence and never credited.
        """
        if not self._closed_loop_enabled or self._closed_loop_terminal is not None:
            return
        document = self._closed_loop_document(status="terminal")
        try:
            certificates = ()
            if self._closed_loop_desync is None:
                flush = getattr(self._closed_loop_producer, "flush", None)
                if callable(flush):
                    certificates = tuple(flush())
            if certificates:
                self._closed_loop_observe(document, certificates, credit=False)
        except Exception as error:
            document["status"] = "refused"
            self._closed_loop_refuse(document, "terminal_settlement_refused",
                                     {"error_type": type(error).__name__,
                                      "error": str(error)})
        document["pending_count"] = self._closed_loop_pending_count()
        self._closed_loop_terminal = document

    def _trim_online_evidence(self) -> None:
        """Bound scoring history only; never alter RTL, RAM, or replay inputs."""
        for evidences in (self._online_instruction_evidence,
                          self._online_pin_evidence):
            while len(evidences) > self._online_evidence_limit:
                action_id = next(iter(evidences))
                del evidences[action_id]
                self._online_pending_sources.pop(action_id, None)

    def _reset_online_credit_evidence(self) -> None:
        """A reset ends every outstanding source-to-output credit chain."""
        self._online_last_gpio_step.clear()
        self._online_pin_evidence.clear()
        self._online_instruction_evidence.clear()
        self._online_pending_sources.clear()

    @staticmethod
    def _witnessed_interaction_gain(interaction: dict,
                                    transaction_ids: set[int]) -> int:
        """Count new edge/path features containing a source's real transaction."""
        if not transaction_ids:
            return 0
        new = set(interaction.get("new_run_features", ()))
        if not new:
            return 0
        matched = set()
        for edge in interaction.get("delta_edges", ()):
            feature = (f"{edge['kind']}:{edge['source']}:{edge['target']}")
            if (feature in new and transaction_ids.intersection(
                    edge.get("witness_event_ids", ()))):
                matched.add(feature)
        for path in interaction.get("delta_observed_paths", ()):
            feature = ("observed_path:" + path["kind"] + ":"
                       + ":".join(path["components"]))
            if (feature in new and transaction_ids.intersection(
                    path.get("witness_event_ids", ()))):
                matched.add(feature)
        return len(matched)

    def _credit_online_interactions(self, interaction: dict) -> dict[str, int]:
        """Credit only newly observed features with a source's real witness.

        Witnesses may arrive in an earlier case than the completed path. Keep
        them until the next nondeferred interaction summary, then consume once.
        """
        if interaction.get("deferred"):
            return {}
        credited: dict[str, int] = {}
        for source_key, witness_ids in self._online_interval_witnesses.items():
            gain = self._witnessed_interaction_gain(interaction, witness_ids)
            if gain:
                self._selection_gains[source_key] += gain
                source_id = source_key[2]
                credited[source_id] = credited.get(source_id, 0) + gain
        self._online_interval_witnesses.clear()
        return credited

    @staticmethod
    def _online_match_mmio(evidences: dict[str, _InstructionEvidence],
                           event: dict) -> None:
        event_id = event.get("event_id")
        if type(event_id) is not int or event.get("kind") != "mmio_acceptance":
            return
        witness = (event.get("address"), event.get("write"),
                   event.get("write_value") if event.get("write") is True else None)
        candidates = [evidence for evidence in evidences.values()
                      if evidence.fetched_at is not None
                      and not evidence.downstream and not evidence.superseded
                      and evidence.expected_mmio == witness
                      and evidence.fetched_at < event_id]
        if not candidates:
            return
        newest = max(candidates, key=lambda item: item.fetched_at)
        newest.ingest((event,))
        if newest.downstream:
            for older in candidates:
                if older is not newest:
                    older.superseded = True

    @staticmethod
    def _online_consumed(case: OnlineCase, events: tuple[dict, ...]) -> bool:
        source = case.source
        if isinstance(source, OnlineInstruction):
            for event in events:
                transaction = event.get("transaction")
                if (event.get("kind") != "memory_read"
                        or event.get("component") != source.component
                        or not isinstance(transaction, dict)
                        or transaction.get("channel_id") != "instr"):
                    continue
                address, data_hex, writers = (event.get("address"), event.get("data_hex"),
                                               event.get("writer_event_ids"))
                if (type(address) is not int or not isinstance(data_hex, str)
                        or not isinstance(writers, (tuple, list))):
                    continue
                try:
                    data = bytes.fromhex(data_hex)
                except ValueError:
                    continue
                if len(data) != len(writers):
                    continue
                if any(source.address <= address + lane < source.address + len(source.data)
                       and writer == source.action_id
                       and data[lane] == source.data[address + lane - source.address]
                       for lane, writer in enumerate(writers)):
                    return True
            return False
        width = source.width
        if type(width) is not int or width < 1:
            return False
        mask = ((1 << width) - 1) << source.bit_offset
        expected = (source.value << source.bit_offset) & mask
        injected = False
        for event in events:
            if (event.get("kind") == "source_injection"
                    and event.get("component") == source.component
                    and event.get("port") == source.port):
                if event.get("action_id") == source.action_id:
                    injected = True
                elif injected:
                    return False
            inputs = event.get("inputs")
            if (injected and event.get("kind") is None
                    and event.get("component") == source.component
                    and isinstance(inputs, dict) and type(inputs.get(source.port)) is int
                    and inputs[source.port] & mask == expected):
                return True
        return False

    def _bind_online_source_action(self, case: OnlineCase, decision: dict) -> dict:
        """Register and require the candidate's declared action before any RTL.

        A refusal raises before the caller issues a single RTL command, so the
        runner, memory and case history stay untouched.  The structured record
        is always stored on the decision, including on the refusing path.  The
        action recorded and evaluated is the one ``register`` returns: a policy
        gate may bind the per-case prerequisites it declares (for example the
        exact fetch slot the action payload names), and the receipt must state
        the action that was actually admitted.
        """
        document = {"schema_version": ONLINE_SOURCE_ACTION_RECEIPT_VERSION,
                    "action": None, "evaluation": None, "refusal": None,
                    "gate_enforce": bool(getattr(self.source_action_gate, "enforce", True))}
        try:
            action = self.online_decoder.source_action(case)
            # Registration is explicit: the gate refuses an unregistered case
            # instead of trusting the caller's claim.
            registered = self.source_action_gate.register(action)
            if (not isinstance(registered, SourceAction)
                    or registered.action_id != action.action_id):
                raise ValueError(
                    "source-action gate register must return the admitted action")
            document["action"] = registered.document()
            try:
                self.source_action_gate.require_case(case)
            except SourceActionPrerequisiteError as refusal:
                document["evaluation"] = refusal.evaluation.document()
                document["refusal"] = {
                    "reason": "source_action_prerequisite_unsatisfied",
                    "detail": {
                        "evaluation_reason": refusal.evaluation.reason,
                        "missing_kinds": [item.kind
                                          for item in refusal.evaluation.missing],
                        "missing_evidence_refs": [item.evidence_ref
                                                  for item in refusal.evaluation.missing]}}
                raise
            document["evaluation"] = self.source_action_gate.evaluate(
                registered).document()
        except Exception as error:
            if document["refusal"] is None:
                detail = ({"refusal": error.reason, **error.detail}
                          if isinstance(error, OnlineSourceActionRefusal)
                          else {"error_type": type(error).__name__,
                                "message": str(error)})
                document["refusal"] = {"reason": "source_action_not_constructible",
                                       "detail": detail}
            raise
        finally:
            decision["source_action"] = document
        return document

    def _finish_online_session(self, *, defer_semantic_hash: bool = False
                               ) -> tuple[ScenarioTrace | None, str | None]:
        """Capture the terminal prefix once, retaining a plan even if cleanup fails."""
        if not self._online_finish_attempted:
            self._online_finish_attempted = True
            # The journal ends here: chains still open are settled once as
            # terminal evidence.  They can no longer influence a slot.
            self._closed_loop_finalize()
            if not getattr(self.session, "_begun", False):
                return None, None
            try:
                self._online_final_trace = self.session.finish(
                    defer_semantic_hash=defer_semantic_hash)
            except BaseException:
                # Keep the observed unfinished status. Cleanup failure cannot
                # turn an executed prefix into a successful testcase.
                try:
                    self._online_final_trace = self.session.trace()
                    self._online_final_plan_hex = self.session.encode_plan().hex()
                except BaseException:
                    pass
                raise
            else:
                self._online_final_plan_hex = self.session.encode_plan().hex()
        return self._online_final_trace, self._online_final_plan_hex

    # ------------------------------------------------------------------
    # Opt-in live path switch (see PATH_SWITCH_ENV)
    # ------------------------------------------------------------------

    def _path_switch_draw(self, raw: bytes) -> bytes:
        """The domain-separated draw one raw record proposes its target with."""
        return hashlib.sha256(_PATH_SWITCH_DOMAIN + raw).digest()

    def _path_switch_refusal(self, reason: str, row, request, pool,
                             rejection=None) -> dict:
        """Record one refused switch attempt and state why it was refused.

        The reason is the operator's own stable name; the rejection, when the
        decoder is the authority that refused, keeps the shipped code, pointer
        and detail verbatim, so a refusal is never re-labelled here.
        """
        self._path_switch_refusals[reason] += 1
        if rejection is not None:
            self._path_switch_codes[rejection["code"]] += 1
        return {"schema_version": PATH_SWITCH_REFUSAL_VERSION, "reason": reason,
                "request": (None if request is None else request.document()),
                "target": (None if row is None else
                           {"path_id": row["path_id"],
                            "switchable": bool(row["switchable"]),
                            "eligible_source_ids": list(row["eligible_source_ids"])}),
                "declared_paths": [entry["path_id"] for entry in pool],
                "switchable_paths": [entry["path_id"] for entry in pool
                                     if entry["switchable"]],
                "rejection": rejection}

    def _apply_path_switch(self, raw: bytes, case):
        """Retarget one decoded case inside the declared switch pool.

        Returns ``(case, record, refusal)``; exactly one of ``record`` and
        ``refusal`` is set.  A granted switch returns the decoder's own
        ``online_path_switch.v1`` record, which states whether the candidate
        identity changed; a refused one returns the shipped rejection document
        and leaves ``case`` untouched, so the caller still submits the unswitched
        candidate and nothing is consumed by the attempt.

        The target is drawn from the declared pool in declaration order by a
        domain-separated digest of the raw record alone, so a replay of the same
        record in the same state proposes the same switch and no search state
        that a replay could not reproduce takes part in the choice.  A row with
        no eligible source is requested as declared: the decoder's own code is
        what refuses it, and that code is recorded instead of being replaced by
        an operator-side guess.
        """
        pool = tuple(self.online_decoder.path_switch_targets())
        self._path_switch_attempts += 1
        if not pool:
            return case, None, self._path_switch_refusal(
                "no_declared_path", None, None, pool)
        draw = self._path_switch_draw(raw)
        row = pool[int.from_bytes(draw[:8], "little") % len(pool)]
        sources = row["eligible_source_ids"] or row["source_ids"]
        if not sources:
            return case, None, self._path_switch_refusal(
                "no_declared_source", row, None, pool)
        source_id = sources[int.from_bytes(draw[8:16], "little") % len(sources)]
        request = PathSwitchRequest(path_id=row["path_id"], source_id=source_id)
        switched, disposition = self.online_decoder.switch_proposal(request)
        if switched is None:
            rejection = (None if disposition.rejection is None
                         else disposition.rejection.document())
            return case, None, self._path_switch_refusal(
                "switch_rejected", row, request, pool, rejection)
        record = disposition.switch
        self._path_switch_granted += 1
        if record is not None and record.changed:
            self._path_switch_changed += 1
        return switched, record, None

    def path_switch_state(self) -> dict:
        """Run-level report of the switch and its own complete counters."""
        enabled = bool(getattr(self, "path_switch", False))
        return {"schema_version": PATH_SWITCH_STATE_VERSION, "enabled": enabled,
                "source": getattr(self, "path_switch_source", "default"),
                "status": "disabled" if not enabled else "active",
                "attempts": self._path_switch_attempts,
                "granted": self._path_switch_granted,
                "changed": self._path_switch_changed,
                "refusals": dict(sorted(self._path_switch_refusals.items())),
                "rejection_codes": dict(sorted(self._path_switch_codes.items())),
                "operator_ids": dict(sorted(self._path_switch_records.items()))}

    def _execute_online_batch(self, batch: InputBatch, *, on_receipt=None) -> tuple[bytes, ...]:
        """Admit inputs to one live runtime; fresh genome replay is inapplicable.

        Findings retain the full encoded online plan for replay_online_session.
        Ordinary slots use only OnlineCaseReceipt's event suffix.
        """
        coverages = []
        before_batch = len(self.receipts)
        for slot, records in enumerate(batch.tests):
            raw = b"".join(records)
            raw_hash = hashlib.sha256(raw).hexdigest()
            identity = (batch.buffer_id, slot)
            previous = self._completed.get(identity)
            if previous is not None:
                if previous[0] != raw_hash:
                    raise ValueError("RFuzz slot identity reused with different input")
                coverages.append(previous[1])
                if on_receipt is not None and previous[2] is not None:
                    on_receipt(previous[2])
                continue
            coverage = bytes(self.counter_count)
            if (self._session_stop_reason is None
                    and self._online_live_duration_seconds is not None
                    and self.first_receipt_completed_at is not None
                    and time.monotonic() - self.first_receipt_completed_at
                    >= self._online_live_duration_seconds):
                self._session_stop_reason = "duration_budget"
            if (self._session_stop_reason is not None
                    or self._online_live_max_tests is not None
                    and len(self.receipts) >= self._online_live_max_tests):
                self._completed[identity] = (raw_hash, coverage, None)
                coverages.append(coverage)
                continue
            slot_started = time.monotonic()
            phase_timing = {name: 0.0 for name in (
                'selection_decode', 'rtl_submit', 'trace_digest',
                'interaction_ingest', 'checker', 'feedback_credit',
                'receipt_build')}
            weights = self._online_weights()
            decision = {"buffer_id": batch.buffer_id, "slot": slot,
                        "raw_sha256": raw_hash,
                        "raw_records_hex": [record.hex() for record in records],
                        "weights": dict(weights), "source_id": None,
                        "path_id": None, "case_id": None,
                        "direction": None, "flow_id": None, "target_id": None,
                        "operator_id": None, "candidate_id": None,
                        "source_selection_reason": None,
                        "candidate_disposition": None,
                        "candidate_disposition_reason": None,
                        "rejection": None,
                        "source_action": None,
                        # Recorded before any RTL command so even a refused
                        # candidate states which search behaviour selected it.
                        "closed_loop_feedback": self._closed_loop_document(
                            status=("disabled" if not self._closed_loop_enabled
                                    else "not_observed")),
                        "admitted_status": "not_admitted", "committed": False}
            self.online_decisions.append(decision)
            self._online_decisions_by_slot[identity] = decision
            case = None
            violations = ()
            commit_refused = False
            pre_rtl_refusal = False
            try:
                if self._session_stop_reason is not None:
                    raise RuntimeError("continuous RFuzz session stopped: " + self._session_stop_reason)
                case, candidate = self.online_decoder.decode_candidate(
                    raw, coverage_hints=weights)
                if case is None:
                    # A classified refusal happens before any RTL command, so the
                    # decoder reports it instead of raising only a message.
                    refusal = candidate.rejection
                    raise RejectionError(
                        "online candidate rejected: "
                        f"{description_of(refusal.code)} "
                        f"[{refusal.code}@{refusal.pointer}]", refusal)
                switch_record = None
                switch_refusal = None
                if self.path_switch:
                    # Opt-in retarget inside the declared switch pool.  A refused
                    # switch consumes nothing, so the unswitched candidate is
                    # still submitted; only a granted change replaces it.
                    case, switch_record, switch_refusal = self._apply_path_switch(
                        raw, case)
                metadata = self.online_decoder.decision_metadata(case)
                index, selected = next((index, source) for index, source in
                    enumerate(self.online_decoder.sources)
                    if source.source_id == metadata["source_id"])
                decision.update(metadata)
                if switch_refusal is not None:
                    decision["path_switch_refusal"] = switch_refusal
                if switch_record is not None:
                    # Even a granted switch that changed nothing states its own
                    # applied record; only a change re-labels the selection.
                    decision["path_switch"] = switch_record.document()
                    self._path_switch_records[switch_record.operator_id] += 1
                if switch_record is not None and switch_record.changed:
                    decision["source_selection_reason"] = "declared_path_switch"
                else:
                    decision["source_selection_reason"] = (
                        "direct_source_byte" if len(raw) > 2 and raw[2] == index
                        else "feedback_weighted_legal_source")
                self._validate_online_runtime_selection(case, selected)
                if self.source_action_gate is not None:
                    # Bind the candidate to its declared action and query the
                    # gate's prerequisites.  This runs before every RTL
                    # command, so a refusal leaves the runner untouched.
                    try:
                        self._bind_online_source_action(case, decision)
                    except BaseException:
                        pre_rtl_refusal = True
                        raise
                decision["admitted_status"] = "submit_attempted"
                key = (0, index, selected.source_id)
                self._selection_uses[key] += 1
                selected_at = time.monotonic()
                phase_timing['selection_decode'] = selected_at - slot_started
                from myfuzz.local_harness.session import observe_local_command_timings
                from myfuzz.scenario.runner import observe_runtime_timings
                local_seconds = 0.0
                local_count = 0
                runner_timing = {name: 0.0 for name in (
                    'scheduler_batch', 'runner_step', 'router_enqueue',
                    'router_drain', 'router_transact', 'observed_output_route')}

                def observe_command(_operation: str, seconds: float) -> None:
                    nonlocal local_seconds, local_count
                    local_seconds += seconds
                    local_count += 1

                def observe_runtime(name: str, seconds: float) -> None:
                    runner_timing[name] += seconds

                try:
                    with (observe_local_command_timings(observe_command),
                          observe_runtime_timings(observe_runtime)):
                        result = self.session.submit_case(case)
                finally:
                    submitted_at = time.monotonic()
                    phase_timing['rtl_submit'] = submitted_at - selected_at
                    decision['runner_timing_seconds'] = runner_timing
                    decision['submit_timing_seconds'] = {
                        'local_command_roundtrip': local_seconds,
                        'host_remainder': max(0.0, phase_timing['rtl_submit'] - local_seconds),
                        'local_command_count': local_count,
                    }
                decision["admitted_status"] = result.status
                if (self.source_action_gate is not None
                        and not self._source_action_gate_observes_itself):
                    # The session does not own this gate, so feed the admitted
                    # case's real events here: later cases may consume them.
                    self.source_action_gate.observe(result)
                committed = self.online_decoder.commit_candidate(case)
                if committed.disposition != "admitted":
                    # The case already reached the session, so a refused commit
                    # cannot claim a clean candidate rejection.
                    commit_refused = True
                    raise RuntimeError(
                        "online commit is uncertain after submit: "
                        f"{committed.reason} [{committed.rejection}]")
                decision["committed"] = True
                self._online_pending_sources[case.source.action_id] = (case, key)
                if isinstance(case.source, OnlineInstruction):
                    self._online_instruction_evidence[case.source.action_id] = (
                        _InstructionEvidence(case.source))
                elif (case.source.component == "gpio_b" and case.source.port == "gpio_in"
                      and case.source.width == 1):
                    self._online_pin_evidence[case.source.action_id] = (
                        _GpioPinIrqEvidence(case.source))
                self._trim_online_evidence()
                document = asdict(case)
                document["source"]["kind"] = ("instruction" if isinstance(case.source, OnlineInstruction)
                                               else "source_event")
                encoded = json.dumps(document, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()
                case_hash = hashlib.sha256(encoded).hexdigest()
                ticks = {name: count - result.local_ticks_before.get(name, 0)
                         for name, count in result.local_ticks_after.items()}
                if any(count < 0 for count in ticks.values()):
                    raise ValueError("online local ticks regressed")
                payload = {"events": result.events, "status": result.status,
                           "local_ticks": ticks}
                semantic_hash = hashlib.sha256(json.dumps(
                    payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
                slot_trace = ScenarioTrace(case_hash, result.status, result.events,
                                           ticks, semantic_hash)
                digest_ready_at = time.monotonic()
                phase_timing['trace_digest'] = digest_ready_at - submitted_at
                if self.case_witness_recorder is not None:
                    # The case's own event slice, handed over exactly once, so
                    # the recorder never re-reads the session journal and never
                    # attributes an earlier case's events to this one.
                    self.case_witness_recorder.observe_case(
                        case_id=case.case_id,
                        component=case.source.component,
                        source_kind=("instruction"
                                     if isinstance(case.source, OnlineInstruction)
                                     else "source_event"),
                        source_id=selected.source_id,
                        events=result.events)
                self._interaction.ingest(result.events)
                ingested_at = time.monotonic()
                phase_timing['interaction_ingest'] = ingested_at - digest_ready_at
                self._online_feedback_event_end = result.event_end
                checks_allowed = result.status in ("running", "complete", "finding")
                violations = tuple(result.violations)
                if self.checker is not None and checks_allowed:
                    violations += tuple(self.checker(slot_trace))
                checked_at = time.monotonic()
                phase_timing['checker'] = checked_at - ingested_at
                if any(not isinstance(item, str) or not item for item in violations):
                    raise ValueError("checker returned invalid violation IDs")
                status = ("dut_violation" if violations or result.status == "finding" else
                          "complete" if result.status == "running" else result.status)
                if status != "complete" or len(self.online_decisions) % self.feedback_interval == 0:
                    interaction = self._interaction.incremental_summary()
                else:
                    interaction = {"schema_version": "interaction_feedback.v1",
                                   "deferred": True, "event_count": result.event_end,
                                   "feature_deltas": {}, "new_features": []}
                deltas = interaction["feature_deltas"]
                interaction["new_run_features"] = sorted(set(deltas) - set(self._interaction_counts))
                self._interaction_counts.update(deltas)
                hits = observed_targets(result.events, self.targets)
                new_hits = set(hits) - self._target_hits
                self._target_hits.update(hits)
                consumed_sources = []
                # Process each new event suffix once. A pending instruction
                # retains only its byte mask and expected transaction.
                for event in result.events:
                    if event.get("kind") == "reset_barrier":
                        self._reset_online_credit_evidence()
                        continue
                    if event.get("kind") == "source_injection":
                        for action_id, pin_evidence in tuple(self._online_pin_evidence.items()):
                            if (action_id != event.get("action_id")
                                    and pin_evidence.source.component == event.get("component")
                                    and pin_evidence.source.port == event.get("port")
                                    and pin_evidence.source.bit_offset == event.get("bit_offset")):
                                del self._online_pin_evidence[action_id]
                                self._online_pending_sources.pop(action_id, None)
                    previous_gpio = self._online_last_gpio_step.get(event.get("component"))
                    for pin_evidence in self._online_pin_evidence.values():
                        pin_evidence.ingest(event, previous_gpio)
                    if (event.get("kind") is None and event.get("component") == "gpio_b"
                            and isinstance(event.get("outputs"), dict)):
                        self._online_last_gpio_step["gpio_b"] = event
                    if event.get("kind") == "memory_read":
                        writers = event.get("writer_event_ids")
                        if not isinstance(writers, (list, tuple)):
                            continue
                        for action_id in set(writers):
                            evidence = self._online_instruction_evidence.get(action_id)
                            if evidence is not None:
                                evidence.ingest((event,))
                    elif event.get("kind") == "mmio_acceptance":
                        self._online_match_mmio(self._online_instruction_evidence,
                                                event)
                for action_id, (pending_case, pending_key) in tuple(self._online_pending_sources.items()):
                    instruction = self._online_instruction_evidence.get(action_id)
                    pin_evidence = self._online_pin_evidence.get(action_id)
                    fetched = instruction is not None and instruction.fetched_at is not None
                    downstream = instruction is not None and instruction.downstream
                    if ((instruction is None and (pin_evidence is None or not pin_evidence.reported)
                         and self._online_consumed(pending_case, result.events))
                            or fetched and not instruction.reported):
                        source_id = pending_key[2]
                        source_targets = self.online_decoder.sources[pending_key[1]].coverage_target_ids
                        source_gain = len(new_hits.intersection(source_targets))
                        if pin_evidence is not None:
                            source_gain = 0
                        consumed_sources.append(source_id)
                        self._hint_source_uses[source_id] += 1
                        if instruction is None or downstream:
                            self._selection_gains[pending_key] += source_gain
                            if instruction is not None and instruction.downstream_event_id is not None:
                                self._online_interval_witnesses.setdefault(pending_key, set()).add(
                                    instruction.downstream_event_id)
                        if instruction is not None:
                            instruction.reported = True
                        if pin_evidence is not None:
                            pin_evidence.reported = True
                    if pin_evidence is not None and pin_evidence.start_event_id is not None:
                        source_targets = self.online_decoder.sources[pending_key[1]].coverage_target_ids
                        self._selection_gains[pending_key] += len(
                            new_hits.intersection(source_targets))
                        self._online_interval_witnesses.setdefault(pending_key, set()).add(
                            pin_evidence.start_event_id)
                        del self._online_pin_evidence[action_id]
                        del self._online_pending_sources[action_id]
                        continue
                    if instruction is not None and downstream and instruction.reported:
                        if pending_key[2] not in consumed_sources:
                            source_targets = self.online_decoder.sources[pending_key[1]].coverage_target_ids
                            source_gain = len(new_hits.intersection(source_targets))
                            consumed_sources.append(pending_key[2])
                            self._selection_gains[pending_key] += source_gain
                            if instruction.downstream_event_id is not None:
                                self._online_interval_witnesses.setdefault(pending_key, set()).add(
                                    instruction.downstream_event_id)
                        del self._online_instruction_evidence[action_id]
                        del self._online_pending_sources[action_id]
                    elif instruction is not None and fetched and instruction.expected_mmio is None:
                        del self._online_instruction_evidence[action_id]
                        del self._online_pending_sources[action_id]
                    elif instruction is not None and instruction.superseded:
                        del self._online_instruction_evidence[action_id]
                        del self._online_pending_sources[action_id]
                    elif (not isinstance(pending_case.source, OnlineInstruction)
                          and pin_evidence is None):
                        # Other port sources have no downstream provenance yet.
                        del self._online_pending_sources[action_id]
                decision["interaction_source_gains"] = self._credit_online_interactions(
                    interaction)
                decision["closed_loop_feedback"] = self._closed_loop_step(
                    interaction=interaction, failures=tuple(violations))
                feedback_ready_at = time.monotonic()
                phase_timing['feedback_credit'] = feedback_ready_at - checked_at
                coverage = bytes(int(target.target_id in hits) for target in self.targets)
                trace, plan_hex = None, None
                if status != "complete":
                    self._session_stop_reason = status
                    trace, plan_hex = self._finish_online_session()
                receipt = ScenarioRfuzzReceipt(
                    self.run_id, batch.buffer_id, slot, raw_hash, case_hash,
                    semantic_hash, status, sum(ticks.values()), coverage.hex(),
                    violations, None, trace,
                    (trace.manifest_sha256 if trace else
                     self.session.manifest_sha256 if self.session is not None else None),
                    ticks, case.path_id, (selected.source_id,), 0, index,
                    effective_genome_sha256=case_hash,
                    applied_source_ids=tuple(dict.fromkeys(consumed_sources)),
                    interaction_feedback=interaction, online_case=document,
                    online_weights=weights, online_plan_hex=plan_hex,
                    source_action=decision["source_action"],
                    closed_loop_feedback=decision["closed_loop_feedback"])
                phase_timing['receipt_build'] = time.monotonic() - feedback_ready_at
            except Exception as exc:
                # A decode refusal and a source-action refusal both touch no RTL
                # and consume no reservation, so both stay clean refusals.
                invalid = ((case is None or pre_rtl_refusal)
                           and isinstance(exc, ValueError))
                # Only a pre-RTL refusal covered by candidate_rejection.v1 becomes
                # a structured rejection. An unclassified error and any
                # post-submit uncertainty keep their handling and invent no code.
                rejection = rejection_of(exc) if invalid else None
                decision["rejection"] = (None if rejection is None
                                         else rejection.document())
                if (self.case_witness_recorder is not None
                        and pre_rtl_refusal and case is not None):
                    # A pre-RTL refusal produced no RTL event slice at all, so
                    # the case is recorded as an explicit null plus reason
                    # instead of a fabricated zero.  Its declared accesses stay
                    # in the gate's own decision record.
                    self.case_witness_recorder.observe_case(
                        case_id=case.case_id,
                        component=case.source.component,
                        source_kind=("instruction"
                                     if isinstance(case.source, OnlineInstruction)
                                     else "source_event"),
                        events=None)
                trace, plan_hex = None, None
                budget_exhausted = (isinstance(exc, ScenarioBudgetExhausted)
                                    or self.session.runner.failure_status == "budget_exhausted"
                                    or self._session_stop_reason == "budget_exhausted")
                from myfuzz.scenario.contracts import ProtocolEnvironmentError
                uncertain_effect = (
                    not isinstance(exc, ProtocolEnvironmentError)
                    and (self.session.runner.failure_status == "uncertain_effect"
                         or getattr(self.session, "_halt_reason", None) == "uncertain_effect"))
                error_status = ("input_invalid" if invalid else
                                "budget_exhausted" if budget_exhausted else
                                "dut_violation" if self._session_stop_reason == "dut_violation"
                                and violations else
                                "uncertain_effect" if uncertain_effect else "environment_error")
                error_interaction = None
                if not invalid:
                    if not self._online_finish_attempted:
                        try:
                            self._interaction.ingest(self.session.runner.events_since(
                                self._online_feedback_event_end))
                            error_interaction = self._interaction.incremental_summary()
                        except (ValueError, RuntimeError):
                            pass
                    # A case that failed after touching the session may still
                    # have settled a certificate; the journal slice is read by
                    # identity, never inferred from the failed status.
                    decision["closed_loop_feedback"] = self._closed_loop_step(
                        interaction=error_interaction)
                    if self._session_stop_reason is None:
                        self._session_stop_reason = error_status
                    try:
                        trace, plan_hex = self._finish_online_session()
                    except Exception:
                        trace = self._online_final_trace
                        plan_hex = self._online_final_plan_hex
                receipt = ScenarioRfuzzReceipt(
                    self.run_id, batch.buffer_id, slot, raw_hash, None, None,
                    error_status, 0,
                    coverage.hex(), violations if error_status == "dut_violation" else (),
                    f"{type(exc).__name__}: {exc}", trace,
                    interaction_feedback=error_interaction,
                    online_case=asdict(case) if case is not None else None,
                    online_weights=weights, online_plan_hex=plan_hex,
                    rejection=decision["rejection"],
                    source_action=decision["source_action"],
                    closed_loop_feedback=decision["closed_loop_feedback"])
            decision["status"] = receipt.status
            phase_timing['total'] = time.monotonic() - slot_started
            decision['phase_timing_seconds'] = phase_timing
            if decision["admitted_status"] == "submit_attempted":
                decision["admitted_status"] = "submit_failed_or_partial"
            if decision["committed"]:
                decision["candidate_disposition"] = "admitted"
                decision["candidate_disposition_reason"] = "rtl_case_committed"
            elif commit_refused:
                decision["candidate_disposition"] = "uncertain"
                decision["candidate_disposition_reason"] = "commit_after_submit_uncertain"
            elif decision["admitted_status"] == "submit_failed_or_partial":
                decision["candidate_disposition"] = "uncertain"
                decision["candidate_disposition_reason"] = "rtl_submit_failed_or_partial"
            elif case is None:
                decision["candidate_disposition"] = "rejected"
                decision["candidate_disposition_reason"] = "decode_rejected"
            elif (decision["source_action"] or {}).get("refusal") is not None:
                # The declared source action could not be admitted before any
                # RTL command; the stable reason rides the existing keys.
                decision["candidate_disposition"] = "rejected"
                decision["candidate_disposition_reason"] = (
                    decision["source_action"]["refusal"]["reason"])
            else:
                decision["candidate_disposition"] = "rejected"
                decision["candidate_disposition_reason"] = "pre_submit_validation_rejected"
            if (receipt.online_plan_hex is not None and self.evidence_dir is not None
                    and not self._online_terminal_evidence_saved):
                # Plan includes every admitted case and instruction reservation;
                # the last raw slot is supplementary evidence, not replay input.
                document = {"schema_version": "scenario_online_rfuzz_evidence.v1",
                            "receipt": receipt,
                            "online_decisions": self.online_decisions,
                            "raw_records_hex": [record.hex() for record in records],
                            "replay_entrypoint": "replay_online_session"}
                run_hash = hashlib.sha256(self.run_id.encode()).hexdigest()[:8]
                destination = self.evidence_dir / (
                    f"online_{receipt.status}_{run_hash}_{batch.buffer_id}_{slot}_{raw_hash[:16]}.json")
                temporary_path = None
                try:
                    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False,
                            dir=self.evidence_dir, prefix=".online-") as handle:
                        temporary_path = Path(handle.name)
                        for fragment in canonical_json_chunks(document):
                            handle.write(fragment)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary_path, destination)
                    self._online_terminal_evidence_saved = True
                finally:
                    if temporary_path is not None:
                        temporary_path.unlink(missing_ok=True)
            self.receipts.append(receipt)
            self._completed[identity] = (raw_hash, coverage, receipt)
            self._max_completed_buffer_id = (batch.buffer_id if self._max_completed_buffer_id is None
                                            else max(batch.buffer_id, self._max_completed_buffer_id))
            if self.first_receipt_completed_at is None:
                self.first_receipt_completed_at = time.monotonic()
            coverages.append(coverage)
            if on_receipt is not None:
                on_receipt(receipt)
        if len(self.receipts) > before_batch:
            self._latest_completed_batch = tuple(self.receipts[before_batch:])
        return tuple(coverages)

    def process_owned_pair(self, input_id: int, coverage_id: int, *,
                           creator_pid: int,
                           on_receipt: Callable[[ScenarioRfuzzReceipt], None] | None = None
                           ) -> tuple[int, int]:
        """Use existing RFuzz SysV framing with slot-aware execution identity."""
        if input_id == coverage_id:
            raise ValueError("input and coverage shared-memory IDs alias")
        with OwnedSegment(input_id, creator_pid=creator_pid) as inputs, \
                OwnedSegment(coverage_id, creator_pid=creator_pid,
                             writable=True) as outputs:
            batch = parse_input_buffer(inputs.read(), input_bytes=RECORD_BYTES,
                                       max_cycles=(self.decoder.max_records if self.decoder is not None else
                                                   self.online_decoder.max_input_bytes // RECORD_BYTES))
            stride = ((self.counter_count + 2 + 7) // 8) * 8
            if 16 + stride * len(batch.tests) > outputs.size:
                raise ValueError("RFuzz coverage capacity is insufficient")
            coverages = (self.execute_batch(batch) if on_receipt is None
                         else self.execute_batch(batch, on_receipt=on_receipt))
            outputs.write(encode_coverage_buffer(
                batch, coverages, counter_count=self.counter_count,
                capacity=outputs.size))
        return coverage_id, input_id
