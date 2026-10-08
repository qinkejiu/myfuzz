"""Versioned source actions, explicit prerequisites and bounded cross-case effects.

P3 requires one upstream source action per testcase with a declared
prerequisite set, source ownership, termination observation and local step
budget, plus cross-case dependencies that are consumed through *explicit*
witnesses instead of a fixed ISR script.  This module owns that contract:

* :class:`SourceAction` is one immutable, versioned ``instruction`` or
  ``external_event`` input decision.  ``payload`` is the *mutable* payload, so
  only ``ownership == "fuzzable"`` actions may carry one; ``bound`` and
  ``fixed`` actions must stay empty because their value is owned by a real
  producer or a fixed declaration outside this record.  CPU IRQ can never be
  driven by a fuzzable action: the declared ``flow_id`` of a driven action is
  one of ``F1..F6``, while the ``interrupt_flow`` token is accepted only inside
  ``prerequisites`` or ``termination_observation``.
* :class:`Prerequisite` is an ordered, content-addressed requirement naming an
  exact piece of real evidence (a RAM byte commit id, an IP register commit
  observation, a delivered/taken IRQ sample, or "this reserved instruction slot
  is still unmaterialized").
* :class:`CrossCaseEffectTracker` records only real evidence that it can
  validate, keyed by exact subject, and answers ``satisfied(action)`` with an
  explicit missing list.  Retention is bounded: capacity eviction, aging and
  reset drop evidence for good, so a later duplicate cannot restore it.
* :class:`SourceActionGate` is the pre-admission query used by callers (and by
  ``ScenarioSession`` when a gate is configured): it refuses an action whose
  prerequisites are not witnessed and ingests the receipt events of admitted
  cases so the next case can consume them.
* :class:`InstructionSlotReservationGate` is one *declared policy* over that
  gate: it binds each instruction action to the exact fetch slot the action
  itself declares it will fill and registers that reservation in the tracker
  before the query.  A fixed slot prerequisite cannot be satisfiable for a
  moving online cursor, so the address has to be the case's own declared one;
  the policy, not the case, owns the reservation reference and the bound.

Nothing here executes instructions, drives CPU results, or invents RTL
semantics.  A witness proves that a recorded observation matched a declared
requirement; it never claims an unobserved causal chain.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
import hashlib
import json
import re
from types import MappingProxyType

ACTION_SCHEMA_VERSION = "source_action.v1"
PREREQUISITE_SCHEMA_VERSION = "source_prerequisite.v1"
TERMINATION_SCHEMA_VERSION = "source_termination_observation.v1"
WITNESS_SCHEMA_VERSION = "cross_case_effect_witness.v1"
EVALUATION_SCHEMA_VERSION = "prerequisite_evaluation.v1"
TRACKER_SCHEMA_VERSION = "cross_case_effect_tracker.v1"
GATE_SCHEMA_VERSION = "source_action_gate.v1"
SLOT_RESERVATION_GATE_SCHEMA_VERSION = "instruction_slot_reservation_gate.v1"

ACTION_KINDS = ("instruction", "external_event")
OWNERSHIP_KINDS = ("fuzzable", "bound", "fixed")
#: Flow categories a source action may actually drive.
DRIVEN_FLOW_IDS = ("F1", "F2", "F3", "F4", "F5", "F6")
#: The interrupt flow is an observation target, never an injectable source.
INTERRUPT_FLOW = "interrupt_flow"
OBSERVED_FLOW_IDS = DRIVEN_FLOW_IDS + (INTERRUPT_FLOW,)
ENDPOINT_CLASSES = ("environment_source", "ip_external_source")
#: Declared endpoint classes that mean "this fuzzable source is the CPU IRQ".
CPU_IRQ_ENDPOINT_CLASSES = ("cpu_irq", "interrupt")

PREREQUISITE_KINDS = ("ram_byte_version", "ip_register_version",
                      "irq_pulse_pending", "irq_input_delivered", "irq_taken",
                      "instruction_slot_unmaterialized",
                      # A declared serial/transport resource must be idle before
                      # this action may be admitted (for example the OpenTitan
                      # UART RX waveform a TL-UL access would collide with).
                      "transport_idle")
IRQ_PREREQUISITE_KINDS = ("irq_pulse_pending", "irq_input_delivered", "irq_taken")
EFFECT_KINDS = ("ram_byte_version", "ip_register_version", "irq_pulse_pending",
                "irq_input_delivered", "irq_taken")
TERMINATION_KINDS = ("consumption", "retirement", "delivery", "incomplete")
TERMINATION_FLOWS = OBSERVED_FLOW_IDS

RETAINED_REASON = "missing_effects"
MATERIALIZED_REASON = "materialized_instruction_slot"
UNKNOWN_SLOT_REASON = "unknown_instruction_slot"
DEGRADED_REASON = "degraded_tracker"

DEFAULT_MAX_EFFECTS = 4096
DEFAULT_MAX_AGE_EVENTS = 131072
DEFAULT_MAX_SLOTS = 512
DEFAULT_MAX_COMPONENTS = 64
MAX_LOCAL_STEP_BUDGET = 1_000_000
MAX_SOURCE_WIDTH_BITS = 1 << 16

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RESET_KINDS = frozenset(("reset_barrier", "gpio_reset_resource", "reset_resource"))
_PULSE_END_KINDS = frozenset(("pulse_expired", "expired_masked",
                              "pulse_cancelled_by_reset", "source_end"))
_MATERIALIZATION_KINDS = frozenset(("instruction_source", "memory_write"))
_SLOT_WORD_BYTES = 4
_SUBJECT_FIELDS = {
    "ram_byte_version": ("memory_id", "generation", "byte_offset"),
    "ip_register_version": ("component", "register", "reset_epoch"),
    "irq_pulse_pending": ("component", "source_event_id"),
    "irq_input_delivered": ("cpu_component", "source_event_id", "cpu_tick"),
    "irq_taken": ("cpu_component", "source_event_id", "cpu_tick"),
    "instruction_slot_unmaterialized": ("component", "address"),
    "instruction_slot_reserved": ("component", "address"),
    "instruction_slot_materialized": ("component", "address"),
    "transport_idle": ("transport", "local_tick", "horizon_tick"),
}


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _text(value: object, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def _uint(value: object, name: str, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def _digest_text(value: object, name: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _aligned(value: object, name: str) -> int:
    _uint(value, name)
    if value % 4:
        raise ValueError(f"{name} must be word aligned")
    return value


def _freeze(subject: Mapping) -> Mapping:
    """Copy one flat subject/payload mapping into an immutable proxy."""
    if not isinstance(subject, Mapping):
        raise ValueError("source action subject must be a mapping")
    frozen = {}
    for key, value in subject.items():
        _text(key, "subject field name")
        if type(value) is bool or not isinstance(value, (int, str)):
            raise ValueError("subject values must be integers or strings")
        if isinstance(value, str):
            _text(value, f"subject value {key}")
        frozen[key] = value
    return MappingProxyType(frozen)


# --------------------------------------------------------------------------
# evidence reference derivations; ingestion and callers must agree exactly
# --------------------------------------------------------------------------

def ram_commit_evidence_ref(commit_id: str) -> str:
    """Exact evidence reference of one commit-stream RAM byte commit."""
    return _digest_text(commit_id, "commit_id")


def legacy_memory_write_evidence_ref(event_id: int) -> str:
    """Exact evidence reference of one legacy ``memory_write`` journal event."""
    return f"memory_write:{_uint(event_id, 'event_id')}"


def ip_register_evidence_ref(component: str, register: str, reset_epoch: int,
                             observation_event_id: int, version: int) -> str:
    """Exact evidence reference of one observed IP register commit."""
    return (f"gpio_register_commit.v1:{_text(component, 'component')}:"
            f"{_uint(reset_epoch, 'reset_epoch')}:"
            f"{_uint(observation_event_id, 'observation_event_id')}:"
            f"{_text(register, 'register')}:{_uint(version, 'version')}")


def irq_pulse_evidence_ref(component: str, source_event_id: int) -> str:
    """Exact evidence reference of one pending IRQ pulse."""
    return (f"irq_pulse_start.v1:{_text(component, 'component')}:"
            f"{_uint(source_event_id, 'source_event_id')}")


def irq_input_evidence_ref(cpu_component: str, source_event_id: int,
                           cpu_tick: int) -> str:
    """Exact evidence reference of one IRQ sample actually delivered to the CPU."""
    return (f"cpu_irq_input.v1:{_text(cpu_component, 'cpu_component')}:"
            f"{_uint(source_event_id, 'source_event_id')}:"
            f"{_uint(cpu_tick, 'cpu_tick')}")


def irq_taken_evidence_ref(cpu_component: str, source_event_id: int,
                           cpu_tick: int) -> str:
    """Exact evidence reference of one IRQ actually taken by the CPU."""
    return (f"cpu_irq_taken.v1:{_text(cpu_component, 'cpu_component')}:"
            f"{_uint(source_event_id, 'source_event_id')}:"
            f"{_uint(cpu_tick, 'cpu_tick')}")


# --------------------------------------------------------------------------
# prerequisite values
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Prerequisite:
    """One ordered, content-addressed prerequisite of a source action.

    ``evidence_ref`` names the exact observation that must be witnessed; a
    witness for the same subject with different evidence never satisfies it.
    """

    kind: str
    subject: Mapping
    evidence_ref: str
    flow_id: str | None = None
    prerequisite_id: str = ""

    def __post_init__(self) -> None:
        if self.kind not in PREREQUISITE_KINDS:
            raise ValueError(f"unsupported prerequisite kind {self.kind!r}")
        subject = _validated_subject(self.kind, self.subject)
        object.__setattr__(self, "subject", subject)
        _text(self.evidence_ref, "prerequisite evidence_ref")
        if self.kind in IRQ_PREREQUISITE_KINDS:
            if self.flow_id != INTERRUPT_FLOW:
                raise ValueError(
                    "IRQ prerequisites must declare flow_id "
                    f"{INTERRUPT_FLOW!r}; the interrupt flow is observed only")
        elif self.flow_id is not None:
            raise ValueError("only IRQ observation prerequisites may declare flow_id")
        expected = _digest(self._material())
        if self.prerequisite_id and self.prerequisite_id != expected:
            raise ValueError(
                "prerequisite_id does not match canonical prerequisite material")
        object.__setattr__(self, "prerequisite_id", expected)

    @classmethod
    def create(cls, kind: str, subject: Mapping, evidence_ref: str, *,
               flow_id: str | None = None) -> Prerequisite:
        return cls(kind=kind, subject=subject, evidence_ref=evidence_ref,
                   flow_id=flow_id)

    def _material(self) -> dict:
        return {"schema_version": PREREQUISITE_SCHEMA_VERSION, "kind": self.kind,
                "subject": dict(self.subject), "evidence_ref": self.evidence_ref,
                "flow_id": self.flow_id}

    def document(self) -> dict:
        return {**self._material(), "prerequisite_id": self.prerequisite_id}

    @classmethod
    def from_document(cls, document: object) -> Prerequisite:
        fields = {"schema_version", "kind", "subject", "evidence_ref", "flow_id",
                  "prerequisite_id"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("prerequisite has unknown or missing fields")
        if document["schema_version"] != PREREQUISITE_SCHEMA_VERSION:
            raise ValueError("unsupported prerequisite schema_version")
        # A loaded record must carry its own content digest; recomputing a
        # missing one would accept a tampered document.
        _digest_text(document["prerequisite_id"], "prerequisite_id")
        return cls(kind=document["kind"], subject=document["subject"],
                   evidence_ref=document["evidence_ref"],
                   flow_id=document["flow_id"],
                   prerequisite_id=document["prerequisite_id"])

    def __hash__(self) -> int:
        return hash(self.prerequisite_id)


def _validated_subject(kind: str, subject: Mapping) -> Mapping:
    expected = _SUBJECT_FIELDS[kind]
    if not isinstance(subject, Mapping) or set(subject) != set(expected):
        raise ValueError(
            f"{kind} prerequisite subject requires exactly {list(expected)}")
    frozen = _freeze(subject)
    if kind in ("ram_byte_version", "ip_register_version", "irq_pulse_pending",
                "irq_input_delivered", "irq_taken"):
        for name in ("generation", "byte_offset", "reset_epoch", "source_event_id",
                     "cpu_tick"):
            if name in frozen:
                _uint(frozen[name], f"subject {name}")
    if kind.startswith("instruction_slot"):
        _aligned(frozen["address"], "subject address")
    if kind == "transport_idle":
        _text(frozen["transport"], "subject transport")
        _uint(frozen["local_tick"], "subject local_tick")
        _uint(frozen["horizon_tick"], "subject horizon_tick")
    return frozen


def ram_commit_prerequisite(memory_id: str, generation: int, byte_offset: int,
                            commit_id: str) -> Prerequisite:
    """Require one committed RAM byte at an exact commit-stream evidence id."""
    return Prerequisite.create("ram_byte_version",
        {"memory_id": _text(memory_id, "memory_id"), "generation": generation,
         "byte_offset": byte_offset}, ram_commit_evidence_ref(commit_id))


def legacy_write_prerequisite(memory_id: str, generation: int, byte_offset: int,
                              event_id: int) -> Prerequisite:
    """Require one committed RAM byte witnessed by a legacy write event."""
    return Prerequisite.create("ram_byte_version",
        {"memory_id": _text(memory_id, "memory_id"), "generation": generation,
         "byte_offset": byte_offset}, legacy_memory_write_evidence_ref(event_id))


def ip_register_prerequisite(component: str, register: str, reset_epoch: int,
                             observation_event_id: int, version: int) -> Prerequisite:
    """Require one IP register commit observed at an exact version."""
    return Prerequisite.create("ip_register_version",
        {"component": _text(component, "component"),
         "register": _text(register, "register"), "reset_epoch": reset_epoch},
        ip_register_evidence_ref(component, register, reset_epoch,
                                 observation_event_id, version))


def irq_pulse_pending_prerequisite(component: str, source_event_id: int) -> Prerequisite:
    """Require one IRQ source pulse that is still pending delivery."""
    return Prerequisite.create("irq_pulse_pending",
        {"component": _text(component, "component"),
         "source_event_id": source_event_id},
        irq_pulse_evidence_ref(component, source_event_id),
        flow_id=INTERRUPT_FLOW)


def irq_input_delivered_prerequisite(cpu_component: str, source_event_id: int,
                                     cpu_tick: int) -> Prerequisite:
    """Require one IRQ sample actually delivered into the CPU IRQ input."""
    return Prerequisite.create("irq_input_delivered",
        {"cpu_component": _text(cpu_component, "cpu_component"),
         "source_event_id": source_event_id, "cpu_tick": cpu_tick},
        irq_input_evidence_ref(cpu_component, source_event_id, cpu_tick),
        flow_id=INTERRUPT_FLOW)


def irq_taken_prerequisite(cpu_component: str, source_event_id: int,
                           cpu_tick: int) -> Prerequisite:
    """Require one IRQ actually taken (accepted) by the CPU at a measured tick."""
    return Prerequisite.create("irq_taken",
        {"cpu_component": _text(cpu_component, "cpu_component"),
         "source_event_id": source_event_id, "cpu_tick": cpu_tick},
        irq_taken_evidence_ref(cpu_component, source_event_id, cpu_tick),
        flow_id=INTERRUPT_FLOW)


def instruction_slot_unmaterialized_prerequisite(component: str, address: int,
                                                 reservation_ref: str) -> Prerequisite:
    """Require a reserved instruction slot that is still unmaterialized.

    This is a negative requirement: it is satisfied only while the tracker
    holds the named reservation and no real materialization of that slot.
    """
    return Prerequisite.create("instruction_slot_unmaterialized",
        {"component": _text(component, "component"),
         "address": _aligned(address, "address")},
        _text(reservation_ref, "reservation_ref"))


# --------------------------------------------------------------------------
# termination observation and source action
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class TerminationObservation:
    """How one case ends: a real consumption/retirement/delivery, or incomplete."""

    kind: str
    evidence_ref: str
    flow_id: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in TERMINATION_KINDS:
            raise ValueError(f"unsupported termination kind {self.kind!r}")
        if self.flow_id is not None and self.flow_id not in TERMINATION_FLOWS:
            raise ValueError(
                "termination observation flow_id must be F1..F6 or "
                f"{INTERRUPT_FLOW!r}")
        if self.kind == "incomplete":
            if self.evidence_ref != "":
                raise ValueError(
                    "an incomplete termination observation must not name "
                    "evidence_ref")
        else:
            _text(self.evidence_ref, "termination evidence_ref")

    def document(self) -> dict:
        return {"schema_version": TERMINATION_SCHEMA_VERSION, "kind": self.kind,
                "evidence_ref": self.evidence_ref, "flow_id": self.flow_id}

    @classmethod
    def from_document(cls, document: object) -> TerminationObservation:
        fields = {"schema_version", "kind", "evidence_ref", "flow_id"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("termination observation has unknown or missing fields")
        if document["schema_version"] != TERMINATION_SCHEMA_VERSION:
            raise ValueError("unsupported termination observation schema_version")
        return cls(document["kind"], document["evidence_ref"], document["flow_id"])


def _normalized_payload(kind: str, ownership: str, payload: Mapping) -> Mapping:
    if ownership != "fuzzable":
        if not isinstance(payload, Mapping) or len(payload):
            raise ValueError(
                "non-fuzzable source action must not carry a mutable payload")
        return MappingProxyType({})
    if not isinstance(payload, Mapping):
        raise ValueError("source action payload must be a mapping")
    if kind == "instruction":
        fields = {"address", "words_hex"}
        if set(payload) != fields:
            raise ValueError("instruction payload has unknown or missing fields")
        address = _aligned(payload["address"], "instruction payload address")
        words = payload["words_hex"]
        if type(words) is not str or not words:
            raise ValueError("instruction payload words_hex must be nonempty")
        try:
            raw = bytes.fromhex(words)
        except ValueError as exc:
            raise ValueError("instruction payload words_hex must be hexadecimal") from exc
        if raw.hex() != words:
            raise ValueError("instruction payload words_hex must be canonical "
                             "lowercase hex")
        if len(raw) % 4:
            raise ValueError("instruction payload words_hex must contain whole "
                             "32-bit words")
        return _freeze({"address": address, "words_hex": words})
    fields = {"port", "bit_offset", "width", "value", "endpoint_class"}
    if not set(payload) <= fields or not {"port", "bit_offset", "width",
                                          "value"} <= set(payload):
        raise ValueError("external_event payload has unknown or missing fields")
    port = _text(payload["port"], "external_event payload port")
    bit_offset = _uint(payload["bit_offset"], "external_event payload bit_offset")
    width = _uint(payload["width"], "external_event payload width",
                  maximum=MAX_SOURCE_WIDTH_BITS)
    if width < 1:
        raise ValueError("external_event payload width must be at least 1")
    value = _uint(payload["value"], "external_event payload value")
    endpoint_class = payload.get("endpoint_class", ENDPOINT_CLASSES[0])
    if endpoint_class in CPU_IRQ_ENDPOINT_CLASSES:
        raise ValueError(
            f"external_event payload endpoint_class {endpoint_class!r} cannot be "
            "a mutable source: the CPU IRQ is a bound real output")
    if endpoint_class not in ENDPOINT_CLASSES:
        raise ValueError(
            f"unknown external_event payload endpoint_class {endpoint_class!r}")
    if value >= 1 << width:
        raise ValueError("external_event payload value must be < 2**width")
    normalized = {"port": port, "bit_offset": bit_offset, "width": width,
                  "value": value, "endpoint_class": endpoint_class}
    if INTERRUPT_FLOW in _canonical(normalized):
        raise ValueError(
            f"{INTERRUPT_FLOW!r} may only appear in termination_observation or "
            "prerequisites, never in a mutable payload")
    return _freeze(normalized)


@dataclass(frozen=True)
class SourceAction:
    """One immutable, versioned upstream source action with its prerequisites."""

    action_id: str
    kind: str
    component: str
    source_id: str
    ownership: str
    flow_id: str
    payload: Mapping
    termination_observation: TerminationObservation
    local_step_budget: int
    prerequisites: tuple[Prerequisite, ...] = ()
    action_sha256: str = ""

    def __post_init__(self) -> None:
        _text(self.action_id, "action_id")
        if self.kind not in ACTION_KINDS:
            raise ValueError(f"unsupported source action kind {self.kind!r}")
        _text(self.component, "component")
        _text(self.source_id, "source_id")
        if self.ownership not in OWNERSHIP_KINDS:
            raise ValueError(f"unsupported source action ownership {self.ownership!r}")
        if self.flow_id == INTERRUPT_FLOW:
            raise ValueError(
                f"flow_id {INTERRUPT_FLOW!r} may only be observed in "
                "termination_observation or prerequisites, not driven by an action")
        if self.flow_id not in DRIVEN_FLOW_IDS:
            raise ValueError(f"unsupported driven flow_id {self.flow_id!r}")
        object.__setattr__(self, "payload",
                           _normalized_payload(self.kind, self.ownership,
                                               self.payload))
        if not isinstance(self.termination_observation, TerminationObservation):
            raise ValueError("source action requires a termination observation")
        if (type(self.local_step_budget) is not int or self.local_step_budget < 1
                or self.local_step_budget > MAX_LOCAL_STEP_BUDGET):
            raise ValueError(
                f"local_step_budget must be an integer in 1..{MAX_LOCAL_STEP_BUDGET}")
        if (not isinstance(self.prerequisites, tuple)
                or any(not isinstance(item, Prerequisite)
                       for item in self.prerequisites)):
            raise ValueError("prerequisites must be an immutable tuple")
        identities = [item.prerequisite_id for item in self.prerequisites]
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate prerequisite in source action")
        expected = _digest(self._material())
        if self.action_sha256 and self.action_sha256 != expected:
            raise ValueError(
                "action_sha256 does not match canonical source action material")
        object.__setattr__(self, "action_sha256", expected)

    @property
    def payload_mutable(self) -> bool:
        """Whether this action carries a payload the fuzzer may vary."""
        return self.ownership == "fuzzable"

    def _material(self) -> dict:
        return {"schema_version": ACTION_SCHEMA_VERSION, "action_id": self.action_id,
                "kind": self.kind, "component": self.component,
                "source_id": self.source_id, "ownership": self.ownership,
                "flow_id": self.flow_id, "payload": dict(self.payload),
                "prerequisites": [item.document() for item in self.prerequisites],
                "termination_observation": self.termination_observation.document(),
                "local_step_budget": self.local_step_budget}

    def document(self) -> dict:
        return {**self._material(), "action_sha256": self.action_sha256}

    @classmethod
    def from_document(cls, document: object) -> SourceAction:
        fields = {"schema_version", "action_id", "kind", "component", "source_id",
                  "ownership", "flow_id", "payload", "prerequisites",
                  "termination_observation", "local_step_budget", "action_sha256"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("source action has unknown or missing fields")
        if document["schema_version"] != ACTION_SCHEMA_VERSION:
            raise ValueError("unsupported source action schema_version")
        if type(document["prerequisites"]) is not list:
            raise ValueError("source action prerequisites must be a list")
        _digest_text(document["action_sha256"], "action_sha256")
        return cls(action_id=document["action_id"], kind=document["kind"],
                   component=document["component"], source_id=document["source_id"],
                   ownership=document["ownership"], flow_id=document["flow_id"],
                   payload=document["payload"],
                   termination_observation=TerminationObservation.from_document(
                       document["termination_observation"]),
                   local_step_budget=document["local_step_budget"],
                   prerequisites=tuple(Prerequisite.from_document(item)
                                       for item in document["prerequisites"]),
                   action_sha256=document["action_sha256"])

    def __hash__(self) -> int:
        return hash(self.action_sha256)


# --------------------------------------------------------------------------
# effect witnesses and evaluation
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class EffectWitness:
    """One validated real observation retained for later cases."""

    kind: str
    subject: Mapping
    evidence_ref: str
    event_id: int
    version: tuple[int, ...] | None = None
    value: int | None = None
    case_id: str | None = None
    witness_id: str = ""

    def __post_init__(self) -> None:
        if self.kind not in EFFECT_KINDS and self.kind not in (
                "instruction_slot_reserved", "instruction_slot_materialized"):
            raise ValueError(f"unsupported effect witness kind {self.kind!r}")
        if self.kind in _SUBJECT_FIELDS:
            object.__setattr__(self, "subject",
                               _validated_subject(self.kind, self.subject))
        else:
            object.__setattr__(self, "subject", _freeze(self.subject))
        _text(self.evidence_ref, "witness evidence_ref")
        _uint(self.event_id, "witness event_id")
        if self.version is not None:
            if (not isinstance(self.version, tuple)
                    or any(type(item) is not int or item < 0 for item in self.version)):
                raise ValueError("witness version must be a tuple of integers")
        if self.value is not None:
            _uint(self.value, "witness value")
        if self.case_id is not None:
            _text(self.case_id, "witness case_id")
        expected = _digest(self._material())
        if self.witness_id and self.witness_id != expected:
            raise ValueError("witness_id does not match canonical witness material")
        object.__setattr__(self, "witness_id", expected)

    def _material(self) -> dict:
        return {"schema_version": WITNESS_SCHEMA_VERSION, "kind": self.kind,
                "subject": dict(self.subject), "evidence_ref": self.evidence_ref,
                "event_id": self.event_id,
                "version": (list(self.version) if self.version is not None else None),
                "value": self.value, "case_id": self.case_id}

    def document(self) -> dict:
        return {**self._material(), "witness_id": self.witness_id}

    @classmethod
    def from_document(cls, document: object) -> EffectWitness:
        fields = {"schema_version", "kind", "subject", "evidence_ref", "event_id",
                  "version", "value", "case_id", "witness_id"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("effect witness has unknown or missing fields")
        if document["schema_version"] != WITNESS_SCHEMA_VERSION:
            raise ValueError("unsupported effect witness schema_version")
        _digest_text(document["witness_id"], "witness_id")
        version = document["version"]
        return cls(kind=document["kind"], subject=document["subject"],
                   evidence_ref=document["evidence_ref"],
                   event_id=document["event_id"],
                   version=None if version is None else tuple(version),
                   value=document["value"], case_id=document["case_id"],
                   witness_id=document["witness_id"])

    def __hash__(self) -> int:
        return hash(self.witness_id)


@dataclass(frozen=True)
class PrerequisiteEvaluation:
    """Result of one prerequisite query; ``bool`` is the admission answer."""

    action_id: str
    satisfied: bool
    missing: tuple[Prerequisite, ...] = ()
    matched: tuple[str, ...] = ()
    reason: str = "satisfied"

    def __bool__(self) -> bool:
        return self.satisfied

    def document(self) -> dict:
        return {"schema_version": EVALUATION_SCHEMA_VERSION,
                "action_id": self.action_id, "satisfied": self.satisfied,
                "reason": self.reason,
                "reason_field": "source_action.prerequisites",
                "missing": [item.document() for item in self.missing],
                "matched_evidence_refs": list(self.matched)}


# --------------------------------------------------------------------------
# bounded cross-case effect tracker
# --------------------------------------------------------------------------

class CrossCaseEffectTracker:
    """Retain real committed effects; never infer them and never revive them.

    Witnesses come only from events that validate against a declared shape
    (commit-stream RAM commit, legacy write with per-lane versions, observed IP
    register commit, IRQ pulse/delivery/take) or from an explicit instruction
    slot reservation.  Every witness keeps its exact evidence reference.

    Retention is bounded by ``max_effects`` records, ``max_age_events`` journal
    distance and ``max_slots`` reserved words.  Capacity eviction, aging and
    reset are permanent: dropped evidence is refused if it is offered again, so
    ``satisfied`` can never be restored by replaying an old event.
    """

    def __init__(self, *, max_effects: int = DEFAULT_MAX_EFFECTS,
                 max_age_events: int = DEFAULT_MAX_AGE_EVENTS,
                 max_slots: int = DEFAULT_MAX_SLOTS,
                 max_components: int = DEFAULT_MAX_COMPONENTS) -> None:
        for value, name in ((max_effects, "max_effects"),
                            (max_age_events, "max_age_events"),
                            (max_slots, "max_slots"),
                            (max_components, "max_components")):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.max_effects = max_effects
        self.max_age_events = max_age_events
        self.max_slots = max_slots
        self.max_components = max_components
        self._effects: "OrderedDict[tuple[str, str], EffectWitness]" = OrderedDict()
        self._barred: "OrderedDict[tuple[str, str], str]" = OrderedDict()
        self._slots: "OrderedDict[str, OrderedDict[int, EffectWitness]]" = OrderedDict()
        self._materialized: "OrderedDict[tuple[str, int], EffectWitness]" = OrderedDict()
        self._pulse_watermarks: "OrderedDict[str, int]" = OrderedDict()
        self._counters = {name: 0 for name in
                          ("malformed", "refused_evidence", "stale", "evicted",
                           "expired", "conflicts", "resets", "refused",
                           "slot_evictions", "restored_attempts",
                           "ram_byte_queries", "ram_byte_entries_examined")}
        self._cursor = 0
        self._epoch = 0
        self._retire_floor = 0
        self._degraded = False

    # -- introspection ----------------------------------------------------
    @property
    def cursor(self) -> int:
        """Highest journal event id observed so far."""
        return self._cursor

    @property
    def epoch(self) -> int:
        """Number of measured reset boundaries applied to retained evidence."""
        return self._epoch

    @property
    def degraded(self) -> bool:
        """Whether a bounded-evidence conflict barred every further claim."""
        return self._degraded

    @property
    def counters(self) -> dict:
        return dict(self._counters)

    @property
    def bounds(self) -> dict:
        return {"max_effects": self.max_effects,
                "max_age_events": self.max_age_events,
                "max_slots": self.max_slots,
                "max_components": self.max_components,
                "max_pending": self.max_effects + 2 * self.max_slots}

    @property
    def pending_count(self) -> int:
        """Retained effect, reservation and materialization records."""
        return (len(self._effects) + len(self._materialized)
                + sum(len(words) for words in self._slots.values()))

    def document(self) -> dict:
        """Bounded snapshot; witnesses are summarized by digest, not copied."""
        return {"schema_version": TRACKER_SCHEMA_VERSION, "epoch": self._epoch,
                "cursor": self._cursor, "effect_count": len(self._effects),
                "slot_count": sum(len(words) for words in self._slots.values()),
                "materialized_count": len(self._materialized),
                "pending_count": self.pending_count, "degraded": self._degraded,
                "bounds": self.bounds, "counters": self.counters,
                "retire_floor": self._retire_floor,
                "effect_digest": _digest(sorted(
                    (kind, subject, witness.evidence_ref)
                    for (kind, subject), witness in self._effects.items()))}

    # -- ingestion --------------------------------------------------------
    def ingest(self, events: Iterable[Mapping], *,
               case_id: str | None = None) -> tuple[EffectWitness, ...]:
        """Validate and retain real evidence; malformed input creates nothing."""
        if isinstance(events, (str, bytes)) or not isinstance(events, Iterable):
            raise ValueError("events must be an iterable of journal mappings")
        if case_id is not None:
            _text(case_id, "case_id")
        created = []
        for event in events:
            created.extend(self._ingest_event(event, case_id))
        return tuple(created)

    def register_instruction_slot(self, component: str, address: int,
                                  reservation_ref: str, *, event_id: int,
                                  count: int = 1) -> tuple[EffectWitness, ...]:
        """Record an explicit reserved-slot declaration; no memory is touched."""
        _text(component, "component")
        _aligned(address, "address")
        _text(reservation_ref, "reservation_ref")
        _uint(event_id, "event_id")
        if type(count) is not int or count < 1:
            raise ValueError("slot count must be a positive integer")
        if event_id <= self._retire_floor:
            self._counters["stale"] += 1
            return ()
        self._cursor = max(self._cursor, event_id)
        words = self._slots.setdefault(component, OrderedDict())
        created = []
        for index in range(count):
            word = address + index * _SLOT_WORD_BYTES
            previous = words.get(word)
            witness = EffectWitness("instruction_slot_reserved",
                                    {"component": component, "address": word},
                                    reservation_ref, event_id)
            if previous is not None:
                if previous.evidence_ref != reservation_ref:
                    self._bar(("instruction_slot_reserved",
                               _canonical({"component": component, "address": word})))
                words.move_to_end(word)
                continue
            words[word] = witness
            created.append(witness)
            while sum(len(entry) for entry in self._slots.values()) > self.max_slots:
                oldest = next(iter(self._slots))
                dropped = self._slots[oldest].popitem(last=False)[1]
                self._counters["slot_evictions"] += 1
                self._retire_floor = max(self._retire_floor, dropped.event_id)
                if not self._slots[oldest]:
                    del self._slots[oldest]
        return tuple(created)

    def reset(self, *, event_id: int, reason: str = "reset_barrier") -> None:
        """Drop every witness at a measured boundary; old evidence cannot return."""
        _uint(event_id, "event_id")
        _text(reason, "reason")
        self._apply_reset(event_id)

    def advance_cursor(self, event_id: int) -> None:
        """Move the age horizon without adding evidence (bounded aging hook)."""
        _uint(event_id, "event_id")
        if event_id <= self._retire_floor:
            self._counters["stale"] += 1
            return
        self._cursor = max(self._cursor, event_id)
        self._prune_aged()

    def note_refusal(self) -> None:
        """Count one caller-visible refusal without changing retained evidence."""
        self._counters["refused"] += 1

    # -- queries ----------------------------------------------------------
    def satisfied(self, action: SourceAction | Iterable[Prerequisite]
                  ) -> PrerequisiteEvaluation:
        """Return True-like only when every prerequisite has exact evidence."""
        if isinstance(action, SourceAction):
            action_id, prerequisites = action.action_id, action.prerequisites
        elif isinstance(action, Prerequisite):
            action_id, prerequisites = "", (action,)
        else:
            if isinstance(action, (str, bytes)):
                raise ValueError("satisfied requires a source action or prerequisites")
            action_id = ""
            prerequisites = tuple(action)
            if any(not isinstance(item, Prerequisite) for item in prerequisites):
                raise ValueError("satisfied requires prerequisite values")
        if not prerequisites:
            return PrerequisiteEvaluation(action_id, True)
        if self._degraded:
            return PrerequisiteEvaluation(action_id, False, prerequisites, (),
                                          DEGRADED_REASON)
        missing, matched, reasons = [], [], set()
        for prerequisite in prerequisites:
            witness, reason = self._match(prerequisite)
            if witness is None:
                missing.append(prerequisite)
                reasons.add(reason)
            else:
                matched.append(witness.evidence_ref)
        if missing:
            reason = reasons.pop() if len(reasons) == 1 else RETAINED_REASON
            return PrerequisiteEvaluation(action_id, False, tuple(missing),
                                          tuple(matched), reason)
        return PrerequisiteEvaluation(action_id, True, (), tuple(matched))

    def matching_witness(self, prerequisite: Prerequisite) -> EffectWitness | None:
        """Return the retained witness satisfying this requirement, if any."""
        if not isinstance(prerequisite, Prerequisite):
            raise ValueError("matching_witness requires a prerequisite")
        witness, _ = self._match(prerequisite)
        return witness

    def retained_ram_witnesses(self, memory_id: str, byte_offset: int
                               ) -> tuple[EffectWitness, ...]:
        """Retained versions of one exact RAM byte, deterministically ordered.

        This is a read of the tracker's *existing* bounded index: it walks the
        retained effect map (at most ``max_effects`` entries, the same index
        ``satisfied`` reads) and never the journal, so evidence already dropped
        by capacity eviction, aging or reset can never be selected again.  The
        order is ``LATEST_EFFECT_ORDER``: highest ``event_id``, then highest
        memory ``generation``, then greatest ``evidence_ref``; the head of the
        order is therefore the latest retained version of that byte.  Counters
        record how many entries were examined, so a reviewer can bound the cost
        of any "latest" claim by the tracker's own declared capacity.
        """
        _text(memory_id, "memory_id")
        _uint(byte_offset, "byte_offset")
        self._counters["ram_byte_queries"] += 1
        self._counters["ram_byte_entries_examined"] += len(self._effects)
        rows = [witness for witness in self._effects.values()
                if witness.kind == "ram_byte_version"
                and witness.subject.get("memory_id") == memory_id
                and witness.subject.get("byte_offset") == byte_offset]
        rows.sort(key=lambda item: (item.event_id, item.subject["generation"],
                                    item.evidence_ref), reverse=True)
        return tuple(rows)

    def _match(self, prerequisite: Prerequisite) -> tuple[EffectWitness | None, str]:
        if prerequisite.kind == "instruction_slot_unmaterialized":
            words = self._slots.get(prerequisite.subject["component"])
            reservation = None if words is None else words.get(
                prerequisite.subject["address"])
            if reservation is None or reservation.evidence_ref != prerequisite.evidence_ref:
                return None, UNKNOWN_SLOT_REASON
            materialized = self._materialized.get(
                (prerequisite.subject["component"], prerequisite.subject["address"]))
            if materialized is not None:
                return None, MATERIALIZED_REASON
            return reservation, "satisfied"
        key = (prerequisite.kind, _canonical(dict(prerequisite.subject)))
        witness = self._effects.get(key)
        if witness is None or witness.evidence_ref != prerequisite.evidence_ref:
            return None, RETAINED_REASON
        return witness, "satisfied"

    # -- internals --------------------------------------------------------
    def _apply_reset(self, event_id: int) -> None:
        self._epoch += 1
        self._counters["resets"] += 1
        self._retire_floor = max(self._retire_floor, event_id)
        self._cursor = max(self._cursor, event_id)
        self._effects.clear()
        self._barred.clear()
        self._slots.clear()
        self._materialized.clear()
        self._pulse_watermarks.clear()
        self._degraded = False

    def _bar(self, key: tuple[str, str]) -> None:
        self._counters["conflicts"] += 1
        if key in self._barred:
            self._barred.move_to_end(key)
            return
        self._barred[key] = "conflicting_evidence"
        if len(self._barred) > self.max_effects:
            self._degraded = True

    def _prune_aged(self) -> None:
        limit = self._cursor - self.max_age_events
        while self._effects:
            key, oldest = next(iter(self._effects.items()))
            if oldest.event_id >= limit:
                break
            del self._effects[key]
            self._retire_floor = max(self._retire_floor, oldest.event_id)
            self._counters["expired"] += 1

    def _store_effect(self, witness: EffectWitness) -> EffectWitness | None:
        if self._degraded:
            return None
        key = (witness.kind, _canonical(dict(witness.subject)))
        if key in self._barred:
            self._counters["refused_evidence"] += 1
            return None
        previous = self._effects.get(key)
        if previous is not None:
            if previous.event_id == witness.event_id:
                if previous.document() == witness.document():
                    return None
                self._bar(key)
                return None
            if previous.event_id > witness.event_id:
                self._counters["stale"] += 1
                return None
            del self._effects[key]
        self._effects[key] = witness
        while len(self._effects) > self.max_effects:
            _, dropped = self._effects.popitem(last=False)
            self._retire_floor = max(self._retire_floor, dropped.event_id)
            self._counters["evicted"] += 1
        return witness

    def _note_materialization(self, event: Mapping, event_id: int) -> None:
        kind = event.get("kind")
        if kind not in _MATERIALIZATION_KINDS:
            return
        component = event.get("component")
        address = event.get("address")
        if (type(component) is not str or not component
                or type(address) is not int or address < 0):
            return
        words = self._slots.get(component)
        if not words:
            return
        offsets = self._materialization_offsets(event)
        if offsets is None:
            return
        for offset in offsets:
            word = offset - (offset % _SLOT_WORD_BYTES)
            if word not in words or (component, word) in self._materialized:
                continue
            if len(self._materialized) >= self.max_slots:
                self._degraded = True
                return
            self._materialized[(component, word)] = EffectWitness(
                "instruction_slot_materialized",
                {"component": component, "address": word},
                f"{kind}:{event_id}:{offset}", event_id)

    @staticmethod
    def _materialization_offsets(event: Mapping) -> tuple[int, ...] | None:
        address = event.get("address")
        if event.get("kind") == "instruction_source":
            data_hex = event.get("data_hex")
            if type(data_hex) is not str or not data_hex:
                return None
            try:
                length = len(bytes.fromhex(data_hex))
            except ValueError:
                return None
            return tuple(address + index for index in range(length)) if length else None
        width = event.get("width_bytes")
        byte_enable = event.get("byte_enable")
        if (type(width) is not int or width < 1 or type(byte_enable) is not int
                or byte_enable < 0 or byte_enable >= 1 << width):
            return None
        return tuple(address + lane for lane in range(width)
                     if byte_enable >> lane & 1)

    def _ingest_event(self, event: object,
                      case_id: str | None) -> tuple[EffectWitness, ...]:
        if not isinstance(event, Mapping):
            self._counters["malformed"] += 1
            return ()
        event_id = event.get("event_id")
        if type(event_id) is not int or event_id < 0:
            self._counters["malformed"] += 1
            return ()
        if event_id <= self._retire_floor:
            self._counters["stale"] += 1
            self._counters["restored_attempts"] += 1
            return ()
        kind = event.get("kind")
        if type(kind) is not str or not kind:
            self._counters["malformed"] += 1
            return ()
        if kind in _RESET_KINDS or kind.endswith("_reset"):
            self._apply_reset(event_id)
            return ()
        self._cursor = max(self._cursor, event_id)
        self._prune_aged()
        self._note_materialization(event, event_id)
        if kind == "memory_write_commit":
            return self._commit_witness(event, event_id, case_id)
        if kind == "memory_write":
            return self._legacy_write_witness(event, event_id, case_id)
        if kind == "gpio_register_commit":
            return self._register_witness(event, event_id, case_id)
        if kind == "pulse_start":
            return self._pulse_witness(event, event_id, case_id)
        if kind == "cpu_irq_input":
            return self._irq_input_witness(event, event_id, case_id)
        if kind == "cpu_irq_taken":
            return self._irq_taken_witness(event, event_id, case_id)
        if kind in _PULSE_END_KINDS:
            self._retire_pulse(event)
        return ()

    def _commit_witness(self, event: Mapping, event_id: int,
                        case_id: str | None) -> tuple[EffectWitness, ...]:
        document = event.get("commit_document")
        commit_id = event.get("commit_id")
        if (not isinstance(document, Mapping) or type(commit_id) is not str
                or _DIGEST.fullmatch(commit_id) is None
                or document.get("commit_id") != commit_id
                or document.get("commit_status") != "complete"
                or document.get("version") is None):
            self._counters["malformed"] += 1
            return ()
        memory_id = document.get("memory_id")
        generation = document.get("generation")
        cells = document.get("enabled_byte_cells")
        if (type(memory_id) is not str or not memory_id
                or type(generation) is not int or generation < 0
                or type(cells) is not list or not cells):
            self._counters["malformed"] += 1
            return ()
        created = []
        for cell in cells:
            if (not isinstance(cell, Mapping)
                    or type(cell.get("byte_offset")) is not int
                    or cell["byte_offset"] < 0):
                self._counters["malformed"] += 1
                continue
            version = cell.get("version")
            if (not isinstance(version, (list, tuple)) or len(version) != 2
                    or any(type(item) is not int or item < 0 for item in version)):
                self._counters["malformed"] += 1
                continue
            value = cell.get("value")
            if value is not None and (type(value) is not int or not 0 <= value < 256):
                self._counters["malformed"] += 1
                continue
            stored = self._store_effect(EffectWitness("ram_byte_version",
                {"memory_id": memory_id, "generation": generation,
                 "byte_offset": cell["byte_offset"]},
                ram_commit_evidence_ref(commit_id), event_id,
                tuple(version), value, case_id))
            if stored is not None:
                created.append(stored)
        return tuple(created)

    def _legacy_write_witness(self, event: Mapping, event_id: int,
                              case_id: str | None) -> tuple[EffectWitness, ...]:
        memory_id = event.get("memory_id")
        generation = event.get("generation")
        byte_offset = event.get("byte_offset")
        version = event.get("version")
        width = event.get("width_bytes")
        byte_enable = event.get("byte_enable")
        if (type(memory_id) is not str or not memory_id
                or type(generation) is not int or generation < 0
                or type(byte_offset) is not int or byte_offset < 0
                or not isinstance(version, (list, tuple)) or len(version) != 2
                or any(type(item) is not int or item < 0 for item in version)
                or type(width) is not int or width < 1
                or type(byte_enable) is not int or byte_enable < 1
                or byte_enable >= 1 << width):
            self._counters["malformed"] += 1
            return ()
        created = []
        for lane in range(width):
            if not byte_enable >> lane & 1:
                continue
            stored = self._store_effect(EffectWitness("ram_byte_version",
                {"memory_id": memory_id, "generation": generation,
                 "byte_offset": byte_offset + lane},
                legacy_memory_write_evidence_ref(event_id), event_id,
                tuple(version), None, case_id))
            if stored is not None:
                created.append(stored)
        return tuple(created)

    def _register_witness(self, event: Mapping, event_id: int,
                          case_id: str | None) -> tuple[EffectWitness, ...]:
        component = event.get("component")
        register = event.get("register")
        reset_epoch = event.get("reset_epoch")
        observation = event.get("observation_event_id")
        resources = event.get("bit_resources")
        if (event.get("status") != "observed"
                or type(component) is not str or not component
                or type(register) is not str or not register
                or type(reset_epoch) is not int or reset_epoch < 0
                or type(observation) is not int or observation < 0
                or not isinstance(resources, list) or not resources):
            self._counters["refused_evidence"] += 1
            return ()
        versions = [item.get("version") for item in resources
                    if isinstance(item, Mapping)]
        if len(versions) != len(resources) or any(
                type(item) is not int or item < 0 for item in versions):
            self._counters["malformed"] += 1
            return ()
        version = max(versions)
        value = event.get("post_value")
        if value is not None and (type(value) is not int or value < 0):
            self._counters["malformed"] += 1
            return ()
        return self._stored(EffectWitness("ip_register_version",
            {"component": component, "register": register,
             "reset_epoch": reset_epoch},
            ip_register_evidence_ref(component, register, reset_epoch,
                                     observation, version),
            event_id, (version,), value, case_id))

    def _pulse_witness(self, event: Mapping, event_id: int,
                       case_id: str | None) -> tuple[EffectWitness, ...]:
        component = event.get("component")
        source_event_id = event.get("source_event_id")
        if (type(component) is not str or not component
                or type(source_event_id) is not int or source_event_id < 1):
            self._counters["malformed"] += 1
            return ()
        if source_event_id <= self._pulse_watermarks.get(component, 0):
            self._counters["refused_evidence"] += 1
            return ()
        return self._stored(EffectWitness("irq_pulse_pending",
            {"component": component, "source_event_id": source_event_id},
            irq_pulse_evidence_ref(component, source_event_id), event_id,
            None, event.get("start_cpu_tick"), case_id))

    def _irq_input_witness(self, event: Mapping, event_id: int,
                           case_id: str | None) -> tuple[EffectWitness, ...]:
        if event.get("value") != 1:
            self._counters["refused_evidence"] += 1
            return ()
        return self._cpu_irq_witness("irq_input_delivered", event, event_id,
                                     case_id, irq_input_evidence_ref)

    def _irq_taken_witness(self, event: Mapping, event_id: int,
                           case_id: str | None) -> tuple[EffectWitness, ...]:
        return self._cpu_irq_witness("irq_taken", event, event_id, case_id,
                                     irq_taken_evidence_ref)

    def _cpu_irq_witness(self, kind: str, event: Mapping, event_id: int,
                         case_id: str | None, reference
                         ) -> tuple[EffectWitness, ...]:
        component = event.get("component")
        source_event_id = event.get("source_event_id")
        cpu_tick = event.get("cpu_tick")
        if (type(component) is not str or not component
                or type(source_event_id) is not int or source_event_id < 1
                or type(cpu_tick) is not int or cpu_tick < 0):
            self._counters["malformed"] += 1
            return ()
        return self._stored(EffectWitness(kind,
            {"cpu_component": component, "source_event_id": source_event_id,
             "cpu_tick": cpu_tick},
            reference(component, source_event_id, cpu_tick), event_id,
            None, None, case_id))

    def _stored(self, witness: EffectWitness) -> tuple[EffectWitness, ...]:
        stored = self._store_effect(witness)
        return () if stored is None else (stored,)

    def _retire_pulse(self, event: Mapping) -> None:
        component = event.get("component")
        source_event_id = event.get("source_event_id")
        if (type(component) is not str or not component
                or type(source_event_id) is not int or source_event_id < 1):
            self._counters["malformed"] += 1
            return
        if component not in self._pulse_watermarks:
            if len(self._pulse_watermarks) >= self.max_components:
                # Losing a watermark could revive an expired pulse.
                self._degraded = True
                return
            self._pulse_watermarks[component] = 0
        self._pulse_watermarks[component] = max(
            self._pulse_watermarks[component], source_event_id)
        self._pulse_watermarks.move_to_end(component)
        key = ("irq_pulse_pending",
               _canonical({"component": component,
                           "source_event_id": source_event_id}))
        if self._effects.pop(key, None) is not None:
            self._counters["expired"] += 1


# --------------------------------------------------------------------------
# explicit pre-admission gate
# --------------------------------------------------------------------------

class SourceActionError(ValueError):
    """Base class for refused source-action operations."""


class SourceActionUnknownAction(SourceActionError):
    """A case or action was queried without being registered in the gate."""


class SourceActionInputMismatch(SourceActionError):
    """A case input does not match the registered action it claims to be."""


class SourceActionPrerequisiteError(SourceActionError):
    """A registered action was refused because evidence is missing."""

    def __init__(self, evaluation: PrerequisiteEvaluation) -> None:
        self.evaluation = evaluation
        missing = ", ".join(item.kind for item in evaluation.missing)
        super().__init__(
            f"source action {evaluation.action_id!r} prerequisites are not "
            f"satisfied ({evaluation.reason}): {missing}")


class SourceActionSlotWindowError(SourceActionError):
    """An instruction action names a word outside the declared slot window."""


#: Declared payload field to the case attribute names that may carry it.
#: ``source_action.v1`` names the declared instruction bytes ``words_hex``
#: while the online case record names the same declared bytes ``data_hex``, so
#: the input check compares one declaration instead of one spelling.
_PAYLOAD_ATTRIBUTES = {
    "instruction": (("address", ("address",)),
                    ("words_hex", ("words_hex", "data_hex"))),
    "external_event": (("port", ("port",)), ("bit_offset", ("bit_offset",)),
                       ("width", ("width",)), ("value", ("value",))),
}


def _declared_attribute(source: object, name: str, spellings: tuple[str, ...],
                        action: SourceAction) -> object:
    """One case attribute under whichever declared spelling the case carries."""
    present = [spelling for spelling in spellings if hasattr(source, spelling)]
    if not present:
        raise SourceActionInputMismatch(
            f"case source does not declare {name} for action "
            f"{action.action_id!r} (expected one of {list(spellings)})")
    values = {getattr(source, spelling) for spelling in present}
    if len(values) != 1:
        # Two spellings of one declared value disagree; refuse instead of
        # choosing one.
        raise SourceActionInputMismatch(
            f"case source declares conflicting {name} spellings for action "
            f"{action.action_id!r}: "
            + ", ".join(f"{spelling}={getattr(source, spelling)!r}"
                        for spelling in present))
    return getattr(source, present[0])


@dataclass
class SourceActionGate:
    """Explicit pre-admission prerequisite gate and effect ingest point.

    A caller registers the :class:`SourceAction` of each case, queries
    ``require``/``require_case`` before any RTL command, and passes each
    admitted receipt to ``observe`` so real effects become available to later
    cases.  With ``enforce=False`` the gate records every refusal and still
    returns the action; it never weakens an evaluation.
    """

    tracker: CrossCaseEffectTracker
    enforce: bool = True
    _actions: dict = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.tracker, CrossCaseEffectTracker):
            raise ValueError("gate requires a CrossCaseEffectTracker")
        if type(self.enforce) is not bool:
            raise ValueError("gate enforce flag must be boolean")

    @property
    def action_ids(self) -> tuple[str, ...]:
        return tuple(self._actions)

    def register(self, action: SourceAction) -> SourceAction:
        if not isinstance(action, SourceAction):
            raise ValueError("gate requires a SourceAction")
        previous = self._actions.get(action.action_id)
        if previous is not None and previous != action:
            raise ValueError(
                f"conflicting registration for action_id {action.action_id}")
        self._actions[action.action_id] = action
        return action

    def evaluate(self, action: SourceAction | str) -> PrerequisiteEvaluation:
        return self._evaluate_resolved(self._resolve(action))

    def require(self, action: SourceAction | str) -> SourceAction:
        resolved = self._resolve(action)
        evaluation = self._evaluate_resolved(resolved)
        if not evaluation.satisfied and self.enforce:
            raise SourceActionPrerequisiteError(evaluation)
        return resolved

    def _evaluate_resolved(self, action: SourceAction) -> PrerequisiteEvaluation:
        evaluation = self.tracker.satisfied(action)
        if not evaluation.satisfied:
            self.tracker.note_refusal()
        return evaluation

    def require_case(self, case: object) -> SourceAction:
        """Bind one online case to its registered action, then check evidence.

        The case must carry exactly the input the action declares; otherwise a
        case could ride another action's prerequisites.  Both checks run before
        any RTL command.
        """
        source = getattr(case, "source", None)
        action_id = getattr(source, "action_id", None)
        if type(action_id) is not str or not action_id:
            raise SourceActionUnknownAction(
                "online case source action is not registered in this gate")
        resolved = self._resolve(action_id)
        self._assert_case_input(resolved, source)
        evaluation = self._evaluate_resolved(resolved)
        if not evaluation.satisfied and self.enforce:
            raise SourceActionPrerequisiteError(evaluation)
        return resolved

    @staticmethod
    def _assert_case_input(action: SourceAction, source: object) -> None:
        component = getattr(source, "component", None)
        if component != action.component:
            raise SourceActionInputMismatch(
                f"case source component {component!r} differs from action "
                f"component {action.component!r}")
        if not action.payload_mutable:
            return
        for name, spellings in _PAYLOAD_ATTRIBUTES[action.kind]:
            actual = _declared_attribute(source, name, spellings, action)
            declared = action.payload[name]
            if actual != declared or type(actual) is not type(declared):
                raise SourceActionInputMismatch(
                    f"case source {name}={actual!r} differs from action "
                    f"{action.action_id!r} declared {declared!r}")

    def observe(self, receipt: object) -> tuple[EffectWitness, ...]:
        """Retain the real events of one admitted case as cross-case effects."""
        events = getattr(receipt, "events", None)
        if events is None:
            raise ValueError("gate observe requires a receipt with events")
        case_id = getattr(receipt, "case_id", None)
        return self.tracker.ingest(events, case_id=case_id)

    def _resolve(self, action: SourceAction | str) -> SourceAction:
        if isinstance(action, SourceAction):
            registered = self._actions.get(action.action_id)
            if registered is None or registered != action:
                raise SourceActionUnknownAction(
                    f"source action {action.action_id!r} is not registered in "
                    "this gate")
            return registered
        if type(action) is not str or not action:
            raise ValueError("gate requires an action or action_id")
        registered = self._actions.get(action)
        if registered is None:
            raise SourceActionUnknownAction(
                f"source action id {action!r} is not registered in this gate")
        return registered

    @property
    def counters(self) -> dict:
        return self.tracker.counters

    def document(self) -> dict:
        return {"schema_version": GATE_SCHEMA_VERSION,
                "enforce": self.enforce, "action_ids": list(self._actions),
                "tracker": self.tracker.document()}


@dataclass
class InstructionSlotReservationGate:
    """Bind every instruction case to the still-unmaterialized slot it fills.

    Declared policy (one rule, no per-case invention), applied by
    :meth:`register` before :meth:`require_case` queries the tracker:

    * an action of kind ``instruction`` on the declared ``component`` gets one
      ``instruction_slot_unmaterialized`` prerequisite per 32-bit word its own
      payload will write (``address`` .. ``address + len(words_hex)/2``), with
      the exact evidence reference
      ``f"{reservation_ref_prefix}:{address:#010x}"``;
    * registering the action also *is* the reservation: the gate records that
      exact reservation in the tracker (``register_instruction_slot``) with the
      same reference, at the session position immediately after the last
      observed journal event.  Nothing is registered before the case that names
      it and the address comes from the action's own declared payload, so a
      fixed slot prerequisite -- which could be satisfied for at most one case
      of a moving online cursor -- is never invented;
    * an instruction action on the declared component whose words leave the
      declared window is refused fail-closed, because admitting it would leave
      the case ungated;
    * any other action (another component, or kind ``external_event``) is
      delegated unchanged, so the policy widens no other flow.

    Bounded: the number of distinct words a case can name is the declared word
    count ``(last_address - first_address) // 4``, so a lazily registered
    reservation can never exceed it.  Construction refuses a tracker whose
    ``max_slots`` capacity is smaller than that bound, because such a tracker
    could evict or degrade a reservation before the case that declares it is
    admitted.  Live reservations are one word per admitted instruction case
    (two for an eight-byte fragment); the declared window is never registered
    up front.

    The gate never satisfies its own requirement: the reservation only says the
    slot is *reserved*, while real ``instruction_source``/Store evidence from a
    previous case is what materializes it and refuses every later case that
    names it (``materialized_instruction_slot``).
    """

    gate: SourceActionGate
    component: str
    first_address: int
    last_address: int
    reservation_ref_prefix: str
    _bound: dict = field(default_factory=dict, repr=False)
    _position: int = field(default=0, repr=False)
    _counters: dict = field(default_factory=lambda: {
        "bound_actions": 0, "reservations": 0, "redeclared_reservations": 0,
        "refused_out_of_window": 0, "queries": 0, "refusals": 0}, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.gate, SourceActionGate):
            raise ValueError("slot reservation gate requires a SourceActionGate")
        _text(self.component, "slot reservation component")
        _aligned(self.first_address, "slot reservation first_address")
        _aligned(self.last_address, "slot reservation last_address")
        if self.first_address >= self.last_address:
            raise ValueError("slot reservation window must be nonempty and "
                             "strictly increasing")
        _text(self.reservation_ref_prefix, "slot reservation_ref_prefix")
        if self.gate.tracker.max_slots < self.declared_words:
            raise ValueError(
                "slot reservation window exceeds the tracker slot capacity: "
                f"{self.declared_words} declared words require max_slots >= "
                f"{self.declared_words}, tracker holds {self.gate.tracker.max_slots}")

    # -- declared policy --------------------------------------------------
    @property
    def declared_words(self) -> int:
        """Distinct 32-bit words the declared window can ever reserve."""
        return (self.last_address - self.first_address) // _SLOT_WORD_BYTES

    def reservation_ref(self, address: int) -> str:
        """Exact declared evidence reference of one reserved online word."""
        return (f"{self.reservation_ref_prefix}:"
                f"{_aligned(address, 'address'):#010x}")

    def declaration(self) -> dict:
        """The bounded policy a reviewer can recompute from a receipt."""
        return {"component": self.component,
                "first_address": self.first_address,
                "last_address": self.last_address,
                "word_bytes": _SLOT_WORD_BYTES,
                "declared_words": self.declared_words,
                "reservation_ref_prefix": self.reservation_ref_prefix,
                "registration": "lazy_per_admitted_case",
                "prerequisite_kind": "instruction_slot_unmaterialized"}

    # -- gate protocol ----------------------------------------------------
    def register(self, action: SourceAction) -> SourceAction:
        """Bind, register and reserve; returns the action actually admitted."""
        bound = self._bind(action)
        registered = self.gate.register(bound)
        self._bound[registered.action_id] = registered
        self._reserve(registered)
        return registered

    def require_case(self, case: object) -> SourceAction:
        self._counters["queries"] += 1
        try:
            return self.gate.require_case(case)
        except SourceActionPrerequisiteError:
            self._counters["refusals"] += 1
            raise

    def evaluate(self, action: SourceAction | str) -> PrerequisiteEvaluation:
        if isinstance(action, str):
            return self.gate.evaluate(action)
        resolved = self._bound.get(getattr(action, "action_id", None), action)
        return self.gate.evaluate(resolved)

    def require(self, action: SourceAction | str) -> SourceAction:
        return self.gate.require(action)

    def observe(self, receipt: object) -> tuple[EffectWitness, ...]:
        return self.gate.observe(receipt)

    @property
    def tracker(self) -> CrossCaseEffectTracker:
        return self.gate.tracker

    @property
    def enforce(self) -> bool:
        return self.gate.enforce

    @property
    def action_ids(self) -> tuple[str, ...]:
        return self.gate.action_ids

    @property
    def counters(self) -> dict:
        return {**self.gate.counters, **self._counters}

    def document(self) -> dict:
        return {"schema_version": SLOT_RESERVATION_GATE_SCHEMA_VERSION,
                "enforce": self.gate.enforce,
                "declaration": self.declaration(),
                "counters": dict(self._counters),
                "action_ids": list(self.gate.action_ids),
                "gate": self.gate.document()}

    # -- internals --------------------------------------------------------
    def _bind(self, action: SourceAction) -> SourceAction:
        if not isinstance(action, SourceAction):
            raise ValueError("slot reservation gate requires a SourceAction")
        if action.kind != "instruction" or action.component != self.component:
            return action
        address = action.payload["address"]
        length = len(bytes.fromhex(action.payload["words_hex"]))
        words = tuple(range(address, address + length, _SLOT_WORD_BYTES))
        if (not words or words[0] < self.first_address
                or words[-1] + _SLOT_WORD_BYTES > self.last_address):
            self._counters["refused_out_of_window"] += 1
            raise SourceActionSlotWindowError(
                f"instruction action {action.action_id!r} writes words "
                f"{words[0]:#x}..{words[-1] + _SLOT_WORD_BYTES:#x}, outside the "
                f"declared slot window {self.first_address:#x}..{self.last_address:#x}")
        prerequisites = tuple(action.prerequisites) + tuple(
            instruction_slot_unmaterialized_prerequisite(
                self.component, word, self.reservation_ref(word))
            for word in words)
        identities = [item.prerequisite_id for item in prerequisites]
        if len(set(identities)) != len(identities):
            raise SourceActionSlotWindowError(
                f"instruction action {action.action_id!r} already declares a "
                "prerequisite for one of its own slots")
        self._counters["bound_actions"] += 1
        return replace(action, prerequisites=prerequisites, action_sha256="")

    def _reserve(self, action: SourceAction) -> None:
        for prerequisite in action.prerequisites:
            if prerequisite.kind != "instruction_slot_unmaterialized":
                continue
            position = max(self.gate.tracker.cursor, self._position) + 1
            self._position = position
            created = self.gate.tracker.register_instruction_slot(
                prerequisite.subject["component"], prerequisite.subject["address"],
                prerequisite.evidence_ref, event_id=position)
            if created:
                self._counters["reservations"] += len(created)
            else:
                self._counters["redeclared_reservations"] += 1


# --------------------------------------------------------------------------
# dynamic prerequisite binding: bounded, trusted, recomputable
# --------------------------------------------------------------------------
#
# The tracker above answers "was this *exact* committed version witnessed?".
# A gate that admits case N still has to name that version *before* the case
# runs, and the version is only decided by the evidence an earlier case really
# produced.  The capability below closes that gap without inventing evidence:
#
# * a *trusted declaration* fixes the only ``(memory_id, byte_offset)`` pairs and
#   the only writer kinds (``STORE``/``ISR``/...) a binding may ever consume;
# * a *binder* selects the latest retained version of one declared byte from the
#   tracker's own bounded retained index (never a journal rescan), pins it as a
#   ``ram_byte_version`` prerequisite of the action, and returns a
#   ``bound_witness.v1`` proof document naming the selected witness;
# * selection is deterministic (``LATEST_EFFECT_ORDER``) and re-checkable: the
#   proof carries content digests and ``verify`` re-reads live tracker state;
# * every policy violation is refused fail-closed, and a request that would turn
#   a committed RAM byte into a fuzzable CPU input is refused explicitly.

BOUND_WITNESS_SCHEMA_VERSION = "bound_witness.v1"
DYNAMIC_EFFECT_BINDING_SCHEMA_VERSION = "dynamic_effect_binding.v1"
DYNAMIC_PREREQUISITE_BINDER_SCHEMA_VERSION = "dynamic_prerequisite_binder.v1"
TRUSTED_RAM_DECLARATION_SCHEMA_VERSION = "trusted_ram_byte_declaration.v1"

#: Deterministic order retained RAM byte versions are considered in: highest
#: journal event id first, then highest memory generation, then the
#: lexicographically greatest evidence reference.  The head of that order is the
#: "latest" witness.  Two retained witnesses can only tie on the first key when
#: the same journal event carried both generations, and on the second key only
#: for one subject -- which the tracker keeps exactly once -- so the reference
#: key is the total-order completion, never a coin flip.
LATEST_EFFECT_ORDER = ("event_id_desc", "generation_desc", "evidence_ref_desc")
SELECTION_STRATEGY = "latest_retained_ram_byte_evidence"

#: Unbound reasons: no prerequisite is injected, and the caller can see why.
UNBOUND_NO_WITNESS = "no_retained_witness"
UNBOUND_WRITER_KIND = "writer_kind_not_declared"
UNBOUND_PROVENANCE = "untrusted_source_provenance"
UNBOUND_VALUE = "missing_witness_value"
#: The reason recorded when a witness was selected and the prerequisite injected.
BOUND_REASON = "bound_latest_retained_witness"

_MISSING = object()


class DynamicBindingError(ValueError):
    """Base class for refused dynamic prerequisite operations."""


class DynamicBindingRefused(DynamicBindingError):
    """A request, declaration or claim was refused fail-closed."""

    def __init__(self, reason: str, detail: str) -> None:
        _text(reason, "refusal reason")
        _text(detail, "refusal detail")
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")


class DynamicBindingUnbound(DynamicBindingError):
    """No retained witness matched the trusted declaration."""

    def __init__(self, reason: str, detail: str) -> None:
        _text(reason, "unbound reason")
        _text(detail, "unbound detail")
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")


def _kind_tuple(values: object, name: str) -> tuple[str, ...]:
    """Validate one declared/requested writer-kind whitelist."""
    if not isinstance(values, tuple) or not values:
        raise ValueError(f"{name} must be a nonempty tuple of kind tokens")
    seen = set()
    for value in values:
        _text(value, name)
        if value != value.strip() or value.upper() != value:
            raise ValueError(f"{name} must be uppercase tokens")
        if value.casefold() in seen:
            raise ValueError(f"{name} must be unique")
        seen.add(value.casefold())
    return tuple(values)


@dataclass(frozen=True)
class TrustedRamByteDeclaration:
    """The only RAM bytes and writer kinds a dynamic binding may consume.

    Declared by the operator (never by a fuzzable case), bounded by construction
    and content-addressed so a reviewer can recompute which policy a
    ``bound_witness.v1`` proof was selected under.  An empty ``writer_kinds``
    means "the declaration does not constrain the writer"; a nonempty one is a
    closed whitelist that no request may widen.
    """

    memory_id: str
    byte_offsets: tuple[int, ...]
    writer_kinds: tuple[str, ...] = ()
    declaration_id: str = ""

    def __post_init__(self) -> None:
        _text(self.memory_id, "declaration memory_id")
        if not isinstance(self.byte_offsets, tuple) or not self.byte_offsets:
            raise ValueError("declaration byte_offsets must be a nonempty tuple")
        for offset in self.byte_offsets:
            _uint(offset, "declaration byte_offset")
        if tuple(sorted(set(self.byte_offsets))) != self.byte_offsets:
            raise ValueError(
                "declaration byte_offsets must be strictly increasing and unique")
        if self.writer_kinds:
            _kind_tuple(self.writer_kinds, "declaration writer_kinds")
        expected = _digest(self._material())
        if self.declaration_id and self.declaration_id != expected:
            raise ValueError(
                "declaration_id does not match canonical declaration material")
        object.__setattr__(self, "declaration_id", expected)

    @property
    def requires_writer_kind(self) -> bool:
        """Whether the declaration closes the set of acceptable writer kinds."""
        return bool(self.writer_kinds)

    def allows(self, memory_id: str, byte_offset: int) -> bool:
        """Whether one exact ``(memory_id, byte_offset)`` pair is declared."""
        return memory_id == self.memory_id and byte_offset in self.byte_offsets

    def allows_writer_kind(self, writer_kind: object) -> bool:
        """Whether one recorded writer kind is acceptable to this declaration."""
        if not self.writer_kinds:
            return True
        return writer_kind in self.writer_kinds

    def _material(self) -> dict:
        return {"schema_version": TRUSTED_RAM_DECLARATION_SCHEMA_VERSION,
                "memory_id": self.memory_id,
                "byte_offsets": list(self.byte_offsets),
                "writer_kinds": list(self.writer_kinds)}

    def document(self) -> dict:
        return {**self._material(), "declaration_id": self.declaration_id}

    @classmethod
    def from_document(cls, document: object) -> TrustedRamByteDeclaration:
        fields = {"schema_version", "memory_id", "byte_offsets", "writer_kinds",
                  "declaration_id"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("declaration has unknown or missing fields")
        if document["schema_version"] != TRUSTED_RAM_DECLARATION_SCHEMA_VERSION:
            raise ValueError("unsupported declaration schema_version")
        _digest_text(document["declaration_id"], "declaration_id")
        if (not isinstance(document["byte_offsets"], list)
                or not isinstance(document["writer_kinds"], list)):
            raise ValueError("declaration whitelists must be lists")
        return cls(memory_id=document["memory_id"],
                   byte_offsets=tuple(document["byte_offsets"]),
                   writer_kinds=tuple(document["writer_kinds"]),
                   declaration_id=document["declaration_id"])


@dataclass(frozen=True)
class BoundWitness:
    """``bound_witness.v1``: the exact retained witness a prerequisite pinned.

    Every field is copied from tracker state at selection time and covered by
    ``bound_witness_id``, so editing the reference, event id, value, case or
    generation is detected on load.  ``verify`` additionally re-reads live
    tracker state, so a self-consistent forgery is refused too.
    """

    memory_id: str
    byte_offset: int
    generation: int
    evidence_ref: str
    event_id: int
    value: int | None
    case_id: str | None
    writer_kind: str | None
    action_id: str
    prerequisite_id: str
    declaration_id: str
    payload_digest: str
    version: tuple[int, ...] | None = None
    consumer_case_id: str | None = None
    tracker_cursor: int = 0
    tracker_epoch: int = 0
    examined: int = 1
    retained_effects: int = 0
    index_bound: int = 0
    bound_witness_id: str = ""

    def __post_init__(self) -> None:
        _text(self.memory_id, "bound witness memory_id")
        _uint(self.byte_offset, "bound witness byte_offset")
        _uint(self.generation, "bound witness generation")
        _text(self.evidence_ref, "bound witness evidence_ref")
        _uint(self.event_id, "bound witness event_id")
        if self.value is not None:
            _uint(self.value, "bound witness value")
        if self.case_id is not None:
            _text(self.case_id, "bound witness case_id")
        if self.writer_kind is not None:
            _text(self.writer_kind, "bound witness writer_kind")
        if self.version is not None:
            if (not isinstance(self.version, tuple)
                    or any(type(item) is not int or item < 0 for item in self.version)):
                raise ValueError("bound witness version must be a tuple of integers")
        _text(self.action_id, "bound witness action_id")
        if self.consumer_case_id is not None:
            _text(self.consumer_case_id, "bound witness consumer_case_id")
        _digest_text(self.prerequisite_id, "bound witness prerequisite_id")
        _digest_text(self.declaration_id, "bound witness declaration_id")
        _digest_text(self.payload_digest, "bound witness payload_digest")
        for value, name in ((self.tracker_cursor, "tracker_cursor"),
                            (self.tracker_epoch, "tracker_epoch"),
                            (self.examined, "examined"),
                            (self.retained_effects, "retained_effects"),
                            (self.index_bound, "index_bound")):
            _uint(value, f"bound witness {name}")
        expected = _digest(self._material())
        if self.bound_witness_id and self.bound_witness_id != expected:
            raise ValueError(
                "bound_witness_id does not match canonical bound witness material")
        object.__setattr__(self, "bound_witness_id", expected)

    @property
    def selection(self) -> dict:
        return {"strategy": SELECTION_STRATEGY, "order": list(LATEST_EFFECT_ORDER),
                "examined": self.examined, "retained_effects": self.retained_effects,
                "index_bound": self.index_bound}

    def _material(self) -> dict:
        return {"schema_version": BOUND_WITNESS_SCHEMA_VERSION,
                "memory_id": self.memory_id, "byte_offset": self.byte_offset,
                "generation": self.generation, "evidence_ref": self.evidence_ref,
                "event_id": self.event_id, "value": self.value,
                "case_id": self.case_id, "writer_kind": self.writer_kind,
                "version": (list(self.version) if self.version is not None else None),
                "action_id": self.action_id,
                "consumer_case_id": self.consumer_case_id,
                "prerequisite_id": self.prerequisite_id,
                "declaration_id": self.declaration_id,
                "payload_digest": self.payload_digest,
                "selection": self.selection,
                "tracker": {"cursor": self.tracker_cursor, "epoch": self.tracker_epoch}}

    def document(self) -> dict:
        return {**self._material(), "bound_witness_id": self.bound_witness_id}

    @classmethod
    def from_document(cls, document: object) -> BoundWitness:
        fields = {"schema_version", "memory_id", "byte_offset", "generation",
                  "evidence_ref", "event_id", "value", "case_id", "writer_kind",
                  "version", "action_id", "consumer_case_id", "prerequisite_id",
                  "declaration_id", "payload_digest", "selection", "tracker",
                  "bound_witness_id"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("bound witness has unknown or missing fields")
        if document["schema_version"] != BOUND_WITNESS_SCHEMA_VERSION:
            raise ValueError("unsupported bound witness schema_version")
        selection = document["selection"]
        if (type(selection) is not dict
                or set(selection) != {"strategy", "order", "examined",
                                      "retained_effects", "index_bound"}):
            raise ValueError("bound witness selection block is malformed")
        if selection["strategy"] != SELECTION_STRATEGY:
            raise ValueError("unsupported bound witness selection strategy")
        if list(selection["order"]) != list(LATEST_EFFECT_ORDER):
            raise ValueError("unsupported bound witness selection order")
        tracker = document["tracker"]
        if (type(tracker) is not dict
                or set(tracker) != {"cursor", "epoch"}):
            raise ValueError("bound witness tracker block is malformed")
        _digest_text(document["bound_witness_id"], "bound_witness_id")
        version = document["version"]
        return cls(memory_id=document["memory_id"],
                   byte_offset=document["byte_offset"],
                   generation=document["generation"],
                   evidence_ref=document["evidence_ref"],
                   event_id=document["event_id"], value=document["value"],
                   case_id=document["case_id"], writer_kind=document["writer_kind"],
                   action_id=document["action_id"],
                   consumer_case_id=document["consumer_case_id"],
                   prerequisite_id=document["prerequisite_id"],
                   declaration_id=document["declaration_id"],
                   payload_digest=document["payload_digest"],
                   version=None if version is None else tuple(version),
                   tracker_cursor=tracker["cursor"], tracker_epoch=tracker["epoch"],
                   examined=selection["examined"],
                   retained_effects=selection["retained_effects"],
                   index_bound=selection["index_bound"],
                   bound_witness_id=document["bound_witness_id"])

    def __hash__(self) -> int:
        return hash(self.bound_witness_id)


@dataclass(frozen=True)
class DynamicEffectBinding:
    """One pre-admission binding decision: a pinned prerequisite or unbound.

    ``bound`` carries the injected prerequisite, the action that now declares it
    and the ``bound_witness.v1`` proof.  ``unbound`` carries the original action
    unchanged, no prerequisite and the reason no witness was eligible.  The
    action payload is never touched in either case: this capability is a
    prerequisite gate, not a mutation source.
    """

    state: str
    reason: str
    action: SourceAction
    memory_id: str
    byte_offset: int
    prerequisite: Prerequisite | None = None
    witness: BoundWitness | None = None
    declaration_id: str = ""
    consumer_case_id: str | None = None
    payload_sha256_before: str = ""
    payload_sha256_after: str = ""
    binding_id: str = ""

    def __post_init__(self) -> None:
        if self.state not in ("bound", "unbound"):
            raise ValueError(f"unsupported dynamic binding state {self.state!r}")
        _text(self.reason, "dynamic binding reason")
        if not isinstance(self.action, SourceAction):
            raise ValueError("dynamic binding requires the source action it binds")
        _text(self.memory_id, "dynamic binding memory_id")
        _uint(self.byte_offset, "dynamic binding byte_offset")
        if self.consumer_case_id is not None:
            _text(self.consumer_case_id, "dynamic binding consumer_case_id")
        _digest_text(self.payload_sha256_before, "dynamic binding payload digest")
        if self.payload_sha256_after != self.payload_sha256_before:
            raise ValueError(
                "dynamic binding must never change the action payload")
        _digest_text(self.declaration_id, "dynamic binding declaration_id")
        if self.state == "bound":
            if not isinstance(self.prerequisite, Prerequisite) or not isinstance(
                    self.witness, BoundWitness):
                raise ValueError("a bound decision requires its prerequisite and proof")
            if self.prerequisite.kind != "ram_byte_version":
                raise ValueError("a bound decision requires a ram_byte_version "
                                 "prerequisite")
            if self.prerequisite not in self.action.prerequisites:
                raise ValueError(
                    "a bound decision requires the action to declare its prerequisite")
        elif self.prerequisite is not None or self.witness is not None:
            raise ValueError("an unbound decision must not carry a prerequisite")
        expected = _digest(self._material())
        if self.binding_id and self.binding_id != expected:
            raise ValueError(
                "binding_id does not match canonical dynamic binding material")
        object.__setattr__(self, "binding_id", expected)

    def __bool__(self) -> bool:
        return self.state == "bound"

    def _material(self) -> dict:
        return {"schema_version": DYNAMIC_EFFECT_BINDING_SCHEMA_VERSION,
                "state": self.state, "reason": self.reason,
                "memory_id": self.memory_id, "byte_offset": self.byte_offset,
                "consumer_case_id": self.consumer_case_id,
                "declaration_id": self.declaration_id,
                "payload_sha256_before": self.payload_sha256_before,
                "payload_sha256_after": self.payload_sha256_after,
                "payload_unchanged": True, "value_injection": False,
                "injected_prerequisite": (self.prerequisite.document()
                                          if self.prerequisite is not None else None),
                "bound_witness": (self.witness.document()
                                  if self.witness is not None else None),
                "action": self.action.document()}

    def document(self) -> dict:
        return {**self._material(), "binding_id": self.binding_id}

    @classmethod
    def from_document(cls, document: object) -> DynamicEffectBinding:
        fields = {"schema_version", "state", "reason", "memory_id", "byte_offset",
                  "consumer_case_id", "declaration_id", "payload_sha256_before",
                  "payload_sha256_after", "payload_unchanged", "value_injection",
                  "injected_prerequisite", "bound_witness", "action", "binding_id"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("dynamic binding has unknown or missing fields")
        if document["schema_version"] != DYNAMIC_EFFECT_BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported dynamic binding schema_version")
        if document["payload_unchanged"] is not True:
            raise ValueError("a dynamic binding must never claim a payload change")
        if document["value_injection"] is not False:
            raise ValueError("a dynamic binding must never inject a value")
        _digest_text(document["binding_id"], "binding_id")
        prerequisite = document["injected_prerequisite"]
        witness = document["bound_witness"]
        return cls(state=document["state"], reason=document["reason"],
                   action=SourceAction.from_document(document["action"]),
                   memory_id=document["memory_id"],
                   byte_offset=document["byte_offset"],
                   prerequisite=(None if prerequisite is None
                                 else Prerequisite.from_document(prerequisite)),
                   witness=(None if witness is None
                            else BoundWitness.from_document(witness)),
                   declaration_id=document["declaration_id"],
                   consumer_case_id=document["consumer_case_id"],
                   payload_sha256_before=document["payload_sha256_before"],
                   payload_sha256_after=document["payload_sha256_after"],
                   binding_id=document["binding_id"])

    def __hash__(self) -> int:
        return hash(self.binding_id)


def _ram_write_provenance(event: Mapping) -> tuple[tuple[str, int, int, str, str | None], ...]:
    """Derive the RAM byte provenance one journal event *declares*.

    Derivation only: the caller must still find the exact witness the tracker
    retained for the same evidence reference and event id, so a forged or
    refused event can never create eligible provenance.
    """
    kind = event.get("kind")
    if kind == "memory_write_commit":
        commit_id = event.get("commit_id")
        document = event.get("commit_document")
        if (type(commit_id) is not str or _DIGEST.fullmatch(commit_id) is None
                or not isinstance(document, Mapping)
                or document.get("commit_id") != commit_id
                or document.get("commit_status") != "complete"):
            return ()
        memory_id, generation = document.get("memory_id"), document.get("generation")
        cells = document.get("enabled_byte_cells")
        if (type(memory_id) is not str or not memory_id
                or type(generation) is not int or generation < 0
                or type(cells) is not list):
            return ()
        reference = ram_commit_evidence_ref(commit_id)
        rows = []
        for cell in cells:
            if not isinstance(cell, Mapping):
                continue
            offset, writer = cell.get("byte_offset"), cell.get("writer_kind")
            if type(offset) is not int or offset < 0:
                continue
            rows.append((memory_id, generation, offset, reference,
                         writer if type(writer) is str and writer else None))
        return tuple(rows)
    if kind == "memory_write":
        event_id = event.get("event_id")
        memory_id, generation = event.get("memory_id"), event.get("generation")
        byte_offset, width = event.get("byte_offset"), event.get("width_bytes")
        byte_enable = event.get("byte_enable")
        if (type(event_id) is not int or event_id < 0
                or type(memory_id) is not str or not memory_id
                or type(generation) is not int or generation < 0
                or type(byte_offset) is not int or byte_offset < 0
                or type(width) is not int or width < 1
                or type(byte_enable) is not int or byte_enable < 1
                or byte_enable >= 1 << width):
            return ()
        writer = event.get("writer_kind")
        reference = legacy_memory_write_evidence_ref(event_id)
        return tuple((memory_id, generation, byte_offset + lane, reference,
                      writer if type(writer) is str and writer else None)
                     for lane in range(width) if byte_enable >> lane & 1)
    return ()


class DynamicPrerequisiteBinder:
    """Bind a later case's action to the latest *retained* RAM byte evidence.

    Boundary this object owns (each rule is enforced, not documented only):

    * **Trusted, bounded whitelist.**  Only the ``(memory_id, byte_offset)``
      pairs and writer kinds of one :class:`TrustedRamByteDeclaration` may be
      consumed.  An undeclared offset, memory or requested source kind is
      refused (``DynamicBindingRefused``); a request may narrow the declared
      writer kinds, never widen them.
    * **Tracker evidence only.**  Candidates come from
      :meth:`CrossCaseEffectTracker.retained_ram_witnesses`, i.e. the tracker's
      own bounded retained index (at most ``max_effects`` entries, the same index
      ``satisfied`` reads).  The journal is never rescanned, and evidence that
      capacity eviction, aging or reset already dropped can never be selected.
    * **Deterministic.**  Candidates are ordered by ``LATEST_EFFECT_ORDER`` and
      the head is selected, so one tracker state always answers one reference.
    * **Recomputable.**  The result carries a ``bound_witness.v1`` proof with
      content digests, and :meth:`verify` re-reads live tracker state and this
      binder's declaration.
    * **Never an input value.**  The committed byte is injected as a
      ``ram_byte_version`` *prerequisite* of the consumer action and never into
      its payload; the payload digest is recorded before and after, and an
      ``external_event`` action whose own mutable ``value`` equals the committed
      byte is refused (``ram_value_input_injection``) because that is
      indistinguishable from using RAM as a CPU input.
    * **Fail-closed.**  A policy violation always refuses.  A missing version is
      refused by default (``require_witness=True``); a recording caller may opt
      out and receive ``state="unbound"`` with a reason, and an unbound decision
      injects nothing and claims nothing.
    * **Version pinning and supersede.**  A bound prerequisite pins one exact
      retained version.  When a later committed write to the same byte changes
      what the tracker retains, the *old* binding stops being satisfied
      (``tracker.satisfied`` reports ``missing_effects`` and :meth:`verify`
      refuses with ``superseded_evidence``) and it is never silently re-pointed;
      the case has to be bound again from its own unbound action, which selects
      the newly retained version.  Binding an action that already pins a
      different version of the same byte is refused
      (``conflicting_prerequisite``), and binding it twice to the identical
      version is idempotent.

    Writer kinds are matched against provenance recorded by :meth:`observe` for
    a witness the tracker really retained (same evidence reference, same event
    id).  A witness whose producing event this binder never observed has no
    provenance and is never eligible for a declaration that names sources, so
    wiring must feed receipts through ``observe``.
    """

    def __init__(self, tracker: CrossCaseEffectTracker | SourceActionGate,
                 declaration: TrustedRamByteDeclaration, *,
                 max_provenance: int | None = None,
                 require_witness: bool = True,
                 require_value: bool = False) -> None:
        target = (tracker if isinstance(tracker, CrossCaseEffectTracker)
                  else getattr(tracker, "tracker", None))
        if not isinstance(target, CrossCaseEffectTracker):
            raise ValueError("binder requires a CrossCaseEffectTracker or a "
                             "source-action gate")
        if not isinstance(declaration, TrustedRamByteDeclaration):
            raise ValueError("binder requires a TrustedRamByteDeclaration")
        if max_provenance is None:
            max_provenance = target.max_effects
        if type(max_provenance) is not int or max_provenance < 1:
            raise ValueError("max_provenance must be a positive integer")
        if type(require_witness) is not bool or type(require_value) is not bool:
            raise ValueError("binder flags must be boolean")
        self._tracker = target
        self._declaration = declaration
        self.max_provenance = max_provenance
        self.require_witness = require_witness
        self.require_value = require_value
        self._provenance: "OrderedDict[tuple[str, int, str, int], str | None]" = \
            OrderedDict()
        self._counters = {name: 0 for name in
                          ("requests", "bound", "unbound", "refused", "idempotent",
                           "verifications", "verify_refusals", "provenance_records",
                           "provenance_evictions")}

    # -- introspection ----------------------------------------------------
    @property
    def tracker(self) -> CrossCaseEffectTracker:
        return self._tracker

    @property
    def declaration(self) -> TrustedRamByteDeclaration:
        return self._declaration

    @property
    def counters(self) -> dict:
        return dict(self._counters)

    @property
    def bounds(self) -> dict:
        return {"max_provenance": self.max_provenance,
                "max_effects": self._tracker.max_effects,
                "max_pending": self._tracker.bounds["max_pending"]}

    def document(self) -> dict:
        """Bounded snapshot of the policy, its counters and its tracker."""
        return {"schema_version": DYNAMIC_PREREQUISITE_BINDER_SCHEMA_VERSION,
                "declaration": self._declaration.document(),
                "bounds": self.bounds, "counters": self.counters,
                "provenance_count": len(self._provenance),
                "require_witness": self.require_witness,
                "require_value": self.require_value,
                "safety": {"payload_mutation": False, "value_injection": False,
                           "selection": SELECTION_STRATEGY,
                           "latest_order": list(LATEST_EFFECT_ORDER)},
                "tracker": self._tracker.document()}

    # -- ingestion --------------------------------------------------------
    def observe(self, receipt: object) -> tuple[EffectWitness, ...]:
        """Ingest one admitted case's receipt and record writer provenance.

        This is the only ingestion path the binder needs: it delegates the
        authoritative validation to the tracker and only records provenance for
        the witnesses the tracker actually retained.
        """
        events = getattr(receipt, "events", None)
        if events is None:
            raise ValueError("binder observe requires a receipt with events")
        case_id = getattr(receipt, "case_id", None)
        created = self._tracker.ingest(events, case_id=case_id)
        self._record_provenance(events)
        return created

    def _record_provenance(self, events: Iterable[Mapping]) -> None:
        if isinstance(events, (str, bytes)) or not isinstance(events, Iterable):
            raise ValueError("binder events must be an iterable of journal mappings")
        for event in events:
            if not isinstance(event, Mapping):
                continue
            event_id = event.get("event_id")
            if type(event_id) is not int or event_id < 0:
                continue
            kind = event.get("kind")
            if type(kind) is not str or not kind:
                continue
            if kind in _RESET_KINDS or kind.endswith("_reset"):
                # A measured reset drops retained evidence: drop its provenance
                # with it so a stale writer kind can never be paired with a
                # fresh witness.
                self._provenance.clear()
                continue
            for memory_id, generation, offset, reference, writer in \
                    _ram_write_provenance(event):
                prerequisite = Prerequisite.create(
                    "ram_byte_version",
                    {"memory_id": memory_id, "generation": generation,
                     "byte_offset": offset}, reference)
                witness = self._tracker.matching_witness(prerequisite)
                if witness is None or witness.event_id != event_id:
                    continue
                key = (memory_id, offset, reference, event_id)
                if key in self._provenance:
                    self._provenance.move_to_end(key)
                    continue
                self._provenance[key] = writer
                self._counters["provenance_records"] += 1
                while len(self._provenance) > self.max_provenance:
                    self._provenance.popitem(last=False)
                    self._counters["provenance_evictions"] += 1

    # -- binding ----------------------------------------------------------
    def bind(self, action: SourceAction, *, memory_id: str, byte_offset: int,
             writer_kinds: tuple[str, ...] | None = None,
             case_id: str | None = None,
             require_witness: bool | None = None,
             require_value: bool | None = None) -> DynamicEffectBinding:
        """Select the latest declared witness and pin it on ``action``."""
        self._counters["requests"] += 1
        return self._bind(action, memory_id=memory_id, byte_offset=byte_offset,
                          writer_kinds=writer_kinds, case_id=case_id,
                          require_witness=(self.require_witness
                                           if require_witness is None
                                           else require_witness),
                          require_value=(self.require_value if require_value is None
                                         else require_value))

    def _bind(self, action, *, memory_id, byte_offset, writer_kinds, case_id,
              require_witness, require_value) -> DynamicEffectBinding:
        if not isinstance(action, SourceAction):
            raise ValueError("binder requires a SourceAction")
        if case_id is not None:
            _text(case_id, "binding case_id")
        if not isinstance(memory_id, str):
            raise ValueError("binding request requires a memory_id")
        _text(memory_id, "binding memory_id")
        _uint(byte_offset, "binding byte_offset")
        if type(require_witness) is not bool or type(require_value) is not bool:
            raise ValueError("binding flags must be boolean")

        # Policy first: a request can only ever narrow the declaration.
        if not self._declaration.allows(memory_id, byte_offset):
            if memory_id != self._declaration.memory_id:
                self._counters["refused"] += 1
                raise DynamicBindingRefused(
                    "undeclared_memory_id",
                    f"undeclared memory_id {memory_id!r}: the trusted declaration "
                    f"covers {self._declaration.memory_id!r} only")
            self._counters["refused"] += 1
            raise DynamicBindingRefused(
                "undeclared_byte_offset",
                f"undeclared byte_offset {byte_offset:#x} for memory_id "
                f"{memory_id!r}: the trusted declaration covers "
                f"{[hex(item) for item in self._declaration.byte_offsets]}")
        requested = (None if writer_kinds is None
                     else _kind_tuple(writer_kinds, "request writer_kinds"))
        effective = self._declaration.writer_kinds
        if requested is not None:
            if (not self._declaration.requires_writer_kind
                    or any(kind not in self._declaration.writer_kinds
                           for kind in requested)):
                self._counters["refused"] += 1
                raise DynamicBindingRefused(
                    "undeclared_writer_kind",
                    f"undeclared writer_kind request {list(requested)}: the request "
                    "may only narrow the declared kinds "
                    f"{list(self._declaration.writer_kinds)}")
            effective = requested
        if self._tracker.degraded:
            self._counters["refused"] += 1
            raise DynamicBindingRefused(
                "degraded_tracker",
                "the tracker is degraded: bounded evidence conflicted, so no "
                "version can be claimed")

        selected, writer_kind, reason, examined = self._select(
            memory_id, byte_offset, effective, require_value)
        if selected is None:
            return self._unbound(action, memory_id, byte_offset, reason, case_id,
                                 require_witness)

        # An action that already pins another version of the same byte must not
        # silently follow the new one: that refusal is the supersede contract.
        subject = _canonical({"memory_id": memory_id,
                              "generation": selected.subject["generation"],
                              "byte_offset": byte_offset})
        for existing in action.prerequisites:
            if (existing.kind == "ram_byte_version"
                    and _canonical(dict(existing.subject)) == subject):
                if existing.evidence_ref != selected.evidence_ref:
                    self._counters["refused"] += 1
                    raise DynamicBindingRefused(
                        "conflicting_prerequisite",
                        f"conflicting prerequisite: action {action.action_id!r} "
                        f"already pins {existing.evidence_ref} while the retained "
                        f"version is now {selected.evidence_ref}")
                self._counters["idempotent"] += 1
                return self._bound(action, existing, memory_id, byte_offset,
                                   selected, writer_kind, case_id, examined)

        value = selected.value
        if (action.kind == "external_event" and action.payload_mutable
                and value is not None and action.payload.get("value") == value):
            self._counters["refused"] += 1
            raise DynamicBindingRefused(
                "ram_value_input_injection",
                f"ram_value_input_injection: the external_event payload value "
                f"{value} equals the committed RAM byte; a committed value must "
                "never become a fuzzable CPU input")

        prerequisite = Prerequisite.create(
            "ram_byte_version",
            {"memory_id": memory_id, "generation": selected.subject["generation"],
             "byte_offset": byte_offset}, selected.evidence_ref)
        bound_action = replace(action,
                               prerequisites=tuple(action.prerequisites)
                               + (prerequisite,), action_sha256="")
        self._counters["bound"] += 1
        return self._bound(bound_action, prerequisite, memory_id, byte_offset,
                           selected, writer_kind, case_id, examined)

    def _select(self, memory_id, byte_offset, effective, require_value):
        """Latest eligible retained version; deterministic, index-bounded."""
        candidates = self._tracker.retained_ram_witnesses(memory_id, byte_offset)
        reasons = set()
        for witness in candidates:
            key = (memory_id, byte_offset, witness.evidence_ref, witness.event_id)
            recorded = self._provenance.get(key, _MISSING)
            if effective:
                if recorded is _MISSING or recorded is None:
                    reasons.add(UNBOUND_PROVENANCE)
                    continue
                if recorded not in effective:
                    reasons.add(UNBOUND_WRITER_KIND)
                    continue
            if require_value and witness.value is None:
                reasons.add(UNBOUND_VALUE)
                continue
            return (witness, (None if recorded is _MISSING else recorded), None,
                    len(candidates))
        if not candidates:
            reason = UNBOUND_NO_WITNESS
        elif UNBOUND_WRITER_KIND in reasons:
            reason = UNBOUND_WRITER_KIND
        elif reasons:
            reason = sorted(reasons)[0]
        else:
            reason = UNBOUND_NO_WITNESS
        return None, None, reason, len(candidates)

    def _unbound(self, action, memory_id, byte_offset, reason, case_id,
                 require_witness):
        detail = {
            UNBOUND_NO_WITNESS:
                f"no retained witness for memory {memory_id!r} byte "
                f"{byte_offset:#x} matches the trusted declaration",
            UNBOUND_PROVENANCE:
                f"untrusted_source_provenance: the retained evidence for memory "
                f"{memory_id!r} byte {byte_offset:#x} has no provenance recorded "
                "by this binder",
            UNBOUND_WRITER_KIND:
                f"writer_kind_not_declared: no retained version of memory "
                f"{memory_id!r} byte {byte_offset:#x} was written by a declared "
                "source kind",
            UNBOUND_VALUE:
                f"missing_witness_value: the retained version of memory "
                f"{memory_id!r} byte {byte_offset:#x} declares no byte value",
        }[reason]
        if require_witness:
            self._counters["unbound"] += 1
            raise DynamicBindingUnbound(reason, detail)
        self._counters["unbound"] += 1
        payload_digest = _digest(dict(action.payload))
        return DynamicEffectBinding(
            state="unbound", reason=reason, action=action, memory_id=memory_id,
            byte_offset=byte_offset, declaration_id=self._declaration.declaration_id,
            consumer_case_id=case_id, payload_sha256_before=payload_digest,
            payload_sha256_after=payload_digest)

    def _bound(self, bound_action, prerequisite, memory_id, byte_offset,
               selected, writer_kind, case_id, examined) -> DynamicEffectBinding:
        payload_digest = _digest(dict(bound_action.payload))
        proof = BoundWitness(
            memory_id=memory_id, byte_offset=byte_offset,
            generation=selected.subject["generation"],
            evidence_ref=selected.evidence_ref, event_id=selected.event_id,
            value=selected.value, case_id=selected.case_id,
            writer_kind=writer_kind, action_id=bound_action.action_id,
            prerequisite_id=prerequisite.prerequisite_id,
            declaration_id=self._declaration.declaration_id,
            payload_digest=payload_digest, version=selected.version,
            consumer_case_id=case_id, tracker_cursor=self._tracker.cursor,
            tracker_epoch=self._tracker.epoch, examined=examined,
            retained_effects=len(self._tracker._effects),
            index_bound=self._tracker.max_effects)
        return DynamicEffectBinding(
            state="bound", reason=BOUND_REASON, action=bound_action,
            memory_id=memory_id, byte_offset=byte_offset, prerequisite=prerequisite,
            witness=proof, declaration_id=self._declaration.declaration_id,
            consumer_case_id=case_id, payload_sha256_before=payload_digest,
            payload_sha256_after=payload_digest)

    # -- verification -----------------------------------------------------
    def verify(self, claim: DynamicEffectBinding | BoundWitness | Mapping, *,
               action: SourceAction | None = None) -> BoundWitness:
        """Re-check one proof against live tracker state and this declaration."""
        self._counters["verifications"] += 1
        try:
            return self._verify(claim, action)
        except DynamicBindingRefused:
            self._counters["verify_refusals"] += 1
            raise

    def _verify(self, claim, action) -> BoundWitness:
        if isinstance(claim, DynamicEffectBinding):
            proof_document = claim.document()["bound_witness"]
            if proof_document is None:
                raise DynamicBindingRefused(
                    "unbound_binding",
                    "the binding is unbound: there is no bound witness to verify")
            action = claim.action if action is None else action
        elif isinstance(claim, BoundWitness):
            proof_document = claim.document()
        elif isinstance(claim, Mapping):
            proof_document = claim
        else:
            raise ValueError("verify requires a bound witness document or binding")
        proof = BoundWitness.from_document(proof_document)
        if proof.declaration_id != self._declaration.declaration_id:
            raise DynamicBindingRefused(
                "declaration_mismatch",
                f"declaration_id {proof.declaration_id} does not match this "
                f"binder's declaration {self._declaration.declaration_id}")
        if not self._declaration.allows(proof.memory_id, proof.byte_offset):
            raise DynamicBindingRefused(
                "undeclared_byte_offset",
                f"undeclared byte_offset {proof.byte_offset:#x} for memory_id "
                f"{proof.memory_id!r}: the trusted declaration covers "
                f"{[hex(item) for item in self._declaration.byte_offsets]}")
        if not self._declaration.allows_writer_kind(proof.writer_kind):
            raise DynamicBindingRefused(
                "undeclared_writer_kind",
                f"undeclared writer_kind {proof.writer_kind!r}: the trusted "
                f"declaration covers {list(self._declaration.writer_kinds)}")
        if self._tracker.degraded:
            raise DynamicBindingRefused(
                "degraded_tracker",
                "the tracker is degraded: bounded evidence conflicted, so no "
                "version can be claimed")
        prerequisite = Prerequisite.create(
            "ram_byte_version",
            {"memory_id": proof.memory_id, "generation": proof.generation,
             "byte_offset": proof.byte_offset}, proof.evidence_ref)
        if prerequisite.prerequisite_id != proof.prerequisite_id:
            raise DynamicBindingRefused(
                "unretained_evidence",
                "the named witness is unretained: the proof does not rebuild the "
                "prerequisite it claims")
        witness = self._tracker.matching_witness(prerequisite)
        if witness is None:
            retained = self._tracker.retained_ram_witnesses(proof.memory_id,
                                                            proof.byte_offset)
            if retained and retained[0].evidence_ref != proof.evidence_ref:
                raise DynamicBindingRefused(
                    "superseded_evidence",
                    "the bound witness was superseded: the retained version of "
                    f"memory {proof.memory_id!r} byte {proof.byte_offset:#x} is now "
                    f"{retained[0].evidence_ref}")
            raise DynamicBindingRefused(
                "unretained_evidence",
                "the named witness is unretained: the tracker does not hold "
                f"{proof.evidence_ref} for memory {proof.memory_id!r} byte "
                f"{proof.byte_offset:#x}")
        if (witness.event_id != proof.event_id or witness.value != proof.value
                or witness.case_id != proof.case_id
                or witness.subject["generation"] != proof.generation
                or witness.subject["memory_id"] != proof.memory_id
                or witness.subject["byte_offset"] != proof.byte_offset):
            raise DynamicBindingRefused(
                "unretained_evidence",
                "the named witness is unretained: the tracker's retained witness "
                "differs from the proof in event id, value, case or subject")
        if self._declaration.requires_writer_kind:
            recorded = self._provenance.get(
                (proof.memory_id, proof.byte_offset, proof.evidence_ref,
                 proof.event_id), _MISSING)
            if recorded is _MISSING or recorded is None:
                raise DynamicBindingRefused(
                    "untrusted_source_provenance",
                    "untrusted_source_provenance: no writer kind was recorded for "
                    "this witness by this binder")
            if recorded != proof.writer_kind or not self._declaration.allows_writer_kind(
                    recorded):
                raise DynamicBindingRefused(
                    "undeclared_writer_kind",
                    f"undeclared writer_kind: the recorded writer {recorded!r} is not "
                    f"the proof's {proof.writer_kind!r} or not declared")
        if action is not None:
            if not isinstance(action, SourceAction):
                raise ValueError("verify requires a SourceAction to compare")
            if _digest(dict(action.payload)) != proof.payload_digest:
                raise DynamicBindingRefused(
                    "payload_changed",
                    "the action payload digest differs from the payload the proof "
                    "was bound to")
            if proof.prerequisite_id not in {item.prerequisite_id
                                             for item in action.prerequisites}:
                raise DynamicBindingRefused(
                    "action_mismatch",
                    f"the proof does not justify any prerequisite of action "
                    f"{action.action_id!r}")
        return proof


def bind_latest_effect(source, action: SourceAction, *, memory_id: str,
                       byte_offset: int,
                       writer_kinds: tuple[str, ...] | None = None,
                       case_id: str | None = None,
                       require_witness: bool | None = None,
                       require_value: bool | None = None,
                       declaration: TrustedRamByteDeclaration | None = None,
                       max_provenance: int | None = None) -> DynamicEffectBinding:
    """One binding decision through a trusted declaration.

    ``source`` is an existing :class:`DynamicPrerequisiteBinder`, or a
    :class:`CrossCaseEffectTracker`/gate together with an explicit
    ``declaration``.  A bare tracker carries no recorded provenance, so a
    declaration that names writer kinds is refused there instead of silently
    degrading to an unbound answer.
    """
    if isinstance(source, DynamicPrerequisiteBinder):
        if declaration is not None:
            raise ValueError(
                "the binder owns its trusted declaration; construct the binder "
                "with the declaration instead of passing both")
        return source.bind(action, memory_id=memory_id, byte_offset=byte_offset,
                           writer_kinds=writer_kinds, case_id=case_id,
                           require_witness=require_witness,
                           require_value=require_value)
    if not isinstance(declaration, TrustedRamByteDeclaration):
        raise ValueError(
            "bind_latest_effect requires a DynamicPrerequisiteBinder, or a "
            "tracker with a trusted declaration")
    if declaration.writer_kinds:
        raise ValueError(
            "a one-shot binding over a bare tracker has no recorded provenance; "
            "construct a DynamicPrerequisiteBinder for a declaration with "
            "writer_kinds")
    return DynamicPrerequisiteBinder(
        source, declaration,
        max_provenance=max_provenance).bind(
            action, memory_id=memory_id, byte_offset=byte_offset,
            writer_kinds=writer_kinds, case_id=case_id,
            require_witness=require_witness, require_value=require_value)


__all__ = [
    "ACTION_SCHEMA_VERSION", "ACTION_KINDS", "BOUND_REASON",
    "BOUND_WITNESS_SCHEMA_VERSION", "CPU_IRQ_ENDPOINT_CLASSES",
    "CrossCaseEffectTracker", "DEFAULT_MAX_AGE_EVENTS", "DEFAULT_MAX_COMPONENTS",
    "DEFAULT_MAX_EFFECTS", "DEFAULT_MAX_SLOTS", "DRIVEN_FLOW_IDS", "EFFECT_KINDS",
    "ENDPOINT_CLASSES", "EVALUATION_SCHEMA_VERSION", "EffectWitness",
    "GATE_SCHEMA_VERSION", "INTERRUPT_FLOW", "IRQ_PREREQUISITE_KINDS",
    "InstructionSlotReservationGate", "OBSERVED_FLOW_IDS", "OWNERSHIP_KINDS",
    "PREREQUISITE_KINDS", "PREREQUISITE_SCHEMA_VERSION", "Prerequisite",
    "PrerequisiteEvaluation", "SLOT_RESERVATION_GATE_SCHEMA_VERSION",
    "SourceAction", "SourceActionError", "SourceActionGate",
    "SourceActionInputMismatch", "SourceActionPrerequisiteError",
    "SourceActionSlotWindowError", "SourceActionUnknownAction",
    "TERMINATION_KINDS", "TRACKER_SCHEMA_VERSION", "TerminationObservation",
    "WITNESS_SCHEMA_VERSION", "instruction_slot_unmaterialized_prerequisite",
    "ip_register_evidence_ref", "ip_register_prerequisite",
    "irq_input_delivered_prerequisite", "irq_input_evidence_ref",
    "irq_pulse_evidence_ref", "irq_pulse_pending_prerequisite",
    "irq_taken_evidence_ref", "irq_taken_prerequisite",
    "legacy_memory_write_evidence_ref", "legacy_write_prerequisite",
    "ram_commit_evidence_ref", "ram_commit_prerequisite",
    "BoundWitness", "DynamicBindingError", "DynamicBindingRefused",
    "DynamicBindingUnbound", "DynamicEffectBinding", "DynamicPrerequisiteBinder",
    "DYNAMIC_EFFECT_BINDING_SCHEMA_VERSION",
    "DYNAMIC_PREREQUISITE_BINDER_SCHEMA_VERSION", "LATEST_EFFECT_ORDER",
    "SELECTION_STRATEGY", "TRUSTED_RAM_DECLARATION_SCHEMA_VERSION",
    "TrustedRamByteDeclaration", "UNBOUND_NO_WITNESS", "UNBOUND_PROVENANCE",
    "UNBOUND_VALUE", "UNBOUND_WRITER_KIND", "bind_latest_effect",
]
