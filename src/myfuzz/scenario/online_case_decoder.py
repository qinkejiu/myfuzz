"""Pure input decoding for reset-free sessions; commit follows admission.

The caller reserves instruction slots in persistent memory, submits the case
through ScenarioSession, then calls commit only after successful admission.
No harness or memory is touched here. Coverage hints affect source selection
and must be recorded with the raw input when reconstructing decoder decisions.

Online source actions (opt-in)
------------------------------
``source_action`` turns one decoded case into a versioned
``source_action.v1`` record so the RFuzz online path can query an explicit
prerequisite gate before any RTL command.  Every field is derived from a
declaration that already exists; nothing is inferred from RTL behaviour:

======================  ====================================================
action field            declaration it comes from
======================  ====================================================
``action_id``           the decoded case source action id (``case:source``)
``kind``                ``OnlineSource.kind``: ``instruction`` -> instruction,
                        ``source`` -> external_event
``component``           ``OnlineSource.component``
``source_id``           ``OnlineSource.source_id``
``ownership``           ``fuzzable``: an instruction source is the decoder's
                        own reserved-slot input, and a source-kind input is
                        accepted only when the compiled ownership map names a
                        fuzzable producer for those bits (a bound or fixed
                        producer, including the CPU IRQ input, is refused)
``flow_id``             ``flow_by_target`` (the declared F1..F6 category of the
                        path target); a decoder without that declaration
                        cannot build an action and refuses with
                        ``flow_category_undeclared``
``payload``             the decoded case input (instruction address/words or
                        external port/offset/width/value)
``prerequisites``       ``OnlineSourceActionDeclaration.prerequisites`` of that
                        source: exact, content-addressed requirements owned by
                        the caller.  This module never derives or invents an
                        evidence reference.
``termination_observation``
                        the declaration's observation, or ``incomplete`` with
                        the declared flow_id, because a case's real
                        termination is only measured after the RTL ran
``local_step_budget``   the declared case budget (``advance_rounds`` times the
                        declared schedule length)
======================  ====================================================

Declared path/source switch operators (opt-in)
----------------------------------------------
``switch_proposal`` retargets the *current* proposal to another declared
path/source of the same ``OnlineCaseDecoder``.  It is an explicit operator
family, never part of the default decode:

* the switch pool is the decoder's own declared candidate set
  (``path_switch_targets()`` lists it): a declared ``path_id``/target, a
  declared flow category, a declared ``source_id`` of the resolved path, or an
  exact declared input slice;
* a slice is decided by the compiled ownership map, so a bound, fixed,
  undeclared, out-of-range or ambiguous slice is refused with its shipped
  ``ownership.*`` code (pointer ``switch.input_slice``), and a declared
  instruction source whose local reservation is already exhausted is refused
  with ``budget.exhausted``;
* an unknown path, target or flow is ``path.undeclared`` and a source or slice
  that the resolved path does not declare is ``path.source_mismatch`` (both
  pointers name the failing ``switch.*`` request field).  No new rejection code
  exists for a switch: every refusal is one of the shipped
  ``candidate_rejection.v1`` codes;
* a refused switch consumes nothing: the current proposal, the instruction
  cursor and the case counter are untouched, so the caller may still submit the
  unswitched case;
* the applied operator is written into the candidate decision
  (``CandidateDisposition.document()['switch']``, an
  ``online_path_switch.v1`` record that round-trips through
  ``PathSwitchRecord.from_document``) and, when it changed the candidate, into
  ``candidate_id`` as ``switch_operator_id``.  ``decision_metadata(case,
  switch=request)`` reproduces that identity and refuses a request that is not
  the applied one.  A switch that resolves to the already selected path/source
  is admitted with ``changed=False`` and leaves ``candidate_id`` unchanged;
* the selection vocabulary stays the shipped one plus
  ``declared_path_switch``, used only when a switch actually changed the
  candidate.

Default decoding is untouched: without ``switch_proposal`` no field of any
decoded case, and no ``candidate_id``, changes (see the operator tests).

Wired versus API-only prerequisites
-----------------------------------
Wired: the online RFuzz executor constructs this action for every admitted
candidate, registers it, queries ``require_case`` before any RTL command and
feeds the case receipt back to the tracker, so every prerequisite a source
declares is enforced and every witness a case produces is retained.  All six
prerequisite kinds (``ram_byte_version``, ``ip_register_version``,
``irq_pulse_pending``, ``irq_input_delivered``, ``irq_taken``,
``instruction_slot_unmaterialized``) travel that one path unchanged.

A *static* declaration can only carry a prerequisite whose exact evidence is
known before the run.  The shipped online instruction policy needs the opposite:
its address is the case's own target slot, which the moving decoder cursor
changes for every case, so a once-declared slot would be satisfiable for at most
one case and refused for every later one.  ``InstructionSlotReservationGate``
(``scenario/source_actions.py``) owns that policy instead: it binds the slot(s)
the action's own declared payload names, registers exactly those reservations in
the tracker (lazily, one word per admitted case, bounded by the declared online
window), and is attached to the session by ``make_ibex_pulp_online_runtime``.
The declarations above stay the only place a *static* prerequisite set and its
evidence references are declared.

API-only, not derived here: no prerequisite kind is synthesised from the
decoder's own state.  In particular the reserved instruction slot is *not*
registered into the tracker automatically, so ``instruction_slot_unmaterialized``
is usable only when the caller registers the reservation
(``CrossCaseEffectTracker.register_instruction_slot``) and declares the same
exact ``reservation_ref`` -- for the shipped Ibex wiring that caller is the
reservation gate, for every other profile it remains the profile's own caller.
A shipped profile that declares no source action prerequisites
(``ibex_uart_online`` today) still binds, registers and observes each action
with an empty prerequisite set when a gate is configured.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from types import MappingProxyType
from collections.abc import Mapping

from .batch import BatchAdvance, BatchSourceEvent
from .dependency import DependencyGraph, DependencyRule
from .genome import DIRECTIONS
from .ownership import OwnershipMap
from .rejection_codes import (
    Rejection, RejectionCode, RejectionError, reject, rejection_of,
    value_summary,
)
from .rv32i_sources import (MmioWindow, decode_instruction_fragment,
                            fragment_bytes, instruction_operator_id)
from .session_runtime import OnlineCase, OnlineInstruction
from .rfuzz_decoder import _RuntimePathCache
from .runtime_path_contract import RuntimePathContract
from .ownership import InputField, InputOwner, compile_ownership
from .source_actions import (MAX_LOCAL_STEP_BUDGET, Prerequisite, SourceAction,
                             TerminationObservation)


CANDIDATE_DECISION_SCHEMA_VERSION = "online_candidate_decision.v1"
#: Dispositions of one decoded candidate; a rejection is never silent.
CANDIDATE_DISPOSITIONS = frozenset({"admitted", "degraded", "rejected", "uncertain"})
#: Selection reasons are shared with the live RFuzz receipt vocabulary.
SOURCE_SELECTION_REASONS = frozenset({"direct_source_byte",
                                      "feedback_weighted_legal_source",
                                      "declared_path_switch"})
#: Selection reason of a case whose identity a requested switch changed.
PATH_SWITCH_SELECTION_REASON = "declared_path_switch"
#: Disposition reasons of one applied or refused path/source switch.
PATH_SWITCH_DISPOSITION_REASONS = frozenset({"declared_switch_applied",
                                             "switch_rejected"})
#: Version of one declared switch request and of the record of its application.
PATH_SWITCH_REQUEST_SCHEMA_VERSION = "online_path_switch_request.v1"
PATH_SWITCH_SCHEMA_VERSION = "online_path_switch.v1"
#: The declared operator families of a switch request.
PATH_SWITCH_FAMILIES = frozenset({"path_switch", "source_switch"})
#: Bound of retained applied-switch records; the oldest identity is evicted
#: first.  The live path only ever needs the current proposal.
MAX_RETAINED_SWITCHES = 4096
#: Version of one caller declaration of a source action's non-derivable fields.
SOURCE_ACTION_DECLARATION_SCHEMA_VERSION = "online_source_action_declaration.v1"
#: Stable reasons an online case cannot be bound to a versioned source action.
SOURCE_ACTION_REFUSAL_REASONS = frozenset({
    "case_not_current_proposal",
    "flow_category_undeclared",
    "local_step_budget_invalid",
})
#: Declared online source kind to the versioned action kind it drives.
SOURCE_ACTION_KIND = MappingProxyType({"instruction": "instruction",
                                       "source": "external_event"})


class OnlineSourceActionRefusal(ValueError):
    """One decoded case cannot be bound to a declared source action.

    ``reason`` is a stable token from
    :data:`SOURCE_ACTION_REFUSAL_REASONS`; ``detail`` is a JSON-safe summary.
    Nothing was driven, so a caller must treat this as a pre-RTL refusal.
    """

    def __init__(self, reason: str, detail: Mapping | None = None) -> None:
        if reason not in SOURCE_ACTION_REFUSAL_REASONS:
            raise ValueError(f"unknown source action refusal reason {reason!r}")
        if detail is not None and not isinstance(detail, Mapping):
            raise ValueError("source action refusal detail must be a mapping")
        self.reason = reason
        self.detail = {key: value_summary(value)
                       for key, value in (detail or {}).items()}
        super().__init__(
            f"online source action refused ({reason}): "
            + json.dumps(self.detail, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False))


@dataclass(frozen=True)
class OnlineSourceActionDeclaration:
    """Caller declaration of the source-action fields a case cannot derive.

    ``prerequisites`` are exact, content-addressed requirements owned by the
    caller: the decoder never derives or invents an evidence reference.
    ``termination_observation`` may declare a concrete observation; when it is
    ``None`` the action declares ``incomplete`` with the declared flow, because
    an online case's real termination is only measurable after execution.
    """

    source_id: str
    prerequisites: tuple[Prerequisite, ...] = ()
    termination_observation: TerminationObservation | None = None

    def __post_init__(self) -> None:
        if type(self.source_id) is not str or not self.source_id.strip():
            raise ValueError("declared source action needs a nonempty source_id")
        if (not isinstance(self.prerequisites, tuple)
                or any(not isinstance(item, Prerequisite)
                       for item in self.prerequisites)):
            raise ValueError("declared prerequisites must be a tuple of Prerequisite")
        identities = [item.prerequisite_id for item in self.prerequisites]
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate prerequisite in source action declaration")
        if (self.termination_observation is not None
                and not isinstance(self.termination_observation,
                                   TerminationObservation)):
            raise ValueError("declared termination must be a TerminationObservation")

    def document(self) -> dict:
        return {"schema_version": SOURCE_ACTION_DECLARATION_SCHEMA_VERSION,
                "source_id": self.source_id,
                "prerequisites": [item.document() for item in self.prerequisites],
                "termination_observation": (
                    None if self.termination_observation is None
                    else self.termination_observation.document())}

    @classmethod
    def from_document(cls, document: object) -> "OnlineSourceActionDeclaration":
        fields = {"schema_version", "source_id", "prerequisites",
                  "termination_observation"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("source action declaration has unknown or missing fields")
        if document["schema_version"] != SOURCE_ACTION_DECLARATION_SCHEMA_VERSION:
            raise ValueError("unsupported source action declaration schema_version")
        prerequisites = document["prerequisites"]
        if type(prerequisites) is not list:
            raise ValueError("source action declaration prerequisites must be a list")
        termination = document["termination_observation"]
        return cls(source_id=document["source_id"],
                   prerequisites=tuple(Prerequisite.from_document(item)
                                       for item in prerequisites),
                   termination_observation=(None if termination is None else
                       TerminationObservation.from_document(termination)))


@dataclass(frozen=True)
class InputSlice:
    """One exact input-bit slice a switch may retarget the mutation to.

    The slice is only a *request*: the compiled ownership map decides whether
    those bits are fuzzable, and the resolved path must declare a source with
    exactly this component, port, offset and width.
    """

    component: str
    port: str
    bit_offset: int
    width: int

    def __post_init__(self) -> None:
        if any(type(value) is not str or not value
               for value in (self.component, self.port)):
            raise ValueError("input slice needs a component and port name")
        if type(self.bit_offset) is not int or self.bit_offset < 0:
            raise ValueError("input slice offset must be nonnegative")
        if type(self.width) is not int or not 1 <= self.width <= 65536:
            raise ValueError("input slice width must be within the batch bound")

    @property
    def field(self) -> tuple[str, str, int, int]:
        return (self.component, self.port, self.bit_offset, self.width)

    def document(self) -> dict:
        return {"component": self.component, "port": self.port,
                "bit_offset": self.bit_offset, "width": self.width}

    @classmethod
    def from_document(cls, document: object) -> "InputSlice":
        fields = {"component", "port", "bit_offset", "width"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("input slice has unknown or missing fields")
        try:
            return cls(**document)
        except TypeError as error:
            raise ValueError("invalid input slice document") from error


@dataclass(frozen=True)
class PathSwitchRequest:
    """One opt-in request to retarget the current proposal.

    Every field is optional but at least one is required.  ``path_id`` names a
    declared path identity or its declared target; ``flow_id`` restricts (and,
    without ``path_id``, selects) the declared paths of one F1..F6 category;
    ``source_id`` names a declared source of the resolved path;
    ``input_slice`` names the exact declared input bits.  Nothing is inferred:
    an unresolved request is refused with an existing rejection code.
    """

    path_id: str | None = None
    flow_id: str | None = None
    source_id: str | None = None
    input_slice: InputSlice | None = None

    def __post_init__(self) -> None:
        for name in ("path_id", "source_id"):
            value = getattr(self, name)
            if value is not None and (type(value) is not str or not value.strip()):
                raise ValueError(f"switch {name} must be a nonempty string")
        if self.flow_id is not None and self.flow_id not in (
                "F1", "F2", "F3", "F4", "F5", "F6"):
            raise ValueError("switch flow must be a declared F1..F6 category")
        if self.input_slice is not None and not isinstance(self.input_slice,
                                                           InputSlice):
            raise ValueError("switch input slice must be an InputSlice")
        if all(value is None for value in (self.path_id, self.flow_id,
                                           self.source_id, self.input_slice)):
            raise ValueError("a switch request needs at least one declared field")

    def document(self) -> dict:
        return {"schema_version": PATH_SWITCH_REQUEST_SCHEMA_VERSION,
                "path_id": self.path_id, "flow_id": self.flow_id,
                "source_id": self.source_id,
                "input_slice": (None if self.input_slice is None
                                else self.input_slice.document())}

    @classmethod
    def from_document(cls, document: object) -> "PathSwitchRequest":
        fields = {"schema_version", "path_id", "flow_id", "source_id",
                  "input_slice"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("switch request has unknown or missing fields")
        if document["schema_version"] != PATH_SWITCH_REQUEST_SCHEMA_VERSION:
            raise ValueError("unsupported switch request schema_version")
        slice_ = document["input_slice"]
        try:
            return cls(path_id=document["path_id"], flow_id=document["flow_id"],
                       source_id=document["source_id"],
                       input_slice=(None if slice_ is None
                                    else InputSlice.from_document(slice_)))
        except TypeError as error:
            raise ValueError("invalid switch request document") from error


@dataclass(frozen=True)
class PathSwitchRecord:
    """Identity of one applied switch, recomputable from its own fields.

    ``families`` names the requested operator families, ``changed`` says
    whether the resolved candidate identity differs from the unswitched one,
    and ``operator_id`` is the content digest of every other field, so a
    tampered record cannot be reloaded.
    """

    families: tuple[str, ...]
    from_path_id: str
    from_source_id: str
    path_id: str
    source_id: str
    flow_id: str | None
    changed: bool
    request: PathSwitchRequest
    ownership_producer: str | None = None

    def __post_init__(self) -> None:
        if (not isinstance(self.families, tuple) or not self.families
                or any(family not in PATH_SWITCH_FAMILIES
                       for family in self.families)
                or self.families != tuple(sorted(set(self.families)))):
            raise ValueError("switch families must be declared, unique and sorted")
        for name in ("from_path_id", "from_source_id", "path_id", "source_id"):
            value = getattr(self, name)
            if type(value) is not str or not value:
                raise ValueError(f"switch record needs a declared {name}")
        if self.flow_id is not None and self.flow_id not in (
                "F1", "F2", "F3", "F4", "F5", "F6"):
            raise ValueError("switch record flow must be an F1..F6 category")
        if type(self.changed) is not bool:
            raise ValueError("switch record changed flag must be boolean")
        if not isinstance(self.request, PathSwitchRequest):
            raise ValueError("switch record needs its own request")
        if self.ownership_producer is not None and (
                type(self.ownership_producer) is not str
                or not self.ownership_producer):
            raise ValueError("switch ownership producer must be a nonempty string")

    def _material(self) -> dict:
        return {"schema_version": PATH_SWITCH_SCHEMA_VERSION,
                "families": list(self.families),
                "from_path_id": self.from_path_id,
                "from_source_id": self.from_source_id,
                "path_id": self.path_id, "source_id": self.source_id,
                "flow_id": self.flow_id, "changed": self.changed,
                "ownership_producer": self.ownership_producer,
                "request": self.request.document()}

    @property
    def operator_id(self) -> str:
        encoded = json.dumps(self._material(), sort_keys=True,
                             separators=(",", ":"), ensure_ascii=False,
                             allow_nan=False).encode("utf-8")
        return "online-path-switch.v1:" + hashlib.sha256(encoded).hexdigest()

    def document(self) -> dict:
        return {**self._material(), "operator_id": self.operator_id}

    @classmethod
    def from_document(cls, document: object) -> "PathSwitchRecord":
        fields = {"schema_version", "families", "from_path_id", "from_source_id",
                  "path_id", "source_id", "flow_id", "changed",
                  "ownership_producer", "request", "operator_id"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("switch record has unknown or missing fields")
        if document["schema_version"] != PATH_SWITCH_SCHEMA_VERSION:
            raise ValueError("unsupported switch record schema_version")
        families = document["families"]
        if type(families) is not list:
            raise ValueError("switch record families must be a list")
        try:
            record = cls(families=tuple(families),
                         from_path_id=document["from_path_id"],
                         from_source_id=document["from_source_id"],
                         path_id=document["path_id"],
                         source_id=document["source_id"],
                         flow_id=document["flow_id"],
                         changed=document["changed"],
                         request=PathSwitchRequest.from_document(
                             document["request"]),
                         ownership_producer=document["ownership_producer"])
        except TypeError as error:
            raise ValueError("invalid switch record document") from error
        # A loaded record must carry its own content digest; recomputing a
        # missing or forged one would accept a tampered identity.
        if document["operator_id"] != record.operator_id:
            raise ValueError("switch record operator id does not match its material")
        return record


@dataclass(frozen=True)
class CandidateDisposition:
    """Machine-readable disposition of one candidate decode or commit.

    ``admitted`` means a legal candidate exists (``selection`` says whether the
    raw byte named the source directly or feedback weights fell back to one).
    ``degraded`` means a legal fallback was substituted, so the candidate is
    usable but the requested mutation was not materialized. ``rejected`` means
    no candidate was produced. ``uncertain`` means the candidate may already
    have reached the caller, so the decoder cannot claim a clean refusal.
    ``switch`` carries the applied switch operator record when one ran; the
    legacy document keys stay unchanged without it.
    """

    disposition: str
    reason: str
    selection: str | None = None
    rejection: Rejection | None = None
    switch: PathSwitchRecord | None = None

    def __post_init__(self) -> None:
        if self.disposition not in CANDIDATE_DISPOSITIONS:
            raise ValueError("unknown candidate disposition")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("candidate disposition requires a stable reason")
        if self.selection is not None and self.selection not in SOURCE_SELECTION_REASONS:
            raise ValueError("unknown source selection reason")
        if self.rejection is not None and not isinstance(self.rejection, Rejection):
            raise ValueError("candidate rejection must be a Rejection value")
        if (self.disposition in ("degraded", "rejected", "uncertain")
                and self.rejection is None):
            raise ValueError(f"{self.disposition} disposition requires a rejection code")
        if self.disposition == "admitted" and self.rejection is not None:
            raise ValueError("admitted disposition carries no rejection")
        if self.switch is not None and not isinstance(self.switch,
                                                      PathSwitchRecord):
            raise ValueError("candidate disposition switch must be a record")

    def document(self) -> dict:
        """Stable disposition record; the legacy receipt keys are unchanged."""
        document = {
            "schema_version": CANDIDATE_DECISION_SCHEMA_VERSION,
            "candidate_disposition": self.disposition,
            "candidate_disposition_reason": self.reason,
            "source_selection_reason": self.selection,
            "rejection": (None if self.rejection is None
                          else self.rejection.document()),
        }
        if self.switch is not None:
            # Only a case an explicit operator ran on carries the extra block,
            # so every default candidate decision stays byte-identical.
            document["switch"] = self.switch.document()
        return document


def _mutation_source(ownership: OwnershipMap, component: str, port: str,
                     bit_offset: int, width: int, *, direction: str) -> str:
    """Bind one mutation to its producer, keeping the refusal code."""
    try:
        return ownership.mutation_source(component, port, bit_offset, width,
                                         direction=direction)
    except RejectionError:
        raise
    except ValueError as error:
        rejection = _ownership_rejection(error, component, port, bit_offset, width)
        if rejection is None:
            raise
        raise RejectionError(str(error), rejection) from error


def _ownership_rejection(error: ValueError, component: str, port: str,
                         bit_offset: int, width: int) -> Rejection | None:
    """Classify one refusal of the compiled ownership map, or None if unknown."""
    message = error.args[0] if error.args else ""
    if not isinstance(message, str):
        return None
    detail = {"component": component, "port": port}
    if message == "undeclared input field":
        return Rejection(RejectionCode.OWNERSHIP_UNDECLARED_FIELD,
                         "source.port", detail)
    if message == "mutation range exceeds input field":
        return Rejection(RejectionCode.OWNERSHIP_RANGE_EXCEEDS_FIELD,
                         "source.bit_offset",
                         {**detail, "bit_offset": bit_offset, "width": width})
    if message == "mutation spans multiple fuzzable sources":
        return Rejection(RejectionCode.OWNERSHIP_AMBIGUOUS_PRODUCER,
                         "source.bit_offset",
                         {**detail, "bit_offset": bit_offset, "width": width})
    if message == "bound input cannot be mutated":
        return Rejection(RejectionCode.OWNERSHIP_BOUND_INPUT, "source.port", detail)
    if message == "fixed input cannot be mutated":
        return Rejection(RejectionCode.OWNERSHIP_FIXED_INPUT, "source.port", detail)
    return None


@dataclass(frozen=True)
class OnlineSource:
    """One configured upstream input and its exploration metadata."""

    source_id: str
    kind: str
    component: str
    direction: str
    path_id: str
    weight: int = 1
    port: str = ""
    bit_offset: int = 0
    width: int = 1
    coverage_target_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.source_id or not self.component or not self.path_id:
            raise ValueError("source identity, component and path are required")
        if self.kind not in ("instruction", "source") or self.direction not in DIRECTIONS:
            raise ValueError("unsupported online source kind or direction")
        if type(self.weight) is not int or self.weight < 1:
            raise ValueError("source weight must be positive")
        if type(self.bit_offset) is not int or self.bit_offset < 0:
            raise ValueError("source offset must be nonnegative")
        if type(self.width) is not int or not 1 <= self.width <= 65536:
            raise ValueError("source width must be within the batch bound")
        if self.kind == "source" and not self.port:
            raise ValueError("external source requires a port")
        if self.kind == "instruction" and (self.port or self.bit_offset or self.width != 1):
            raise ValueError("instruction source cannot describe an input port")
        if (not isinstance(self.coverage_target_ids, tuple)
                or any(not isinstance(target, str) or not target
                       for target in self.coverage_target_ids)
                or len(set(self.coverage_target_ids)) != len(self.coverage_target_ids)):
            raise ValueError("coverage target IDs must be unique nonempty strings")


@dataclass(frozen=True)
class OnlineDependencySource:
    """Declared online graph node; instruction is distinct from boot memory."""

    source_id: str
    kind: str
    component: str
    directions: tuple[str, ...]
    port: str = ""
    bit_offset: int = 0
    width: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.directions, tuple) or not self.directions:
            raise ValueError("online graph source needs declared directions")
        for direction in self.directions:
            OnlineSource(self.source_id, self.kind, self.component, direction,
                         "graph-node", port=self.port, bit_offset=self.bit_offset,
                         width=self.width)


class OnlineDependencyGraph(DependencyGraph):
    """Caller-declared online paths using the existing AND/OR traversal.

    This is a checked declaration, not automatic discovery of RTL behavior.
    Instruction nodes never masquerade as initial memory-image mutations.
    """

    def __init__(self, *, sources: tuple[OnlineDependencySource, ...],
                 rules: tuple[DependencyRule, ...]) -> None:
        if not isinstance(sources, tuple) or any(
                not isinstance(source, OnlineDependencySource) for source in sources):
            raise ValueError("online dependency nodes must be a tuple")
        super().__init__(sources=(), rules=rules)
        self.sources = {source.source_id: source for source in sources}
        if len(self.sources) != len(sources):
            raise ValueError("online graph source identities must be unique")


class OnlineCaseDecoder(_RuntimePathCache):
    """Weighted source selection with a caller-owned instruction reservation.

    Only one outstanding proposal is supported. decode does not consume slots
    or increment case identity. commit must follow successful submit_case; a
    rejected proposal can be replaced by another decode at the same cursor.
    path_id is the graph target when graph is supplied. Without a graph the
    configuration is explicitly untrusted_manual; labels do not prove paths.
    Pass template.max_steps to max_steps to validate the local case budget.
    """

    def __init__(self, *, sources: tuple[OnlineSource, ...],
                 ownership: OwnershipMap, schedule: tuple[str, ...],
                 instruction_start: int, instruction_end: int,
                 instruction_cursor: int | None = None,
                 windows: tuple[MmioWindow, ...] = (), advance_rounds: int = 16,
                 max_input_bytes: int = 4096,
                 graph: DependencyGraph | None = None,
                 max_steps: int | None = None,
                 allowed_mmio_operations: tuple[str, ...] = ("LW", "SW", "SB"),
                 support_words: int = 0,
                 runtime_contract: RuntimePathContract | None = None,
                 flow_by_target: Mapping[str, str] | None = None,
                 source_actions: tuple[OnlineSourceActionDeclaration, ...] = ()) -> None:
        self._runtime_contract = None
        if not isinstance(sources, tuple) or not sources or any(
                not isinstance(source, OnlineSource) for source in sources):
            raise ValueError("configured online sources are required")
        if len({source.source_id for source in sources}) != len(sources):
            raise ValueError("source identities must be unique")
        BatchAdvance(schedule)
        if len(set(schedule)) != len(schedule):
            raise ValueError("schedule must name each component once")
        if not isinstance(ownership, OwnershipMap):
            raise ValueError("compiled ownership is required")
        cursor = instruction_start if instruction_cursor is None else instruction_cursor
        if any(type(value) is not int or value < 0 or value % 4
               for value in (instruction_start, instruction_end, cursor)) or not (
                   instruction_start <= cursor <= instruction_end <= 1 << 32):
            raise ValueError("instruction reservation and cursor must be aligned RV32 addresses")
        if type(advance_rounds) is not int or not 1 <= advance_rounds <= 4096:
            raise ValueError("advance rounds exceed the online budget")
        if max_steps is not None and (type(max_steps) is not int or max_steps < 1
                                      or advance_rounds * len(schedule) > max_steps):
            raise ValueError("online advances exceed the caller per-case max_steps")
        if graph is not None and not isinstance(graph, DependencyGraph):
            raise ValueError("dependency graph must be a declared graph")
        if type(max_input_bytes) is not int or not 1 <= max_input_bytes <= 65536:
            raise ValueError("invalid input byte bound")
        if runtime_contract is not None:
            if graph is None:
                raise ValueError('runtime contract requires dependency graph')
            self._initialize_runtime_paths(graph, ownership, runtime_contract,
                tuple((source.direction, source.path_id) for source in sources))
            graph, ownership = self.graph, self.ownership
        for source in sources:
            if source.component not in schedule:
                raise ValueError("source component is absent from schedule")
            if graph is not None:
                node = graph.sources.get(source.source_id)
                if node is None or (node.kind, node.component, node.port,
                                    node.bit_offset, node.width) != (
                                        source.kind, source.component, source.port,
                                        source.bit_offset, source.width) or \
                        source.direction not in node.directions:
                    raise ValueError("online source disagrees with dependency node")
                paths = (self.paths_for(source.path_id, direction=source.direction)
                         if runtime_contract is not None else
                         graph.paths_to(source.path_id, direction=source.direction))
                if not any(source.source_id in path.source_ids for path in paths):
                    raise ValueError("declared path target does not reach this source")
            if source.kind == "source":
                _mutation_source(ownership, source.component, source.port,
                                 source.bit_offset, source.width,
                                 direction=source.direction)
        cpu_components = {source.component for source in sources
                          if source.kind == "instruction"}
        if len(cpu_components) > 1:
            raise ValueError("one instruction cursor supports one CPU")
        if type(support_words) is not int or not 0 <= support_words <= 4096:
            raise ValueError("fixed support words must be within 0..4096")
        self.support_words = support_words
        if runtime_contract is not None:
            self._source_runtime_paths = MappingProxyType({source.source_id:
                tuple(path for path in self.paths_for(source.path_id, direction=source.direction)
                      if source.source_id in path.source_ids) for source in sources})
        self._instruction_component = next(iter(cpu_components), None)
        self.sources, self.ownership = sources, ownership
        self.graph = graph
        if runtime_contract is not None:
            self._path_candidates = tuple(
                (self.path_identifier(path, direction=direction),
                 tuple(source for source in sources
                       if source.direction == direction and source.path_id == path.target
                       and source.source_id in path.source_ids))
                for direction, path in self.runtime_paths
                if any(source.direction == direction and source.path_id == path.target
                       and source.source_id in path.source_ids for source in sources)
            )
        else:
            self._path_candidates = tuple(
                (path_id, tuple(source for source in sources
                                if (source.direction, source.path_id) == (direction, path_id)))
                for direction, path_id in dict.fromkeys(
                    (source.direction, source.path_id) for source in sources)
            )
        if flow_by_target is not None:
            if runtime_contract is None or not isinstance(flow_by_target, Mapping):
                raise ValueError("flow categories require declared runtime paths")
            declared_targets = {source.path_id for source in sources}
            if (set(flow_by_target) != declared_targets
                    or any(type(flow) is not str or flow not in
                           {"F1", "F2", "F3", "F4", "F5", "F6"}
                           for flow in flow_by_target.values())):
                raise ValueError("each runtime path target needs an F1-F6 flow category")
            self.flow_by_target = MappingProxyType(dict(sorted(flow_by_target.items())))
        else:
            self.flow_by_target = None
        if (not isinstance(source_actions, tuple)
                or any(not isinstance(item, OnlineSourceActionDeclaration)
                       for item in source_actions)):
            raise ValueError("declared source actions must be a tuple of declarations")
        if source_actions and (runtime_contract is None or flow_by_target is None):
            # A declared action names a flow category of a stable runtime path,
            # so without both declarations no action could ever be built.
            raise ValueError(
                "declared source actions require declared runtime paths and flows")
        declared_source_ids = {source.source_id for source in sources}
        seen_declarations: set[str] = set()
        for declaration in source_actions:
            if declaration.source_id not in declared_source_ids:
                raise ValueError(
                    "source action declaration names an undeclared online source")
            if declaration.source_id in seen_declarations:
                raise ValueError("duplicate source action declaration")
            seen_declarations.add(declaration.source_id)
        self.source_actions = MappingProxyType(
            {item.source_id: item for item in source_actions})
        self.paths_validated = graph is not None
        self.dependency_mode = "declared_graph" if graph is not None else "untrusted_manual"
        if runtime_contract is not None:
            self.dependency_mode = 'runtime_contract'
        self.from_document_replay_only = False
        self.trusted_for_search = graph is not None
        self.max_steps = max_steps
        self.instruction_start, self.instruction_end = instruction_start, instruction_end
        self.instruction_cursor = cursor
        self._initial_instruction_cursor = cursor
        if (not isinstance(allowed_mmio_operations, tuple) or not allowed_mmio_operations
                or any(operation not in ("LW", "SW", "SB") for operation in allowed_mmio_operations)
                or len(set(allowed_mmio_operations)) != len(allowed_mmio_operations)):
            raise ValueError("allowed MMIO operations must be a nonempty distinct supported tuple")
        self.allowed_mmio_operations = allowed_mmio_operations
        self.windows = windows
        self.advances = (BatchAdvance(schedule),) * advance_rounds
        self.max_input_bytes = max_input_bytes
        self._sequence = 0
        self._proposal: OnlineCase | None = None
        #: Raw input and applied switch of the current proposal; both are the
        #: only state ``switch_proposal`` needs to retarget it exactly.
        self._proposal_raw: bytes | None = None
        self._proposal_switch: PathSwitchRecord | None = None
        self._switch_records: dict[str, PathSwitchRecord] = {}

    def document(self) -> dict:
        """Stable construction manifest; live cursor and case count are absent.

        Raw inputs also need their per-case coverage hints and acceptance order
        for replay. A declared graph manifest records declarations, not proof
        that the real RTL completed their candidate paths.
        """
        graph = None
        if self.graph is not None:
            nodes = []
            for _, node in sorted(self.graph.sources.items()):
                record = asdict(node)
                record["directions"] = list(node.directions)
                nodes.append(record)
            rules = []
            for rule in sorted((rule for values in self.graph.rules.values()
                                for rule in values),
                               key=lambda rule: (rule.target, rule.kind, rule.prerequisites)):
                record = asdict(rule)
                record["prerequisites"] = list(rule.prerequisites)
                rules.append(record)
            graph = {"nodes": nodes, "rules": rules}
        document = {
            "schema_version": "online_case_decoder.v1",
            "sources": [asdict(source) for source in self.sources],
            "graph": graph,
            "dependency_mode": self.dependency_mode,
            "ownership": self.ownership.document(),
            "instruction_start": self.instruction_start,
            "instruction_end": self.instruction_end,
            "initial_instruction_cursor": self._initial_instruction_cursor,
            "mmio_windows": [asdict(window) for window in self.windows],
            "allowed_mmio_operations": list(self.allowed_mmio_operations),
            "schedule": list(self.advances[0].schedule),
            "advance_rounds": len(self.advances),
            "max_steps": self.max_steps,
            "max_input_bytes": self.max_input_bytes,
            "support_words": self.support_words,
        }
        if self.runtime_contract is not None:
            document['schema_version'] = 'online_case_decoder.v2'
            document['graph'] = self.graph.edge_document()
            document['runtime_contract'] = self.runtime_contract.document()
            document['path_mapping'] = self._path_mapping_document()
            if self.flow_by_target is not None:
                document['schema_version'] = 'online_case_decoder.v3'
                document['flow_by_target'] = dict(self.flow_by_target)
        if self.source_actions:
            # Declared prerequisites change admission, so they belong to the
            # manifest identity.  A decoder without declarations keeps the
            # older schema and stays byte-identical for existing traces.
            document['schema_version'] = 'online_case_decoder.v4'
            document['source_actions'] = [item.document()
                                          for item in self.source_actions.values()]
        return document

    def path_target(self, path_id):
        return self.resolve_path_id(path_id)[1].target if self.runtime_contract is not None else path_id

    def _case_source_identity(self, case: OnlineCase) -> tuple[OnlineSource, str]:
        """Resolve the declared source and target of one decoded case."""
        matching = next(((path_id, path_sources) for path_id, path_sources
                         in self._path_candidates if path_id == case.path_id), None)
        if matching is None:
            reject(RejectionCode.PATH_UNDECLARED,
                   "case path is not declared by this decoder", "case.path_id",
                   path_id=case.path_id)
        _, path_sources = matching
        selected = next((source for source in path_sources
                         if case.source.action_id == f"{case.case_id}:{source.source_id}"
                         and case.source.component == source.component
                         and ((source.kind == "instruction"
                               and isinstance(case.source, OnlineInstruction))
                              or (source.kind == "source"
                                  and isinstance(case.source, BatchSourceEvent)
                                  and (case.source.port, case.source.bit_offset,
                                       case.source.width) ==
                                  (source.port, source.bit_offset, source.width)))), None)
        if selected is None or selected.direction != case.direction:
            reject(RejectionCode.PATH_SOURCE_MISMATCH,
                   "case source is not declared on selected path",
                   "case.source.action_id", path_id=case.path_id,
                   action_id=case.source.action_id, direction=case.direction)
        return selected, self.path_target(case.path_id)

    def source_action(self, case: OnlineCase) -> SourceAction:
        """Build the versioned source action of one decoded online case.

        Every field comes from an existing declaration (see the module
        docstring); an action that cannot be derived exactly is refused with
        :class:`OnlineSourceActionRefusal` instead of being invented.  The
        returned action is not registered anywhere: the online RFuzz path
        registers it with its prerequisite gate before any RTL command.
        """
        if not isinstance(case, OnlineCase):
            reject(RejectionCode.DECODE_MALFORMED_RECORD,
                   "online source action requires a decoded case", "case")
        if self._proposal is None or case != self._proposal:
            raise OnlineSourceActionRefusal(
                "case_not_current_proposal",
                {"case_id": getattr(case, "case_id", None)})
        selected, target = self._case_source_identity(case)
        flow_id = (None if self.flow_by_target is None
                   else self.flow_by_target.get(target))
        if flow_id is None:
            raise OnlineSourceActionRefusal(
                "flow_category_undeclared",
                {"target_id": target, "path_id": case.path_id,
                 "source_id": selected.source_id})
        kind = SOURCE_ACTION_KIND[selected.kind]
        if selected.kind == "instruction":
            # The decoder drives the instruction bytes it decoded into the
            # slot the caller reserved; no ownership field describes them.
            payload = {"address": case.source.address,
                       "words_hex": case.source.data_hex}
        else:
            # The compiled ownership map is the authority on mutability: a
            # bound or fixed producer (including the CPU IRQ input) refuses.
            _mutation_source(self.ownership, selected.component, selected.port,
                             selected.bit_offset, selected.width,
                             direction=selected.direction)
            payload = {"port": case.source.port,
                       "bit_offset": case.source.bit_offset,
                       "width": case.source.width, "value": case.source.value}
        budget = len(self.advances) * len(self.advances[0].schedule)
        if not 1 <= budget <= MAX_LOCAL_STEP_BUDGET:
            raise OnlineSourceActionRefusal(
                "local_step_budget_invalid",
                {"local_step_budget": budget, "advance_rounds": len(self.advances),
                 "schedule_length": len(self.advances[0].schedule)})
        declaration = self.source_actions.get(selected.source_id)
        prerequisites = () if declaration is None else declaration.prerequisites
        termination = (None if declaration is None
                       else declaration.termination_observation)
        if termination is None:
            # Nothing has run yet: claim no consumption, retirement or delivery.
            termination = TerminationObservation("incomplete", "", flow_id)
        return SourceAction(action_id=case.source.action_id, kind=kind,
                            component=selected.component,
                            source_id=selected.source_id, ownership="fuzzable",
                            flow_id=flow_id, payload=payload,
                            termination_observation=termination,
                            local_step_budget=budget,
                            prerequisites=tuple(prerequisites))

    def decision_metadata(self, case: OnlineCase, *,
                          switch: PathSwitchRequest | None = None
                          ) -> dict[str, str | None]:
        """Return the declared identity of a decoded case for candidate traces.

        Legacy decoders have no trusted flow declaration and return None for
        flow_id. Runtime path IDs remain the graph's stable edge identities.
        When an applied switch changed the candidate, its operator id is part
        of ``candidate_id``; ``switch`` asserts that this case is the current
        proposal's switched identity and refuses any other request.  A case no
        switch changed keeps exactly the shipped identity keys and digest.
        """
        if not isinstance(case, OnlineCase):
            reject(RejectionCode.DECODE_MALFORMED_RECORD,
                   "online decision metadata requires a case", "case")
        selected, target = self._case_source_identity(case)
        if self._proposal is not None and case == self._proposal:
            record = self._proposal_switch
        else:
            record = self._switch_records.get(case.case_id)
        if switch is not None:
            if not isinstance(switch, PathSwitchRequest):
                reject(RejectionCode.DECODE_MALFORMED_RECORD,
                       "a switch request is required", "switch")
            if (self._proposal is None or case != self._proposal
                    or record is None or record.request != switch):
                reject(RejectionCode.SLOT_PROPOSAL_MISMATCH,
                       "switch identity requires the current switched proposal "
                       "and its own applied request", "switch.request",
                       case_id=case.case_id)
        operator_id = (instruction_operator_id(case.source.data)
                       if isinstance(case.source, OnlineInstruction)
                       else 'external_event')
        identity = {"direction": case.direction,
                "flow_id": (self.flow_by_target[target]
                            if self.flow_by_target is not None else None),
                "path_id": case.path_id, "target_id": target,
                "source_id": selected.source_id, "operator_id": operator_id}
        if record is not None and record.changed:
            # Only a case whose identity a switch changed commits to the
            # operator, so every unswitched candidate id is untouched.
            identity["switch_operator_id"] = record.operator_id
        candidate_digest = hashlib.sha256(json.dumps(
            identity, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        return {"case_id": case.case_id, **identity,
                "candidate_id": 'online-candidate.v1:' + candidate_digest}

    def sources_for(self, path_id):
        if self.runtime_contract is None:
            return tuple(source for source in self.sources if source.path_id == path_id)
        direction, path = self.resolve_path_id(path_id)
        return tuple(source for source in self.sources if source.direction == direction
                     and source.path_id == path.target and source.source_id in path.source_ids)

    @classmethod
    def from_document(cls, document):
        schemas = ('online_case_decoder.v1', 'online_case_decoder.v2',
                   'online_case_decoder.v3', 'online_case_decoder.v4')
        if not isinstance(document, dict) or document.get('schema_version') not in schemas:
            raise ValueError('unknown online decoder schema')
        try:
            schema = document['schema_version']
            edge_mode = schema in ('online_case_decoder.v2', 'online_case_decoder.v3',
                                   'online_case_decoder.v4')
            flow_mode = schema in ('online_case_decoder.v3', 'online_case_decoder.v4')
            action_mode = schema == 'online_case_decoder.v4'
            graph_doc = document['graph']
            graph = None
            if edge_mode:
                graph = OnlineDependencyGraph.from_edge_document(graph_doc, source_factory=OnlineDependencySource)
            elif graph_doc is not None:
                graph = OnlineDependencyGraph(sources=tuple(OnlineDependencySource(**{**row, 'directions': tuple(row['directions'])}) for row in graph_doc['nodes']),
                    rules=tuple(DependencyRule(**{**row, 'prerequisites': tuple(row['prerequisites'])}) for row in graph_doc['rules']))
            ownership_doc = document['ownership']
            ownership = compile_ownership(tuple(InputField(**row) for row in ownership_doc['fields']),
                tuple(InputOwner(**row) for row in ownership_doc['owners']))
            decoder = cls(sources=tuple(OnlineSource(**{**row, 'coverage_target_ids': tuple(row['coverage_target_ids'])}) for row in document['sources']),
                ownership=ownership, graph=graph, schedule=tuple(document['schedule']),
                instruction_start=document['instruction_start'], instruction_end=document['instruction_end'],
                instruction_cursor=document['initial_instruction_cursor'], windows=tuple(
                    MmioWindow(**{**row, 'write_widths': tuple(row['write_widths'])})
                    if 'write_widths' in row else MmioWindow(**row)
                    for row in document['mmio_windows']),
                advance_rounds=document['advance_rounds'], max_steps=document['max_steps'], max_input_bytes=document['max_input_bytes'],
                support_words=document['support_words'], allowed_mmio_operations=tuple(document['allowed_mmio_operations']),
                runtime_contract=RuntimePathContract.from_document(document['runtime_contract']) if edge_mode else None,
                flow_by_target=document['flow_by_target'] if flow_mode else None,
                source_actions=(tuple(OnlineSourceActionDeclaration.from_document(row)
                                      for row in document['source_actions'])
                                if action_mode else ()))
            if json.dumps(decoder.document(), sort_keys=True, separators=(',', ':')) != json.dumps(document, sort_keys=True, separators=(',', ':')):
                raise ValueError('online decoder manifest is not canonical')
            decoder.from_document_replay_only = True
            decoder.trusted_for_search = False
            return decoder
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError('invalid online decoder document') from error

    def decode(self, raw: bytes, *, coverage_hints: Mapping[str, int] | None = None
               ) -> OnlineCase:
        """Decode bytes; optional positive source weights bias uncovered paths.

        The complete raw input selects a declared path using feedback-weighted
        path priority. A domain-separated digest mixes transport bytes so a
        fixed low-order path byte cannot freeze exploration.
        Byte 2 directly names a configured source only if it belongs to that
        path and remains legal. Other values use coverage-weighted source
        selection within the chosen path. Payload bytes 3..7 lead mutation
        entropy, so the Rust client's
        fixed template/path/source bytes cannot freeze operation or pin value.
        Exhausted CPU reservations are excluded from source selection. A final
        slot too small for a multiword fragment receives a legal NOP. No
        earlier accepted instruction slot is overwritten.

        A refusal raises a ValueError that also carries a versioned rejection;
        use decode_candidate when the disposition must be recorded as well.
        """
        return self._decode_case(raw, coverage_hints=coverage_hints)[0]

    def _decode_case(self, raw: bytes, *, coverage_hints: Mapping[str, int] | None = None
                     ) -> tuple[OnlineCase, Rejection | None, bool]:
        """Decode one case and report its degradation and direct selection."""
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= self.max_input_bytes:
            reject(RejectionCode.DECODE_UNBOUNDED_INPUT,
                   "online input must be nonempty bounded bytes", "input.raw",
                   length=(len(raw) if isinstance(raw, bytes) else raw),
                   max_input_bytes=self.max_input_bytes)
        hints = {} if coverage_hints is None else dict(coverage_hints)
        if set(hints) - {source.source_id for source in self.sources} or any(
                type(value) is not int or not 1 <= value <= 65536
                for value in hints.values()):
            reject(RejectionCode.DECODE_BAD_COVERAGE_HINT,
                   "coverage hints must be bounded positive source weights",
                   "input.coverage_hints",
                   hints=sorted(hints.items(), key=lambda item: str(item[0])))
        eligible = tuple(source for source in self.sources
                         if source.kind != "instruction" or
                         self.instruction_cursor + 4 <= self.instruction_end)
        if not eligible:
            reject(RejectionCode.BUDGET_EXHAUSTED,
                   "no online source remains within its admission bounds",
                   "instruction.cursor", cursor=self.instruction_cursor,
                   instruction_end=self.instruction_end)
        eligible_set = set(eligible)
        candidates = tuple((path_id, tuple(source for source in path_sources
                                            if source in eligible_set))
                           for path_id, path_sources in self._path_candidates)
        candidates = tuple((path_id, path_sources) for path_id, path_sources in candidates
                           if path_sources)
        # A path's priority is its strongest legal upstream source. A path
        # with more declared sources should not gain weight solely by size.
        path_weights = tuple(max(hints.get(source.source_id, source.weight)
                                 for source in path_sources)
                             for _, path_sources in candidates)
        path_entropy = hashlib.sha256(b"myfuzz.online.path.v1\0" + raw).digest()
        path_selector = int.from_bytes(path_entropy[:8], "little") % sum(path_weights)
        for (path_id, path_sources), weight in zip(candidates, path_weights):
            if path_selector < weight:
                break
            path_selector -= weight
        weights = tuple(hints.get(source.source_id, source.weight)
                        for source in path_sources)
        direct = raw[2] if len(raw) > 2 else len(self.sources)
        direct_selected = direct < len(self.sources) and self.sources[direct] in path_sources
        if direct_selected:
            selected = self.sources[direct]
        else:
            selector = int.from_bytes(raw[:8], "little") % sum(weights)
            for source, weight in zip(path_sources, weights):
                if selector < weight:
                    selected = source
                    break
                selector -= weight
        entropy = self._case_entropy(raw)
        digest = hashlib.sha256(raw).hexdigest()[:24]
        case_id = f"online-{self._sequence}-{digest}"
        source_input, supports, degradation = self._materialize_case(
            case_id, selected, entropy)
        case = OnlineCase(case_id, selected.direction, path_id,
                          source_input, self.advances, support_instructions=supports)
        self._proposal = case
        self._proposal_raw = raw
        self._proposal_switch = None
        return case, degradation, direct_selected

    @staticmethod
    def _case_entropy(raw: bytes) -> bytes:
        """The twelve mutation-entropy bytes of one raw input.

        Payload bytes 3.. lead, so the client's fixed template/path/source
        bytes cannot freeze the operation or the pin value.  The unswitched
        decode and an applied switch share this rule exactly.
        """
        if len(raw) >= 8:
            payload = raw[3:]
            return (payload * ((12 + len(payload) - 1) // len(payload)))[:12]
        return raw

    def _materialize_case(self, case_id: str, selected: OnlineSource,
                          entropy: bytes
                          ) -> tuple[OnlineInstruction | BatchSourceEvent,
                                     tuple[OnlineInstruction, ...],
                                     Rejection | None]:
        """Build one source input (and fixed support) from decoded entropy.

        The one declaration-driven materialization used by both the unswitched
        decode and an applied switch, so a retargeted case cannot be built by a
        second, divergent rule.
        """
        action_id = f"{case_id}:{selected.source_id}"
        degradation = None
        if selected.kind == "instruction":
            data = fragment_bytes(decode_instruction_fragment(
                entropy, windows=self.windows,
                allowed_mmio_operations=self.allowed_mmio_operations))
            if self.instruction_cursor + len(data) > self.instruction_end:
                degradation = Rejection(
                    RejectionCode.SLOT_OUT_OF_RESERVATION, "instruction.cursor",
                    {"cursor": self.instruction_cursor,
                     "instruction_end": self.instruction_end,
                     "requested_bytes": len(data)})
                data = fragment_bytes(decode_instruction_fragment(b"\x00"))
            source_input = OnlineInstruction(action_id, selected.component,
                                             self.instruction_cursor, data.hex())
        else:
            _mutation_source(self.ownership, selected.component, selected.port,
                             selected.bit_offset, selected.width,
                             direction=selected.direction)
            # Values are relative to their source slice; bound bits are absent.
            value = int.from_bytes(entropy, "little") & ((1 << selected.width) - 1)
            source_input = BatchSourceEvent(action_id, selected.component,
                                            selected.port, value,
                                            selected.bit_offset, selected.width)
        supports = ()
        if selected.kind == "source" and self._instruction_component is not None:
            count = min(self.support_words,
                        (self.instruction_end - self.instruction_cursor) // 4)
            if count:
                # Fixed execution assistance is not a selectable mutation source.
                nop = fragment_bytes(decode_instruction_fragment(b"\x00"))
                supports = (OnlineInstruction(
                    f"{case_id}:fixed-support", self._instruction_component,
                    self.instruction_cursor, (nop * count).hex()),)
        return source_input, supports, degradation

    # ------------------------------------------------------------------
    # Declared path/source switch operators (opt-in, see the module docstring)
    # ------------------------------------------------------------------

    @property
    def current_switch(self) -> PathSwitchRecord | None:
        """The applied switch record of the current proposal, if any."""
        return self._proposal_switch if self._proposal is not None else None

    def path_switch_targets(self, *, flow_id: str | None = None
                            ) -> tuple[dict, ...]:
        """List the declared switch pool: paths, flows and their sources.

        This is the complete set ``switch_proposal`` may resolve into, in
        declaration order.  A row reports every declared source of the path and
        the subset that is currently allowed, so a caller can see why a path is
        not switchable instead of being refused without a reason.
        """
        if flow_id is not None and flow_id not in ("F1", "F2", "F3", "F4", "F5", "F6"):
            raise ValueError("switch flow must be a declared F1..F6 category")
        rows = []
        for path_id, path_sources in self._path_candidates:
            flow = (None if self.flow_by_target is None
                    else self.flow_by_target.get(self.path_target(path_id)))
            if flow_id is not None and flow != flow_id:
                continue
            eligible = tuple(source for source in path_sources
                             if self._source_eligible(source))
            rows.append({"path_id": path_id,
                         "target_id": self.path_target(path_id),
                         "direction": path_sources[0].direction,
                         "flow_id": flow,
                         "source_ids": tuple(source.source_id
                                             for source in path_sources),
                         "eligible_source_ids": tuple(source.source_id
                                                      for source in eligible),
                         "switchable": bool(eligible)})
        return tuple(rows)

    def _source_eligible(self, source: OnlineSource) -> bool:
        """Whether one declared source may be materialized in the current state."""
        return (source.kind != "instruction"
                or self.instruction_cursor + 4 <= self.instruction_end)

    def _switch_ownership_producer(self, slice_: InputSlice,
                                   direction: str) -> str:
        """Bind one requested slice to its fuzzable producer, or refuse.

        The compiled ownership map stays the only authority; a refusal keeps its
        shipped ``ownership.*`` code and is re-pointed at the request field that
        carried the rejected slice.
        """
        try:
            return _mutation_source(self.ownership, slice_.component,
                                    slice_.port, slice_.bit_offset,
                                    slice_.width, direction=direction)
        except RejectionError as error:
            rejection = error.rejection
            raise RejectionError(
                str(error), Rejection(rejection.code, "switch.input_slice",
                                      rejection.detail)) from error

    def _resolve_switch(self, switch: PathSwitchRequest
                        ) -> tuple[str, OnlineSource, PathSwitchRecord]:
        """Resolve one request inside the declared pool, or refuse it."""
        proposal = self._proposal
        base_source, _ = self._case_source_identity(proposal)
        declared = tuple(self._path_candidates)
        if switch.flow_id is not None:
            if self.flow_by_target is None:
                reject(RejectionCode.PATH_UNDECLARED,
                       "this decoder declares no flow category to switch inside",
                       "switch.flow_id", flow_id=switch.flow_id)
            pool = tuple(entry for entry in declared
                         if self.flow_by_target.get(self.path_target(entry[0]))
                         == switch.flow_id)
            if not pool:
                reject(RejectionCode.PATH_UNDECLARED,
                       "requested flow declares no switchable path",
                       "switch.flow_id", flow_id=switch.flow_id,
                       declared_flows=sorted(set(self.flow_by_target.values())))
        else:
            pool = declared
        base_entry = next((entry for entry in declared
                           if entry[0] == proposal.path_id), None)
        if base_entry is None:
            reject(RejectionCode.PATH_UNDECLARED,
                   "current proposal path is not declared by this decoder",
                   "switch.path_id", path_id=proposal.path_id)
        if switch.path_id is not None:
            matched = tuple(entry for entry in pool
                            if entry[0] == switch.path_id
                            or self.path_target(entry[0]) == switch.path_id)
            if not matched:
                reject(RejectionCode.PATH_UNDECLARED,
                       "requested path is not a declared switch target",
                       "switch.path_id", path_id=switch.path_id,
                       flow_id=switch.flow_id,
                       declared_path_ids=sorted(entry[0] for entry in pool))
            path_id, path_sources = matched[0]
        elif switch.flow_id is not None:
            path_id, path_sources = pool[0]
        else:
            path_id, path_sources = base_entry
        direction = (proposal.direction if path_id == proposal.path_id
                     else path_sources[0].direction)
        eligible = tuple(source for source in path_sources
                         if self._source_eligible(source))
        producer = None
        if switch.source_id is not None:
            selected = next((source for source in path_sources
                             if source.source_id == switch.source_id), None)
            if selected is None:
                reject(RejectionCode.PATH_SOURCE_MISMATCH,
                       "requested source is not declared on the resolved path",
                       "switch.source_id", path_id=path_id,
                       source_id=switch.source_id,
                       declared_source_ids=sorted(source.source_id
                                                  for source in path_sources))
            if selected not in eligible:
                reject(RejectionCode.BUDGET_EXHAUSTED,
                       "switched instruction source has no room in its reservation",
                       "switch.source_id", source_id=selected.source_id,
                       instruction_cursor=self.instruction_cursor,
                       instruction_end=self.instruction_end)
        elif switch.input_slice is not None:
            slice_ = switch.input_slice
            producer = self._switch_ownership_producer(slice_, direction)
            selected = next(
                (source for source in path_sources if source.kind == "source"
                 and (source.component, source.port, source.bit_offset,
                      source.width) == slice_.field), None)
            if selected is None:
                reject(RejectionCode.PATH_SOURCE_MISMATCH,
                       "requested input slice is not a declared source on the "
                       "resolved path", "switch.input_slice",
                       path_id=path_id, component=slice_.component,
                       port=slice_.port, bit_offset=slice_.bit_offset,
                       width=slice_.width)
        elif path_id == proposal.path_id:
            selected = next((source for source in path_sources
                             if source.source_id == base_source.source_id),
                            None)
            if selected is None:
                reject(RejectionCode.PATH_SOURCE_MISMATCH,
                       "current proposal source is not declared on its path",
                       "switch.source_id", path_id=path_id,
                       source_id=base_source.source_id)
        elif eligible:
            selected = eligible[0]
        else:
            reject(RejectionCode.BUDGET_EXHAUSTED,
                   "resolved path has no source within its admission bounds",
                   "switch.path_id", path_id=path_id,
                   instruction_cursor=self.instruction_cursor,
                   instruction_end=self.instruction_end)
        if producer is None and selected.kind == "source":
            producer = self._switch_ownership_producer(
                InputSlice(selected.component, selected.port,
                           selected.bit_offset, selected.width), direction)
        families = tuple(sorted(
            family for family, requested in
            (("path_switch", switch.path_id is not None
              or switch.flow_id is not None),
             ("source_switch", switch.source_id is not None
              or switch.input_slice is not None))
            if requested))
        flow = (None if self.flow_by_target is None
                else self.flow_by_target.get(self.path_target(path_id)))
        record = PathSwitchRecord(
            families=families, from_path_id=proposal.path_id,
            from_source_id=base_source.source_id, path_id=path_id,
            source_id=selected.source_id, flow_id=flow,
            changed=(path_id != proposal.path_id
                     or selected.source_id != base_source.source_id),
            request=switch, ownership_producer=producer)
        return path_id, selected, record

    def _switch_base_selection(self, raw: bytes, record: PathSwitchRecord) -> str:
        """The unswitched selection reason, for a switch that changed nothing."""
        direct = raw[2] if len(raw) > 2 else len(self.sources)
        direct_selected = (direct < len(self.sources)
                           and self.sources[direct].source_id
                           == record.from_source_id)
        return ("direct_source_byte" if direct_selected
                else "feedback_weighted_legal_source")

    def switch_proposal(self, switch: PathSwitchRequest
                        ) -> tuple[OnlineCase | None, CandidateDisposition]:
        """Retarget the current proposal inside the declared pool (opt-in).

        Nothing is inferred and nothing is consumed by a refusal: the current
        proposal, the instruction cursor and the case counter stay exactly as
        they were, so the caller may still submit the unswitched case.  A
        granted switch returns the retargeted case together with the applied
        ``online_path_switch.v1`` record; the retargeted case keeps the raw
        input identity, the current proposal's declared advance budget, and is
        built by the same materialization rule as the unswitched case.
        """
        if not isinstance(switch, PathSwitchRequest):
            reject(RejectionCode.DECODE_MALFORMED_RECORD,
                   "a switch request is required", "switch")
        if self._proposal is None or self._proposal_raw is None:
            reject(RejectionCode.SLOT_PROPOSAL_MISMATCH,
                   "a switch requires the current decoded proposal",
                   "instruction.proposal")
        try:
            path_id, selected, record = self._resolve_switch(switch)
        except RejectionError as error:
            return None, CandidateDisposition("rejected", "switch_rejected",
                                              None, error.rejection)
        except ValueError as error:
            rejection = rejection_of(error)
            if rejection is None:
                raise
            return None, CandidateDisposition("rejected", "switch_rejected",
                                              None, rejection)
        raw = self._proposal_raw
        entropy = self._case_entropy(raw)
        proposal = self._proposal
        source_input, supports, degradation = self._materialize_case(
            proposal.case_id, selected, entropy)
        case = OnlineCase(proposal.case_id, selected.direction, path_id,
                          source_input, proposal.advances,
                          support_instructions=supports)
        self._proposal = case
        self._proposal_switch = record
        self._switch_records[proposal.case_id] = record
        while len(self._switch_records) > MAX_RETAINED_SWITCHES:
            self._switch_records.pop(next(iter(self._switch_records)))
        selection = (PATH_SWITCH_SELECTION_REASON if record.changed
                     else self._switch_base_selection(raw, record))
        if degradation is not None:
            return case, CandidateDisposition(
                "degraded", "instruction_reservation_fallback", selection,
                degradation, record)
        return case, CandidateDisposition("admitted", "declared_switch_applied",
                                          selection, None, record)

    def decode_candidate(self, raw: bytes, *,
                         coverage_hints: Mapping[str, int] | None = None
                         ) -> tuple[OnlineCase | None, CandidateDisposition]:
        """Decode one candidate and report its disposition with a failure code.

        The decoded case is returned unchanged; this call only adds the
        machine-readable disposition. A refusal that cannot be classified is
        re-raised unchanged rather than reported with an invented code.
        """
        try:
            case, degradation, direct_selected = self._decode_case(
                raw, coverage_hints=coverage_hints)
        except RejectionError as error:
            return None, CandidateDisposition("rejected", "decode_rejected",
                                              None, error.rejection)
        except ValueError as error:
            rejection = rejection_of(error)
            if rejection is None:
                raise
            return None, CandidateDisposition("rejected", "decode_rejected",
                                              None, rejection)
        selection = ("direct_source_byte" if direct_selected
                     else "feedback_weighted_legal_source")
        if degradation is not None:
            return case, CandidateDisposition(
                "degraded", "instruction_reservation_fallback", selection,
                degradation)
        return case, CandidateDisposition("admitted", "decoder_case_ready",
                                          selection, None)

    def commit(self, case: OnlineCase) -> None:
        """Advance decoder state after the caller successfully admits this case."""
        if self._proposal is None or case != self._proposal:
            reject(RejectionCode.SLOT_PROPOSAL_MISMATCH,
                   "commit requires the current decoded proposal",
                   "instruction.proposal",
                   case_id=getattr(case, "case_id", None))
        cursor = self.instruction_cursor
        fragments = ((case.source,) if isinstance(case.source, OnlineInstruction)
                     else case.support_instructions)
        for fragment in fragments:
            if fragment.address != cursor or cursor + len(fragment.data) > self.instruction_end:
                reject(RejectionCode.SLOT_OUT_OF_RESERVATION,
                       "instruction cursor or reservation changed before admission",
                       "instruction.cursor", cursor=cursor,
                       address=fragment.address, length=len(fragment.data),
                       instruction_end=self.instruction_end)
            cursor += len(fragment.data)
        self.instruction_cursor = cursor
        self._sequence += 1
        self._proposal = None
        self._proposal_raw = None
        self._proposal_switch = None

    def commit_candidate(self, case: OnlineCase) -> CandidateDisposition:
        """Commit after admission; a refusal is uncertain, never silently lost.

        The caller submits the case before committing, so a refusal here cannot
        claim the input never reached the RTL. The disposition is therefore
        ``uncertain`` and carries the exact code.
        """
        try:
            self.commit(case)
        except RejectionError as error:
            return CandidateDisposition("uncertain", "commit_after_submit_uncertain",
                                        None, error.rejection)
        except ValueError as error:
            rejection = rejection_of(error)
            if rejection is None:
                raise
            return CandidateDisposition("uncertain", "commit_after_submit_uncertain",
                                        None, rejection)
        return CandidateDisposition("admitted", "reservation_committed")
