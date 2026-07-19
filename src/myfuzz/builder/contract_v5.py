"""Compose-v5 protocol-agnostic contract hypothesis grammar.

This module intentionally does not discover a protocol by port or module name.
It provides the small canonical IR that later discovery stages can emit after
they have built a behavior-backed hypothesis from real RTL evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Mapping

from .contracts.experiment import canonical_json, content_digest
from .input_model import InputValidationError


CONTRACT_V5_GRAMMAR_VERSION = "myfuzz.contract-hypothesis-grammar/v5.0"
CONTRACT_V5_CANONICAL_SCHEMA = "myfuzz.contract-hypothesis-canonical/v5"
CONTRACT_V5_AMBIGUITY_SCHEMA = "myfuzz.contract-hypothesis-ambiguity/v5"

CONTRACT_V5_DIRECTIONS = frozenset({"input", "output", "inout", "internal"})
CONTRACT_V5_POLARITIES = frozenset({"active_high", "active_low", "level", "edge", "data"})
CONTRACT_V5_SIGNAL_ROLES = frozenset({
    "clock",
    "reset",
    "request_valid",
    "request_ready",
    "response_valid",
    "response_ready",
    "address",
    "write_data",
    "read_data",
    "byte_enable",
    "write_enable",
    "operation",
    "id",
    "error",
    "state",
    "external_event",
    "payload",
})
CONTRACT_V5_PREDICATE_KINDS = frozenset({
    "true",
    "signal_is",
    "signal_nonzero",
    "rose",
    "fell",
    "changed",
    "not",
    "and",
    "or",
})
CONTRACT_V5_ORDERING_RELATIONS = frozenset({
    "may_follow",
    "must_precede",
    "excludes",
})


@dataclass(frozen=True)
class ContractV5SignalRef:
    """A local signal candidate and its behavior-derived semantic role.

    ``source_id``, ``module`` and ``port`` are evidence references only.  They
    are deliberately removed from the canonical contract digest so that two
    renamed RTL designs can still compare equal.
    """

    source_id: str
    module: str
    port: str
    direction: str
    width: int
    role: str
    polarity: str = "level"

    def __post_init__(self) -> None:
        for name, value in (
            ("source_id", self.source_id),
            ("module", self.module),
            ("port", self.port),
            ("direction", self.direction),
            ("role", self.role),
            ("polarity", self.polarity),
        ):
            if not isinstance(value, str) or not value:
                raise InputValidationError(f"Contract v5 signal {name} must be a non-empty string")
        if self.direction not in CONTRACT_V5_DIRECTIONS:
            raise InputValidationError(f"Contract v5 signal direction {self.direction!r} is unsupported")
        if self.role not in CONTRACT_V5_SIGNAL_ROLES:
            raise InputValidationError(f"Contract v5 signal role {self.role!r} is unsupported")
        if self.polarity not in CONTRACT_V5_POLARITIES:
            raise InputValidationError(f"Contract v5 signal polarity {self.polarity!r} is unsupported")
        if isinstance(self.width, bool) or not isinstance(self.width, int) or self.width <= 0:
            raise InputValidationError("Contract v5 signal width must be a positive integer")


@dataclass(frozen=True)
class ContractV5Predicate:
    """Bit-level predicate over local signal source IDs."""

    kind: str
    signal: str | None = None
    value: int | None = None
    children: tuple["ContractV5Predicate", ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or self.kind not in CONTRACT_V5_PREDICATE_KINDS:
            raise InputValidationError(f"Contract v5 predicate kind {self.kind!r} is unsupported")
        if self.signal is not None and (not isinstance(self.signal, str) or not self.signal):
            raise InputValidationError("Contract v5 predicate signal must be a non-empty string")
        if self.value is not None and (
            isinstance(self.value, bool) or not isinstance(self.value, int) or self.value < 0
        ):
            raise InputValidationError("Contract v5 predicate value must be a non-negative integer")
        if not isinstance(self.children, tuple):
            raise InputValidationError("Contract v5 predicate children must be a tuple")
        for child in self.children:
            if not isinstance(child, ContractV5Predicate):
                raise InputValidationError("Contract v5 predicate children must be predicates")


@dataclass(frozen=True)
class ContractV5Event:
    """A behavior event such as accept, stall, response, reset, or error."""

    name: str
    kind: str
    guard: ContractV5Predicate
    payload_signals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, value in (("name", self.name), ("kind", self.kind)):
            if not isinstance(value, str) or not _is_canonical_token(value):
                raise InputValidationError(f"Contract v5 event {name} must be a canonical token")
        if not isinstance(self.guard, ContractV5Predicate):
            raise InputValidationError("Contract v5 event guard must be a predicate")
        if not isinstance(self.payload_signals, tuple):
            raise InputValidationError("Contract v5 event payload_signals must be a tuple")
        for signal in self.payload_signals:
            if not isinstance(signal, str) or not signal:
                raise InputValidationError("Contract v5 event payload signals must be non-empty strings")


@dataclass(frozen=True)
class ContractV5Ordering:
    before: str
    after: str
    relation: str = "must_precede"

    def __post_init__(self) -> None:
        for name, value in (("before", self.before), ("after", self.after), ("relation", self.relation)):
            if not isinstance(value, str) or not value:
                raise InputValidationError(f"Contract v5 ordering {name} must be a non-empty string")
        if self.relation not in CONTRACT_V5_ORDERING_RELATIONS:
            raise InputValidationError(f"Contract v5 ordering relation {self.relation!r} is unsupported")


@dataclass(frozen=True)
class ContractV5Hypothesis:
    interface_kind: str
    interface_role: str
    signals: tuple[ContractV5SignalRef, ...]
    events: tuple[ContractV5Event, ...]
    invariants: tuple[ContractV5Predicate, ...] = ()
    ordering: tuple[ContractV5Ordering, ...] = ()
    source_evidence: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, value in (("interface_kind", self.interface_kind), ("interface_role", self.interface_role)):
            if not isinstance(value, str) or not _is_canonical_token(value):
                raise InputValidationError(f"Contract v5 {name} must be a canonical token")
        if not self.signals:
            raise InputValidationError("Contract v5 hypothesis requires at least one signal")
        if not isinstance(self.signals, tuple):
            raise InputValidationError("Contract v5 signals must be a tuple")
        if not isinstance(self.events, tuple):
            raise InputValidationError("Contract v5 events must be a tuple")
        if not isinstance(self.invariants, tuple):
            raise InputValidationError("Contract v5 invariants must be a tuple")
        if not isinstance(self.ordering, tuple):
            raise InputValidationError("Contract v5 ordering must be a tuple")
        if not isinstance(self.source_evidence, Mapping):
            raise InputValidationError("Contract v5 source_evidence must be an object")
        _require_unique("Contract v5 signal source IDs", (signal.source_id for signal in self.signals))
        _require_unique("Contract v5 event names", (event.name for event in self.events))


@dataclass(frozen=True)
class ContractV5CanonicalHypothesis:
    payload: Mapping[str, object]
    digest: str

    def to_dict(self) -> dict[str, object]:
        value = dict(self.payload)
        value["digest"] = self.digest
        return value


@dataclass(frozen=True)
class ContractV5AmbiguityReport:
    status: str
    surviving_count: int
    canonical_class_count: int
    canonical_digests: tuple[str, ...]
    selected_digest: str | None
    reason: str
    digest: str
    schema: str = CONTRACT_V5_AMBIGUITY_SCHEMA
    grammar_version: str = CONTRACT_V5_GRAMMAR_VERSION

    def __post_init__(self) -> None:
        if self.status not in {"empty", "unique", "ambiguous"}:
            raise InputValidationError("Contract v5 ambiguity status is invalid")
        if self.surviving_count < 0 or self.canonical_class_count < 0:
            raise InputValidationError("Contract v5 ambiguity counts must be non-negative")
        if not isinstance(self.canonical_digests, tuple):
            raise InputValidationError("Contract v5 canonical_digests must be a tuple")
        if self.digest != content_digest(self.payload_dict()):
            raise InputValidationError("Contract v5 ambiguity report digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def canonicalize_contract_v5_hypothesis(
    hypothesis: ContractV5Hypothesis,
) -> ContractV5CanonicalHypothesis:
    """Return the alpha-renamed canonical semantics for a hypothesis.

    Names from RTL evidence are used only to resolve local references.  The
    canonical payload contains deterministic ``sN`` and ``eN`` IDs instead.
    """

    if not isinstance(hypothesis, ContractV5Hypothesis):
        raise InputValidationError("Contract v5 canonicalization requires a hypothesis")

    signal_map, signal_widths, signals = _canonical_signal_map(hypothesis.signals)
    event_map, events = _canonical_event_map(hypothesis.events, signal_map, signal_widths)

    invariants = tuple(
        sorted(
            (
                _canonical_predicate(invariant, signal_map, signal_widths)
                for invariant in hypothesis.invariants
            ),
            key=canonical_json,
        )
    )
    ordering = tuple(
        sorted(
            (
                _canonical_ordering(edge, event_map)
                for edge in hypothesis.ordering
            ),
            key=canonical_json,
        )
    )

    payload: dict[str, object] = {
        "schema": CONTRACT_V5_CANONICAL_SCHEMA,
        "grammar_version": CONTRACT_V5_GRAMMAR_VERSION,
        "interface_kind": hypothesis.interface_kind,
        "interface_role": hypothesis.interface_role,
        "signals": signals,
        "events": events,
        "invariants": invariants,
        "ordering": ordering,
    }
    return ContractV5CanonicalHypothesis(payload=payload, digest=content_digest(payload))


def contract_v5_hypothesis_digest(hypothesis: ContractV5Hypothesis) -> str:
    return canonicalize_contract_v5_hypothesis(hypothesis).digest


def classify_contract_v5_ambiguity(
    hypotheses: tuple[ContractV5Hypothesis, ...],
) -> ContractV5AmbiguityReport:
    """Classify whether surviving hypotheses select one canonical contract."""

    if not isinstance(hypotheses, tuple):
        raise InputValidationError("Contract v5 ambiguity classification requires a tuple")
    if not hypotheses:
        payload = _ambiguity_payload(
            status="empty",
            surviving_count=0,
            canonical_class_count=0,
            canonical_digests=(),
            selected_digest=None,
            reason="no surviving contract hypotheses",
        )
        return ContractV5AmbiguityReport(**payload, digest=content_digest(payload))

    digests = tuple(sorted({contract_v5_hypothesis_digest(hypothesis) for hypothesis in hypotheses}))
    if len(digests) == 1:
        payload = _ambiguity_payload(
            status="unique",
            surviving_count=len(hypotheses),
            canonical_class_count=1,
            canonical_digests=digests,
            selected_digest=digests[0],
            reason="all surviving hypotheses share one canonical contract",
        )
        return ContractV5AmbiguityReport(**payload, digest=content_digest(payload))

    payload = _ambiguity_payload(
        status="ambiguous",
        surviving_count=len(hypotheses),
        canonical_class_count=len(digests),
        canonical_digests=digests,
        selected_digest=None,
        reason="multiple non-equivalent canonical contract hypotheses survived",
    )
    return ContractV5AmbiguityReport(**payload, digest=content_digest(payload))


def _canonical_signal_map(
    signals: tuple[ContractV5SignalRef, ...],
) -> tuple[dict[str, str], dict[str, int], tuple[dict[str, object], ...]]:
    shapes: dict[tuple[str, str, int, str], str] = {}
    for signal in signals:
        shape = (signal.role, signal.direction, signal.width, signal.polarity)
        if shape in shapes:
            raise InputValidationError(
                "Contract v5 alpha-renaming is ambiguous for duplicate signal "
                f"role/direction/width/polarity: {shape!r}"
            )
        shapes[shape] = signal.source_id

    ordered_shapes = tuple(sorted(shapes))
    signal_map = {
        shapes[shape]: f"s{index}"
        for index, shape in enumerate(ordered_shapes)
    }
    signal_widths = {signal.source_id: signal.width for signal in signals}
    canonical_signals = tuple(
        {
            "id": signal_map[shapes[shape]],
            "role": shape[0],
            "direction": shape[1],
            "width": shape[2],
            "polarity": shape[3],
        }
        for shape in ordered_shapes
    )
    return signal_map, signal_widths, canonical_signals


def _canonical_event_map(
    events: tuple[ContractV5Event, ...],
    signal_map: Mapping[str, str],
    signal_widths: Mapping[str, int],
) -> tuple[dict[str, str], tuple[dict[str, object], ...]]:
    canonical_without_ids: list[tuple[str, dict[str, object]]] = []
    for event in events:
        payload = tuple(sorted(_require_signal(signal, signal_map) for signal in event.payload_signals))
        canonical_without_ids.append((
            event.name,
            {
                "kind": event.kind,
                "guard": _canonical_predicate(event.guard, signal_map, signal_widths),
                "payload_signals": payload,
            },
        ))

    seen = set()
    for _name, event_payload in canonical_without_ids:
        key = canonical_json(event_payload)
        if key in seen:
            raise InputValidationError(
                "Contract v5 alpha-renaming is ambiguous for duplicate event semantics"
            )
        seen.add(key)

    ordered = tuple(sorted(canonical_without_ids, key=lambda item: canonical_json(item[1])))
    event_map = {name: f"e{index}" for index, (name, _payload) in enumerate(ordered)}
    canonical_events = tuple(
        {"id": event_map[name], **payload}
        for name, payload in ordered
    )
    return event_map, canonical_events


def _canonical_ordering(
    ordering: ContractV5Ordering,
    event_map: Mapping[str, str],
) -> dict[str, object]:
    return {
        "before": _require_event(ordering.before, event_map),
        "after": _require_event(ordering.after, event_map),
        "relation": ordering.relation,
    }


def _canonical_predicate(
    predicate: ContractV5Predicate,
    signal_map: Mapping[str, str],
    signal_widths: Mapping[str, int],
) -> dict[str, object]:
    kind = predicate.kind
    if kind == "true":
        if predicate.signal is not None or predicate.value is not None or predicate.children:
            raise InputValidationError("Contract v5 true predicate must not carry signal/value/children")
        return {"kind": "true"}

    if kind in {"signal_is", "signal_nonzero", "rose", "fell", "changed"}:
        if predicate.signal is None:
            raise InputValidationError(f"Contract v5 predicate {kind} requires a signal")
        if predicate.children:
            raise InputValidationError(f"Contract v5 predicate {kind} must not carry children")
        signal_id = _require_signal(predicate.signal, signal_map)
        result: dict[str, object] = {"kind": kind, "signal": signal_id}
        if kind == "signal_is":
            if predicate.value is None:
                raise InputValidationError("Contract v5 signal_is predicate requires a value")
            if predicate.value >= (1 << signal_widths[predicate.signal]):
                raise InputValidationError("Contract v5 signal_is predicate value does not fit signal width")
            result["value"] = predicate.value
        elif predicate.value is not None:
            raise InputValidationError(f"Contract v5 predicate {kind} must not carry a value")
        return result

    if kind == "not":
        if predicate.signal is not None or predicate.value is not None or len(predicate.children) != 1:
            raise InputValidationError("Contract v5 not predicate requires exactly one child")
        return {
            "kind": "not",
            "children": (_canonical_predicate(predicate.children[0], signal_map, signal_widths),),
        }

    if kind in {"and", "or"}:
        if predicate.signal is not None or predicate.value is not None or not predicate.children:
            raise InputValidationError(f"Contract v5 {kind} predicate requires child predicates only")
        children = tuple(
            sorted(
                (
                    _canonical_predicate(child, signal_map, signal_widths)
                    for child in predicate.children
                ),
                key=canonical_json,
            )
        )
        return {"kind": kind, "children": children}

    raise InputValidationError(f"Contract v5 predicate kind {kind!r} is unsupported")


def _ambiguity_payload(
    *,
    status: str,
    surviving_count: int,
    canonical_class_count: int,
    canonical_digests: tuple[str, ...],
    selected_digest: str | None,
    reason: str,
) -> dict[str, object]:
    return {
        "schema": CONTRACT_V5_AMBIGUITY_SCHEMA,
        "grammar_version": CONTRACT_V5_GRAMMAR_VERSION,
        "status": status,
        "surviving_count": surviving_count,
        "canonical_class_count": canonical_class_count,
        "canonical_digests": canonical_digests,
        "selected_digest": selected_digest,
        "reason": reason,
    }


def _require_signal(signal: str, signal_map: Mapping[str, str]) -> str:
    if signal not in signal_map:
        raise InputValidationError(f"Contract v5 predicate references unknown signal {signal!r}")
    return signal_map[signal]


def _require_event(event: str, event_map: Mapping[str, str]) -> str:
    if event not in event_map:
        raise InputValidationError(f"Contract v5 ordering references unknown event {event!r}")
    return event_map[event]


def _require_unique(label: str, values: object) -> None:
    seen: set[object] = set()
    for value in values:
        if value in seen:
            raise InputValidationError(f"{label} must be unique")
        seen.add(value)


def _is_canonical_token(value: str) -> bool:
    if not value:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789_-.")
    return all(char in allowed for char in value)
