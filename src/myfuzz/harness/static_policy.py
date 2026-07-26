"""Target-independent, immutable static semantic projection policies.

Declarations use only stable numeric IDs.  The optional ``diagnostics``
mapping is accepted for callers that carry display metadata, but is ignored by
validation, compilation, and hashing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Literal

from .abi import RawBitAbi, content_hash


_MAX_INTEGER = (1 << 31) - 1
_MAX_POLICY_PARAMETER = 256
_ACTION_KINDS = frozenset(
    (
        "mask_align",
        "legal_set",
        "dependency_gate",
        "mutual_exclusion",
        "rarity_fold",
        "entropy_mix",
    )
)
_DECLARATION_KEYS = _ACTION_KINDS | frozenset(("diagnostics",))


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = _MAX_INTEGER) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer in {minimum}..{maximum}")
    return value


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{label} must be an array")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return value


@dataclass(frozen=True, slots=True)
class StaticPolicyParameters:
    direct_ratio: int
    event_rarity: int
    legal_set_strength: int
    mutual_exclusion: Literal["none", "one_hot", "priority"]

    def __post_init__(self) -> None:
        _integer(self.direct_ratio, "direct_ratio", minimum=1, maximum=_MAX_POLICY_PARAMETER)
        _integer(self.event_rarity, "event_rarity", minimum=1, maximum=_MAX_POLICY_PARAMETER)
        _integer(
            self.legal_set_strength,
            "legal_set_strength",
            minimum=1,
            maximum=_MAX_POLICY_PARAMETER,
        )
        if self.mutual_exclusion not in {"none", "one_hot", "priority"}:
            raise ValueError("mutual_exclusion must be none, one_hot, or priority")


StaticParameterValue = int | str | tuple[int, ...]


@dataclass(frozen=True, slots=True)
class StaticAction:
    action_id: int
    kind: str
    destination_id: int
    raw_lo: int
    raw_hi: int
    parameters: tuple[tuple[str, StaticParameterValue], ...]

    def __post_init__(self) -> None:
        _integer(self.action_id, "action_id")
        if self.kind not in _ACTION_KINDS:
            raise ValueError(f"unsupported static action kind: {self.kind}")
        _integer(self.destination_id, "destination_id")
        _integer(self.raw_lo, "raw_lo")
        _integer(self.raw_hi, "raw_hi")
        if self.raw_hi < self.raw_lo:
            raise ValueError("raw_hi must not precede raw_lo")
        if not isinstance(self.parameters, tuple):
            raise ValueError("static action parameters must be an immutable tuple")
        previous = ""
        for item in self.parameters:
            if not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], str) or not item[0]:
                raise ValueError("static action parameter must be a non-empty key/value pair")
            key, value = item
            if key <= previous:
                raise ValueError("static action parameters must be uniquely sorted")
            previous = key
            if isinstance(value, bool) or not isinstance(value, (int, str, tuple)):
                raise ValueError("static action parameter has an unsupported value")
            if isinstance(value, int):
                _integer(value, f"static action parameter {key}")
            elif isinstance(value, str):
                if not value:
                    raise ValueError("static action string parameter must be non-empty")
            else:
                for entry in value:
                    _integer(entry, f"static action parameter {key}")


@dataclass(frozen=True, slots=True)
class StaticPolicyPlan:
    raw_abi: RawBitAbi
    parameters: StaticPolicyParameters
    actions: tuple[StaticAction, ...]
    plan_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.raw_abi, RawBitAbi):
            raise TypeError("raw_abi must be RawBitAbi")
        self.raw_abi.validate_total_use()
        if not isinstance(self.parameters, StaticPolicyParameters):
            raise TypeError("parameters must be StaticPolicyParameters")
        if not isinstance(self.actions, tuple) or any(not isinstance(item, StaticAction) for item in self.actions):
            raise ValueError("actions must be an immutable tuple of StaticAction records")
        if tuple(sorted(self.actions, key=_action_key)) != self.actions:
            raise ValueError("static actions must be in canonical order")
        if not isinstance(self.plan_hash, str) or len(self.plan_hash) != 64:
            raise ValueError("plan_hash must be a SHA-256 digest")
        try:
            int(self.plan_hash, 16)
        except ValueError as error:
            raise ValueError("plan_hash must be a SHA-256 digest") from error


@dataclass(frozen=True, slots=True)
class _SemanticAction:
    action_id: int
    kind: str
    destination_id: int
    values: tuple[int, ...]


def _action_key(action: StaticAction) -> tuple[int, int, int, int, str, tuple[tuple[str, StaticParameterValue], ...]]:
    return (
        action.action_id,
        action.destination_id,
        action.raw_lo,
        action.raw_hi,
        action.kind,
        action.parameters,
    )


def _semantic_key(action: _SemanticAction) -> tuple[int, int, str, tuple[int, ...]]:
    return (action.action_id, action.destination_id, action.kind, action.values)


def _declaration_record(
    value: object,
    label: str,
    allowed: frozenset[str],
) -> Mapping[str, object]:
    record = _mapping(value, label)
    unknown = set(record) - allowed
    if unknown:
        raise ValueError(f"{label} contains unknown keys")
    if set(record) != allowed:
        raise ValueError(f"{label} must declare exactly {sorted(allowed)}")
    return record


def _destination_ranges(raw_abi: RawBitAbi) -> dict[int, tuple[int, int, int]]:
    ranges: dict[int, tuple[int, int, int]] = {}
    for destination in raw_abi.destinations:
        if destination.destination_id in ranges:
            raise ValueError("raw ABI has duplicate destination IDs")
        matches = tuple(use for use in raw_abi.uses if use.destination_id == destination.destination_id)
        if len(matches) == 1:
            use = matches[0]
            if use.destination_lo == 0 and use.raw_hi - use.raw_lo + 1 == destination.width:
                ranges[destination.destination_id] = (use.raw_lo, use.raw_hi, destination.width)
                continue
        ranges[destination.destination_id] = (-1, -1, destination.width)
    return ranges


def _stable_ids(value: object, label: str, known: set[int], *, nonempty: bool = True) -> tuple[int, ...]:
    values = tuple(_integer(item, label) for item in _sequence(value, label))
    if (nonempty and not values) or len(values) != len(set(values)) or not set(values) <= known:
        raise ValueError(f"{label} must contain unique known stable IDs")
    return tuple(sorted(values))


def _raw_bits(value: object, label: str, raw_width: int) -> tuple[int, ...]:
    values = tuple(_integer(item, label, maximum=raw_width - 1) for item in _sequence(value, label))
    if not values or len(values) != len(set(values)):
        raise ValueError(f"{label} must contain unique raw-bit IDs")
    return tuple(sorted(values))


def validate_static_declarations(
    declarations: Mapping[str, object],
    raw_abi: RawBitAbi,
) -> tuple[_SemanticAction, ...]:
    """Validate and canonically normalize declared, numeric static semantics."""
    if not isinstance(raw_abi, RawBitAbi):
        raise TypeError("raw_abi must be RawBitAbi")
    raw_abi.validate_total_use()
    source = _mapping(declarations, "static declarations")
    unknown = set(source) - _DECLARATION_KEYS
    if unknown:
        raise ValueError("unknown static declaration key")
    if "diagnostics" in source and not isinstance(source["diagnostics"], Mapping):
        raise ValueError("diagnostics must be an object")

    ranges = _destination_ranges(raw_abi)
    known_destinations = set(ranges)
    result: list[_SemanticAction] = []
    action_ids: set[int] = set()

    def add(kind: str, record: Mapping[str, object], values: tuple[int, ...]) -> None:
        action_id = _integer(record["action_id"], f"{kind}.action_id")
        if action_id in action_ids:
            raise ValueError("static action IDs must be unique")
        action_ids.add(action_id)
        destination_id = _integer(record["destination_id"], f"{kind}.destination_id")
        if destination_id not in known_destinations:
            raise ValueError(f"{kind} references an unknown destination")
        if ranges[destination_id][0] < 0:
            raise ValueError("static policy requires one contiguous raw slice per transformed destination")
        result.append(_SemanticAction(action_id, kind, destination_id, values))

    for item in _sequence(source.get("mask_align", ()), "mask_align"):
        record = _declaration_record(
            item,
            "mask_align declaration",
            frozenset(("action_id", "destination_id", "alignment")),
        )
        destination_id = _integer(record["destination_id"], "mask_align.destination_id")
        width = ranges.get(destination_id, (0, 0, 0))[2]
        alignment = _integer(record["alignment"], "alignment", minimum=1)
        if alignment & (alignment - 1) or alignment > 1 << width:
            raise ValueError("alignment must be a destination-width power of two")
        add("mask_align", record, (alignment,))

    for item in _sequence(source.get("legal_set", ()), "legal_set"):
        record = _declaration_record(
            item,
            "legal_set declaration",
            frozenset(("action_id", "destination_id", "values")),
        )
        destination_id = _integer(record["destination_id"], "legal_set.destination_id")
        width = ranges.get(destination_id, (0, 0, 0))[2]
        values = _stable_ids(record["values"], "legal_set.values", set(range(1 << width)))
        add("legal_set", record, values)

    for item in _sequence(source.get("dependency_gate", ()), "dependency_gate"):
        record = _declaration_record(
            item,
            "dependency_gate declaration",
            frozenset(("action_id", "destination_id", "gate_bit")),
        )
        gate_bit = _integer(record["gate_bit"], "gate_bit", maximum=raw_abi.raw_width - 1)
        add("dependency_gate", record, (gate_bit,))

    for item in _sequence(source.get("mutual_exclusion", ()), "mutual_exclusion"):
        record = _declaration_record(
            item,
            "mutual_exclusion declaration",
            frozenset(("action_id", "destination_id", "peer_ids")),
        )
        destination_id = _integer(record["destination_id"], "mutual_exclusion.destination_id")
        peers = _stable_ids(record["peer_ids"], "mutual_exclusion.peer_ids", known_destinations)
        if destination_id in peers:
            raise ValueError("mutual_exclusion cannot include its destination as a peer")
        add("mutual_exclusion", record, peers)

    for item in _sequence(source.get("rarity_fold", ()), "rarity_fold"):
        record = _declaration_record(
            item,
            "rarity_fold declaration",
            frozenset(("action_id", "destination_id", "fold_bits")),
        )
        destination_id = _integer(record["destination_id"], "rarity_fold.destination_id")
        if ranges.get(destination_id, (0, 0, 0))[2] != 1:
            raise ValueError("rarity_fold requires a one-bit event destination")
        add("rarity_fold", record, _raw_bits(record["fold_bits"], "rarity_fold.fold_bits", raw_abi.raw_width))

    for item in _sequence(source.get("entropy_mix", ()), "entropy_mix"):
        record = _declaration_record(
            item,
            "entropy_mix declaration",
            frozenset(("action_id", "destination_id", "selector_bits")),
        )
        add("entropy_mix", record, _raw_bits(record["selector_bits"], "entropy_mix.selector_bits", raw_abi.raw_width))

    return tuple(sorted(result, key=_semantic_key))


def _parameters(**values: StaticParameterValue) -> tuple[tuple[str, StaticParameterValue], ...]:
    return tuple(sorted(values.items()))


def _compile_actions(
    semantic: tuple[_SemanticAction, ...],
    raw_abi: RawBitAbi,
    parameters: StaticPolicyParameters,
) -> tuple[StaticAction, ...]:
    ranges = _destination_ranges(raw_abi)
    actions: list[StaticAction] = []
    transformed: set[int] = set()
    entropy_destinations: set[int] = set()
    for declaration in semantic:
        raw_lo, raw_hi, width = ranges[declaration.destination_id]
        if declaration.kind == "mask_align":
            alignment = declaration.values[0]
            action_parameters = _parameters(
                alignment=alignment,
                mask=((1 << width) - 1) & ~(alignment - 1),
            )
        elif declaration.kind == "legal_set":
            action_parameters = _parameters(
                strength=parameters.legal_set_strength,
                values=declaration.values,
            )
        elif declaration.kind == "dependency_gate":
            action_parameters = _parameters(gate_bit=declaration.values[0])
        elif declaration.kind == "mutual_exclusion":
            action_parameters = _parameters(
                mode=parameters.mutual_exclusion,
                peer_ids=declaration.values,
            )
        elif declaration.kind == "rarity_fold":
            action_parameters = _parameters(
                fold_bits=declaration.values,
                rarity=parameters.event_rarity,
            )
        else:
            action_parameters = _parameters(
                direct_ratio=parameters.direct_ratio,
                selector_bits=declaration.values,
            )
            entropy_destinations.add(declaration.destination_id)
        actions.append(
            StaticAction(
                declaration.action_id,
                declaration.kind,
                declaration.destination_id,
                raw_lo,
                raw_hi,
                action_parameters,
            )
        )
        if declaration.kind != "entropy_mix":
            transformed.add(declaration.destination_id)

    next_action_id = max((item.action_id for item in semantic), default=-1) + 1
    for destination_id in sorted(transformed - entropy_destinations):
        raw_lo, raw_hi, _ = ranges[destination_id]
        actions.append(
            StaticAction(
                next_action_id,
                "entropy_mix",
                destination_id,
                raw_lo,
                raw_hi,
                _parameters(
                    direct_ratio=parameters.direct_ratio,
                    selector_bits=tuple(range(raw_lo, raw_hi + 1)),
                ),
            )
        )
        next_action_id += 1
    return tuple(sorted(actions, key=_action_key))


def abi_document(raw_abi: RawBitAbi) -> dict[str, object]:
    """Return the complete canonical ABI identity document for policy hashes."""
    return {
        "raw_width": raw_abi.raw_width,
        "destinations": [
            {
                "destination_id": item.destination_id,
                "component_id": item.component_id,
                "port_id": item.port_id,
                "width": item.width,
            }
            for item in raw_abi.destinations
        ],
        "uses": [
            {
                "raw_lo": item.raw_lo,
                "raw_hi": item.raw_hi,
                "destination_id": item.destination_id,
                "destination_lo": item.destination_lo,
                "action": item.action,
                "category": item.category,
            }
            for item in raw_abi.uses
        ],
        "abi_hash": raw_abi.abi_hash,
    }


def action_documents(actions: tuple[StaticAction, ...]) -> list[dict[str, object]]:
    return [
        {
            "action_id": action.action_id,
            "kind": action.kind,
            "destination_id": action.destination_id,
            "raw_lo": action.raw_lo,
            "raw_hi": action.raw_hi,
            "parameters": [[key, value] for key, value in action.parameters],
        }
        for action in actions
    ]


def compile_static_policy(
    raw_abi: RawBitAbi,
    declarations: Mapping[str, object],
    parameters: StaticPolicyParameters,
) -> StaticPolicyPlan:
    """Compile only explicit semantics into a deterministic static policy plan."""
    if not isinstance(parameters, StaticPolicyParameters):
        raise TypeError("parameters must be StaticPolicyParameters")
    semantic = validate_static_declarations(declarations, raw_abi)
    actions = _compile_actions(semantic, raw_abi, parameters)
    document = {
        "raw_abi": abi_document(raw_abi),
        "parameters": asdict(parameters),
        "actions": action_documents(actions),
    }
    return StaticPolicyPlan(raw_abi, parameters, actions, content_hash(document))


__all__ = [
    "StaticAction",
    "StaticPolicyParameters",
    "StaticPolicyPlan",
    "abi_document",
    "action_documents",
    "compile_static_policy",
    "validate_static_declarations",
]
