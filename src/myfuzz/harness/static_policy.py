"""Target-independent, immutable static semantic projection policies.

Declarations use only stable numeric IDs.  The optional ``diagnostics``
mapping is accepted for callers that carry display metadata, but is ignored by
validation, compilation, and hashing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Literal

from .abi import RawBitAbi, RawBitUse, RawDestination, content_hash


_MAX_INTEGER = (1 << 31) - 1
_MAX_POLICY_PARAMETER = 256
_MAX_ACTION_VALUE = (1 << 4096) - 1
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
_ACTION_PARAMETER_KEYS = {
    "mask_align": frozenset(("alignment", "mask")),
    "legal_set": frozenset(("strength", "values")),
    "dependency_gate": frozenset(("gate_bit",)),
    "mutual_exclusion": frozenset(("mode", "peer_ids")),
    "rarity_fold": frozenset(("fold_bits", "rarity")),
    "entropy_mix": frozenset(("direct_ratio", "selector_bits")),
}
_FRAGMENTS_KEY = "fragments"
_RAW_ABI_ACTIONS = frozenset(("direct", "mask", "gate", "delay_select", "fold_xor"))
_RAW_ABI_CATEGORIES = frozenset(
    (
        "direct",
        "protocol_legality",
        "progress",
        "dependency_consistency",
        "event_rarity",
        "address_validity",
    )
)


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = _MAX_INTEGER) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer in {minimum}..{maximum}")
    return value


def _action_value(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_ACTION_VALUE:
        raise ValueError(f"{label} must be a bounded non-negative integer")
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
                _action_value(value, f"static action parameter {key}")
            elif isinstance(value, str):
                if not value:
                    raise ValueError("static action string parameter must be non-empty")
            else:
                for entry in value:
                    _action_value(entry, f"static action parameter {key}")
        keys = frozenset(item[0] for item in self.parameters)
        expected = _ACTION_PARAMETER_KEYS[self.kind]
        if keys not in {expected, expected | {_FRAGMENTS_KEY}}:
            raise ValueError(f"{self.kind} parameters must declare exactly {sorted(expected)}")
        if _FRAGMENTS_KEY in keys:
            fragments = dict(self.parameters)[_FRAGMENTS_KEY]
            if not isinstance(fragments, tuple) or not fragments or len(fragments) % 3:
                raise ValueError("fragments must contain raw_lo/raw_hi/destination_lo triples")
            for raw_lo, raw_hi, destination_lo in zip(fragments[::3], fragments[1::3], fragments[2::3]):
                if raw_hi < raw_lo or destination_lo < 0:
                    raise ValueError("fragments must contain valid raw-bit slices")
        values = dict(self.parameters)
        if self.kind == "mask_align":
            alignment = values["alignment"]
            if not isinstance(alignment, int) or alignment < 1 or alignment & (alignment - 1):
                raise ValueError("mask_align alignment must be a positive power of two")
        elif self.kind == "legal_set":
            legal_values = values["values"]
            if (
                not isinstance(values["strength"], int)
                or not 1 <= values["strength"] <= _MAX_POLICY_PARAMETER
                or not isinstance(legal_values, tuple)
                or not legal_values
                or tuple(sorted(set(legal_values))) != legal_values
            ):
                raise ValueError("legal_set parameters must contain sorted values and bounded strength")
        elif self.kind == "dependency_gate":
            if not isinstance(values["gate_bit"], int):
                raise ValueError("dependency_gate gate_bit must be an integer")
        elif self.kind == "mutual_exclusion":
            peers = values["peer_ids"]
            if (
                values["mode"] not in {"none", "one_hot", "priority"}
                or not isinstance(peers, tuple)
                or not peers
                or tuple(sorted(set(peers))) != peers
            ):
                raise ValueError("mutual_exclusion parameters must be canonical")
        elif self.kind == "rarity_fold":
            fold_bits = values["fold_bits"]
            if (
                not isinstance(values["rarity"], int)
                or not 1 <= values["rarity"] <= _MAX_POLICY_PARAMETER
                or not isinstance(fold_bits, tuple)
                or not fold_bits
                or tuple(sorted(set(fold_bits))) != fold_bits
            ):
                raise ValueError("rarity_fold parameters must be canonical")
        else:
            selector_bits = values["selector_bits"]
            if (
                not isinstance(values["direct_ratio"], int)
                or not 1 <= values["direct_ratio"] <= _MAX_POLICY_PARAMETER
                or not isinstance(selector_bits, tuple)
                or not selector_bits
                or tuple(sorted(set(selector_bits))) != selector_bits
            ):
                raise ValueError("entropy_mix parameters must be canonical")


@dataclass(frozen=True, slots=True)
class StaticPolicyPlan:
    raw_abi: RawBitAbi
    parameters: StaticPolicyParameters
    actions: tuple[StaticAction, ...]
    plan_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.raw_abi, RawBitAbi):
            raise TypeError("raw_abi must be RawBitAbi")
        canonical_abi = _canonical_raw_abi(self.raw_abi)
        object.__setattr__(self, "raw_abi", canonical_abi)
        if not isinstance(self.parameters, StaticPolicyParameters):
            raise TypeError("parameters must be StaticPolicyParameters")
        if not isinstance(self.actions, tuple) or any(not isinstance(item, StaticAction) for item in self.actions):
            raise ValueError("actions must be an immutable tuple of StaticAction records")
        if tuple(sorted(self.actions, key=_action_key)) != self.actions:
            raise ValueError("static actions must be in canonical order")
        _validate_plan_actions(canonical_abi, self.parameters, self.actions)
        if not isinstance(self.plan_hash, str) or len(self.plan_hash) != 64:
            raise ValueError("plan_hash must be a SHA-256 digest")
        try:
            int(self.plan_hash, 16)
        except ValueError as error:
            raise ValueError("plan_hash must be a SHA-256 digest") from error
        if self.plan_hash != _plan_hash(canonical_abi, self.parameters, self.actions):
            raise ValueError("plan_hash does not match static policy content hash")


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


def _raw_abi_geometry_document(
    raw_width: int,
    destinations: tuple[RawDestination, ...],
    uses: tuple[RawBitUse, ...],
) -> dict[str, object]:
    return {
        "raw_width": raw_width,
        "destinations": [
            {
                "destination_id": item.destination_id,
                "component_id": item.component_id,
                "port_id": item.port_id,
                "width": item.width,
            }
            for item in destinations
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
            for item in uses
        ],
    }


def _canonical_raw_abi(raw_abi: RawBitAbi) -> RawBitAbi:
    if not isinstance(raw_abi, RawBitAbi):
        raise TypeError("raw_abi must be RawBitAbi")
    _validate_raw_abi_records(raw_abi)
    raw_abi.validate_total_use()
    destinations = tuple(sorted(raw_abi.destinations, key=lambda item: item.destination_id))
    if len(destinations) != len({item.destination_id for item in destinations}):
        raise ValueError("raw ABI has duplicate destination IDs")
    uses = tuple(sorted(raw_abi.uses, key=lambda item: item.raw_lo))
    geometry = _raw_abi_geometry_document(raw_abi.raw_width, destinations, uses)
    canonical = RawBitAbi(raw_abi.raw_width, destinations, uses, content_hash(geometry))
    if any(layout is None for layout in _destination_layouts(canonical).values()):
        raise ValueError("raw ABI has incomplete or overlapping destination geometry")
    return canonical


def _validate_raw_abi_records(raw_abi: RawBitAbi) -> None:
    _integer(raw_abi.raw_width, "raw ABI raw_width", minimum=1)
    if not isinstance(raw_abi.destinations, tuple) or not isinstance(raw_abi.uses, tuple):
        raise ValueError("raw ABI destinations and uses must be immutable tuples")
    for destination in raw_abi.destinations:
        if not isinstance(destination, RawDestination):
            raise ValueError("raw ABI destination must be RawDestination")
        _integer(destination.destination_id, "raw ABI destination_id")
        if destination.component_id is not None:
            _integer(destination.component_id, "raw ABI component_id")
        _integer(destination.port_id, "raw ABI port_id")
        _integer(destination.width, "raw ABI destination width", minimum=1)
    for use in raw_abi.uses:
        if not isinstance(use, RawBitUse):
            raise ValueError("raw ABI use must be RawBitUse")
        _integer(use.raw_lo, "raw ABI raw_lo")
        _integer(use.raw_hi, "raw ABI raw_hi")
        _integer(use.destination_id, "raw ABI use destination_id")
        _integer(use.destination_lo, "raw ABI destination_lo")
        if not isinstance(use.action, str) or use.action not in _RAW_ABI_ACTIONS:
            raise ValueError("raw ABI action is not an explicit semantic action")
        if not isinstance(use.category, str) or use.category not in _RAW_ABI_CATEGORIES:
            raise ValueError("raw ABI category is not an explicit semantic category")


def _destination_layouts(raw_abi: RawBitAbi) -> dict[int, tuple[int, int, int, tuple[int, ...]] | None]:
    layouts: dict[int, tuple[int, int, int, tuple[int, ...]] | None] = {}
    for destination in raw_abi.destinations:
        matches = tuple(use for use in raw_abi.uses if use.destination_id == destination.destination_id)
        cursor = 0
        for use in sorted(matches, key=lambda item: item.destination_lo):
            width = use.raw_hi - use.raw_lo + 1
            if use.destination_lo != cursor:
                layouts[destination.destination_id] = None
                break
            cursor += width
        else:
            if cursor != destination.width:
                layouts[destination.destination_id] = None
                continue
            ordered = tuple(sorted(matches, key=lambda item: item.raw_lo))
            fragments = tuple(
                value
                for use in ordered
                for value in (use.raw_lo, use.raw_hi, use.destination_lo)
            )
            layouts[destination.destination_id] = (
                ordered[0].raw_lo,
                ordered[-1].raw_hi,
                destination.width,
                fragments,
            )
    return layouts


def _stable_ids(value: object, label: str, known: set[int], *, nonempty: bool = True) -> tuple[int, ...]:
    values = tuple(_integer(item, label) for item in _sequence(value, label))
    if (nonempty and not values) or len(values) != len(set(values)) or not set(values) <= known:
        raise ValueError(f"{label} must contain unique known stable IDs")
    return tuple(sorted(values))


def _legal_values(value: object, label: str, width: int) -> tuple[int, ...]:
    values = tuple(_action_value(item, label) for item in _sequence(value, label))
    if not values or len(values) != len(set(values)) or any(item >= 1 << width for item in values):
        raise ValueError(f"{label} must contain unique values representable by its destination")
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
    raw_abi = _canonical_raw_abi(raw_abi)
    source = _mapping(declarations, "static declarations")
    unknown = set(source) - _DECLARATION_KEYS
    if unknown:
        raise ValueError("unknown static declaration key")
    if "diagnostics" in source and not isinstance(source["diagnostics"], Mapping):
        raise ValueError("diagnostics must be an object")

    layouts = _destination_layouts(raw_abi)
    known_destinations = set(layouts)
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
        if layouts[destination_id] is None:
            raise ValueError("static policy requires complete raw slices for transformed destinations")
        result.append(_SemanticAction(action_id, kind, destination_id, values))

    for item in _sequence(source.get("mask_align", ()), "mask_align"):
        record = _declaration_record(
            item,
            "mask_align declaration",
            frozenset(("action_id", "destination_id", "alignment")),
        )
        destination_id = _integer(record["destination_id"], "mask_align.destination_id")
        layout = layouts.get(destination_id)
        width = layout[2] if layout is not None else 0
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
        layout = layouts.get(destination_id)
        width = layout[2] if layout is not None else 0
        values = _legal_values(record["values"], "legal_set.values", width)
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
        layout = layouts.get(destination_id)
        if layout is None or layout[2] != 1:
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
    layouts = _destination_layouts(raw_abi)
    actions: list[StaticAction] = []
    transform_max_ids: dict[int, int] = {}
    entropy_max_ids: dict[int, int] = {}
    for declaration in semantic:
        layout = layouts[declaration.destination_id]
        if layout is None:
            raise ValueError("static policy requires complete raw slices for transformed destinations")
        raw_lo, raw_hi, width, fragments = layout

        def action_parameters(**values: StaticParameterValue) -> tuple[tuple[str, StaticParameterValue], ...]:
            if len(fragments) > 3:
                values[_FRAGMENTS_KEY] = fragments
            return _parameters(**values)

        if declaration.kind == "mask_align":
            alignment = declaration.values[0]
            parameters_for_action = action_parameters(
                alignment=alignment,
                mask=((1 << width) - 1) & ~(alignment - 1),
            )
        elif declaration.kind == "legal_set":
            parameters_for_action = action_parameters(
                strength=parameters.legal_set_strength,
                values=declaration.values,
            )
        elif declaration.kind == "dependency_gate":
            parameters_for_action = action_parameters(gate_bit=declaration.values[0])
        elif declaration.kind == "mutual_exclusion":
            if (
                parameters.mutual_exclusion == "priority"
                and any(peer_id > declaration.destination_id for peer_id in declaration.values)
            ):
                raise ValueError("priority peers must have lower stable IDs")
            parameters_for_action = action_parameters(
                mode=parameters.mutual_exclusion,
                peer_ids=declaration.values,
            )
        elif declaration.kind == "rarity_fold":
            parameters_for_action = action_parameters(
                fold_bits=declaration.values,
                rarity=parameters.event_rarity,
            )
        else:
            parameters_for_action = action_parameters(
                direct_ratio=parameters.direct_ratio,
                selector_bits=declaration.values,
            )
            entropy_max_ids[declaration.destination_id] = max(
                declaration.action_id,
                entropy_max_ids.get(declaration.destination_id, -1),
            )
        actions.append(
            StaticAction(
                declaration.action_id,
                declaration.kind,
                declaration.destination_id,
                raw_lo,
                raw_hi,
                parameters_for_action,
            )
        )
        if declaration.kind != "entropy_mix":
            transform_max_ids[declaration.destination_id] = max(
                declaration.action_id,
                transform_max_ids.get(declaration.destination_id, -1),
            )

    missing_direct = tuple(
        destination_id
        for destination_id, transform_max_id in sorted(transform_max_ids.items())
        if entropy_max_ids.get(destination_id, -1) <= transform_max_id
    )
    used_action_ids = {item.action_id for item in semantic}
    for destination_id in missing_direct:
        next_action_id = transform_max_ids[destination_id] + 1
        while next_action_id in used_action_ids:
            next_action_id += 1
        if next_action_id > _MAX_INTEGER:
            raise ValueError("static action IDs leave no generated direct action IDs")
        layout = layouts[destination_id]
        if layout is None:
            raise ValueError("static policy requires complete raw slices for transformed destinations")
        raw_lo, raw_hi, _, fragments = layout
        selector_bits = tuple(
            raw_bit
            for fragment_lo, fragment_hi in zip(fragments[::3], fragments[1::3])
            for raw_bit in range(fragment_lo, fragment_hi + 1)
        )
        generated_parameters: dict[str, StaticParameterValue] = {
            "direct_ratio": parameters.direct_ratio,
            "selector_bits": selector_bits,
        }
        if len(fragments) > 3:
            generated_parameters[_FRAGMENTS_KEY] = fragments
        actions.append(
            StaticAction(
                next_action_id,
                "entropy_mix",
                destination_id,
                raw_lo,
                raw_hi,
                _parameters(**generated_parameters),
            )
        )
        used_action_ids.add(next_action_id)
        next_action_id += 1
    return tuple(sorted(actions, key=_action_key))


def abi_document(raw_abi: RawBitAbi) -> dict[str, object]:
    """Return the complete canonical ABI identity document for policy hashes."""
    raw_abi = _canonical_raw_abi(raw_abi)
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


def _plan_hash(
    raw_abi: RawBitAbi,
    parameters: StaticPolicyParameters,
    actions: tuple[StaticAction, ...],
) -> str:
    return content_hash(
        {
            "raw_abi": abi_document(raw_abi),
            "parameters": asdict(parameters),
            "actions": action_documents(actions),
        }
    )


def _validate_plan_actions(
    raw_abi: RawBitAbi,
    parameters: StaticPolicyParameters,
    actions: tuple[StaticAction, ...],
) -> None:
    layouts = _destination_layouts(raw_abi)
    action_ids: set[int] = set()
    transform_max_ids: dict[int, int] = {}
    entropy_max_ids: dict[int, int] = {}

    for action in actions:
        if action.action_id in action_ids:
            raise ValueError("static action IDs must be unique")
        action_ids.add(action.action_id)
        layout = layouts.get(action.destination_id)
        if layout is None:
            raise ValueError("static action references an incomplete destination")
        raw_lo, raw_hi, width, fragments = layout
        if (action.raw_lo, action.raw_hi) != (raw_lo, raw_hi):
            raise ValueError("static action raw range does not match its destination")
        values = dict(action.parameters)
        expected_fragments = fragments if len(fragments) > 3 else None
        if values.get(_FRAGMENTS_KEY) != expected_fragments:
            raise ValueError("static action fragments do not match its destination geometry")

        if action.kind == "mask_align":
            alignment = values["alignment"]
            if (
                not isinstance(alignment, int)
                or alignment < 1
                or alignment & (alignment - 1)
                or alignment > 1 << width
                or values["mask"] != ((1 << width) - 1) & ~(alignment - 1)
            ):
                raise ValueError("mask_align action parameters do not match its destination")
        elif action.kind == "legal_set":
            legal_values = values["values"]
            if values["strength"] != parameters.legal_set_strength:
                raise ValueError("legal_set action strength does not match the policy")
            if (
                not isinstance(values["strength"], int)
                or not 1 <= values["strength"] <= _MAX_POLICY_PARAMETER
                or not isinstance(legal_values, tuple)
                or not legal_values
                or tuple(sorted(set(legal_values))) != legal_values
                or any(value >= 1 << width for value in legal_values)
            ):
                raise ValueError("legal_set action parameters do not match its destination")
        elif action.kind == "dependency_gate":
            gate_bit = values["gate_bit"]
            if not isinstance(gate_bit, int) or gate_bit >= raw_abi.raw_width:
                raise ValueError("dependency_gate action parameters do not match raw ABI")
        elif action.kind == "mutual_exclusion":
            peers = values["peer_ids"]
            invalid_priority_order = values["mode"] == "priority" and any(
                peer_id > action.destination_id for peer_id in peers
            )
            if (
                values["mode"] != parameters.mutual_exclusion
                or not isinstance(peers, tuple)
                or not peers
                or tuple(sorted(set(peers))) != peers
                or action.destination_id in peers
                or not set(peers) <= set(layouts)
                or invalid_priority_order
            ):
                if invalid_priority_order:
                    raise ValueError("priority peers must have lower stable IDs")
                raise ValueError("mutual_exclusion action parameters do not match the policy")
        elif action.kind == "rarity_fold":
            fold_bits = values["fold_bits"]
            if (
                width != 1
                or values["rarity"] != parameters.event_rarity
                or not isinstance(fold_bits, tuple)
                or not fold_bits
                or tuple(sorted(set(fold_bits))) != fold_bits
                or any(value >= raw_abi.raw_width for value in fold_bits)
            ):
                raise ValueError("rarity_fold action parameters do not match the policy")
        else:
            selector_bits = values["selector_bits"]
            if (
                values["direct_ratio"] != parameters.direct_ratio
                or not isinstance(selector_bits, tuple)
                or not selector_bits
                or tuple(sorted(set(selector_bits))) != selector_bits
                or any(value >= raw_abi.raw_width for value in selector_bits)
            ):
                raise ValueError("entropy_mix action parameters do not match the policy")
            entropy_max_ids[action.destination_id] = max(
                action.action_id,
                entropy_max_ids.get(action.destination_id, -1),
            )
        if action.kind != "entropy_mix":
            transform_max_ids[action.destination_id] = max(
                action.action_id,
                transform_max_ids.get(action.destination_id, -1),
            )

    for destination_id, transform_max_id in transform_max_ids.items():
        if entropy_max_ids.get(destination_id, -1) <= transform_max_id:
            raise ValueError(
                "every transformed destination's direct branch must follow its transforms"
            )


def compile_static_policy(
    raw_abi: RawBitAbi,
    declarations: Mapping[str, object],
    parameters: StaticPolicyParameters,
) -> StaticPolicyPlan:
    """Compile only explicit semantics into a deterministic static policy plan."""
    if not isinstance(parameters, StaticPolicyParameters):
        raise TypeError("parameters must be StaticPolicyParameters")
    canonical_abi = _canonical_raw_abi(raw_abi)
    semantic = validate_static_declarations(declarations, canonical_abi)
    actions = _compile_actions(semantic, canonical_abi, parameters)
    return StaticPolicyPlan(canonical_abi, parameters, actions, _plan_hash(canonical_abi, parameters, actions))


__all__ = [
    "StaticAction",
    "StaticPolicyParameters",
    "StaticPolicyPlan",
    "abi_document",
    "action_documents",
    "compile_static_policy",
    "validate_static_declarations",
]
