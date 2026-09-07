"""Bounded deterministic projection of raw fuzz samples onto protocol fields."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from myfuzz.contracts import content_hash

from .abi import RawBitAbi, RawBitUse


_ACTION_KINDS = frozenset(("direct", "mask", "gate", "delay_select", "fold_xor", "constant"))
_CATEGORIES = frozenset(
    (
        "direct",
        "protocol_legality",
        "progress",
        "dependency_consistency",
        "event_rarity",
        "address_validity",
    )
)
_TEMPORAL_KINDS = frozenset(("gate", "delay_select"))
_MAX_STATE_BITS = 4096
_MAX_FIELD_GROUPS = 64
_MAX_TEMPORAL_CYCLES = 65_535


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class ProjectionAction:
    action_id: int
    destination_id: int
    kind: str
    category: str
    max_cycles: int | None
    state_lo: int
    state_width: int
    value_width: int
    counter_width: int
    constant_value: int | None = None
    active: bool = True


@dataclass(frozen=True, slots=True)
class ProjectionState:
    value: int
    width: int

    @classmethod
    def initial(cls, plan: "ProjectionPlan") -> "ProjectionState":
        return cls(value=0, width=plan.max_state_bits)


@dataclass(frozen=True, slots=True)
class ProjectionPlan:
    raw_abi: RawBitAbi
    field_order: tuple[int, ...]
    actions: tuple[ProjectionAction, ...]
    max_state_bits: int
    max_temporal_cycles: int
    plan_hash: str

    def __post_init__(self) -> None:
        self.raw_abi.validate_total_use()
        if not 1 <= self.max_state_bits <= _MAX_STATE_BITS:
            raise ValueError(f"max_state_bits must be in 1..{_MAX_STATE_BITS}")
        if len(self.field_order) > _MAX_FIELD_GROUPS:
            raise ValueError(f"projection supports at most {_MAX_FIELD_GROUPS} field groups")
        destination_ids = {item.destination_id for item in self.raw_abi.destinations}
        if len(self.field_order) != len(set(self.field_order)) or set(self.field_order) != destination_ids:
            raise ValueError("field_order must contain every raw ABI destination exactly once")
        if not 0 <= self.max_temporal_cycles <= _MAX_TEMPORAL_CYCLES:
            raise ValueError("max_temporal_cycles is outside the bounded range")
        for action in self.actions:
            if action.destination_id not in destination_ids:
                raise ValueError("projection action references an unknown destination")
            if action.kind not in _ACTION_KINDS or action.category not in _CATEGORIES:
                raise ValueError("projection action kind/category is unsupported")
            if action.kind == "constant":
                if action.constant_value is None or not 0 <= action.constant_value < 1 << action.value_width:
                    raise ValueError("constant projection action value is outside its destination width")
            elif action.constant_value is not None:
                raise ValueError("only constant projection actions may declare a constant value")
            if action.state_lo < 0 or action.state_width < 0:
                raise ValueError("projection action has an invalid state slice")
            if action.state_lo + action.state_width > self.max_state_bits:
                raise ValueError("projection action state exceeds max_state_bits")
            if action.kind in _TEMPORAL_KINDS and action.max_cycles is None:
                raise ValueError("temporal projection action requires finite max_cycles")


@dataclass(frozen=True, slots=True)
class ProjectionResult:
    driven_fields: tuple[tuple[int, int], ...]
    next_state: ProjectionState
    correction_counts: tuple[tuple[str, int], ...]
    protocol_events: tuple[tuple[int, str], ...]
    cycles_consumed: int
    sample_consumed: bool
    projection_count: int = 0
    protocol_event_count: int = 0
    timeout_count: int = 0
    violation_count: int = 0
    no_progress_count: int = 0


def _action_document(action: ProjectionAction) -> dict[str, object]:
    return {
        "action_id": action.action_id,
        "destination_id": action.destination_id,
        "kind": action.kind,
        "category": action.category,
        "max_cycles": action.max_cycles,
        "state_lo": action.state_lo,
        "state_width": action.state_width,
        "value_width": action.value_width,
        "counter_width": action.counter_width,
        "constant_value": action.constant_value,
        "active": action.active,
    }


def _abi_with_actions(
    direct: RawBitAbi,
    actions: tuple[ProjectionAction, ...],
) -> RawBitAbi:
    first_action = {
        action.destination_id: action
        for action in reversed(actions)
    }
    uses = tuple(
        RawBitUse(
            use.raw_lo,
            use.raw_hi,
            use.destination_id,
            use.destination_lo,
            first_action[use.destination_id].kind
            if use.destination_id in first_action
            else use.action,
            first_action[use.destination_id].category
            if use.destination_id in first_action
            else use.category,
        )
        for use in direct.uses
    )
    document = {
        "raw_width": direct.raw_width,
        "destinations": [
            {
                "destination_id": item.destination_id,
                "component_id": item.component_id,
                "port_id": item.port_id,
                "width": item.width,
            }
            for item in direct.destinations
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
    from .abi import content_hash as abi_content_hash

    result = RawBitAbi(direct.raw_width, direct.destinations, uses, abi_content_hash(document))
    result.validate_total_use()
    before = tuple(
        (item.raw_lo, item.raw_hi, item.destination_id, item.destination_lo)
        for item in direct.uses
    )
    after = tuple(
        (item.raw_lo, item.raw_hi, item.destination_id, item.destination_lo)
        for item in result.uses
    )
    if before != after or direct.destinations != result.destinations:
        raise ValueError("dependency-aware projection changed raw ABI geometry")
    return result


def build_projection_plan(
    raw_abi: RawBitAbi,
    action_records: Sequence[object],
    *,
    field_order: tuple[int, ...] | None = None,
    max_state_bits: int = _MAX_STATE_BITS,
) -> ProjectionPlan:
    """Compile explicit action records into fixed state slices and a derived ABI."""
    if not isinstance(raw_abi, RawBitAbi):
        raise TypeError("raw_abi must be RawBitAbi")
    raw_abi.validate_total_use()
    state_cap = _integer(max_state_bits, "max_state_bits", minimum=1)
    if state_cap > _MAX_STATE_BITS:
        raise ValueError(f"max_state_bits must not exceed {_MAX_STATE_BITS}")
    order = (
        tuple(item.destination_id for item in raw_abi.destinations)
        if field_order is None
        else tuple(field_order)
    )
    if len(order) > _MAX_FIELD_GROUPS:
        raise ValueError(f"projection supports at most {_MAX_FIELD_GROUPS} field groups")
    destination_widths = {item.destination_id: item.width for item in raw_abi.destinations}
    if len(order) != len(set(order)) or set(order) != set(destination_widths):
        raise ValueError("field_order must contain every raw ABI destination exactly once")
    if not isinstance(action_records, Sequence) or isinstance(
        action_records, (str, bytes, bytearray)
    ):
        raise ValueError("projection actions must be an array")

    parsed: list[tuple[int, int, str, str, int | None, int | None, bool]] = []
    seen: set[int] = set()
    for index, value in enumerate(action_records):
        if not isinstance(value, Mapping):
            raise ValueError(f"projection action {index} must be an object")
        action_id = _integer(value.get("action_id"), f"projection action {index}.action_id")
        if action_id in seen:
            raise ValueError("projection action IDs must be unique")
        seen.add(action_id)
        destination_id = _integer(
            value.get("destination_id"),
            f"projection action {index}.destination_id",
        )
        if destination_id not in destination_widths:
            raise ValueError("projection action references an unknown destination")
        kind = _string(value.get("kind"), f"projection action {index}.kind")
        category = _string(value.get("category"), f"projection action {index}.category")
        if kind not in _ACTION_KINDS:
            raise ValueError(f"unsupported projection action kind: {kind}")
        if category not in _CATEGORIES:
            raise ValueError(f"unsupported projection category: {category}")
        max_cycles_value = value.get("max_cycles")
        if kind in _TEMPORAL_KINDS:
            if max_cycles_value is None:
                raise ValueError("temporal projection action requires finite max_cycles")
            max_cycles = _integer(max_cycles_value, "max_cycles", minimum=1)
            if max_cycles > _MAX_TEMPORAL_CYCLES:
                raise ValueError("max_cycles exceeds the finite temporal bound")
        elif max_cycles_value is not None:
            max_cycles = _integer(max_cycles_value, "max_cycles", minimum=1)
        else:
            max_cycles = None
        active = value.get("active", True)
        if not isinstance(active, bool):
            raise ValueError("projection action active flag must be boolean")
        constant_value = value.get("constant_value")
        if kind == "constant":
            constant_value = _integer(
                constant_value, f"projection action {index}.constant_value"
            )
            if constant_value >= 1 << destination_widths[destination_id]:
                raise ValueError("constant projection action value is outside its destination width")
        elif constant_value is not None:
            raise ValueError("only constant projection actions may declare a constant value")
        parsed.append((action_id, destination_id, kind, category, max_cycles, constant_value, active))

    cursor = 0
    actions: list[ProjectionAction] = []
    for action_id, destination_id, kind, category, max_cycles, constant_value, active in sorted(
        parsed, key=lambda item: (order.index(item[1]), item[0])
    ):
        value_width = destination_widths[destination_id]
        counter_width = max(1, (max_cycles or 0).bit_length()) if kind in _TEMPORAL_KINDS else 0
        state_width = value_width + counter_width + 1 if kind in _TEMPORAL_KINDS else 0
        if cursor + state_width > state_cap:
            raise ValueError("projection state exceeds max_state_bits")
        actions.append(
            ProjectionAction(
                action_id,
                destination_id,
                kind,
                category,
                max_cycles,
                cursor,
                state_width,
                value_width,
                counter_width,
                constant_value,
                active,
            )
        )
        cursor += state_width

    frozen_actions = tuple(actions)
    projected_abi = _abi_with_actions(raw_abi, frozen_actions)
    used_state_bits = max(1, cursor)
    max_temporal_cycles = max(
        (action.max_cycles or 0 for action in frozen_actions),
        default=0,
    )
    document = {
        "raw_abi_hash": projected_abi.abi_hash,
        "field_order": list(order),
        "actions": [_action_document(action) for action in frozen_actions],
        "max_state_bits": used_state_bits,
        "max_temporal_cycles": max_temporal_cycles,
    }
    return ProjectionPlan(
        projected_abi,
        order,
        frozen_actions,
        used_state_bits,
        max_temporal_cycles,
        content_hash(document),
    )


def _slice(value: int, lo: int, width: int) -> int:
    return (value >> lo) & ((1 << width) - 1)


def _replace_slice(value: int, lo: int, width: int, replacement: int) -> int:
    mask = ((1 << width) - 1) << lo
    return (value & ~mask) | ((replacement << lo) & mask)


def project_sample(
    plan: ProjectionPlan,
    raw_value: int,
    state: ProjectionState,
) -> ProjectionResult:
    """Consume one sample and perform at most one bounded projection step."""
    if not isinstance(plan, ProjectionPlan):
        raise TypeError("plan must be ProjectionPlan")
    if isinstance(raw_value, bool) or not isinstance(raw_value, int) or not 0 <= raw_value < 1 << plan.raw_abi.raw_width:
        raise ValueError("raw_value is outside the unsigned raw ABI range")
    if not isinstance(state, ProjectionState):
        raise TypeError("state must be ProjectionState")
    if state.width != plan.max_state_bits:
        raise ValueError("projection state width does not match plan")
    if isinstance(state.value, bool) or not isinstance(state.value, int) or not 0 <= state.value < 1 << state.width:
        raise ValueError("projection state value is outside its width")

    direct_values = {
        destination.destination_id: 0 for destination in plan.raw_abi.destinations
    }
    for use in plan.raw_abi.uses:
        width = use.raw_hi - use.raw_lo + 1
        direct_values[use.destination_id] |= (
            _slice(raw_value, use.raw_lo, width) << use.destination_lo
        )
    driven = dict(direct_values)
    next_state_value = state.value
    corrections = {category: 0 for category in sorted({action.category for action in plan.actions})}
    events: list[tuple[int, str]] = []
    timeout_count = 0
    violation_count = 0
    no_progress_count = 0
    projected: set[int] = set()

    for action in plan.actions:
        destination_id = action.destination_id
        original = driven[destination_id]
        mask = (1 << action.value_width) - 1
        value = original
        if action.kind == "fold_xor" and action.value_width > 1:
            shift = (action.value_width + 1) // 2
            value = (original ^ (original >> shift)) & mask
            if value != original:
                events.append((destination_id, "fold"))
        elif action.kind == "mask":
            value = original & mask
        elif action.kind == "constant":
            assert action.constant_value is not None
            value = action.constant_value
        elif action.kind in _TEMPORAL_KINDS:
            assert action.max_cycles is not None
            latched = _slice(state.value, action.state_lo, action.value_width)
            counter_lo = action.state_lo + action.value_width
            remaining = _slice(state.value, counter_lo, action.counter_width)
            active_lo = counter_lo + action.counter_width
            holding = bool(_slice(state.value, active_lo, 1))
            next_state_value = _replace_slice(
                next_state_value,
                action.state_lo,
                action.state_width,
                0,
            )
            if action.kind == "gate":
                if holding:
                    value = latched
                    events.append((destination_id, "hold"))
                    if remaining <= 1:
                        timeout_count += 1
                        violation_count += 1
                        no_progress_count += 1
                        events.append((destination_id, "timeout"))
                    else:
                        next_state_value = _replace_slice(
                            next_state_value,
                            action.state_lo,
                            action.value_width,
                            latched,
                        )
                        next_state_value = _replace_slice(
                            next_state_value,
                            counter_lo,
                            action.counter_width,
                            remaining - 1,
                        )
                        next_state_value = _replace_slice(next_state_value, active_lo, 1, 1)
                elif value != 0:
                    next_state_value = _replace_slice(
                        next_state_value,
                        action.state_lo,
                        action.value_width,
                        value,
                    )
                    next_state_value = _replace_slice(
                        next_state_value,
                        counter_lo,
                        action.counter_width,
                        action.max_cycles,
                    )
                    next_state_value = _replace_slice(next_state_value, active_lo, 1, 1)
                    events.append((destination_id, "hold_start"))
            else:
                if holding:
                    no_progress_count += 1
                    if remaining <= 1:
                        value = latched
                        events.append((destination_id, "release"))
                    else:
                        value = 0
                        next_state_value = _replace_slice(
                            next_state_value,
                            action.state_lo,
                            action.value_width,
                            latched,
                        )
                        next_state_value = _replace_slice(
                            next_state_value,
                            counter_lo,
                            action.counter_width,
                            remaining - 1,
                        )
                        next_state_value = _replace_slice(next_state_value, active_lo, 1, 1)
                        events.append((destination_id, "delay"))
                elif value != 0:
                    next_state_value = _replace_slice(
                        next_state_value,
                        action.state_lo,
                        action.value_width,
                        value,
                    )
                    next_state_value = _replace_slice(
                        next_state_value,
                        counter_lo,
                        action.counter_width,
                        action.max_cycles,
                    )
                    next_state_value = _replace_slice(next_state_value, active_lo, 1, 1)
                    value = 0
                    no_progress_count += 1
                    events.append((destination_id, "delay_start"))
        if value != original:
            corrections[action.category] += 1
        driven[destination_id] = value
        if action.kind != "direct":
            projected.add(destination_id)

    return ProjectionResult(
        driven_fields=tuple((destination_id, driven[destination_id]) for destination_id in plan.field_order),
        next_state=ProjectionState(next_state_value, plan.max_state_bits),
        correction_counts=tuple(sorted(corrections.items())),
        protocol_events=tuple(events),
        cycles_consumed=1,
        sample_consumed=True,
        projection_count=len(projected),
        protocol_event_count=len(events),
        timeout_count=timeout_count,
        violation_count=violation_count,
        no_progress_count=no_progress_count,
    )


__all__ = [
    "ProjectionAction",
    "ProjectionPlan",
    "ProjectionResult",
    "ProjectionState",
    "build_projection_plan",
    "project_sample",
]
