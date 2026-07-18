"""ConstraintIR v1 validation and cycle-accurate software reference interpreter."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from .contracts import ConstraintIR
from .input_model import InputValidationError
from .rawbits import RawBitsLayout, RawBitsLayoutEntry


class ConstraintPrimitive(str, Enum):
    DIRECT = "DIRECT"
    TIEOFF = "TIEOFF"
    MASK = "MASK"
    RANGE = "RANGE"
    ENUM = "ENUM"
    ONEHOT = "ONEHOT"
    PULSE = "PULSE"
    HOLD = "HOLD"
    DEPENDENCY = "DEPENDENCY"
    RESET_SEQUENCE = "RESET_SEQUENCE"


@dataclass
class _State:
    value: int = 0
    remaining: int = 0


def build_constraint_ir(
    layout: RawBitsLayout, constraints: Iterable[Mapping[str, Any]],
) -> ConstraintIR:
    values = tuple(dict(item) for item in constraints)
    by_target = {entry.target: entry for entry in layout.entries}
    seen: set[str] = set()
    normalized: list[Mapping[str, Any]] = []
    for index, value in enumerate(values):
        target = _text(value.get("target"), f"constraints[{index}].target")
        if target in seen:
            raise InputValidationError(f"duplicate constraint target {target!r}")
        seen.add(target)
        try:
            primitive = ConstraintPrimitive(value.get("primitive"))
        except ValueError as exc:
            raise InputValidationError(f"constraints[{index}].primitive: unsupported primitive") from exc
        try:
            entry = by_target[target]
        except KeyError as exc:
            raise InputValidationError(f"constraint target {target!r} is absent from RawBits layout") from exc
        normalized.append(_validate_constraint(
            value, entry, primitive, index, by_target=by_target, available=seen - {target},
        ))
    missing = set(by_target) - seen
    if missing:
        raise InputValidationError("missing constraint target(s): " + ", ".join(sorted(missing)))
    return ConstraintIR(layout.digest, layout.cycle_width, tuple(normalized))


class ConstraintInterpreter:
    """Evaluate RAW and CONSTRAINED modes with explicit reset and drain transitions."""

    def __init__(self, layout: RawBitsLayout, constraint_ir: ConstraintIR):
        if constraint_ir.layout_digest != layout.digest or constraint_ir.cycle_width != layout.cycle_width:
            raise InputValidationError("ConstraintIR and RawBits layout are incompatible")
        self.layout = layout
        self.constraints = tuple(constraint_ir.constraints)
        self.entries = {entry.target: entry for entry in layout.entries}
        self.states = {item["target"]: _State() for item in self.constraints}
        self.cycles_since_reset = 0
        self.last_outputs = {item["target"]: 0 for item in self.constraints}

    def reset(self) -> None:
        for state in self.states.values():
            state.value = 0
            state.remaining = 0
        self.cycles_since_reset = 0
        self.last_outputs = {item["target"]: 0 for item in self.constraints}

    def step(self, raw_bits: int, *, constrained: bool) -> dict[str, int]:
        if isinstance(raw_bits, bool) or not isinstance(raw_bits, int) or not 0 <= raw_bits < (1 << self.layout.cycle_width):
            raise InputValidationError("raw_bits does not fit the RawBits layout")
        outputs: dict[str, int] = {}
        for item in self.constraints:
            target = item["target"]
            entry = self.entries[target]
            raw = (raw_bits >> entry.offset) & ((1 << entry.raw_width) - 1)
            primitive = ConstraintPrimitive(item["primitive"])
            if not constrained and primitive is not ConstraintPrimitive.TIEOFF:
                value = raw & ((1 << entry.value_width) - 1)
            else:
                value = self._constrained_value(item, entry, raw, outputs)
            outputs[target] = value & ((1 << entry.value_width) - 1)
        self.last_outputs = outputs
        self.cycles_since_reset += 1
        return dict(outputs)

    def drain(self) -> dict[str, int]:
        outputs = {}
        for item in self.constraints:
            target = item["target"]
            idle = item.get("idle_value")
            outputs[target] = self.last_outputs[target] if idle is None else int(idle)
        self.last_outputs = outputs
        self.cycles_since_reset += 1
        return dict(outputs)

    def _constrained_value(
        self,
        item: Mapping[str, Any],
        entry: RawBitsLayoutEntry,
        raw: int,
        outputs: Mapping[str, int],
    ) -> int:
        primitive = ConstraintPrimitive(item["primitive"])
        state = self.states[item["target"]]
        value_mask = (1 << entry.value_width) - 1
        if primitive is ConstraintPrimitive.DIRECT:
            return raw
        if primitive is ConstraintPrimitive.TIEOFF:
            return int(item["value"])
        if primitive is ConstraintPrimitive.MASK:
            return raw & int(item["mask"])
        if primitive is ConstraintPrimitive.RANGE:
            minimum, maximum = int(item["minimum"]), int(item["maximum"])
            return minimum + raw % (maximum - minimum + 1)
        if primitive is ConstraintPrimitive.ENUM:
            values = item["values"]
            return int(values[raw % len(values)])
        if primitive is ConstraintPrimitive.ONEHOT:
            return 1 << (raw % entry.value_width)
        if primitive is ConstraintPrimitive.PULSE:
            if state.remaining > 0:
                state.remaining -= 1
                return 1
            if raw & 1:
                duration_bits = raw >> 1
                duration = 1 + duration_bits % int(item["max_cycles"])
                state.remaining = duration - 1
                return 1
            return 0
        if primitive is ConstraintPrimitive.HOLD:
            payload = raw & value_mask
            update = (raw >> entry.value_width) & 1
            if update:
                state.value = payload
            return state.value
        if primitive is ConstraintPrimitive.DEPENDENCY:
            source = item["source"]
            source_value = outputs.get(source, self.last_outputs.get(source))
            if source_value is None:
                raise InputValidationError(f"dependency source {source!r} is not available")
            return raw if source_value == int(item["equals"]) else int(item["fallback"])
        if primitive is ConstraintPrimitive.RESET_SEQUENCE:
            return int(item["active_value"]) if self.cycles_since_reset < int(item["assert_cycles"]) else int(item["inactive_value"])
        raise AssertionError(primitive)


def _validate_constraint(
    value: Mapping[str, Any], entry: RawBitsLayoutEntry,
    primitive: ConstraintPrimitive, index: int, *,
    by_target: Mapping[str, RawBitsLayoutEntry], available: set[str],
) -> Mapping[str, Any]:
    common = {"target", "primitive", "provenance", "idle_value"}
    primitive_fields = {
        ConstraintPrimitive.DIRECT: set(),
        ConstraintPrimitive.TIEOFF: {"value"},
        ConstraintPrimitive.MASK: {"mask"},
        ConstraintPrimitive.RANGE: {"minimum", "maximum"},
        ConstraintPrimitive.ENUM: {"values"},
        ConstraintPrimitive.ONEHOT: set(),
        ConstraintPrimitive.PULSE: {"max_cycles"},
        ConstraintPrimitive.HOLD: set(),
        ConstraintPrimitive.DEPENDENCY: {"source", "equals", "fallback"},
        ConstraintPrimitive.RESET_SEQUENCE: {"assert_cycles", "active_value", "inactive_value"},
    }
    extra = set(value) - common - primitive_fields[primitive]
    if extra:
        raise InputValidationError(
            f"constraints[{index}]: unsupported field(s): " + ", ".join(sorted(extra))
        )
    result = dict(value)
    result["primitive"] = primitive.value
    result["target"] = entry.target
    result["offset"] = entry.offset
    result["raw_width"] = entry.raw_width
    result["value_width"] = entry.value_width
    result["provenance"] = _text(value.get("provenance"), f"constraints[{index}].provenance")
    limit = 1 << entry.value_width
    if primitive is ConstraintPrimitive.TIEOFF:
        _bounded(value.get("value"), limit, f"constraints[{index}].value")
    elif primitive is ConstraintPrimitive.MASK:
        _bounded(value.get("mask"), limit, f"constraints[{index}].mask")
    elif primitive is ConstraintPrimitive.RANGE:
        minimum = _bounded(value.get("minimum"), limit, f"constraints[{index}].minimum")
        maximum = _bounded(value.get("maximum"), limit, f"constraints[{index}].maximum")
        if minimum > maximum:
            raise InputValidationError(f"constraints[{index}]: minimum exceeds maximum")
    elif primitive is ConstraintPrimitive.ENUM:
        values = value.get("values")
        if not isinstance(values, (tuple, list)) or not values:
            raise InputValidationError(f"constraints[{index}].values: expected a non-empty array")
        result["values"] = tuple(
            _bounded(item, limit, f"constraints[{index}].values") for item in values
        )
    elif primitive is ConstraintPrimitive.PULSE:
        if entry.value_width != 1 or entry.raw_width < 2:
            raise InputValidationError("PULSE requires value_width 1 and at least two raw bits")
        _positive(value.get("max_cycles"), f"constraints[{index}].max_cycles")
    elif primitive is ConstraintPrimitive.HOLD:
        if entry.raw_width < entry.value_width + 1:
            raise InputValidationError("HOLD requires one update-control bit")
    elif primitive is ConstraintPrimitive.DEPENDENCY:
        source = _text(value.get("source"), f"constraints[{index}].source")
        if source not in by_target:
            raise InputValidationError(
                f"constraints[{index}].source: target {source!r} is absent from RawBits layout"
            )
        if source not in available:
            raise InputValidationError(
                f"constraints[{index}].source: dependency source {source!r} must be defined earlier"
            )
        _bounded(
            value.get("equals"), 1 << by_target[source].value_width,
            f"constraints[{index}].equals",
        )
        _bounded(value.get("fallback"), limit, f"constraints[{index}].fallback")
    elif primitive is ConstraintPrimitive.RESET_SEQUENCE:
        _positive(value.get("assert_cycles"), f"constraints[{index}].assert_cycles")
        _bounded(value.get("active_value"), limit, f"constraints[{index}].active_value")
        _bounded(value.get("inactive_value"), limit, f"constraints[{index}].inactive_value")
    idle = value.get("idle_value")
    if idle is not None:
        _bounded(idle, limit, f"constraints[{index}].idle_value")
    return result


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputValidationError(f"{path}: expected a non-empty string")
    return value


def _positive(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InputValidationError(f"{path}: expected a positive integer")
    return value


def _bounded(value: object, limit: int, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < limit:
        raise InputValidationError(f"{path}: expected an integer in [0, {limit})")
    return value
