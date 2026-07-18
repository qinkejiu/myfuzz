"""Superset RawBits slot layout and auditable A/B/C consumption mapping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .constraint_engine import ConstraintInterpreter, build_constraint_ir
from .contracts import AccessRecord, ConstraintIR
from .input_model import InputValidationError
from .large_soc_constraints import LargeSocExternalContract, build_large_soc_external_contract
from .rawbits import RawBitsLayout, build_rawbits_layout


_RECORD_FIELDS = (
    ("ip_select", 32),
    ("read_write", 1),
    ("offset", 32),
    ("data", 32),
)


@dataclass(frozen=True)
class SchemeInputUse:
    scheme: str
    used_bits: int
    ignored_bits: int
    utilization: float
    used_mask: int
    ignored_mask: int

    def to_dict(self) -> dict[str, object]:
        width = max(1, (self.used_bits + self.ignored_bits + 3) // 4)
        return {
            "scheme": self.scheme,
            "used_bits": self.used_bits,
            "ignored_bits": self.ignored_bits,
            "utilization": self.utilization,
            "used_mask_hex": f"0x{self.used_mask:0{width}x}",
            "ignored_mask_hex": f"0x{self.ignored_mask:0{width}x}",
        }


@dataclass(frozen=True)
class SupersetInputContract:
    layout: RawBitsLayout
    external: LargeSocExternalContract
    scheme_use: tuple[SchemeInputUse, ...]
    flat_targets: tuple[str, ...]


@dataclass(frozen=True)
class DecodedExperimentSlot:
    sequence: int
    scheme: str
    access_record: AccessRecord | None
    external_inputs: Mapping[str, int]
    flat_inputs: Mapping[str, int]


class ExperimentInputDecoder:
    """Stateful decoder because constrained GPIO HOLD semantics span input slots."""

    def __init__(self, contract: SupersetInputContract):
        self.contract = contract
        self._entries = {entry.target: entry for entry in contract.layout.entries}
        self._external_interpreter = ConstraintInterpreter(
            contract.external.layout, contract.external.constraint_ir,
        )

    def reset(self) -> None:
        self._external_interpreter.reset()

    def decode(self, raw_bits: int, *, sequence: int, scheme: str) -> DecodedExperimentSlot:
        if scheme not in {"flat_random", "generated_raw", "generated_constrained"}:
            raise InputValidationError(f"unknown experiment scheme {scheme!r}")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise InputValidationError("slot sequence must be a non-negative integer")
        if isinstance(raw_bits, bool) or not isinstance(raw_bits, int) or not 0 <= raw_bits < (1 << self.contract.layout.cycle_width):
            raise InputValidationError("slot raw_bits does not fit the superset layout")

        if scheme == "flat_random":
            flat = {target[len("flat__"):]: self._extract(raw_bits, target)
                    for target in self.contract.flat_targets}
            return DecodedExperimentSlot(sequence, scheme, None, {}, flat)

        record_values = {name: self._extract(raw_bits, f"record__{name}")
                         for name, _width in _RECORD_FIELDS}
        record = AccessRecord(**record_values)
        packed_external = 0
        for external_entry in self.contract.external.layout.entries:
            value = self._extract(raw_bits, f"external__{external_entry.target}")
            packed_external |= value << external_entry.offset
        external = self._external_interpreter.step(
            packed_external, constrained=scheme == "generated_constrained",
        )
        return DecodedExperimentSlot(sequence, scheme, record, external, {})

    def _extract(self, raw_bits: int, target: str) -> int:
        entry = self._entries[target]
        return (raw_bits >> entry.offset) & ((1 << entry.raw_width) - 1)


def build_superset_constraint_ir(contract: SupersetInputContract) -> ConstraintIR:
    """Lift the external B/C constraints into the shared input namespace."""
    constraints = []
    for entry in contract.layout.entries:
        if not entry.target.startswith("external__"):
            constraints.append({
                "target": entry.target,
                "primitive": "DIRECT",
                "provenance": "experiment_superset_passthrough",
            })
    for raw in contract.external.constraint_ir.constraints:
        item = {key: value for key, value in raw.items()
                if key not in {"offset", "raw_width", "value_width"}}
        item["target"] = f"external__{item['target']}"
        if "source" in item:
            item["source"] = f"external__{item['source']}"
        constraints.append(item)
    return build_constraint_ir(contract.layout, constraints)


def build_superset_input_contract(
    flat_inputs: Iterable[Mapping[str, object]],
) -> SupersetInputContract:
    external = build_large_soc_external_contract()
    normalized_flat: list[tuple[str, int]] = []
    for index, item in enumerate(flat_inputs):
        target = item.get("target")
        width = item.get("width")
        if not isinstance(target, str) or not target.isidentifier():
            raise InputValidationError(f"flat_inputs[{index}].target must be an identifier")
        if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
            raise InputValidationError(f"flat_inputs[{index}].width must be positive")
        normalized_flat.append((target, width))
    if not normalized_flat or len({name for name, _width in normalized_flat}) != len(normalized_flat):
        raise InputValidationError("flat input bank must be non-empty and have unique targets")

    entries = [
        {"target": f"record__{name}", "width": width,
         "purpose": "AccessRecord v1 field", "provenance": "experiment_manifest"}
        for name, width in _RECORD_FIELDS
    ]
    entries.extend({
        "target": f"external__{entry.target}", "raw_width": entry.raw_width,
        "value_width": entry.value_width, "purpose": entry.purpose,
        "provenance": entry.provenance,
    } for entry in external.layout.entries)
    entries.extend({
        "target": f"flat__{target}", "width": width,
        "purpose": "scheme A directly exposed child input", "provenance": "flat_shell",
    } for target, width in normalized_flat)
    layout = build_rawbits_layout(entries)
    masks = {"flat": 0, "generated": 0}
    for entry in layout.entries:
        mask = ((1 << entry.raw_width) - 1) << entry.offset
        if entry.target.startswith("flat__"):
            masks["flat"] |= mask
        else:
            masks["generated"] |= mask
    all_mask = (1 << layout.cycle_width) - 1
    uses = tuple(
        _scheme_use(name, masks[key], all_mask, layout.cycle_width)
        for name, key in (
            ("flat_random", "flat"),
            ("generated_raw", "generated"),
            ("generated_constrained", "generated"),
        )
    )
    return SupersetInputContract(
        layout, external, uses, tuple(f"flat__{name}" for name, _width in sorted(normalized_flat)),
    )


def _scheme_use(name: str, used_mask: int, all_mask: int, total: int) -> SchemeInputUse:
    used = used_mask.bit_count()
    return SchemeInputUse(name, used, total - used, used / total, used_mask, all_mask ^ used_mask)
