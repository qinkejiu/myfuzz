"""Derive a generic CPU control plane and native RawBits v3 layout from SoCIR."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .contracts import ControlPlaneIRV1, RegisterModelIRV1, SoCIRV2, seal_contract
from .input_model import InputValidationError
from .rawbits_v3 import RawBitsV3Layout, build_rawbits_v3_layout


CONTROL_OPCODES = (
    "MMIO_READ", "MMIO_WRITE", "MMIO_RMW", "POLL", "WAIT_CYCLES", "WAIT_IRQ",
    "IRQ_ACK", "MEM_READ", "MEM_WRITE", "FENCE", "SET_EXTERNAL", "PULSE_EXTERNAL",
    "FAULT_ACCESS", "RESET_DOMAIN", "SEQUENCE_CONTINUE", "SEQUENCE_END",
)


@dataclass(frozen=True)
class GeneratedControlPlane:
    control_ir: ControlPlaneIRV1
    layout: RawBitsV3Layout


def build_control_plane(
    soc: SoCIRV2,
    *,
    cpu_profile_digest: str,
    register_models: Iterable[RegisterModelIRV1] = (),
    timeout_width: int = 16,
    sequence_width: int = 8,
) -> GeneratedControlPlane:
    _sha256(soc.digest, "soc.digest")
    _sha256(cpu_profile_digest, "cpu_profile_digest")
    if timeout_width <= 0 or sequence_width <= 0:
        raise InputValidationError("control-plane counter widths must be positive")
    views = tuple(soc.address_views)
    if not views:
        raise InputValidationError("control plane requires at least one addressable region")
    target_width = _bits_for_count(len(views))
    address_width = max(int(view["local_address_width"]) for view in views)
    reset_width = _bits_for_count(max(1, len(soc.reset_domains)))
    driven_boundaries = tuple(
        item for item in soc.external_boundaries if str(item["direction"]) == "input"
    )
    external_width = max((int(item["width"]) for item in driven_boundaries), default=1)
    external_select_width = _bits_for_count(max(1, len(driven_boundaries)))
    opcode_width = _bits_for_count(len(CONTROL_OPCODES))
    fields = (
        _field("opcode", opcode_width, "control.opcode", 0, len(CONTROL_OPCODES) - 1, 0, "operation set"),
        _field("target_region", target_width, "control.target_region", 0, len(views) - 1, 0, "SoC address views"),
        _field("address", address_width, "control.local_address", 0, (1 << address_width) - 1, 0, "widest local address view"),
        _field("write_data", 32, "control.write_data", 0, (1 << 32) - 1, 0, "CPU data width"),
        _field("write_strobe", 4, "control.write_strobe", 0, 15, 15, "32-bit byte lanes"),
        _field("compare_data", 32, "control.compare_data", 0, (1 << 32) - 1, 0, "poll/RMW comparison value"),
        _field("compare_mask", 32, "control.compare_mask", 0, (1 << 32) - 1, (1 << 32) - 1, "poll/RMW selected bits"),
        _field("wait_cycles", timeout_width, "control.wait_cycles", 0, (1 << timeout_width) - 1, 0, "bounded wait"),
        _field("timeout_cycles", timeout_width, "control.timeout_cycles", 1, (1 << timeout_width) - 1, 1, "bounded transaction timeout"),
        _field("sequence_control", sequence_width, "control.sequence", 0, (1 << sequence_width) - 1, 0, "scenario sequencing"),
        _field("irq_value", 32, "control.irq", 0, (1 << 32) - 1, 0, "interrupt pending/claim mapper"),
        _field("reset_domain", reset_width, "control.reset_domain", 0, max(0, len(soc.reset_domains) - 1), 0, "SoC reset graph"),
        _field("external_select", external_select_width, "control.external_select", 0,
               max(0, len(driven_boundaries) - 1), 0, "declared driven external boundary index"),
        _field("external_value", external_width, "control.external", 0, (1 << external_width) - 1, 0, "external/fault-capable boundary"),
        _field("fault_kind", 2, "control.fault_kind", 0, 3, 0, "bounded fault selector"),
        _field("fault_response", 2, "control.fault_response", 0, 3, 0, "explicit external error response"),
    )
    operations = tuple({
        "opcode": index, "name": name, "consumers": _operation_consumers(name),
        "provenance": {"source": "cpu_control_plane_profile/v1"},
    } for index, name in enumerate(CONTROL_OPCODES))
    models = tuple(register_models)
    for model in models:
        _sha256(model.digest, f"register model {model.name}.digest")
    control = seal_contract(ControlPlaneIRV1(
        soc_digest=soc.digest,
        cpu_profile_digest=cpu_profile_digest,
        register_model_digests=tuple({"name": model.name, "digest": model.digest} for model in models),
        fields=fields,
        operations=operations,
        provenance={"source": "SoCIR+CpuExecutionProfile+RegisterModelIR", "mode_out_of_band": True},
    ))
    layout = build_rawbits_v3_layout(tuple({
        "name": field["name"], "width": field["width"], "source": "fuzz",
        "consumer": field["consumer"], "minimum": field["minimum"], "maximum": field["maximum"],
        "default": field["default"], "provenance": field["provenance"],
    } for field in fields))
    return GeneratedControlPlane(control, layout)  # type: ignore[arg-type]


def _field(name: str, width: int, consumer: str, minimum: int, maximum: int,
           default: int, reason: str) -> Mapping[str, object]:
    return {
        "name": name, "width": width, "consumer": consumer, "minimum": minimum,
        "maximum": maximum, "default": default,
        "provenance": {"source": "derived", "reason": reason},
    }


def _operation_consumers(name: str) -> tuple[str, ...]:
    return {
        "MMIO_READ": ("target_region", "address", "timeout_cycles"),
        "MMIO_WRITE": ("target_region", "address", "write_data", "write_strobe", "timeout_cycles"),
        "MMIO_RMW": ("target_region", "address", "write_data", "compare_mask", "timeout_cycles"),
        "POLL": ("target_region", "address", "compare_data", "compare_mask", "timeout_cycles"),
        "WAIT_CYCLES": ("wait_cycles",), "WAIT_IRQ": ("irq_value", "timeout_cycles"),
        "IRQ_ACK": ("irq_value",),
        "MEM_READ": ("target_region", "address", "timeout_cycles"),
        "MEM_WRITE": ("target_region", "address", "write_data", "write_strobe", "timeout_cycles"),
        "FENCE": ("sequence_control",),
        "SET_EXTERNAL": ("external_select", "external_value"),
        "PULSE_EXTERNAL": ("external_select", "external_value", "wait_cycles"),
        "FAULT_ACCESS": ("target_region", "address", "fault_kind", "fault_response", "timeout_cycles"),
        "RESET_DOMAIN": ("reset_domain", "timeout_cycles"),
        "SEQUENCE_CONTINUE": ("sequence_control",), "SEQUENCE_END": ("sequence_control",),
    }[name]


def _bits_for_count(count: int) -> int:
    return max(1, (count - 1).bit_length())


def _sha256(value: str, path: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise InputValidationError(f"{path}: expected a lowercase SHA-256 digest")
