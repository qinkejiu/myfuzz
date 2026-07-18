"""Derive conservative bit/cycle constraints from SoC and control contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .contracts import SoCIRV2, TemporalConstraintIRV2
from .control_plane import CONTROL_OPCODES, GeneratedControlPlane
from .input_model import InputValidationError
from .temporal_v2 import build_temporal_constraint_ir_v2


@dataclass(frozen=True)
class SynthesizedConstraints:
    ir: TemporalConstraintIRV2
    protocol_safe_degenerate: bool
    mode_outputs: Mapping[str, str]
    evidence: tuple[Mapping[str, object], ...]


def synthesize_temporal_constraints(
    soc: SoCIRV2,
    control: GeneratedControlPlane,
    *, operation_timeout_limit: int = 65535,
) -> SynthesizedConstraints:
    if control.control_ir.soc_digest != soc.digest:
        raise InputValidationError("constraint synthesis received a ControlPlane for another SoCIR")
    if operation_timeout_limit <= 0:
        raise InputValidationError("operation timeout limit must be positive")
    fields = {item.name: item for item in control.layout.fields}
    for required in ("opcode", "sequence_control", "address", "target_region"):
        if required not in fields:
            raise InputValidationError(f"constraint synthesis requires RawBits field {required}")
    opcode = fields["opcode"]
    address = fields["address"]
    target_region = fields["target_region"]
    wait_cycles = fields.get("wait_cycles")
    timeout_cycles = fields.get("timeout_cycles")
    if opcode.width != max(1, (len(CONTROL_OPCODES) - 1).bit_length()):
        raise InputValidationError("opcode RawBits width differs from the operation vocabulary")
    if fields["sequence_control"].width < 2:
        raise InputValidationError("scenario sequencing requires two sequence_control bits")
    if wait_cycles is None or timeout_cycles is None:
        raise InputValidationError("scenario sequencing requires wait and timeout fields")
    ordered_views = tuple(sorted(soc.address_views, key=lambda item: str(item["instance_id"])))
    externally_driven_instances = {
        str(boundary["instance_id"])
        for boundary in soc.external_boundaries
        if str(boundary.get("direction")) == "input"
    }
    progress_independent_targets = tuple(
        index for index, view in enumerate(ordered_views)
        if str(view["instance_id"]) not in externally_driven_instances
    )
    if not progress_independent_targets:
        raise InputValidationError("scenario constraints require a progress-independent address view")

    # Common operations remain likely, while reset/fault paths retain non-zero
    # mass. scenario_guidance_enable is supplied from a raw sequence bit, so D
    # can still select the unmodified opcode on individual accepted records.
    weighted = {
        "MMIO_READ": 5, "MMIO_WRITE": 5, "MMIO_RMW": 3, "POLL": 3,
        "WAIT_CYCLES": 2, "WAIT_IRQ": 2, "IRQ_ACK": 2, "MEM_READ": 3,
        "MEM_WRITE": 3, "FENCE": 1, "SET_EXTERNAL": 2, "PULSE_EXTERNAL": 2,
        "FAULT_ACCESS": 1, "RESET_DOMAIN": 1, "SEQUENCE_CONTINUE": 2,
        "SEQUENCE_END": 2,
    }
    constraints = [
        {
            "id": "scenario_opcode_weight", "primitive": "CHOICE_WEIGHT", "priority": 0,
            "domain": "global", "dst": "weighted_opcode", "raw_slice": "raw_opcode",
            "slice_width": opcode.width, "choices": tuple(range(len(CONTROL_OPCODES))),
            "integer_weights": tuple(weighted[name] for name in CONTROL_OPCODES), "width": opcode.width,
        },
        {
            "id": "scenario_opcode_raw_bypass", "primitive": "DEPENDENCY", "priority": 1,
            "domain": "global", "dst": "guided_opcode", "predicate": "scenario_guidance_enable",
            "true_value": "weighted_opcode", "false_value": "raw_opcode", "width": opcode.width,
        },
        {
            "id": "scenario_state_sequence", "primitive": "SEQUENCE", "priority": 2,
            "domain": "global", "state": "scenario_state", "initial": "MEM_WRITE",
            "states": (
                "MEM_WRITE", "MEM_READ", "MMIO_WRITE", "MMIO_READ",
                "SET_EXTERNAL", "PULSE_EXTERNAL", "WAIT_CYCLES", "FENCE",
            ),
            "terminal": (),
            "transitions": tuple(
                {"from": source, "to": target, "guard": "control_done", "priority": index}
                for index, (source, target) in enumerate((
                    ("MEM_WRITE", "MEM_READ"), ("MEM_READ", "MMIO_WRITE"),
                    ("MMIO_WRITE", "MMIO_READ"), ("MMIO_READ", "SET_EXTERNAL"),
                    ("SET_EXTERNAL", "PULSE_EXTERNAL"),
                    ("PULSE_EXTERNAL", "WAIT_CYCLES"),
                    ("WAIT_CYCLES", "FENCE"), ("FENCE", "MEM_WRITE"),
                ))
            ),
        },
        {
            "id": "scenario_sequence_select", "primitive": "DEPENDENCY", "priority": 3,
            "domain": "global", "dst": "scenario_opcode", "predicate": "scenario_sequence_enable",
            "true_value": "scenario_state_opcode", "false_value": "guided_opcode",
            "width": opcode.width,
        },
        {
            "id": "scenario_wait_bound", "primitive": "CHOICE_WEIGHT", "priority": 4,
            "domain": "global", "dst": "scenario_wait_cycles", "raw_slice": "raw_wait_cycles",
            "slice_width": wait_cycles.width, "choices": (1, 2, 4, 8, 16, 32, 64, 128),
            "integer_weights": (1, 2, 3, 4, 4, 3, 2, 1), "width": wait_cycles.width,
        },
        {
            "id": "scenario_timeout_bound", "primitive": "CHOICE_WEIGHT", "priority": 5,
            "domain": "global", "dst": "scenario_timeout_cycles",
            "raw_slice": "raw_timeout_cycles", "slice_width": timeout_cycles.width,
            "choices": (16, 32, 64, 128, 256, 512, 1024),
            "integer_weights": (1, 2, 3, 4, 3, 2, 1), "width": timeout_cycles.width,
        },
        {
            "id": "scenario_address_align", "primitive": "BIT_MASK", "priority": 6,
            "domain": "global", "dst": "scenario_aligned_address", "sample": "raw_address",
            "mask": ((1 << address.width) - 1) & ~0x3, "width": address.width,
        },
        {
            "id": "scenario_target_region", "primitive": "CHOICE_WEIGHT", "priority": 7,
            "domain": "global", "dst": "scenario_target_region", "raw_slice": "raw_target_region",
            "slice_width": target_region.width, "choices": progress_independent_targets,
            "integer_weights": tuple(1 for _target in progress_independent_targets),
            "width": target_region.width,
        },
        {
            "id": "record_stability", "primitive": "STABLE_UNTIL", "priority": 8,
            "domain": "global", "dst": "stable_record_bits", "sample": "raw_record_bits",
            "activate": "control_accepted", "release": "control_done",
            "width": control.layout.cycle_width, "reset": 0,
        },
        {
            "id": "operation_timeout", "primitive": "TIMEOUT", "priority": 9,
            "domain": "global", "active": "control_active", "clear": "control_done",
            "limit": operation_timeout_limit, "fired": "operation_timeout_fired",
        },
    ]
    evidence = [
        {"constraint_id": "scenario_opcode_weight", "source": "ControlPlaneIR.operations",
         "reason": "weighted guidance with non-zero raw/fault/reset paths"},
        {"constraint_id": "scenario_opcode_raw_bypass", "source": "RawBits.sequence_control[0]",
         "reason": "per-record raw bypass prevents mandatory device-sequence legalization"},
        {"constraint_id": "scenario_state_sequence", "source": "ControlPlaneIR.operations",
         "reason": "state advances only on completed operations across read/write/external/wait/fence phases"},
        {"constraint_id": "scenario_sequence_select", "source": "RawBits.sequence_control[1]",
         "reason": "each accepted record can enable or bypass stateful scenario guidance"},
        {"constraint_id": "scenario_wait_bound", "source": "ControlPlaneIR.wait_cycles",
         "reason": "D wait and pulse durations remain bounded while preserving bit-derived choices"},
        {"constraint_id": "scenario_timeout_bound", "source": "ControlPlaneIR.timeout_cycles",
         "reason": "D transactions terminate within a bit-derived exploration budget"},
        {"constraint_id": "scenario_address_align", "source": "ControlPlaneIR.address",
         "reason": "CPU word loads and stores require the bit-derived address low bits to be zero"},
        {"constraint_id": "scenario_target_region", "source": "SoCIR.address_views+external_boundaries",
         "reason": "D ordinary accesses select bit-derived regions that do not require an external completion input"},
        {"constraint_id": "record_stability", "source": "control mailbox valid/done contract",
         "reason": "accepted bit record remains stable until terminal completion"},
        {"constraint_id": "operation_timeout", "source": "ControlPlaneIR.timeout_cycles",
         "reason": "bounded recovery is a cycle-level structural invariant"},
    ]
    fault_sinks = []
    driven_boundaries = tuple(
        boundary for boundary in soc.external_boundaries
        if str(boundary.get("direction")) == "input"
    )
    for index, boundary in enumerate(driven_boundaries):
        name = f"external_{index}_drive"
        fault_sinks.append(name)
        constraints.append({
            "id": f"external_{index}_fault", "primitive": "FAULT_INJECT",
            "priority": len(constraints), "domain": "global", "dst": name,
            "enable": f"external_{index}_fault_enable", "kind": "stuck_at_one",
            "value": (1 << int(boundary["width"])) - 1, "cycles": 1,
            "width": int(boundary["width"]),
        })
        evidence.append({
            "constraint_id": f"external_{index}_fault", "source": boundary.get("provenance", {}),
            "reason": "only an explicitly declared external input is fault-capable",
        })
    external_protocol = any(
        str(item.get("protocol")) in {"axi_lite", "apb3", "apb4"}
        for item in soc.external_boundaries
    )
    ir = build_temporal_constraint_ir_v2(
        rawbits_layout_digest=control.layout.digest, soc_digest=soc.digest,
        constraints=constraints, fault_capable_sinks=fault_sinks,
    )
    return SynthesizedConstraints(
        ir, not external_protocol,
        {"B_GENERATED_RAW": "raw_opcode",
         "C_PROTOCOL_SAFE": "protocol_safe_opcode" if external_protocol else "raw_opcode",
         "D_SCENARIO_CONSTRAINED": "scenario_opcode"},
        tuple(evidence),
    )
