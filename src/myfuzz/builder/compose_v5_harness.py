"""Compose-v5 scheme-A rawbits harness emission."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping

from .flat_shell import EmittedFlatShell
from .input_model import InputValidationError
from .rawbits_v5 import RawBitsV5Layout


_SV_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


@dataclass(frozen=True)
class EmittedComposeV5SchemeAHarness:
    module_name: str
    flat_module_name: str
    rtl: str
    layout_digest: str
    rawbits_width: int
    observe_width: int
    input_bindings: tuple[Mapping[str, object], ...]
    observations: tuple[Mapping[str, object], ...]


@dataclass(frozen=True)
class EmittedComposeV5SchemeABundle:
    flat: EmittedFlatShell
    layout: RawBitsV5Layout
    harness: EmittedComposeV5SchemeAHarness
    rtl: str


def emit_compose_v5_scheme_a_rawbits_harness(
    flat: EmittedFlatShell,
    layout: RawBitsV5Layout,
    *,
    module_name: str = "compose_v5_scheme_a_harness",
) -> EmittedComposeV5SchemeAHarness:
    """Bind one v5 rawbits record directly to a scheme-A flat top.

    The harness is intentionally combinational.  Clock and reset ports are not
    special top-level ports here; if discovery marked them as clock/reset
    fields, their bits still come from ``rawbits_i`` exactly like the rest of
    scheme A.
    """

    _identifier(module_name, "compose-v5 scheme-A harness module name")
    if not isinstance(flat, EmittedFlatShell):
        raise InputValidationError("compose-v5 scheme-A harness requires an emitted flat shell")
    if not isinstance(layout, RawBitsV5Layout):
        raise InputValidationError("compose-v5 scheme-A harness requires a RawBitsV5Layout")
    _identifier(flat.module_name, "compose-v5 scheme-A flat module name")

    layout_by_owner = {field.owner: field for field in layout.fields}
    input_bindings: list[dict[str, object]] = []
    observations: list[dict[str, object]] = []
    observe_offset = 0
    used_layout_owners: set[str] = set()

    for external in flat.external_ports:
        top_port = _identifier(external.get("name"), "compose-v5 flat external port")
        instance = _identifier(external.get("instance"), f"compose-v5 flat port {top_port} instance")
        child_port = _identifier(external.get("child_port"), f"compose-v5 flat port {top_port} child port")
        direction = _direction(external.get("direction"), f"compose-v5 flat port {top_port} direction")
        width = _positive(external.get("width"), f"compose-v5 flat port {top_port} width")
        owner = f"{instance}.{child_port}"
        if direction == "input":
            try:
                field = layout_by_owner[owner]
            except KeyError as exc:
                raise InputValidationError(
                    f"compose-v5 scheme-A harness missing rawbits field for {owner}"
                ) from exc
            if field.width != width:
                raise InputValidationError(
                    f"compose-v5 scheme-A harness width mismatch for {owner}"
                )
            used_layout_owners.add(owner)
            input_bindings.append({
                "owner": owner,
                "top_port": top_port,
                "kind": field.kind,
                "offset": field.offset,
                "width": field.width,
            })
            continue
        observations.append({
            "owner": owner,
            "top_port": top_port,
            "direction": direction,
            "offset": observe_offset,
            "width": width,
        })
        observe_offset += width

    unused = set(layout_by_owner) - used_layout_owners
    if unused:
        raise InputValidationError(
            "compose-v5 scheme-A harness has unused rawbits field(s): "
            + ", ".join(sorted(unused))
        )

    observe_width = max(1, observe_offset)
    signal_lines = []
    assign_lines = [
        f"  localparam logic [255:0] EXPECTED_LAYOUT_DIGEST = 256'h{layout.digest};",
    ]
    instance_lines = []
    for external in flat.external_ports:
        top_port = str(external["name"])
        width = int(external["width"])
        signal_lines.append(f"  logic {_range(width)}{top_port};")
        instance_lines.append(f"    .{top_port}({top_port})")
    for binding in input_bindings:
        top_port = str(binding["top_port"])
        offset = int(binding["offset"])
        width = int(binding["width"])
        assign_lines.append(f"  assign {top_port} = rawbits_i[{offset} +: {width}];")
    if observations:
        for observation in observations:
            top_port = str(observation["top_port"])
            offset = int(observation["offset"])
            width = int(observation["width"])
            assign_lines.append(f"  assign observe_o[{offset} +: {width}] = {top_port};")
    else:
        assign_lines.append("  assign observe_o = 1'b0;")

    lines = [
        f"module {module_name} (",
        f"  input logic [{layout.record_width_bits - 1}:0] rawbits_i,",
        f"  output logic [{observe_width - 1}:0] observe_o",
        ");",
        f"  localparam int RAWBITS_WIDTH = {layout.record_width_bits};",
        f"  localparam int OBSERVE_WIDTH = {observe_width};",
        *signal_lines,
        *assign_lines,
        f"  {flat.module_name} i_flat (",
        ",\n".join(instance_lines),
        "  );",
        "endmodule",
    ]
    return EmittedComposeV5SchemeAHarness(
        module_name=module_name,
        flat_module_name=flat.module_name,
        rtl="\n".join(lines) + "\n",
        layout_digest=layout.digest,
        rawbits_width=layout.record_width_bits,
        observe_width=observe_width,
        input_bindings=tuple(input_bindings),
        observations=tuple(observations),
    )


def _identifier(value: object, path: str) -> str:
    if not isinstance(value, str) or not _SV_IDENTIFIER.fullmatch(value):
        raise InputValidationError(f"{path}: expected a simple Verilog identifier")
    return value


def _direction(value: object, path: str) -> str:
    if value not in {"input", "output"}:
        raise InputValidationError(f"{path}: expected input or output")
    return str(value)


def _positive(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InputValidationError(f"{path}: expected a positive integer")
    return value


def _range(width: int) -> str:
    return "" if width == 1 else f"[{width - 1}:0] "
