"""Deterministic dual-mode RawBits v2 SystemVerilog harness emission."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .constraint_engine import ConstraintPrimitive
from .contracts import ConstraintIR, CoverageABI, CoverageABIV2
from .input_model import InputValidationError, PortDirection
from .rawbits import RawBitsLayout


_SV_KEYWORDS = {
    "always", "always_comb", "always_ff", "assign", "begin", "case", "default",
    "else", "end", "endcase", "endmodule", "enum", "generate", "if", "inout",
    "input", "integer", "logic", "module", "output", "parameter", "reg", "wire",
}


@dataclass(frozen=True)
class HarnessPort:
    name: str
    direction: PortDirection
    width: int
    role: str = "signal"
    reset_active_low: bool = True


@dataclass(frozen=True)
class EmittedHarness:
    module_name: str
    rtl: str
    observed_ports: tuple[str, ...]
    layout_digest: str


def emit_dual_mode_harness(
    soc_module: str,
    layout: RawBitsLayout,
    constraint_ir: ConstraintIR,
    ports: tuple[HarnessPort, ...],
    *,
    module_name: str = "generated_harness_top",
    reset_cycles: int = 2,
    drain_cycles: int = 4,
    coverage_abi: CoverageABI | CoverageABIV2 | None = None,
) -> EmittedHarness:
    for value, label in ((soc_module, "soc_module"), (module_name, "module_name")):
        if not value.isidentifier() or value in _SV_KEYWORDS:
            raise InputValidationError(f"Harness {label} must be an identifier")
    if reset_cycles <= 0 or drain_cycles <= 0:
        raise InputValidationError("Harness reset_cycles and drain_cycles must be positive")
    if constraint_ir.layout_digest != layout.digest or constraint_ir.cycle_width != layout.cycle_width:
        raise InputValidationError("Harness ConstraintIR and RawBits layout are incompatible")
    if not ports or len({port.name for port in ports}) != len(ports):
        raise InputValidationError("Harness ports must be non-empty and unique")
    for port in ports:
        if not port.name.isidentifier() or port.name in _SV_KEYWORDS or port.width <= 0:
            raise InputValidationError("Harness port names and widths must be valid")
        if port.direction is PortDirection.INOUT:
            raise InputValidationError("Harness does not infer inout behavior")
    if coverage_abi is not None:
        if coverage_abi.width <= 0:
            raise InputValidationError("Harness CoverageABI width must be positive")
        if (
            not coverage_abi.port_name.isidentifier()
            or coverage_abi.port_name in _SV_KEYWORDS
            or coverage_abi.port_name in {port.name for port in ports}
        ):
            raise InputValidationError("Harness CoverageABI port name is invalid or conflicts with a SoC port")
        included_offsets = sorted(
            int(point["offset"]) for point in coverage_abi.points if point.get("included")
        )
        if included_offsets != list(range(coverage_abi.width)):
            raise InputValidationError("Harness CoverageABI included offsets do not cover its width")
        if isinstance(coverage_abi, CoverageABIV2):
            source_offsets = [int(point["source_offset"]) for point in coverage_abi.points if point.get("included")]
            if any(value < 0 or value >= coverage_abi.transport_width for value in source_offsets):
                raise InputValidationError("Harness CoverageABI v2 source offset exceeds transport width")
    clocks = [port for port in ports if port.role == "clock"]
    resets = [port for port in ports if port.role == "reset"]
    if len(clocks) != 1 or len(resets) != 1:
        raise InputValidationError("Harness requires exactly one clock and one reset port")
    constraints = {str(item["target"]): item for item in constraint_ir.constraints}
    fuzz_inputs = [
        port for port in ports
        if port.direction is PortDirection.INPUT and port.role not in {"clock", "reset"}
    ]
    if set(constraints) != {port.name for port in fuzz_inputs}:
        raise InputValidationError("Harness constraints must cover every non-clock/reset SoC input exactly once")
    entries = {entry.target: entry for entry in layout.entries}
    if set(entries) != set(constraints):
        raise InputValidationError("Harness layout and ConstraintIR targets differ")
    port_by_name = {port.name: port for port in fuzz_inputs}
    evaluation_inputs = [port_by_name[str(item["target"])] for item in constraint_ir.constraints]

    observed = tuple(sorted(port.name for port in ports if port.direction is PortDirection.OUTPUT))
    lines = [f"module {module_name} #(",
        f" parameter integer RESET_CYCLES={reset_cycles}, DRAIN_CYCLES={drain_cycles}",
        ") (",
        " input logic clk_i, input logic harness_resetn_i, input logic start_i,",
        " input logic mode_constrained_i, input logic [15:0] format_version_i,",
        " input logic [255:0] layout_digest_i,",
        f" input logic [{layout.cycle_width - 1}:0] raw_bits_i,",
        " input logic raw_bits_valid_i, input logic end_i,",
        " output logic raw_bits_ready_o, output logic done_o, output logic format_error_o",
    ]
    output_declarations = [
        f" output logic {_range(port.width)}observe__{port.name}"
        for port in ports if port.direction is PortDirection.OUTPUT
    ]
    if coverage_abi is not None:
        output_declarations += [
            f" output logic {_range(coverage_abi.width)}coverage_o",
            " output logic coverage_valid_o",
        ]
        lines.insert(6, " input logic [255:0] coverage_abi_digest_i,")
        if isinstance(coverage_abi, CoverageABIV2):
            lines.insert(6, f" input logic [{coverage_abi.epoch_width - 1}:0] coverage_epoch_i,")
    if output_declarations:
        lines.append(",\n" + ",\n".join(output_declarations))
    lines += [
        ");",
        f" localparam logic [255:0] EXPECTED_LAYOUT_DIGEST=256'h{layout.digest};",
        " localparam logic [2:0] ST_IDLE=0, ST_RESET=1, ST_RUN=2, ST_DRAIN=3, ST_DONE=4;",
        " logic [2:0] state; integer reset_count, drain_count, consumed_cycles;",
    ]
    if isinstance(coverage_abi, CoverageABIV2):
        lines.append(f" logic {_range(coverage_abi.transport_width)}coverage_transport;")
        for point in coverage_abi.points:
            if point.get("included"):
                target = ("coverage_o" if coverage_abi.width == 1
                          else f"coverage_o[{point['offset']}]")
                source = ("coverage_transport" if coverage_abi.transport_width == 1
                          else f"coverage_transport[{point['source_offset']}]")
                lines.append(f" assign {target}={source};")
    for port in fuzz_inputs:
        entry = entries[port.name]
        lines.append(f" logic {_range(entry.raw_width)}raw__{port.name};")
        lines.append(
            f" assign raw__{port.name}=raw_bits_i[{entry.offset} +: {entry.raw_width}];"
        )
        lines.append(f" logic {_range(port.width)}value__{port.name}, next__{port.name};")
        item = constraints[port.name]
        if item["primitive"] == ConstraintPrimitive.PULSE.value:
            lines.append(f" integer pulse_remaining__{port.name}, next_pulse_remaining__{port.name};")
    reset_port = resets[0]
    reset_active = "1'b0" if reset_port.reset_active_low else "1'b1"
    reset_inactive = "1'b1" if reset_port.reset_active_low else "1'b0"
    lines += [
        " always_comb begin",
        "  raw_bits_ready_o=(state==ST_RUN) && !end_i;",
        "  done_o=(state==ST_DONE);",
    ]
    if coverage_abi is not None:
        lines.append("  coverage_valid_o=done_o;")
    for port in fuzz_inputs:
        lines.append(f"  next__{port.name}=value__{port.name};")
        if constraints[port.name]["primitive"] == ConstraintPrimitive.PULSE.value:
            lines.append(f"  next_pulse_remaining__{port.name}=pulse_remaining__{port.name};")
    lines.append("  if (state==ST_RUN && raw_bits_valid_i && raw_bits_ready_o) begin")
    for port in evaluation_inputs:
        item = constraints[port.name]
        entry = entries[port.name]
        raw = f"raw__{port.name}"
        raw_value = (
            raw if entry.raw_width <= entry.value_width
            else f"{raw}[{entry.value_width - 1}:0]"
        )
        primitive = ConstraintPrimitive(item["primitive"])
        if primitive is ConstraintPrimitive.TIEOFF:
            lines.append(f"   next__{port.name}={port.width}'d{item['value']};")
            continue
        lines.append("   if (!mode_constrained_i) begin")
        lines.append(f"    next__{port.name}={raw_value};")
        if primitive is ConstraintPrimitive.PULSE:
            lines.append(f"    next_pulse_remaining__{port.name}=0;")
        lines.append("   end else begin")
        lines.extend(_constrained_sv(port, item, entry, raw))
        lines.append("   end")
    lines += [
        "  end",
        "  if (state==ST_DRAIN) begin",
    ]
    for port in fuzz_inputs:
        item = constraints[port.name]
        if item.get("idle_value") is not None:
            lines.append(f"   next__{port.name}={port.width}'d{item['idle_value']};")
        if item["primitive"] == ConstraintPrimitive.PULSE.value:
            lines.append(f"   next_pulse_remaining__{port.name}=0;")
    lines += ["  end", " end"]
    lines += [
        " always_ff @(posedge clk_i or negedge harness_resetn_i) begin",
        "  if (!harness_resetn_i) begin",
        "   state<=ST_IDLE; reset_count<=0; drain_count<=0; consumed_cycles<=0; format_error_o<=0;",
    ]
    for port in fuzz_inputs:
        lines.append(f"   value__{port.name}<='0;")
        if constraints[port.name]["primitive"] == ConstraintPrimitive.PULSE.value:
            lines.append(f"   pulse_remaining__{port.name}<=0;")
    lines += [
        "  end else begin",
        "   case (state)",
        "    ST_IDLE: if (start_i) begin",
        "     if (format_version_i != 16'd2 || layout_digest_i != EXPECTED_LAYOUT_DIGEST"
        + (
            f" || coverage_abi_digest_i != 256'h{coverage_abi.manifest_digest}"
            if coverage_abi is not None else ""
        ) + ") begin",
        "      format_error_o<=1; state<=ST_DONE;",
        "     end else begin reset_count<=0; consumed_cycles<=0; state<=ST_RESET; end",
        "    end",
        "    ST_RESET: if (reset_count + 1 >= RESET_CYCLES) state<=ST_RUN; else reset_count<=reset_count+1;",
        "    ST_RUN: begin",
        "     if (end_i) begin drain_count<=0; state<=ST_DRAIN; end",
        "     else if (raw_bits_valid_i && raw_bits_ready_o) begin",
    ]
    for port in fuzz_inputs:
        lines.append(f"      value__{port.name}<=next__{port.name};")
        if constraints[port.name]["primitive"] == ConstraintPrimitive.PULSE.value:
            lines.append(f"      pulse_remaining__{port.name}<=next_pulse_remaining__{port.name};")
    lines += [
        "      consumed_cycles<=consumed_cycles+1;",
        "     end",
        "    end",
        "    ST_DRAIN: begin",
    ]
    for port in fuzz_inputs:
        lines.append(f"     value__{port.name}<=next__{port.name};")
        if constraints[port.name]["primitive"] == ConstraintPrimitive.PULSE.value:
            lines.append(f"     pulse_remaining__{port.name}<=next_pulse_remaining__{port.name};")
    lines += [
        "     if (drain_count + 1 >= DRAIN_CYCLES) state<=ST_DONE; else drain_count<=drain_count+1;",
        "    end",
        "    ST_DONE: state<=ST_DONE;",
        "    default: state<=ST_IDLE;",
        "   endcase",
        "  end",
        " end",
        f" logic soc_reset; assign soc_reset=(state==ST_RESET || state==ST_IDLE) ? {reset_active} : {reset_inactive};",
        f" {soc_module} u_soc (",
    ]
    bindings = []
    for port in ports:
        if port.role == "clock":
            signal = "clk_i"
        elif port.role == "reset":
            signal = "soc_reset"
        elif port.direction is PortDirection.INPUT:
            signal = f"value__{port.name}"
        else:
            signal = f"observe__{port.name}"
        bindings.append(f"  .{port.name}({signal})")
    if coverage_abi is not None:
        bindings.append(f"  .{coverage_abi.port_name}({'coverage_transport' if isinstance(coverage_abi, CoverageABIV2) else 'coverage_o'})")
        if isinstance(coverage_abi, CoverageABIV2):
            bindings.append("  .coverage_epoch_i(coverage_epoch_i)")
    lines.append(",\n".join(bindings))
    lines += [" );", "endmodule"]
    return EmittedHarness(module_name, "\n".join(lines) + "\n", observed, layout.digest)


def _constrained_sv(
    port: HarnessPort, item: Mapping[str, object], entry: object, raw: str,
) -> list[str]:
    primitive = ConstraintPrimitive(item["primitive"])
    name = port.name
    raw_value = raw if entry.raw_width <= port.width else f"{raw}[{port.width - 1}:0]"
    if primitive is ConstraintPrimitive.DIRECT:
        return [f"    next__{name}={raw_value};"]
    if primitive is ConstraintPrimitive.MASK:
        return [f"    next__{name}={raw_value} & {port.width}'d{item['mask']};"]
    if primitive is ConstraintPrimitive.RANGE:
        span = int(item["maximum"]) - int(item["minimum"]) + 1
        return [f"    next__{name}={port.width}'d{item['minimum']} + ({raw} % {span});"]
    if primitive is ConstraintPrimitive.ENUM:
        values = item["values"]
        result = [f"    case ({raw} % {len(values)})"]
        result.extend(f"     {index}: next__{name}={port.width}'d{value};" for index, value in enumerate(values))
        result += [f"     default: next__{name}={port.width}'d{values[0]};", "    endcase"]
        return result
    if primitive is ConstraintPrimitive.ONEHOT:
        return [f"    next__{name}={port.width}'d1 << ({raw} % {port.width});"]
    if primitive is ConstraintPrimitive.PULSE:
        return [
            f"    if (pulse_remaining__{name}>0) begin next__{name}=1; next_pulse_remaining__{name}=pulse_remaining__{name}-1; end",
            f"    else if ({raw}[0]) begin next__{name}=1; next_pulse_remaining__{name}=(({raw} >> 1) % {item['max_cycles']}); end",
            f"    else begin next__{name}=0; next_pulse_remaining__{name}=0; end",
        ]
    if primitive is ConstraintPrimitive.HOLD:
        return [f"    if ({raw}[{port.width}]) next__{name}={raw}[{port.width - 1}:0];"]
    if primitive is ConstraintPrimitive.DEPENDENCY:
        source = item["source"]
        return [
            f"    if (next__{source} == {item['equals']}) next__{name}={raw_value};",
            f"    else next__{name}={port.width}'d{item['fallback']};",
        ]
    if primitive is ConstraintPrimitive.RESET_SEQUENCE:
        return [
            f"    next__{name}=(consumed_cycles < {item['assert_cycles']}) ? "
            f"{port.width}'d{item['active_value']} : {port.width}'d{item['inactive_value']};",
        ]
    raise AssertionError(primitive)


def _range(width: int) -> str:
    return "" if width == 1 else f"[{width - 1}:0] "
