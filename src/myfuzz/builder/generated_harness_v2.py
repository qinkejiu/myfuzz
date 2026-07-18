"""Single-binary B/C/D RawBits v3 harness for a generated SoCIR v2 top."""

from __future__ import annotations

from dataclasses import dataclass
import re

from .contracts import CoverageABIV2
from .constraint_synthesis import SynthesizedConstraints
from .control_plane import CONTROL_OPCODES, GeneratedControlPlane
from .generated_soc_v2 import EmittedSocIRV2, SocExternalPort
from .input_model import InputValidationError
from .temporal_rtl import emit_temporal_constraint_rtl


MODE_B_GENERATED_RAW = 0
MODE_C_PROTOCOL_SAFE = 1
MODE_D_SCENARIO_CONSTRAINED = 2


@dataclass(frozen=True)
class EmittedGeneratedHarnessV2:
    module_name: str
    rtl: str
    layout_digest: str
    soc_digest: str
    constraint_digest: str
    protocol_safe_degenerate: bool
    boundary_ports: tuple[SocExternalPort, ...]
    coverage_abi_digest: str | None = None


def emit_generated_harness_v2(
    soc: EmittedSocIRV2,
    control: GeneratedControlPlane,
    constraints: SynthesizedConstraints,
    *,
    module_name: str = "myfuzz_generated_harness_v2",
    reset_cycles: int = 2,
    drain_cycles: int = 16,
    coverage_abi: CoverageABIV2 | None = None,
    embed_soc_rtl: bool = True,
) -> EmittedGeneratedHarnessV2:
    """Emit one harness whose out-of-band mode is immutable per testcase."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module_name):
        raise InputValidationError("generated harness module_name must be a Verilog identifier")
    if reset_cycles <= 0 or drain_cycles <= 0:
        raise InputValidationError("generated harness reset/drain cycles must be positive")
    if not soc.soc_digest or control.control_ir.soc_digest != soc.soc_digest:
        raise InputValidationError("generated harness SoC and ControlPlane digests differ")
    ir = constraints.ir
    if ir.soc_digest != soc.soc_digest or ir.rawbits_layout_digest != control.layout.digest:
        raise InputValidationError("generated harness constraint contract digests differ")
    if not constraints.protocol_safe_degenerate:
        raise InputValidationError("non-degenerate C mode requires a protocol-safe record mapper")
    _validate_soc_control_ports(soc, control.layout.cycle_width)
    _validate_coverage_abi(coverage_abi)

    fields = {field.name: field for field in control.layout.fields}
    opcode = fields.get("opcode")
    address = fields.get("address")
    target_region = fields.get("target_region")
    sequence = fields.get("sequence_control")
    external_select = fields.get("external_select")
    external_value = fields.get("external_value")
    fault_kind = fields.get("fault_kind")
    irq_value = fields.get("irq_value")
    reset_domain = fields.get("reset_domain")
    wait_cycles = fields.get("wait_cycles")
    required_fields = (
        opcode, address, target_region, sequence, external_select, external_value, fault_kind, wait_cycles,
        irq_value, reset_domain,
    )
    if any(field is None for field in required_fields):
        raise InputValidationError("generated harness is missing required control fields")
    temporal = emit_temporal_constraint_rtl(ir, module_name=f"{module_name}_constraints")
    supported_inputs = {
        "raw_opcode", "scenario_guidance_enable", "raw_record_bits",
        "scenario_sequence_enable", "scenario_state_opcode", "raw_wait_cycles",
        "raw_timeout_cycles", "raw_address", "raw_target_region",
        "control_accepted", "control_done", "control_active",
    }
    supported_inputs.update(
        f"external_{index}_fault_enable"
        for index, _boundary in enumerate(
            port for port in soc.external_port_specs
            if port.kind == "boundary" and port.direction == "input"
        )
    )
    unknown_inputs = set(temporal.input_ports) - supported_inputs
    if unknown_inputs:
        raise InputValidationError(
            "generated harness has no dispatcher for Temporal input(s): " + ", ".join(sorted(unknown_inputs))
        )
    required_outputs = {
        "scenario_opcode", "scenario_state", "scenario_wait_cycles", "scenario_timeout_cycles",
        "scenario_aligned_address", "scenario_target_region", "operation_timeout_fired",
    }
    missing_outputs = required_outputs - set(temporal.output_ports)
    if missing_outputs:
        raise InputValidationError(
            "generated harness constraint outputs missing: " + ", ".join(sorted(missing_outputs))
        )

    boundaries = tuple(port for port in soc.external_port_specs if port.kind == "boundary")
    driven_boundaries = tuple(port for port in boundaries if port.direction == "input")
    observed_boundaries = tuple(port for port in boundaries if port.direction == "output")
    environment_ports = tuple(port for port in soc.external_port_specs if port.kind == "environment")
    supported_environment = {
        "external_irq_sources", "reset_domain_select", "reset_domain_start",
        "reset_domain_busy", "reset_domain_done", "reset_domain_error", "reset_epoch",
    }
    unsupported_environment = tuple(
        port.name for port in environment_ports if port.name not in supported_environment
    )
    if unsupported_environment:
        raise InputValidationError(
            "generated harness has no environment dispatcher for: " + ", ".join(unsupported_environment)
        )
    if tuple(port.selection_index for port in driven_boundaries) != tuple(range(len(driven_boundaries))):
        raise InputValidationError("generated SoC driven boundary indices are not contiguous")
    environment_by_name = {port.name: port for port in environment_ports}
    reset_select_port = environment_by_name.get("reset_domain_select")
    port_lines = [
        "input logic clk_i", "input logic harness_resetn_i", "input logic start_i",
        "input logic [1:0] mode_i", "input logic [15:0] format_version_i",
        "input logic [255:0] layout_digest_i", "input logic [255:0] soc_digest_i",
        "input logic [255:0] constraint_digest_i",
        f"input logic [{control.layout.cycle_width - 1}:0] raw_bits_i",
        "input logic raw_bits_valid_i", "input logic end_i",
        "output logic raw_bits_ready_o", "output logic raw_bits_consumed_o",
        "output logic done_o", "output logic format_error_o", "output logic runtime_error_o",
        "output logic [1:0] latched_mode_o", "output logic control_accepted_o",
        "output logic control_done_o", "output logic [31:0] control_status_o",
        "output logic [31:0] control_result_o",
    ]
    if coverage_abi is not None:
        port_lines.extend((
            f"input logic [{coverage_abi.epoch_width - 1}:0] coverage_epoch_i",
            "input logic [255:0] coverage_abi_digest_i",
            f"output logic [{coverage_abi.width - 1}:0] coverage_o",
            f"output logic [{coverage_abi.width - 1}:0] coverage_live_o",
            "output logic coverage_valid_o",
        ))
    port_lines.extend(_port_decl(port) for port in observed_boundaries)
    lines = [
        f'module {module_name} #(parameter BOOT_ROM_HEX_FILE="",',
        f"  parameter integer RESET_CYCLES={reset_cycles}, DRAIN_CYCLES={drain_cycles}) (",
        "  " + ",\n  ".join(port_lines),
        ");",
        f"  localparam logic [255:0] EXPECTED_LAYOUT_DIGEST=256'h{control.layout.digest};",
        f"  localparam logic [255:0] EXPECTED_SOC_DIGEST=256'h{soc.soc_digest};",
        f"  localparam logic [255:0] EXPECTED_CONSTRAINT_DIGEST=256'h{ir.digest};",
        "  localparam logic [2:0] ST_IDLE=0,ST_RESET=1,ST_RUN=2,ST_DRAIN=3,ST_DONE=4;",
        "  localparam logic [1:0] MODE_B=0,MODE_C=1,MODE_D=2;",
        "  logic [2:0] state; logic [1:0] mode_latched;",
        "  integer reset_count,drain_count;",
        f"  logic [{control.layout.cycle_width - 1}:0] pending_record,selected_record;",
        "  logic pending_valid,control_start,control_accepted,control_done,control_active;",
        "  logic [31:0] control_status,control_result;",
        f"  logic [{opcode.width - 1}:0] scenario_opcode;",
        f"  logic [{opcode.width - 1}:0] scenario_state_opcode;",
        f"  logic [{wait_cycles.width - 1}:0] scenario_wait_cycles;",
        f"  logic [{fields['timeout_cycles'].width - 1}:0] scenario_timeout_cycles;",
        f"  logic [{address.width - 1}:0] scenario_aligned_address;",
        f"  logic [{target_region.width - 1}:0] scenario_target_region;",
        "  logic [2:0] scenario_state;",
        "  logic temporal_ready,temporal_error,operation_timeout_fired;",
        "  logic record_fire;",
        "  logic [31:0] external_irq_sources_value;",
        f"  logic [{(reset_select_port.width if reset_select_port else 1)-1}:0] reset_domain_select_value;",
        "  logic reset_domain_start_value,reset_domain_busy_value,reset_domain_done_value;",
        "  logic reset_domain_error_value;logic [31:0] reset_epoch_value;",
        "  wire soc_resetn=(state!=ST_IDLE)&&(state!=ST_RESET);",
        "  assign record_fire=raw_bits_valid_i&&raw_bits_ready_o;",
        "  assign raw_bits_consumed_o=record_fire;",
        "  assign latched_mode_o=mode_latched;",
        "  assign control_accepted_o=control_accepted; assign control_done_o=control_done;",
        "  assign control_status_o=control_status; assign control_result_o=control_result;",
    ]
    if coverage_abi is not None:
        lines.extend((
            f"  localparam logic [255:0] EXPECTED_COVERAGE_ABI_DIGEST=256'h{coverage_abi.manifest_digest};",
            f"  wire [{coverage_abi.transport_width - 1}:0] coverage_transport;",
            f"  wire [{coverage_abi.width - 1}:0] coverage_live;",
            f"  logic [{coverage_abi.width - 1}:0] coverage_frozen;",
            "  assign coverage_o=coverage_frozen;",
            "  assign coverage_live_o=coverage_live;",
            "  assign coverage_valid_o=(state==ST_DONE)&&!format_error_o&&!runtime_error_o;",
        ))
        for point in coverage_abi.points:
            if point.get("included"):
                lines.append(
                    f"  assign coverage_live[{int(point['offset'])}]=coverage_transport[{int(point['source_offset'])}];"
                )
    if reset_select_port is None:
        lines.append(
            "  assign reset_domain_busy_value=0;assign reset_domain_done_value=0;"
            "assign reset_domain_error_value=0;assign reset_epoch_value=0;"
        )
    for index, boundary in enumerate(driven_boundaries):
        width = "" if boundary.width == 1 else f"[{boundary.width - 1}:0] "
        lines.extend((
            f"  logic {width}external_{index}_value;",
            f"  logic {width}external_{index}_fault_drive;",
            f"  integer external_{index}_pulse_remaining;",
            f"  wire {width}external_{index}_soc_value="
            f"(|external_{index}_fault_drive)?external_{index}_fault_drive:external_{index}_value;",
        ))
    lines += [
        "  always_comb begin",
        f"    scenario_state_opcode={CONTROL_OPCODES.index('MEM_WRITE')};",
        "    case (scenario_state)",
        f"      3'd0: scenario_state_opcode={CONTROL_OPCODES.index('MEM_WRITE')};",
        f"      3'd1: scenario_state_opcode={CONTROL_OPCODES.index('MEM_READ')};",
        f"      3'd2: scenario_state_opcode={CONTROL_OPCODES.index('MMIO_WRITE')};",
        f"      3'd3: scenario_state_opcode={CONTROL_OPCODES.index('MMIO_READ')};",
        f"      3'd4: scenario_state_opcode={CONTROL_OPCODES.index('SET_EXTERNAL')};",
        f"      3'd5: scenario_state_opcode={CONTROL_OPCODES.index('PULSE_EXTERNAL')};",
        f"      3'd6: scenario_state_opcode={CONTROL_OPCODES.index('WAIT_CYCLES')};",
        f"      3'd7: scenario_state_opcode={CONTROL_OPCODES.index('FENCE')};",
        "      default: scenario_state_opcode='0;",
        "    endcase",
        "    selected_record=pending_record;",
        f"    if (mode_latched==MODE_D) selected_record[{opcode.offset} +: {opcode.width}]=scenario_opcode;",
        f"    if (mode_latched==MODE_D) selected_record[{address.offset} +: {address.width}]=scenario_aligned_address;",
        f"    if (mode_latched==MODE_D) selected_record[{target_region.offset} +: {target_region.width}]=scenario_target_region;",
        f"    if (mode_latched==MODE_D) selected_record[{fields['timeout_cycles'].offset} +: {fields['timeout_cycles'].width}]=scenario_timeout_cycles;",
        f"    if (mode_latched==MODE_D) selected_record[{wait_cycles.offset} +: {wait_cycles.width}]=scenario_wait_cycles;",
        "    raw_bits_ready_o=(state==ST_RUN)&&!end_i&&!pending_valid&&!control_active&&"
        "!reset_domain_busy_value&&temporal_ready;",
        "    done_o=(state==ST_DONE);",
        "    control_start=((state==ST_RUN)||(state==ST_DRAIN))&&pending_valid&&!control_active&&"
        "!reset_domain_busy_value&&!temporal_error;",
        "  end",
        "  always_ff @(posedge clk_i or negedge harness_resetn_i) begin",
        "    if (!harness_resetn_i) begin",
        "      state<=ST_IDLE; mode_latched<=MODE_B; reset_count<=0; drain_count<=0;",
        "      pending_record<='0; pending_valid<=0; format_error_o<=0; runtime_error_o<=0;",
        *( ["      coverage_frozen<='0;"] if coverage_abi is not None else [] ),
        "      external_irq_sources_value<=0;",
        "      reset_domain_select_value<=0;reset_domain_start_value<=0;",
    ]
    for index, _boundary in enumerate(driven_boundaries):
        lines.append(f"      external_{index}_value<='0; external_{index}_pulse_remaining<=0;")
    lines += [
        "    end else begin",
        "      external_irq_sources_value<=0;",
        "      reset_domain_start_value<=0;",
        f"      if (control_accepted && selected_record[{opcode.offset} +: {opcode.width}]=="
        f"{CONTROL_OPCODES.index('WAIT_IRQ')})",
        f"        external_irq_sources_value<=selected_record[{irq_value.offset} +: {irq_value.width}];",
        f"      if (control_accepted && selected_record[{opcode.offset} +: {opcode.width}]=="
        f"{CONTROL_OPCODES.index('RESET_DOMAIN')}) begin",
        f"        reset_domain_select_value<=selected_record[{reset_domain.offset} +: {reset_domain.width}];",
        "        reset_domain_start_value<=1;",
        "      end",
    ]
    for index, boundary in enumerate(driven_boundaries):
        value_slice = f"selected_record[{external_value.offset} +: {boundary.width}]"
        lines.extend((
            f"      if (external_{index}_pulse_remaining>0) begin",
            f"        external_{index}_pulse_remaining<=external_{index}_pulse_remaining-1;",
            f"        if (external_{index}_pulse_remaining==1) external_{index}_value<='0;",
            "      end",
            f"      if (control_accepted && selected_record[{external_select.offset} +: {external_select.width}]=={index}) begin",
            f"        if (selected_record[{opcode.offset} +: {opcode.width}]=={CONTROL_OPCODES.index('SET_EXTERNAL')}) begin",
            f"          external_{index}_value<={value_slice}; external_{index}_pulse_remaining<=0;",
            f"        end else if (selected_record[{opcode.offset} +: {opcode.width}]=={CONTROL_OPCODES.index('PULSE_EXTERNAL')}) begin",
            f"          external_{index}_value<={value_slice};",
            f"          external_{index}_pulse_remaining<=(selected_record[{wait_cycles.offset} +: {wait_cycles.width}]==0)?1:"
            f"selected_record[{wait_cycles.offset} +: {wait_cycles.width}];",
            "        end",
            "      end",
        ))
    lines += [
        "      case (state)",
        "        ST_IDLE: if (start_i) begin",
        "          format_error_o<=0; runtime_error_o<=0; pending_valid<=0;",
        *( ["          coverage_frozen<='0;"] if coverage_abi is not None else [] ),
        "          if (format_version_i!=16'd3 || layout_digest_i!=EXPECTED_LAYOUT_DIGEST ||",
        "              soc_digest_i!=EXPECTED_SOC_DIGEST || constraint_digest_i!=EXPECTED_CONSTRAINT_DIGEST ||",
        *( ["              coverage_abi_digest_i!=EXPECTED_COVERAGE_ABI_DIGEST ||"] if coverage_abi is not None else [] ),
        "              mode_i==2'd3) begin",
        "            format_error_o<=1; state<=ST_DONE;",
        "          end else begin mode_latched<=mode_i; reset_count<=0; state<=ST_RESET; end",
        "        end",
        "        ST_RESET: begin",
        "          if (mode_i!=mode_latched) begin format_error_o<=1; state<=ST_DONE; end",
        "          else if (reset_count+1>=RESET_CYCLES) state<=ST_RUN; else reset_count<=reset_count+1;",
        "        end",
        "        ST_RUN: begin",
        "          if (mode_i!=mode_latched) begin format_error_o<=1; pending_valid<=0; drain_count<=0; state<=ST_DRAIN; end",
        "          else if (temporal_error || operation_timeout_fired) begin runtime_error_o<=1; pending_valid<=0; drain_count<=0; state<=ST_DRAIN; end",
        "          else begin",
        "            if (record_fire) begin pending_record<=raw_bits_i; pending_valid<=1; end",
        "            if (control_accepted) pending_valid<=0;",
        *( ["            if (end_i) coverage_frozen<=coverage_live;"] if coverage_abi is not None else [] ),
        "            if (end_i) begin drain_count<=0; state<=ST_DRAIN; end",
        "          end",
        "        end",
        "        ST_DRAIN: begin",
        "          if (control_accepted) pending_valid<=0;",
        "          if (mode_i!=mode_latched) format_error_o<=1;",
        "          if ((!control_active&&!pending_valid&&!reset_domain_busy_value) || drain_count+1>=DRAIN_CYCLES) begin",
        "            pending_valid<=0; state<=ST_DONE;",
        "          end",
        "          else drain_count<=drain_count+1;",
        "        end",
        "        ST_DONE: state<=ST_DONE;",
        "        default: begin runtime_error_o<=1; state<=ST_DONE; end",
        "      endcase",
        "    end",
        "  end",
    ]
    temporal_bindings = [
        ".clk(clk_i)", ".rst_n(harness_resetn_i)", ".raw_bits_valid(record_fire)",
        ".raw_bits_ready(temporal_ready)", ".constraint_runtime_error(temporal_error)",
    ]
    for _domain, port in temporal.domain_reset_ports.items():
        temporal_bindings.append(f".{port}(state==ST_RESET)")
    input_expr = {
        "raw_opcode": f"raw_bits_i[{opcode.offset} +: {opcode.width}]",
        "scenario_guidance_enable": f"raw_bits_i[{sequence.offset}]",
        "scenario_sequence_enable": f"raw_bits_i[{sequence.offset + 1}]",
        "scenario_state_opcode": "scenario_state_opcode",
        "raw_wait_cycles": f"raw_bits_i[{wait_cycles.offset} +: {wait_cycles.width}]",
        "raw_timeout_cycles": f"raw_bits_i[{fields['timeout_cycles'].offset} +: {fields['timeout_cycles'].width}]",
        "raw_address": f"raw_bits_i[{address.offset} +: {address.width}]",
        "raw_target_region": f"raw_bits_i[{target_region.offset} +: {target_region.width}]",
        "raw_record_bits": "pending_record",
        "control_accepted": "control_accepted",
        "control_done": "control_done",
        "control_active": "control_active",
    }
    for index, _boundary in enumerate(driven_boundaries):
        input_expr[f"external_{index}_fault_enable"] = (
            f"record_fire&&(raw_bits_i[{external_select.offset} +: {external_select.width}]=={index})"
            f"&&(|raw_bits_i[{fault_kind.offset} +: {fault_kind.width}])"
        )
    temporal_bindings.extend(f".{port}({input_expr[name]})" for name, port in temporal.input_ports.items())
    for name, port in temporal.output_ports.items():
        if name == "operation_timeout_fired":
            temporal_bindings.append(f".{port}(operation_timeout_fired)")
        elif name == "scenario_opcode":
            temporal_bindings.append(f".{port}(scenario_opcode)")
        elif name == "scenario_state":
            temporal_bindings.append(f".{port}(scenario_state)")
        elif name == "scenario_wait_cycles":
            temporal_bindings.append(f".{port}(scenario_wait_cycles)")
        elif name == "scenario_timeout_cycles":
            temporal_bindings.append(f".{port}(scenario_timeout_cycles)")
        elif name == "scenario_aligned_address":
            temporal_bindings.append(f".{port}(scenario_aligned_address)")
        elif name == "scenario_target_region":
            temporal_bindings.append(f".{port}(scenario_target_region)")
        elif re.fullmatch(r"external_[0-9]+_drive", name):
            temporal_bindings.append(f".{port}({name.replace('_drive', '_fault_drive')})")
        else:
            temporal_bindings.append(f".{port}()")
    lines.extend((
        f"  {temporal.module_name} i_constraints(",
        "    " + ",\n    ".join(temporal_bindings),
        "  );",
        f"  {soc.module_name} #(.BOOT_ROM_HEX_FILE(BOOT_ROM_HEX_FILE)) i_soc(",
    ))
    soc_bindings = [
        ".clk(clk_i)", ".resetn(soc_resetn)", ".control_raw_bits(selected_record)",
        ".control_start(control_start)", ".control_accepted(control_accepted)",
        ".control_done(control_done)", ".control_active(control_active)",
        ".control_status(control_status)", ".control_result(control_result)",
    ]
    soc_bindings.extend(
        f".{port.name}(external_{port.selection_index}_soc_value)"
        if port.direction == "input" else f".{port.name}({port.name})"
        for port in boundaries
    )
    environment_signals = {
        "external_irq_sources": "external_irq_sources_value",
        "reset_domain_select": "reset_domain_select_value",
        "reset_domain_start": "reset_domain_start_value",
        "reset_domain_busy": "reset_domain_busy_value",
        "reset_domain_done": "reset_domain_done_value",
        "reset_domain_error": "reset_domain_error_value",
        "reset_epoch": "reset_epoch_value",
    }
    soc_bindings.extend(f".{port.name}({environment_signals[port.name]})" for port in environment_ports)
    if coverage_abi is not None:
        soc_bindings.extend((
            f".{coverage_abi.port_name}(coverage_transport)",
            ".coverage_epoch_i(coverage_epoch_i)",
        ))
    lines.extend(("    " + ",\n    ".join(soc_bindings), "  );", "endmodule", ""))
    rtl = "\n".join(lines) + temporal.rtl + (soc.rtl if embed_soc_rtl else "")
    return EmittedGeneratedHarnessV2(
        module_name, rtl, control.layout.digest, soc.soc_digest, ir.digest,
        constraints.protocol_safe_degenerate, boundaries,
        None if coverage_abi is None else coverage_abi.manifest_digest,
    )


def _validate_soc_control_ports(soc: EmittedSocIRV2, raw_width: int) -> None:
    expected = {
        "control_raw_bits": ("input", raw_width), "control_start": ("input", 1),
        "control_accepted": ("output", 1), "control_done": ("output", 1),
        "control_active": ("output", 1), "control_status": ("output", 32),
        "control_result": ("output", 32),
    }
    actual = {port.name: (port.direction, port.width) for port in soc.external_port_specs if port.kind == "control"}
    if actual != expected:
        raise InputValidationError("generated SoC does not expose the complete control mailbox ABI")
    for port in soc.external_port_specs:
        if port.direction not in {"input", "output"} or port.width <= 0:
            raise InputValidationError(f"invalid generated SoC external port {port.name}")


def _port_decl(port: SocExternalPort) -> str:
    width = "" if port.width == 1 else f"[{port.width - 1}:0] "
    return f"{port.direction} logic {width}{port.name}"


def _validate_coverage_abi(coverage_abi: CoverageABIV2 | None) -> None:
    if coverage_abi is None:
        return
    included = sorted(
        (point for point in coverage_abi.points if point.get("included")),
        key=lambda point: int(point["offset"]),
    )
    if [int(point["offset"]) for point in included] != list(range(coverage_abi.width)):
        raise InputValidationError("generated harness requires dense CoverageABI v2 offsets")
    source_offsets = [int(point["source_offset"]) for point in included]
    if any(offset < 0 or offset >= coverage_abi.transport_width for offset in source_offsets):
        raise InputValidationError("generated harness CoverageABI v2 source offset is out of range")
