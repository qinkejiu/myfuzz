"""Campaign harnesses for the disconnected A and shared generated B/C targets."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .atomic_target import BuiltTarget, build_verilator_target
from .contracts import CoverageABIV2, ElaborationManifest, ResolvedFile
from .experiment_inputs import (
    SupersetInputContract, build_superset_constraint_ir,
)
from .flat_shell import EmittedFlatShell
from .harness import EmittedHarness
from .input_model import InputValidationError


@dataclass(frozen=True)
class LargeSocCampaignTargets:
    cpu_id: str
    flat: BuiltTarget
    generated: BuiltTarget


def emit_large_flat_campaign_harness(
    flat: EmittedFlatShell,
    contract: SupersetInputContract,
    coverage_abi: CoverageABIV2,
    *,
    module_name: str | None = None,
) -> EmittedHarness:
    """Drive every scheme-A child input directly from its exclusive RawBits bank."""
    module = module_name or f"{flat.module_name}_campaign_harness"
    _validate(module, coverage_abi)
    entries = {entry.target: entry for entry in contract.layout.entries}
    connections = []
    declarations = []
    for port in flat.external_ports:
        name = str(port["name"])
        width = int(port["width"])
        if port["direction"] == "input":
            entry = entries[f"flat__{name}"]
            signal = f"raw_bits_i[{entry.offset} +: {entry.raw_width}]"
        else:
            signal = f"observe__{name}"
            declarations.append(f"  wire {_range(width)}{signal};")
        connections.append(f"    .{name}({signal})")
    projection = _coverage_projection(coverage_abi)
    rtl = f"""module {module}(
  input wire clk_i, input wire harness_resetn_i, input wire start_i,
  input wire mode_constrained_i, input wire [15:0] format_version_i,
  input wire [255:0] layout_digest_i, input wire [255:0] coverage_abi_digest_i,
  input wire [{coverage_abi.epoch_width - 1}:0] coverage_epoch_i,
  input wire [{contract.layout.cycle_width - 1}:0] raw_bits_i,
  input wire raw_bits_valid_i, input wire end_i,
  output wire raw_bits_ready_o, output wire done_o, output wire format_error_o,
  output wire [{coverage_abi.width - 1}:0] coverage_o, output wire coverage_valid_o
);
  localparam [255:0] EXPECTED_LAYOUT_DIGEST=256'h{contract.layout.digest};
  localparam [255:0] EXPECTED_COVERAGE_DIGEST=256'h{coverage_abi.manifest_digest};
  localparam [2:0] ST_IDLE=0,ST_RESET=1,ST_RUN=2,ST_DRAIN=3,ST_DONE=4;
  reg [2:0] state; reg [3:0] phase_count; reg local_format_error;
  wire [{coverage_abi.transport_width - 1}:0] coverage_transport;
{chr(10).join(declarations)}
  wire unused_mode=mode_constrained_i;
  assign raw_bits_ready_o=(state==ST_RUN)&&!end_i;
  assign done_o=state==ST_DONE;
  assign coverage_valid_o=done_o;
  assign format_error_o=local_format_error;
{projection}
  always @(posedge clk_i or negedge harness_resetn_i) begin
    if (!harness_resetn_i) begin state<=ST_IDLE; phase_count<=0; local_format_error<=0; end
    else case(state)
      ST_IDLE: if(start_i) begin
        if(format_version_i!=16'd2||layout_digest_i!=EXPECTED_LAYOUT_DIGEST||
           coverage_abi_digest_i!=EXPECTED_COVERAGE_DIGEST) begin
          local_format_error<=1; state<=ST_DONE;
        end else begin phase_count<=0; state<=ST_RESET; end
      end
      ST_RESET: if(phase_count==1) begin phase_count<=0; state<=ST_RUN; end
                else phase_count<=phase_count+1'b1;
      ST_RUN: if(end_i) begin phase_count<=0; state<=ST_DRAIN; end
      ST_DRAIN: if(phase_count==3) state<=ST_DONE; else phase_count<=phase_count+1'b1;
      ST_DONE: state<=ST_DONE;
      default: state<=ST_IDLE;
    endcase
  end
  {flat.module_name} u_flat(
{',\n'.join(connections)},
    .coverage_epoch_i(coverage_epoch_i), .{coverage_abi.port_name}(coverage_transport));
endmodule
"""
    return EmittedHarness(module, rtl, tuple(sorted(
        str(port["name"]) for port in flat.external_ports if port["direction"] == "output"
    )), contract.layout.digest)


def emit_large_generated_campaign_harness(
    generated_top: str,
    contract: SupersetInputContract,
    coverage_abi: CoverageABIV2,
    *,
    module_name: str = "generated_large_soc_campaign_harness",
) -> EmittedHarness:
    """Transaction-paced campaign wrapper shared byte-for-byte by schemes B and C."""
    _validate(module_name, coverage_abi)
    rtl = f"""module {module_name}(
  input wire clk_i, input wire harness_resetn_i, input wire start_i,
  input wire mode_constrained_i, input wire [15:0] format_version_i,
  input wire [255:0] layout_digest_i, input wire [255:0] coverage_abi_digest_i,
  input wire [{coverage_abi.epoch_width - 1}:0] coverage_epoch_i,
  input wire [{contract.layout.cycle_width - 1}:0] raw_bits_i,
  input wire raw_bits_valid_i, input wire end_i,
  output wire raw_bits_ready_o, output wire done_o, output wire format_error_o,
  output wire [{coverage_abi.width - 1}:0] coverage_o, output wire coverage_valid_o
);
  localparam [255:0] EXPECTED_LAYOUT_DIGEST=256'h{contract.layout.digest};
  localparam [255:0] EXPECTED_COVERAGE_DIGEST=256'h{coverage_abi.manifest_digest};
  localparam [2:0] ST_IDLE=0,ST_RESET=1,ST_RUN=2,ST_DRAIN=3,ST_DONE=4;
  reg [2:0] state; reg [3:0] phase_count; reg local_format_error;
  reg [31:0] sequence_index;
  wire inner_ready,inner_consumed,inner_format_error,terminal_valid;
  wire terminal_timed_out,terminal_read_write,cpu_fault,recovering,recovery_error;
  wire [31:0] terminal_sequence,terminal_address,terminal_cycles,restart_count;
  wire [7:0] terminal_route; wire [1:0] terminal_response;
  wire [{coverage_abi.transport_width - 1}:0] coverage_transport;
  wire execution_resetn=harness_resetn_i&&(state!=ST_IDLE)&&(state!=ST_RESET);
  assign raw_bits_ready_o=(state==ST_RUN)&&!end_i&&inner_ready;
  assign done_o=state==ST_DONE;
  assign coverage_valid_o=done_o;
  assign format_error_o=local_format_error||inner_format_error;
{_coverage_projection(coverage_abi)}
  always @(posedge clk_i or negedge harness_resetn_i) begin
    if(!harness_resetn_i) begin state<=ST_IDLE; phase_count<=0; sequence_index<=0; local_format_error<=0; end
    else begin
      if(inner_consumed) sequence_index<=sequence_index+1'b1;
      case(state)
        ST_IDLE: if(start_i) begin
          if(format_version_i!=16'd2||layout_digest_i!=EXPECTED_LAYOUT_DIGEST||
             coverage_abi_digest_i!=EXPECTED_COVERAGE_DIGEST) begin
            local_format_error<=1; state<=ST_DONE;
          end else begin phase_count<=0; sequence_index<=0; state<=ST_RESET; end
        end
        ST_RESET: if(phase_count==3) begin phase_count<=0; state<=ST_RUN; end
                  else phase_count<=phase_count+1'b1;
        ST_RUN: if(end_i) begin phase_count<=0; state<=ST_DRAIN; end
        ST_DRAIN: if(phase_count==7) state<=ST_DONE; else phase_count<=phase_count+1'b1;
        ST_DONE: state<=ST_DONE;
        default: state<=ST_IDLE;
      endcase
    end
  end
  {generated_top} u_generated(
    .clk_i(clk_i),.resetn_i(execution_resetn),.mode_constrained_i(mode_constrained_i),
    .layout_digest_i(layout_digest_i),.raw_bits_i(raw_bits_i),
    .raw_bits_valid_i(raw_bits_valid_i&&(state==ST_RUN)&&!end_i),
    .raw_bits_ready_o(inner_ready),.raw_bits_consumed_o(inner_consumed),
    .sequence_i(sequence_index),.terminal_capture_ack_i(terminal_valid),
    .terminal_valid_o(terminal_valid),.terminal_timed_out_o(terminal_timed_out),
    .terminal_sequence_o(terminal_sequence),.terminal_route_o(terminal_route),
    .terminal_read_write_o(terminal_read_write),.terminal_address_o(terminal_address),
    .terminal_response_o(terminal_response),.terminal_cycles_o(terminal_cycles),
    .cpu_fault_o(cpu_fault),.recovering_o(recovering),.restart_count_o(restart_count),
    .recovery_error_o(recovery_error),.format_error_o(inner_format_error),
    .coverage_epoch_i(coverage_epoch_i),.{coverage_abi.port_name}(coverage_transport));
endmodule
"""
    return EmittedHarness(module_name, rtl, (), contract.layout.digest)


def build_large_soc_campaign_targets(
    qualification: object,
    output_dir: str | Path,
    *,
    verilator_bin: str = "verilator",
    jobs: int = 1,
) -> LargeSocCampaignTargets:
    """Compile one scheme-A target and one byte-identical shared B/C target."""
    from .large_soc_flat import emit_large_flat_soc

    cpu_id = str(qualification.cpu_id)
    root = Path(qualification.output_dir)
    flat = emit_large_flat_soc(cpu_id)
    flat_abi = _coverage_v2(qualification.flat_coverage["coverage_abi"])
    generated_abi = _coverage_v2(qualification.generated_coverage["coverage_abi"])
    if tuple(_included_ids(flat_abi)) != tuple(_included_ids(generated_abi)):
        raise InputValidationError("campaign targets require identical A and B/C point IDs")
    if flat_abi.catalog_digest != generated_abi.catalog_digest:
        raise InputValidationError("campaign targets require identical A and B/C catalog digests")
    flat_harness = emit_large_flat_campaign_harness(
        flat, qualification.input_contract, flat_abi,
    )
    generated_harness = emit_large_generated_campaign_harness(
        qualification.generated_top, qualification.input_contract, generated_abi,
        module_name=f"myfuzz_{cpu_id}_generated_campaign_harness",
    )
    constraints = build_superset_constraint_ir(qualification.input_contract)
    evidence_common = {
        "rfuzz_config": {
            "format": "RFUZZ RawBits v2",
            "layout": qualification.input_contract.layout.to_dict(),
            "scheme_input_use": [item.to_dict() for item in qualification.input_contract.scheme_use],
        },
        "address_graph": {"windows": []},
        "port_bindings": {"component_boundaries": [
            "cpu0", "ram0", "ram1", "dp_ram0", "regs0", "regs1", "lfsr0", "gpio0", "apb0",
        ]},
    }
    flat_target = build_verilator_target(
        Path(output_dir) / "flat", manifest=_manifest(qualification.flat_coverage["instrumented_manifest"]),
        source_root=root / "instrumented_flat", harness=flat_harness,
        layout=qualification.input_contract.layout, constraint_ir=constraints,
        coverage_abi=flat_abi,
        evidence={
            **evidence_common,
            "original_soc_rtl": root / "project/generated/flat_top.sv",
            "connection_graph": {"scheme": "A", "connections": []},
            "instrumentation_manifest": Path(str(qualification.flat_coverage["instrumentation_manifest"])),
            "generation_report": {"scheme": "A", "cpu_id": cpu_id, "common_points": flat_abi.width},
        }, verilator_bin=verilator_bin, jobs=jobs,
    )
    generated_target = build_verilator_target(
        Path(output_dir) / "generated",
        manifest=_manifest(qualification.generated_coverage["instrumented_manifest"]),
        source_root=root / "instrumented_generated", harness=generated_harness,
        layout=qualification.input_contract.layout, constraint_ir=constraints,
        coverage_abi=generated_abi,
        evidence={
            **evidence_common,
            "original_soc_rtl": root / "project/generated/large_soc.sv",
            "connection_graph": {"scheme": "B_C", "generated_soc": True},
            "instrumentation_manifest": Path(str(qualification.generated_coverage["instrumentation_manifest"])),
            "generation_report": {"scheme": "B_C", "cpu_id": cpu_id, "common_points": generated_abi.width},
        }, verilator_bin=verilator_bin, jobs=jobs,
    )
    return LargeSocCampaignTargets(cpu_id, flat_target, generated_target)


def _coverage_projection(coverage_abi: CoverageABIV2) -> str:
    lines = []
    for point in coverage_abi.points:
        if not point.get("included"):
            continue
        target = ("coverage_o" if coverage_abi.width == 1
                  else f"coverage_o[{point['offset']}]")
        source = ("coverage_transport" if coverage_abi.transport_width == 1
                  else f"coverage_transport[{point['source_offset']}]")
        lines.append(f"  assign {target}={source};")
    return "\n".join(lines)


def _validate(module_name: str, coverage_abi: CoverageABIV2) -> None:
    if not module_name.isidentifier():
        raise InputValidationError("campaign harness module name must be a Verilog identifier")
    if coverage_abi.width <= 0 or coverage_abi.transport_width < coverage_abi.width:
        raise InputValidationError("campaign harness requires a valid CoverageABI v2")


def _range(width: int) -> str:
    return "" if width == 1 else f"[{width - 1}:0] "


def _coverage_v2(value: Mapping[str, object]) -> CoverageABIV2:
    return CoverageABIV2(
        str(value["catalog_digest"]), str(value["port_name"]), int(value["width"]),
        int(value["epoch_width"]), tuple(value["points"]), int(value["transport_width"]),
        str(value["writer"]), str(value["sampling"]), str(value["schema"]),
    )


def _manifest(value: Mapping[str, object]) -> ElaborationManifest:
    return ElaborationManifest(
        str(value["schema"]), str(value["stage"]), str(value["top_module"]),
        str(value["language"]),
        tuple(ResolvedFile(str(item["path"]), str(item["sha256"]), int(item["size"]))
              for item in value["sources"]),
        tuple(str(item) for item in value["include_dirs"]),
        tuple(str(item) for item in value["defines"]),
        tuple((str(item[0]), str(item[1])) for item in value["parameters"]),
        tuple((str(item[0]), str(item[1])) for item in value["tools"]),
        None if value["parent_digest"] is None else str(value["parent_digest"]),
        str(value["digest"]),
    )


def _included_ids(abi: CoverageABIV2) -> tuple[str, ...]:
    return tuple(str(point["point_id"]) for point in abi.points if point.get("included"))
