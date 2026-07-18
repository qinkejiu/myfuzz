"""Protocol-only RawBits v4 harness for a generated SoCIR v4 top."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re

from .axi_lite_v4 import (
    AxiLiteV4Capability, build_axi_lite_v4_layout, emit_axi_lite_v4_frontend_rtl,
    emit_axi_lite_v4_monitor_rtl,
)
from .generated_soc_v2 import SocExternalPort
from .generated_soc_v4 import EmittedSocIRV4
from .contracts import CoverageABIV2, content_digest
from .input_model import InputValidationError
from .rawbits_v4 import RawBitsV4Lane, RawBitsV4Layout, RawBitsV4Submode


@dataclass(frozen=True)
class EmittedHarnessV4:
    module_name: str
    rtl: str
    layout: RawBitsV4Layout
    soc_digest: str
    protocol_profile_digest: str
    coverage_abi_digest: str | None = None
    environment_ports: tuple[SocExternalPort, ...] = ()
    schema: str = "myfuzz.generated-harness/v4"
    boot_rom_parameter: bool = False
    legality_rules: tuple[tuple[str, int], ...] = ()


def emit_protocol_harness_v4(
    soc: EmittedSocIRV4,
    *,
    module_name: str = "myfuzz_generated_harness_v4",
    layout: RawBitsV4Layout | None = None,
    coverage_abi: CoverageABIV2 | None = None,
    embed_soc_rtl: bool = True,
) -> EmittedHarnessV4:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module_name):
        raise InputValidationError("v4 harness module_name must be a Verilog identifier")
    capability = soc.fabric_capability
    protocol_profile_digest = content_digest({
        "schema": "myfuzz.protocol-profile-instance/v4",
        "protocol": "axi_lite",
        "capability": asdict(capability),
    })
    layout = layout or build_axi_lite_v4_layout(AxiLiteV4Capability(
        capability.address_width, capability.data_width,
        capability.awprot_present, capability.arprot_present,
        max_write_outstanding=capability.write_reorder_depth,
        max_read_outstanding=capability.read_reorder_depth,
    ))
    cpu_semantic_enabled = any(
        lane.lane == RawBitsV4Lane.CPU_SEMANTIC.name for lane in layout.lanes
    )
    boot_rom_parameter = bool(
        cpu_semantic_enabled
        and re.search(
            rf"module\s+{re.escape(soc.module_name)}\s*#\s*\([^)]*BOOT_ROM_HEX_FILE",
            soc.rtl,
        )
    )
    width = layout.record_width_bytes * 8
    frontend = emit_axi_lite_v4_frontend_rtl(
        AxiLiteV4Capability(
            capability.address_width, capability.data_width,
            capability.awprot_present, capability.arprot_present,
            max_write_outstanding=capability.write_reorder_depth,
            max_read_outstanding=capability.read_reorder_depth,
        ),
        module_name=f"{module_name}_frontend", layout=layout,
    )
    monitor = emit_axi_lite_v4_monitor_rtl(
        frontend.capability, module_name=f"{module_name}_monitor",
    )
    trace = {item.name: item for item in soc.external_port_specs if item.kind == "verification_master"}
    required = {f"trace_{name}" for name in (
        "awvalid", "awready", "awaddr", "wvalid", "wready", "wdata", "wstrb",
        "bvalid", "bready", "bresp", "arvalid", "arready", "araddr", "rvalid",
        "rready", "rdata", "rresp",
    )}
    if capability.awprot_present:
        required.add("trace_awprot")
    if capability.arprot_present:
        required.add("trace_arprot")
    if not required <= set(trace):
        raise InputValidationError("generated v4 SoC lacks a complete verification master boundary")
    coverage_names = set()
    if coverage_abi is not None:
        _validate_coverage_abi(coverage_abi, soc, embed_soc_rtl=embed_soc_rtl)
        coverage_names = {coverage_abi.port_name, "coverage_epoch_i"}
    environment = tuple(
        item for item in soc.external_port_specs
        if item.kind != "verification_master" and item.name not in coverage_names
    )
    if any(item.name in {
        "clk", "resetn", "infrastructure_reset", "select_trace", "cpu_execute", "cpu_ready",
    } for item in environment):
        raise InputValidationError("generated v4 SoC external port collides with harness control")
    port_lines = [
        "input logic clk_i", "input logic harness_resetn_i", "input logic start_i", "input logic end_i",
        "input logic [2:0] lane_i", "input logic [7:0] submode_i",
        f"input logic [{width - 1}:0] record_i", "input logic record_valid_i",
        "input logic [255:0] layout_digest_i", "input logic [255:0] soc_digest_i",
        "output logic record_ready_o", "output logic record_consumed_o", "output logic done_o",
        "output logic format_error_o", "output logic runtime_error_o", "output logic [2:0] lane_latched_o",
        "output logic observed_protocol_valid_o", "output logic [7:0] violation_rule_o",
        "output logic [63:0] violation_cycle_o", "output logic [255:0] violation_snapshot_o",
        "output logic [255:0] wire_snapshot_o",
    ]
    if coverage_abi is not None:
        port_lines.extend((
            f"input logic [{coverage_abi.epoch_width-1}:0] coverage_epoch_i",
            "input logic [255:0] coverage_abi_digest_i",
            f"output logic [{coverage_abi.width-1}:0] coverage_o",
            f"output logic [{coverage_abi.width-1}:0] coverage_live_o",
            "output logic coverage_valid_o",
        ))
    if cpu_semantic_enabled:
        port_lines.extend(("input logic cpu_execute_i", "output logic cpu_ready_o"))
    port_lines.extend(_decl(item) for item in environment)
    lines = [
        (f'module {module_name} #(parameter BOOT_ROM_HEX_FILE="") ('
         if boot_rom_parameter else f"module {module_name} ("),
        "  " + ",\n  ".join(port_lines), ");",
        f"  localparam logic [255:0] EXPECTED_LAYOUT_DIGEST=256'h{layout.digest};",
        f"  localparam logic [255:0] EXPECTED_SOC_DIGEST=256'h{soc.soc_digest};",
        "  localparam logic [2:0] ST_IDLE=0,ST_RESET=1,ST_RUN=2,ST_DONE=3;",
        "  wire start_format_invalid = " + (
            "(lane_i==3'd0)||(lane_i>3'd4)||(lane_i==3'd1&&submode_i!=8'd1)||(lane_i==3'd2&&(submode_i!=8'd2&&submode_i!=8'd3))||(lane_i==3'd3&&submode_i!=8'd4)||(lane_i==3'd4&&(submode_i!=8'd5&&submode_i!=8'd6));"
            if cpu_semantic_enabled else
            "(lane_i==3'd0)||(lane_i>3'd3)||(lane_i==3'd1&&submode_i!=8'd1)||(lane_i==3'd2&&(submode_i!=8'd2&&submode_i!=8'd3))||(lane_i==3'd3&&submode_i!=8'd4);"
        ),
        "  logic [2:0] state; logic [2:0] lane_latched; logic [7:0] submode_latched;",
        "  logic format_error_latched,runtime_error_latched; logic infrastructure_reset,select_trace,soc_resetn,cpu_execute,soc_cpu_ready;",
        "  logic dut_reset_event,frontend_consumed,frontend_error,monitor_violation; logic [31:0] ignored_intents;",
        f"  logic [{capability.address_width-1}:0] trace_awaddr,trace_araddr; logic [31:0] trace_wdata,trace_rdata; logic [3:0] trace_wstrb;",
        "  logic trace_awvalid,trace_awready,trace_wvalid,trace_wready,trace_bvalid,trace_bready,trace_arvalid,trace_arready,trace_rvalid,trace_rready;",
        "  logic [1:0] trace_bresp,trace_rresp;",
        "  logic [255:0] master_snapshot;",
    ]
    if coverage_abi is not None:
        lines.extend((
            f"  localparam logic [255:0] EXPECTED_COVERAGE_ABI_DIGEST=256'h{coverage_abi.manifest_digest};",
            f"  wire [{coverage_abi.transport_width-1}:0] coverage_transport;",
            f"  wire [{coverage_abi.width-1}:0] coverage_live;",
            f"  logic [{coverage_abi.width-1}:0] coverage_frozen;",
            "  assign coverage_o=coverage_frozen;assign coverage_live_o=coverage_live;",
            "  assign coverage_valid_o=(state==ST_DONE)&&!format_error_latched&&!runtime_error_latched;",
        ))
        for point in coverage_abi.points:
            if point.get("included"):
                lines.append(
                    f"  assign coverage_live[{int(point['offset'])}]=coverage_transport[{int(point['source_offset'])}];"
                )
    if capability.awprot_present:
        lines.append("  logic [2:0] trace_awprot;")
    if capability.arprot_present:
        lines.append("  logic [2:0] trace_arprot;")
    snapshot_awprot = "trace_awprot" if capability.awprot_present else "3'd0"
    snapshot_arprot = "trace_arprot" if capability.arprot_present else "3'd0"
    lines.extend([
        "  assign wire_snapshot_o=master_snapshot;",
        "  assign infrastructure_reset=(state==ST_RESET); assign select_trace="
        + ("(lane_latched!=3'd4);" if cpu_semantic_enabled else "(lane_latched!=3'd0);"),
        "  assign cpu_execute=" + (
            "(lane_latched==3'd4)?cpu_execute_i:1'b1;"
            if cpu_semantic_enabled else "1'b1;"
        ),
        "  assign soc_resetn=harness_resetn_i&&(state!=ST_RESET)&&!dut_reset_event;",
        "  assign record_ready_o=(state==ST_RUN)&&!format_error_latched;",
        "  assign lane_latched_o=lane_latched; assign format_error_o=format_error_latched; assign runtime_error_o=runtime_error_latched;",
        "  assign observed_protocol_valid_o=!monitor_violation;",
        "  always_comb begin",
        "    trace_awvalid='0;trace_awaddr='0;trace_wvalid='0;trace_wdata='0;trace_wstrb='0;trace_bready='0;trace_arvalid='0;trace_araddr='0;trace_rready='0;dut_reset_event=1'b0;frontend_error=1'b0;frontend_consumed=1'b0;",
    ])
    if cpu_semantic_enabled:
        lines.append("  assign cpu_ready_o=soc_cpu_ready;")
    if capability.awprot_present:
        lines.append("    trace_awprot='0;")
    if capability.arprot_present:
        lines.append("    trace_arprot='0;")
    lines.extend([
        "    if (lane_latched==3'd2) begin",
        "      trace_awvalid=frontend_awvalid;trace_awaddr=frontend_awaddr;trace_wvalid=frontend_wvalid;trace_wdata=frontend_wdata;trace_wstrb=frontend_wstrb;trace_bready=frontend_bready;trace_arvalid=frontend_arvalid;trace_araddr=frontend_araddr;trace_rready=frontend_rready;dut_reset_event=frontend_reset;frontend_error=frontend_decoder_error;frontend_consumed=frontend_consumed_i;",
        "    end else if (lane_latched==3'd1 || lane_latched==3'd3) begin",
        "      trace_awvalid=record_valid_i&&direct_awvalid;trace_awaddr=direct_awaddr;trace_wvalid=record_valid_i&&direct_wvalid;trace_wdata=direct_wdata;trace_wstrb=direct_wstrb;trace_bready=record_valid_i&&direct_bready;trace_arvalid=record_valid_i&&direct_arvalid;trace_araddr=direct_araddr;trace_rready=record_valid_i&&direct_rready;dut_reset_event=record_valid_i&&direct_reset;",
        "    end",
    ])
    if capability.awprot_present:
        lines.append("      trace_awprot=(lane_latched==3'd2)?frontend_awprot:direct_awprot;")
    if capability.arprot_present:
        lines.append("      trace_arprot=(lane_latched==3'd2)?frontend_arprot:direct_arprot;")
    lines.extend([
        "  end",
    ])
    lines.extend(_direct_decode(layout, width))
    lines.extend(_frontend_instance(frontend.module_name, width, capability))
    lines.extend(_monitor_instance(monitor.module_name, capability))
    lines.append(
        f"  {soc.module_name}"
        + (" #(.BOOT_ROM_HEX_FILE(BOOT_ROM_HEX_FILE))" if boot_rom_parameter else "")
        + " i_soc("
    )
    soc_connections = [".clk(clk_i),.resetn(soc_resetn),.infrastructure_reset(infrastructure_reset),.select_trace(select_trace),.cpu_execute(cpu_execute),.cpu_ready(soc_cpu_ready),.master_locked(),.trace_selected()"]
    for name in sorted(trace):
        if name in {
            "master_locked", "trace_selected", "infrastructure_reset", "select_trace",
            "cpu_execute", "cpu_ready", "master_snapshot",
        }:
            continue
        soc_connections.append(f".{name}({name})")
    soc_connections.append(".master_snapshot(master_snapshot)")
    soc_connections.extend(f".{item.name}({item.name})" for item in environment)
    if coverage_abi is not None:
        soc_connections.extend((
            f".{coverage_abi.port_name}(coverage_transport)",
            ".coverage_epoch_i(coverage_epoch_i)",
        ))
    lines.append("    " + ",\n    ".join(soc_connections))
    lines.extend([
        "  );",
        "  always_ff @(posedge clk_i or negedge harness_resetn_i) begin",
        "    if(!harness_resetn_i) begin state<=ST_IDLE;lane_latched<=0;submode_latched<=0;format_error_latched<=0;runtime_error_latched<=0;"
        + ("coverage_frozen<='0;" if coverage_abi is not None else "") + "end",
        "    else begin",
        "      if(state==ST_IDLE&&start_i) begin lane_latched<=lane_i;submode_latched<=submode_i;format_error_latched<=|(layout_digest_i^EXPECTED_LAYOUT_DIGEST)||(soc_digest_i^EXPECTED_SOC_DIGEST)||(start_format_invalid)"
        + ("||(coverage_abi_digest_i!=EXPECTED_COVERAGE_ABI_DIGEST)" if coverage_abi is not None else "") + ";"
        + ("coverage_frozen<='0;" if coverage_abi is not None else "") + "state<=ST_RESET;end",
        "      else if(state==ST_RESET) state<=ST_RUN;",
        "      else if(state==ST_RUN&&frontend_error) format_error_latched<=1'b1;",
        "      else if(state==ST_RUN&&end_i) begin " + ("coverage_frozen<=coverage_live;" if coverage_abi is not None else "") + "state<=ST_DONE;end",
        "    end",
        "  end",
        "  assign record_consumed_o=(lane_latched==3'd2)?frontend_consumed_i:(((lane_latched==3'd1||lane_latched==3'd3)"
        + ("||lane_latched==3'd4" if cpu_semantic_enabled else "")
        + ")&&record_ready_o&&record_valid_i&&!frontend_error);",
        "  assign done_o=(state==ST_DONE);",
        "endmodule",
    ])
    rtl = "\n".join(lines) + "\n" + frontend.rtl + monitor.rtl
    if embed_soc_rtl:
        rtl += soc.rtl
    return EmittedHarnessV4(
        module_name, rtl, layout, soc.soc_digest, protocol_profile_digest,
        None if coverage_abi is None else coverage_abi.manifest_digest,
        environment, boot_rom_parameter=boot_rom_parameter,
        legality_rules=tuple(sorted(monitor.rule_ids.items())),
    )


def _decl(item: SocExternalPort) -> str:
    width = "" if item.width == 1 else f"[{item.width-1}:0] "
    return f"{item.direction} logic {width}{item.name}"


def _validate_coverage_abi(
    coverage_abi: CoverageABIV2, soc: EmittedSocIRV4, *, embed_soc_rtl: bool,
) -> None:
    if coverage_abi.epoch_width < 64:
        raise InputValidationError("v4 coverage epoch width must be at least 64 bits")
    included = tuple(point for point in coverage_abi.points if point.get("included"))
    if tuple(int(point["offset"]) for point in included) != tuple(range(coverage_abi.width)):
        raise InputValidationError("v4 coverage ABI primary offsets must be dense")
    ports = {item.name: item for item in soc.external_port_specs}
    transport = ports.get(coverage_abi.port_name)
    epoch = ports.get("coverage_epoch_i")
    boundary_matches = (
        transport is not None and transport.direction == "output"
        and transport.width == coverage_abi.transport_width
        and epoch is not None and epoch.direction == "input"
        and epoch.width == coverage_abi.epoch_width
    )
    if embed_soc_rtl and not boundary_matches:
        raise InputValidationError("generated v4 SoC does not expose the declared coverage ABI")


def _direct_decode(layout: RawBitsV4Layout, width: int) -> list[str]:
    fields = {field.name: field for lane in (RawBitsV4Lane.RAW_ESCAPE, RawBitsV4Lane.ADVERSARIAL_MUTATION) for field in layout.lane_layout(lane).fields}
    addr_width = fields["raw_awaddr"].width
    data_width = fields["raw_wdata"].width
    def expr(prefix: str, name: str) -> str:
        field = fields[f"{prefix}_{name}"]
        return f"record_i[{field.offset}]" if field.width == 1 else f"record_i[{field.offset} +: {field.width}]"
    lines = [
        "  logic direct_awvalid,direct_wvalid,direct_bready,direct_arvalid,direct_rready,direct_reset;",
        f"  logic [{addr_width-1}:0] direct_awaddr,direct_araddr; logic [{data_width-1}:0] direct_wdata; logic [3:0] direct_wstrb;",
        "  logic [2:0] direct_awprot,direct_arprot;",
        "  always_comb begin direct_awvalid=0;direct_awaddr=0;direct_awprot=0;direct_wvalid=0;direct_wdata=0;direct_wstrb=0;direct_bready=0;direct_arvalid=0;direct_araddr=0;direct_arprot=0;direct_rready=0;direct_reset=0;",
        "    if(lane_latched==3'd1) begin",
    ]
    for target, source in (("awvalid", "awvalid"), ("awaddr", "awaddr"), ("wvalid", "wvalid"), ("wdata", "wdata"), ("wstrb", "wstrb"), ("bready", "bready"), ("arvalid", "arvalid"), ("araddr", "araddr"), ("rready", "rready"), ("reset", "dut_reset")):
        lines.append(f"      direct_{target}={expr('raw', source)};")
    if "raw_awprot" in fields:
        lines.append(f"      direct_awprot={expr('raw', 'awprot')};")
    if "raw_arprot" in fields:
        lines.append(f"      direct_arprot={expr('raw', 'arprot')};")
    lines.append("    end else if(lane_latched==3'd3) begin")
    for target, source in (("awvalid", "awvalid"), ("awaddr", "awaddr"), ("wvalid", "wvalid"), ("wdata", "wdata"), ("wstrb", "wstrb"), ("bready", "bready"), ("arvalid", "arvalid"), ("araddr", "araddr"), ("rready", "rready"), ("reset", "dut_reset")):
        lines.append(f"      direct_{target}={expr('mutation', source)};")
    if "mutation_awprot" in fields:
        lines.append(f"      direct_awprot={expr('mutation', 'awprot')};")
    if "mutation_arprot" in fields:
        lines.append(f"      direct_arprot={expr('mutation', 'arprot')};")
    lines.append("    end end")
    return lines


def _frontend_instance(name: str, width: int, capability: AxiLiteV4Capability) -> list[str]:
    ports = [
        ".clk_i(clk_i),.resetn_i(soc_resetn),.submode_i(submode_latched),.record_i(record_i),.record_valid_i(record_valid_i&&record_ready_o)",
        ".record_consumed_o(frontend_consumed_i),.decoder_error_o(frontend_decoder_error),.dut_reset_event_o(frontend_reset)",
        ".m_awvalid_o(frontend_awvalid),.m_awready_i(trace_awready),.m_awaddr_o(frontend_awaddr)",
        ".m_wvalid_o(frontend_wvalid),.m_wready_i(trace_wready),.m_wdata_o(frontend_wdata),.m_wstrb_o(frontend_wstrb)",
        ".m_bvalid_i(trace_bvalid),.m_bready_o(frontend_bready),.m_bresp_i(trace_bresp)",
        ".m_arvalid_o(frontend_arvalid),.m_arready_i(trace_arready),.m_araddr_o(frontend_araddr)",
        ".m_rvalid_i(trace_rvalid),.m_rready_o(frontend_rready),.m_rdata_i(trace_rdata),.m_rresp_i(trace_rresp),.ignored_intents_o(ignored_intents)",
    ]
    if capability.awprot_present:
        ports.append(".m_awprot_o(frontend_awprot)")
    if capability.arprot_present:
        ports.append(".m_arprot_o(frontend_arprot)")
    declarations = [
        "  logic frontend_consumed_i,frontend_decoder_error,frontend_reset,frontend_awvalid,frontend_wvalid,frontend_bready,frontend_arvalid,frontend_rready;",
        "  logic [1:0] frontend_bresp,frontend_rresp;",
        f"  logic [{capability.address_width-1}:0] frontend_awaddr,frontend_araddr; logic [31:0] frontend_wdata,frontend_rdata; logic [3:0] frontend_wstrb;",
    ]
    if capability.awprot_present:
        declarations.append("  logic [2:0] frontend_awprot;")
    if capability.arprot_present:
        declarations.append("  logic [2:0] frontend_arprot;")
    return declarations + [f"  {name} i_frontend(", "    " + ",\n    ".join(ports), "  );"]


def _monitor_instance(name: str, capability: AxiLiteV4Capability) -> list[str]:
    ports = [
        ".clk_i(clk_i),.monitor_resetn_i(harness_resetn_i&&(state!=ST_IDLE)&&(state!=ST_RESET)),.bus_resetn_i(soc_resetn)",
        ".m_awvalid_i(trace_awvalid),.m_awready_i(trace_awready),.m_awaddr_i(trace_awaddr)",
        ".m_wvalid_i(trace_wvalid),.m_wready_i(trace_wready),.m_wdata_i(trace_wdata),.m_wstrb_i(trace_wstrb)",
        ".m_bvalid_i(trace_bvalid),.m_bready_i(trace_bready),.m_bresp_i(trace_bresp)",
        ".m_arvalid_i(trace_arvalid),.m_arready_i(trace_arready),.m_araddr_i(trace_araddr)",
        ".m_rvalid_i(trace_rvalid),.m_rready_i(trace_rready),.m_rdata_i(trace_rdata),.m_rresp_i(trace_rresp)",
        ".violation_valid_o(monitor_violation),.violation_rule_o(violation_rule_o),.violation_cycle_o(violation_cycle_o),.violation_snapshot_o(violation_snapshot_o)",
    ]
    if capability.awprot_present:
        ports.append(".m_awprot_i(trace_awprot)")
    if capability.arprot_present:
        ports.append(".m_arprot_i(trace_arprot)")
    return [f"  {name} i_monitor(", "    " + ",\n    ".join(ports), "  );"]
