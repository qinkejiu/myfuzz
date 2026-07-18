"""Deterministic AXI-Lite v4 waveform front-end and independent monitor model."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import re
from typing import Mapping

from .builtin_profiles import builtin_profile_registry
from .input_model import InputValidationError
from .profiles import ChannelRule, PortRule, ProfileRegistry
from .rawbits_v4 import (
    RawBitsV4Lane, RawBitsV4Layout, RawBitsV4Submode, build_rawbits_v4_layout,
)


@dataclass(frozen=True)
class AxiLiteV4Capability:
    address_width: int
    data_width: int = 32
    awprot_present: bool = False
    arprot_present: bool = False
    max_write_outstanding: int = 1
    max_read_outstanding: int = 1
    schema: str = "myfuzz.axi-lite-capability/v4"

    def __post_init__(self) -> None:
        if (
            isinstance(self.address_width, bool)
            or not isinstance(self.address_width, int)
            or not 1 <= self.address_width <= 64
        ):
            raise InputValidationError("AXI-Lite address_width must be 1..64")
        if isinstance(self.data_width, bool) or not isinstance(self.data_width, int) or self.data_width != 32:
            raise InputValidationError("AXI-Lite v4 first-stage data_width must be 32")
        for name in ("awprot_present", "arprot_present"):
            if not isinstance(getattr(self, name), bool):
                raise InputValidationError(f"AXI-Lite {name} must be boolean")
        for name in ("max_write_outstanding", "max_read_outstanding"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise InputValidationError(f"AXI-Lite {name} must be positive")

    @property
    def strobe_width(self) -> int:
        return self.data_width // 8


def axi_lite_v4_profile_registry() -> ProfileRegistry:
    """Return the legacy registry plus a higher-priority, PROT-aware v4 profile."""
    registry = builtin_profile_registry()
    for role in ("initiator", "target"):
        base = registry.query("axi_lite", role)[0]
        direction = next(
            port.direction for port in base.ports if port.semantic == "axi_lite.awvalid"
        )
        ports = base.ports + (
            PortRule("axi_lite.awprot", direction, ("s_axi_awprot", "m_axi_awprot", "awprot"), False),
            PortRule("axi_lite.arprot", direction, ("s_axi_arprot", "m_axi_arprot", "arprot"), False),
        )
        channels = tuple(
            ChannelRule(
                channel.name,
                channel.signals + (("axi_lite.awprot",) if channel.name == "write_address" else ())
                + (("axi_lite.arprot",) if channel.name == "read_address" else ()),
            )
            for channel in base.channels
        )
        registry.register(replace(
            base,
            name=f"axi_lite_{role}_v4",
            priority=base.priority + 1,
            ports=ports,
            channels=channels,
            version="4.0",
            width_rules=base.width_rules + ("awprot_width == 3 when present", "arprot_width == 3 when present"),
        ))
    return registry


@dataclass(frozen=True)
class AxiLiteMasterSignals:
    awvalid: bool = False
    awaddr: int = 0
    awprot: int = 0
    wvalid: bool = False
    wdata: int = 0
    wstrb: int = 0
    bready: bool = False
    arvalid: bool = False
    araddr: int = 0
    arprot: int = 0
    rready: bool = False
    dut_reset: bool = False


@dataclass(frozen=True)
class AxiLiteSlaveFeedback:
    awready: bool = False
    wready: bool = False
    bvalid: bool = False
    bresp: int = 0
    arready: bool = False
    rvalid: bool = False
    rdata: int = 0
    rresp: int = 0
    resetn: bool = True


@dataclass(frozen=True)
class AxiLiteGuardedIntent:
    aw_start: bool = False
    awaddr: int = 0
    awprot: int = 0
    w_start: bool = False
    wdata: int = 0
    wstrb: int = 0
    bready: bool = False
    ar_start: bool = False
    araddr: int = 0
    arprot: int = 0
    rready: bool = False
    dut_reset: bool = False


@dataclass(frozen=True)
class AxiLiteViolation:
    cycle: int
    rule_id: str
    snapshot: Mapping[str, object]


@dataclass(frozen=True)
class EmittedAxiLiteV4Frontend:
    module_name: str
    rtl: str
    layout: RawBitsV4Layout
    capability: AxiLiteV4Capability


@dataclass(frozen=True)
class EmittedAxiLiteV4Monitor:
    module_name: str
    rtl: str
    capability: AxiLiteV4Capability
    rule_ids: Mapping[str, int]


AXI_LITE_V4_RULE_IDS = {
    "RESET_MASTER_VALID_LOW": 1,
    "AW_STABLE_UNTIL_READY": 2,
    "W_STABLE_UNTIL_READY": 3,
    "AR_STABLE_UNTIL_READY": 4,
    "B_STABLE_UNTIL_READY": 5,
    "R_STABLE_UNTIL_READY": 6,
    "B_WITHOUT_WRITE_REQUEST": 7,
    "R_WITHOUT_READ_REQUEST": 8,
    "WRITE_OUTSTANDING_CAPABILITY_EXCEEDED": 9,
    "READ_OUTSTANDING_CAPABILITY_EXCEEDED": 10,
}


def axi_lite_protocol_fields(capability: AxiLiteV4Capability) -> tuple[Mapping[str, object], ...]:
    """Return canonical protocol-lane fields without relying on a concrete IP name."""
    capability.__post_init__()
    literal = [RawBitsV4Submode.LITERAL_TRACE.name]
    guarded = [RawBitsV4Submode.GUARDED_INTENT.name]
    fields = [
        _field("literal_awvalid", 1, literal),
        _field("literal_awaddr", capability.address_width, literal),
        _field("literal_wvalid", 1, literal),
        _field("literal_wdata", capability.data_width, literal),
        _field("literal_wstrb", capability.strobe_width, literal),
        _field("literal_bready", 1, literal),
        _field("literal_arvalid", 1, literal),
        _field("literal_araddr", capability.address_width, literal),
        _field("literal_rready", 1, literal),
        _field("literal_dut_reset", 1, literal),
        _field("guarded_aw_start", 1, guarded),
        _field("guarded_awaddr", capability.address_width, guarded),
        _field("guarded_w_start", 1, guarded),
        _field("guarded_wdata", capability.data_width, guarded),
        _field("guarded_wstrb", capability.strobe_width, guarded),
        _field("guarded_bready", 1, guarded),
        _field("guarded_ar_start", 1, guarded),
        _field("guarded_araddr", capability.address_width, guarded),
        _field("guarded_rready", 1, guarded),
        _field("guarded_dut_reset", 1, guarded),
    ]
    if capability.awprot_present:
        fields.extend((_field("literal_awprot", 3, literal), _field("guarded_awprot", 3, guarded)))
    if capability.arprot_present:
        fields.extend((_field("literal_arprot", 3, literal), _field("guarded_arprot", 3, guarded)))
    return tuple(fields)


def build_axi_lite_protocol_layout(capability: AxiLiteV4Capability):
    return build_rawbits_v4_layout({
        RawBitsV4Lane.PROTOCOL_WAVEFORM: axi_lite_protocol_fields(capability),
    })


def build_axi_lite_v4_layout(capability: AxiLiteV4Capability) -> RawBitsV4Layout:
    """Build the shared first-stage B/C/D layout without filtering master bits."""
    capability.__post_init__()
    return build_rawbits_v4_layout({
        RawBitsV4Lane.RAW_ESCAPE: _direct_master_fields(capability, "raw", "RAW_LITERAL"),
        RawBitsV4Lane.PROTOCOL_WAVEFORM: axi_lite_protocol_fields(capability),
        RawBitsV4Lane.ADVERSARIAL_MUTATION: _direct_master_fields(capability, "mutation", "MUTATION"),
    })


def _direct_master_fields(
    capability: AxiLiteV4Capability, prefix: str, submode: str,
) -> tuple[Mapping[str, object], ...]:
    mode = [submode]
    fields = [
        _field(f"{prefix}_awvalid", 1, mode),
        _field(f"{prefix}_awaddr", capability.address_width, mode),
        _field(f"{prefix}_wvalid", 1, mode),
        _field(f"{prefix}_wdata", capability.data_width, mode),
        _field(f"{prefix}_wstrb", capability.strobe_width, mode),
        _field(f"{prefix}_bready", 1, mode),
        _field(f"{prefix}_arvalid", 1, mode),
        _field(f"{prefix}_araddr", capability.address_width, mode),
        _field(f"{prefix}_rready", 1, mode),
        _field(f"{prefix}_dut_reset", 1, mode),
    ]
    if capability.awprot_present:
        fields.append(_field(f"{prefix}_awprot", 3, mode))
    if capability.arprot_present:
        fields.append(_field(f"{prefix}_arprot", 3, mode))
    return tuple(fields)


def pack_axi_lite_protocol_record(
    layout: RawBitsV4Layout,
    submode: RawBitsV4Submode,
    values: Mapping[str, int | bool],
) -> int:
    fields = _submode_fields(layout, submode)
    expected = {field.name for field in fields}
    missing, unknown = expected - set(values), set(values) - expected
    if missing or unknown:
        detail = sorted(missing or unknown)
        kind = "missing" if missing else "unknown"
        raise InputValidationError(
            f"AXI-Lite {submode.name} record has {kind} field(s): {', '.join(detail)}"
        )
    record = 0
    for field in fields:
        raw = values[field.name]
        value = int(raw) if isinstance(raw, bool) else raw
        _bits(value, field.width, field.name)
        record |= value << field.offset
    return record


def unpack_axi_lite_protocol_record(
    layout: RawBitsV4Layout,
    submode: RawBitsV4Submode,
    record: int,
) -> dict[str, int]:
    lane = layout.lane_layout(RawBitsV4Lane.PROTOCOL_WAVEFORM)
    _bits(record, layout.record_width_bytes * 8, "protocol_record")
    if record & ~lane.used_mask_for(submode):
        raise InputValidationError("AXI-Lite record has nonzero bits outside its submode mask")
    return {
        field.name: (record >> field.offset) & ((1 << field.width) - 1)
        for field in _submode_fields(layout, submode)
    }


def emit_axi_lite_v4_frontend_rtl(
    capability: AxiLiteV4Capability,
    *,
    module_name: str = "myfuzz_axi_lite_v4_frontend",
    layout: RawBitsV4Layout | None = None,
) -> EmittedAxiLiteV4Frontend:
    capability.__post_init__()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module_name):
        raise InputValidationError("AXI-Lite v4 front-end module name is invalid")
    layout = layout or build_axi_lite_protocol_layout(capability)
    if layout.lane_layout(RawBitsV4Lane.PROTOCOL_WAVEFORM).width <= 0:
        raise InputValidationError("AXI-Lite v4 layout has no protocol lane")
    width = layout.record_width_bytes * 8
    fields = {
        field.name: field
        for field in layout.lane_layout(RawBitsV4Lane.PROTOCOL_WAVEFORM).fields
    }
    literal_mask = layout.lane_layout(RawBitsV4Lane.PROTOCOL_WAVEFORM).used_mask_for(
        RawBitsV4Submode.LITERAL_TRACE
    )
    guarded_mask = layout.lane_layout(RawBitsV4Lane.PROTOCOL_WAVEFORM).used_mask_for(
        RawBitsV4Submode.GUARDED_INTENT
    )

    def bit(name: str) -> str:
        field = fields[name]
        return f"record_i[{field.offset}]"

    def part(name: str) -> str:
        field = fields[name]
        return f"record_i[{field.offset} +: {field.width}]"

    ports = [
        "input logic clk_i", "input logic resetn_i", "input logic [7:0] submode_i",
        f"input logic [{width - 1}:0] record_i", "input logic record_valid_i",
        "output logic record_consumed_o", "output logic decoder_error_o",
        "output logic dut_reset_event_o", "output logic m_awvalid_o",
        "input logic m_awready_i", f"output logic [{capability.address_width - 1}:0] m_awaddr_o",
    ]
    if capability.awprot_present:
        ports.append("output logic [2:0] m_awprot_o")
    ports.extend((
        "output logic m_wvalid_o", "input logic m_wready_i",
        f"output logic [{capability.data_width - 1}:0] m_wdata_o",
        f"output logic [{capability.strobe_width - 1}:0] m_wstrb_o",
        "input logic m_bvalid_i", "output logic m_bready_o",
        "input logic [1:0] m_bresp_i", "output logic m_arvalid_o",
        "input logic m_arready_i", f"output logic [{capability.address_width - 1}:0] m_araddr_o",
    ))
    if capability.arprot_present:
        ports.append("output logic [2:0] m_arprot_o")
    ports.extend((
        "input logic m_rvalid_i", "output logic m_rready_o",
        f"input logic [{capability.data_width - 1}:0] m_rdata_i",
        "input logic [1:0] m_rresp_i", "output logic [31:0] ignored_intents_o",
    ))
    lines = [
        f"module {module_name} (",
        "  " + ",\n  ".join(ports),
        ");",
        f"  localparam logic [7:0] GUARDED_INTENT=8'd{RawBitsV4Submode.GUARDED_INTENT.value};",
        f"  localparam logic [7:0] LITERAL_TRACE=8'd{RawBitsV4Submode.LITERAL_TRACE.value};",
        f"  localparam logic [{width - 1}:0] LITERAL_MASK={width}'h{literal_mask:x};",
        f"  localparam logic [{width - 1}:0] GUARDED_MASK={width}'h{guarded_mask:x};",
        "  logic aw_pending,w_pending,ar_pending;",
        f"  logic [{capability.address_width - 1}:0] awaddr_pending,araddr_pending;",
        f"  logic [{capability.data_width - 1}:0] wdata_pending;",
        f"  logic [{capability.strobe_width - 1}:0] wstrb_pending;",
    ]
    if capability.awprot_present:
        lines.append("  logic [2:0] awprot_pending;")
    if capability.arprot_present:
        lines.append("  logic [2:0] arprot_pending;")
    lines.extend((
        "  always_comb begin",
        "    record_consumed_o=1'b0;decoder_error_o=1'b0;dut_reset_event_o=1'b0;",
        "    m_awvalid_o=1'b0;m_awaddr_o='0;m_wvalid_o=1'b0;m_wdata_o='0;m_wstrb_o='0;",
        "    m_bready_o=1'b0;m_arvalid_o=1'b0;m_araddr_o='0;m_rready_o=1'b0;",
    ))
    if capability.awprot_present:
        lines.append("    m_awprot_o='0;")
    if capability.arprot_present:
        lines.append("    m_arprot_o='0;")
    lines.extend((
        "    case (submode_i)",
        "      LITERAL_TRACE: begin",
        "        decoder_error_o=record_valid_i&&|(record_i&~LITERAL_MASK);",
        "        record_consumed_o=record_valid_i&&!decoder_error_o;",
        f"        dut_reset_event_o=record_valid_i&&{bit('literal_dut_reset')};",
        f"        m_awvalid_o=record_valid_i&&{bit('literal_awvalid')};",
        f"        m_awaddr_o={part('literal_awaddr')};",
        f"        m_wvalid_o=record_valid_i&&{bit('literal_wvalid')};",
        f"        m_wdata_o={part('literal_wdata')};m_wstrb_o={part('literal_wstrb')};",
        f"        m_bready_o=record_valid_i&&{bit('literal_bready')};",
        f"        m_arvalid_o=record_valid_i&&{bit('literal_arvalid')};",
        f"        m_araddr_o={part('literal_araddr')};",
        f"        m_rready_o=record_valid_i&&{bit('literal_rready')};",
    ))
    if capability.awprot_present:
        lines.append(f"        m_awprot_o={part('literal_awprot')};")
    if capability.arprot_present:
        lines.append(f"        m_arprot_o={part('literal_arprot')};")
    lines.extend((
        "      end",
        "      GUARDED_INTENT: begin",
        "        decoder_error_o=record_valid_i&&|(record_i&~GUARDED_MASK);",
        "        record_consumed_o=record_valid_i&&!decoder_error_o;",
        f"        dut_reset_event_o=record_valid_i&&{bit('guarded_dut_reset')};",
        "        if (!dut_reset_event_o) begin",
        "          m_awvalid_o=aw_pending;m_awaddr_o=awaddr_pending;",
        "          m_wvalid_o=w_pending;m_wdata_o=wdata_pending;m_wstrb_o=wstrb_pending;",
        f"          m_bready_o=record_valid_i&&{bit('guarded_bready')};",
        "          m_arvalid_o=ar_pending;m_araddr_o=araddr_pending;",
        f"          m_rready_o=record_valid_i&&{bit('guarded_rready')};",
    ))
    if capability.awprot_present:
        lines.append("          m_awprot_o=awprot_pending;")
    if capability.arprot_present:
        lines.append("          m_arprot_o=arprot_pending;")
    lines.extend((
        "        end",
        "      end",
        "      default: decoder_error_o=record_valid_i;",
        "    endcase",
        "  end",
        "  always_ff @(posedge clk_i or negedge resetn_i) begin",
        "    if (!resetn_i) begin",
        "      aw_pending<=0;w_pending<=0;ar_pending<=0;awaddr_pending<='0;",
        "      wdata_pending<='0;wstrb_pending<='0;araddr_pending<='0;ignored_intents_o<=0;",
    ))
    if capability.awprot_present:
        lines.append("      awprot_pending<='0;")
    if capability.arprot_present:
        lines.append("      arprot_pending<='0;")
    lines.extend((
        "    end else if (submode_i!=GUARDED_INTENT || dut_reset_event_o) begin",
        "      aw_pending<=0;w_pending<=0;ar_pending<=0;",
        "    end else begin",
        "      if (aw_pending&&m_awready_i) aw_pending<=0;",
        "      if (w_pending&&m_wready_i) w_pending<=0;",
        "      if (ar_pending&&m_arready_i) ar_pending<=0;",
        "      if (record_consumed_o) ignored_intents_o<=ignored_intents_o+",
        f"        ({bit('guarded_aw_start')}&&aw_pending&&!m_awready_i)+",
        f"        ({bit('guarded_w_start')}&&w_pending&&!m_wready_i)+",
        f"        ({bit('guarded_ar_start')}&&ar_pending&&!m_arready_i);",
        f"      if (record_consumed_o&&{bit('guarded_aw_start')}) begin",
        "        if (!aw_pending||m_awready_i) begin aw_pending<=1;",
        f"          awaddr_pending<={part('guarded_awaddr')};",
    ))
    if capability.awprot_present:
        lines.append(f"          awprot_pending<={part('guarded_awprot')};")
    lines.extend((
        "        end",
        "      end",
        f"      if (record_consumed_o&&{bit('guarded_w_start')}) begin",
        "        if (!w_pending||m_wready_i) begin w_pending<=1;",
        f"          wdata_pending<={part('guarded_wdata')};wstrb_pending<={part('guarded_wstrb')};",
        "        end",
        "      end",
        f"      if (record_consumed_o&&{bit('guarded_ar_start')}) begin",
        "        if (!ar_pending||m_arready_i) begin ar_pending<=1;",
        f"          araddr_pending<={part('guarded_araddr')};",
    ))
    if capability.arprot_present:
        lines.append(f"          arprot_pending<={part('guarded_arprot')};")
    lines.extend((
        "        end",
        "      end",
        "    end",
        "  end",
        "endmodule",
    ))
    return EmittedAxiLiteV4Frontend(module_name, "\n".join(lines) + "\n", layout, capability)


def emit_axi_lite_v4_monitor_rtl(
    capability: AxiLiteV4Capability,
    *,
    module_name: str = "myfuzz_axi_lite_v4_monitor",
) -> EmittedAxiLiteV4Monitor:
    capability.__post_init__()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module_name):
        raise InputValidationError("AXI-Lite v4 monitor module name is invalid")
    ports = [
        "input logic clk_i", "input logic monitor_resetn_i", "input logic bus_resetn_i",
        "input logic m_awvalid_i", "input logic m_awready_i",
        f"input logic [{capability.address_width - 1}:0] m_awaddr_i",
    ]
    if capability.awprot_present:
        ports.append("input logic [2:0] m_awprot_i")
    ports.extend((
        "input logic m_wvalid_i", "input logic m_wready_i",
        f"input logic [{capability.data_width - 1}:0] m_wdata_i",
        f"input logic [{capability.strobe_width - 1}:0] m_wstrb_i",
        "input logic m_bvalid_i", "input logic m_bready_i", "input logic [1:0] m_bresp_i",
        "input logic m_arvalid_i", "input logic m_arready_i",
        f"input logic [{capability.address_width - 1}:0] m_araddr_i",
    ))
    if capability.arprot_present:
        ports.append("input logic [2:0] m_arprot_i")
    ports.extend((
        "input logic m_rvalid_i", "input logic m_rready_i",
        f"input logic [{capability.data_width - 1}:0] m_rdata_i",
        "input logic [1:0] m_rresp_i", "output logic violation_valid_o",
        "output logic [7:0] violation_rule_o", "output logic [63:0] violation_cycle_o",
        "output logic [255:0] violation_snapshot_o",
    ))
    awprot = "m_awprot_i" if capability.awprot_present else "3'b0"
    arprot = "m_arprot_i" if capability.arprot_present else "3'b0"
    rules = AXI_LITE_V4_RULE_IDS
    lines = [
        f"module {module_name} (",
        "  " + ",\n  ".join(ports),
        ");",
        "  logic [63:0] cycle_count;logic previous_valid;",
        "  logic previous_awvalid,previous_awready,previous_wvalid,previous_wready;",
        "  logic previous_arvalid,previous_arready,previous_bvalid,previous_bready;",
        "  logic previous_rvalid,previous_rready;",
        f"  logic [{capability.address_width - 1}:0] previous_awaddr,previous_araddr;",
        "  logic [2:0] previous_awprot,previous_arprot;",
        f"  logic [{capability.data_width - 1}:0] previous_wdata,previous_rdata;",
        f"  logic [{capability.strobe_width - 1}:0] previous_wstrb;",
        "  logic [1:0] previous_bresp,previous_rresp;",
        "  logic [32:0] aw_count,w_count,b_count,ar_count,r_count;",
        "  logic [32:0] aw_next,w_next,b_next,ar_next,r_next;",
        "  logic [32:0] write_pairs_before,write_pairs_after;",
        "  logic violation_now;logic [7:0] rule_now;",
        "  wire aw_fire=m_awvalid_i&&m_awready_i;wire w_fire=m_wvalid_i&&m_wready_i;",
        "  wire b_fire=m_bvalid_i&&m_bready_i;wire ar_fire=m_arvalid_i&&m_arready_i;",
        "  wire r_fire=m_rvalid_i&&m_rready_i;",
        "  always_comb begin",
        "    aw_next=aw_count+aw_fire;w_next=w_count+w_fire;b_next=b_count+b_fire;",
        "    ar_next=ar_count+ar_fire;r_next=r_count+r_fire;",
        "    write_pairs_before=(aw_count<w_count)?aw_count:w_count;",
        "    write_pairs_after=(aw_next<w_next)?aw_next:w_next;",
        "    violation_now=0;rule_now=0;",
        f"    if (!bus_resetn_i&&(m_awvalid_i||m_wvalid_i||m_arvalid_i)) begin violation_now=1;rule_now=8'd{rules['RESET_MASTER_VALID_LOW']};end",
        f"    else if (bus_resetn_i&&previous_valid&&previous_awvalid&&!previous_awready&&(!m_awvalid_i||m_awaddr_i!=previous_awaddr||{awprot}!=previous_awprot)) begin violation_now=1;rule_now=8'd{rules['AW_STABLE_UNTIL_READY']};end",
        f"    else if (bus_resetn_i&&previous_valid&&previous_wvalid&&!previous_wready&&(!m_wvalid_i||m_wdata_i!=previous_wdata||m_wstrb_i!=previous_wstrb)) begin violation_now=1;rule_now=8'd{rules['W_STABLE_UNTIL_READY']};end",
        f"    else if (bus_resetn_i&&previous_valid&&previous_arvalid&&!previous_arready&&(!m_arvalid_i||m_araddr_i!=previous_araddr||{arprot}!=previous_arprot)) begin violation_now=1;rule_now=8'd{rules['AR_STABLE_UNTIL_READY']};end",
        f"    else if (bus_resetn_i&&previous_valid&&previous_bvalid&&!previous_bready&&(!m_bvalid_i||m_bresp_i!=previous_bresp)) begin violation_now=1;rule_now=8'd{rules['B_STABLE_UNTIL_READY']};end",
        f"    else if (bus_resetn_i&&previous_valid&&previous_rvalid&&!previous_rready&&(!m_rvalid_i||m_rdata_i!=previous_rdata||m_rresp_i!=previous_rresp)) begin violation_now=1;rule_now=8'd{rules['R_STABLE_UNTIL_READY']};end",
        f"    else if (bus_resetn_i&&b_fire&&(write_pairs_before<=b_count)) begin violation_now=1;rule_now=8'd{rules['B_WITHOUT_WRITE_REQUEST']};end",
        f"    else if (bus_resetn_i&&r_fire&&(ar_count<=r_count)) begin violation_now=1;rule_now=8'd{rules['R_WITHOUT_READ_REQUEST']};end",
        f"    else if (bus_resetn_i&&write_pairs_after>=b_next&&(write_pairs_after-b_next)>{capability.max_write_outstanding}) begin violation_now=1;rule_now=8'd{rules['WRITE_OUTSTANDING_CAPABILITY_EXCEEDED']};end",
        f"    else if (bus_resetn_i&&ar_next>=r_next&&(ar_next-r_next)>{capability.max_read_outstanding}) begin violation_now=1;rule_now=8'd{rules['READ_OUTSTANDING_CAPABILITY_EXCEEDED']};end",
        "  end",
        "  always_ff @(posedge clk_i or negedge monitor_resetn_i) begin",
        "    if (!monitor_resetn_i) begin",
        "      cycle_count<=0;previous_valid<=0;aw_count<=0;w_count<=0;b_count<=0;ar_count<=0;r_count<=0;",
        "      violation_valid_o<=0;violation_rule_o<=0;violation_cycle_o<=0;violation_snapshot_o<=0;",
        "    end else begin",
        "      if (!violation_valid_o&&violation_now) begin",
        "        violation_valid_o<=1;violation_rule_o<=rule_now;violation_cycle_o<=cycle_count;",
        f"        violation_snapshot_o<={{bus_resetn_i,m_awvalid_i,m_awready_i,m_awaddr_i,{awprot},m_wvalid_i,m_wready_i,m_wdata_i,m_wstrb_i,m_bvalid_i,m_bready_i,m_bresp_i,m_arvalid_i,m_arready_i,m_araddr_i,{arprot},m_rvalid_i,m_rready_i,m_rdata_i,m_rresp_i}};",
        "      end",
        "      cycle_count<=cycle_count+1;",
        "      if (!bus_resetn_i) begin",
        "        previous_valid<=0;aw_count<=0;w_count<=0;b_count<=0;ar_count<=0;r_count<=0;",
        "      end else begin",
        "        previous_valid<=1;aw_count<=aw_next;w_count<=w_next;b_count<=b_next;ar_count<=ar_next;r_count<=r_next;",
        "        previous_awvalid<=m_awvalid_i;previous_awready<=m_awready_i;previous_awaddr<=m_awaddr_i;",
        f"        previous_awprot<={awprot};previous_wvalid<=m_wvalid_i;previous_wready<=m_wready_i;",
        "        previous_wdata<=m_wdata_i;previous_wstrb<=m_wstrb_i;",
        "        previous_bvalid<=m_bvalid_i;previous_bready<=m_bready_i;previous_bresp<=m_bresp_i;",
        "        previous_arvalid<=m_arvalid_i;previous_arready<=m_arready_i;previous_araddr<=m_araddr_i;",
        f"        previous_arprot<={arprot};previous_rvalid<=m_rvalid_i;previous_rready<=m_rready_i;",
        "        previous_rdata<=m_rdata_i;previous_rresp<=m_rresp_i;",
        "      end",
        "    end",
        "  end",
        "endmodule",
    ]
    return EmittedAxiLiteV4Monitor(module_name, "\n".join(lines) + "\n", capability, rules)


class AxiLiteV4Frontend:
    """Cycle-exact reference model for literal and one-entry-per-channel guarded drive."""

    def __init__(self, capability: AxiLiteV4Capability) -> None:
        capability.__post_init__()
        self.capability = capability
        self.reset()

    def reset(self) -> None:
        self._aw: tuple[int, int] | None = None
        self._w: tuple[int, int] | None = None
        self._ar: tuple[int, int] | None = None
        self.ignored_intents = 0

    def step_literal(self, trace: AxiLiteMasterSignals) -> AxiLiteMasterSignals:
        _validate_master(trace, self.capability)
        return trace

    def step_guarded(
        self,
        intent: AxiLiteGuardedIntent,
        feedback: AxiLiteSlaveFeedback,
    ) -> AxiLiteMasterSignals:
        _validate_intent(intent, self.capability)
        _validate_feedback(feedback, self.capability)
        resetting = intent.dut_reset or not feedback.resetn
        if resetting:
            output = AxiLiteMasterSignals(dut_reset=intent.dut_reset)
            self._aw = self._w = self._ar = None
            return output

        output = AxiLiteMasterSignals(
            awvalid=self._aw is not None,
            awaddr=0 if self._aw is None else self._aw[0],
            awprot=0 if self._aw is None else self._aw[1],
            wvalid=self._w is not None,
            wdata=0 if self._w is None else self._w[0],
            wstrb=0 if self._w is None else self._w[1],
            bready=intent.bready,
            arvalid=self._ar is not None,
            araddr=0 if self._ar is None else self._ar[0],
            arprot=0 if self._ar is None else self._ar[1],
            rready=intent.rready,
        )
        if output.awvalid and feedback.awready:
            self._aw = None
        if output.wvalid and feedback.wready:
            self._w = None
        if output.arvalid and feedback.arready:
            self._ar = None
        self._aw = self._accept(self._aw, intent.aw_start, (intent.awaddr, intent.awprot))
        self._w = self._accept(self._w, intent.w_start, (intent.wdata, intent.wstrb))
        self._ar = self._accept(self._ar, intent.ar_start, (intent.araddr, intent.arprot))
        return output

    def _accept(self, pending, start: bool, payload):
        if not start:
            return pending
        if pending is not None:
            self.ignored_intents += 1
            return pending
        return payload


class AxiLiteV4Monitor:
    """Observe both sides without repairing wires; retain the first protocol violation."""

    def __init__(self, capability: AxiLiteV4Capability) -> None:
        capability.__post_init__()
        self.capability = capability
        self.reset()

    def reset(self) -> None:
        self.cycle = 0
        self.first_violation: AxiLiteViolation | None = None
        self._previous: tuple[AxiLiteMasterSignals, AxiLiteSlaveFeedback] | None = None
        self._aw_accepted = self._w_accepted = self._b_accepted = 0
        self._ar_accepted = self._r_accepted = 0

    @property
    def protocol_valid(self) -> bool:
        return self.first_violation is None

    def observe(self, master: AxiLiteMasterSignals, feedback: AxiLiteSlaveFeedback) -> None:
        _validate_master(master, self.capability)
        _validate_feedback(feedback, self.capability)
        snapshot = {"master": asdict(master), "feedback": asdict(feedback)}
        if not feedback.resetn:
            if master.awvalid or master.wvalid or master.arvalid:
                self._violate("RESET_MASTER_VALID_LOW", snapshot)
            self._previous = None
            self._aw_accepted = self._w_accepted = self._b_accepted = 0
            self._ar_accepted = self._r_accepted = 0
            self.cycle += 1
            return

        if self._previous is not None:
            previous_master, previous_feedback = self._previous
            self._stable(
                previous_master.awvalid and not previous_feedback.awready,
                master.awvalid and (master.awaddr, master.awprot) ==
                (previous_master.awaddr, previous_master.awprot),
                "AW_STABLE_UNTIL_READY", snapshot,
            )
            self._stable(
                previous_master.wvalid and not previous_feedback.wready,
                master.wvalid and (master.wdata, master.wstrb) ==
                (previous_master.wdata, previous_master.wstrb),
                "W_STABLE_UNTIL_READY", snapshot,
            )
            self._stable(
                previous_master.arvalid and not previous_feedback.arready,
                master.arvalid and (master.araddr, master.arprot) ==
                (previous_master.araddr, previous_master.arprot),
                "AR_STABLE_UNTIL_READY", snapshot,
            )
            self._stable(
                previous_feedback.bvalid and not previous_master.bready,
                feedback.bvalid and feedback.bresp == previous_feedback.bresp,
                "B_STABLE_UNTIL_READY", snapshot,
            )
            self._stable(
                previous_feedback.rvalid and not previous_master.rready,
                feedback.rvalid and (feedback.rdata, feedback.rresp) ==
                (previous_feedback.rdata, previous_feedback.rresp),
                "R_STABLE_UNTIL_READY", snapshot,
            )

        write_outstanding_before = min(self._aw_accepted, self._w_accepted) - self._b_accepted
        read_outstanding_before = self._ar_accepted - self._r_accepted
        if feedback.bvalid and master.bready and write_outstanding_before <= 0:
            self._violate("B_WITHOUT_WRITE_REQUEST", snapshot)
        if feedback.rvalid and master.rready and read_outstanding_before <= 0:
            self._violate("R_WITHOUT_READ_REQUEST", snapshot)

        self._aw_accepted += int(master.awvalid and feedback.awready)
        self._w_accepted += int(master.wvalid and feedback.wready)
        self._ar_accepted += int(master.arvalid and feedback.arready)
        self._b_accepted += int(feedback.bvalid and master.bready)
        self._r_accepted += int(feedback.rvalid and master.rready)
        if min(self._aw_accepted, self._w_accepted) - self._b_accepted > self.capability.max_write_outstanding:
            self._violate("WRITE_OUTSTANDING_CAPABILITY_EXCEEDED", snapshot)
        if self._ar_accepted - self._r_accepted > self.capability.max_read_outstanding:
            self._violate("READ_OUTSTANDING_CAPABILITY_EXCEEDED", snapshot)
        self._previous = (master, feedback)
        self.cycle += 1

    def _stable(self, active: bool, condition: bool, rule: str, snapshot) -> None:
        if active and not condition:
            self._violate(rule, snapshot)

    def _violate(self, rule: str, snapshot: Mapping[str, object]) -> None:
        if self.first_violation is None:
            self.first_violation = AxiLiteViolation(self.cycle, rule, snapshot)


def _field(name: str, width: int, submodes: list[str]) -> Mapping[str, object]:
    return {
        "name": name,
        "width": width,
        "source": "v4_controller",
        "consumer": "axi_lite_verification_frontend",
        "used": True,
        "submodes": submodes,
        "default_interpretation": "literal_unsigned_lsb0",
        "provenance": {"source": "axi_lite_protocol_profile", "version": "v4"},
    }


def _submode_fields(
    layout: RawBitsV4Layout,
    submode: RawBitsV4Submode,
):
    if submode not in {RawBitsV4Submode.GUARDED_INTENT, RawBitsV4Submode.LITERAL_TRACE}:
        raise InputValidationError(f"unsupported AXI-Lite protocol submode {submode}")
    lane = layout.lane_layout(RawBitsV4Lane.PROTOCOL_WAVEFORM)
    return tuple(
        field for field in lane.fields
        if field.used and submode.name in field.submodes
    )


def _validate_master(value: AxiLiteMasterSignals, capability: AxiLiteV4Capability) -> None:
    if not isinstance(value, AxiLiteMasterSignals):
        raise InputValidationError("AXI-Lite master signals have the wrong type")
    _bits(value.awaddr, capability.address_width, "awaddr")
    _bits(value.awprot, 3, "awprot")
    _bits(value.wdata, capability.data_width, "wdata")
    _bits(value.wstrb, capability.strobe_width, "wstrb")
    _bits(value.araddr, capability.address_width, "araddr")
    _bits(value.arprot, 3, "arprot")
    for name in (
        "awvalid", "wvalid", "bready", "arvalid", "rready", "dut_reset",
    ):
        if not isinstance(getattr(value, name), bool):
            raise InputValidationError(f"AXI-Lite {name} must be boolean")
    if not capability.awprot_present and value.awprot:
        raise InputValidationError("AXI-Lite awprot is nonzero but capability marks it absent")
    if not capability.arprot_present and value.arprot:
        raise InputValidationError("AXI-Lite arprot is nonzero but capability marks it absent")


def _validate_intent(value: AxiLiteGuardedIntent, capability: AxiLiteV4Capability) -> None:
    if not isinstance(value, AxiLiteGuardedIntent):
        raise InputValidationError("AXI-Lite guarded intent has the wrong type")
    _validate_master(AxiLiteMasterSignals(
        awaddr=value.awaddr, awprot=value.awprot, wdata=value.wdata,
        wstrb=value.wstrb, araddr=value.araddr, arprot=value.arprot,
    ), capability)
    for name in (
        "aw_start", "w_start", "bready", "ar_start", "rready", "dut_reset",
    ):
        if not isinstance(getattr(value, name), bool):
            raise InputValidationError(f"AXI-Lite {name} must be boolean")


def _validate_feedback(value: AxiLiteSlaveFeedback, capability: AxiLiteV4Capability) -> None:
    if not isinstance(value, AxiLiteSlaveFeedback):
        raise InputValidationError("AXI-Lite slave feedback has the wrong type")
    _bits(value.bresp, 2, "bresp")
    _bits(value.rdata, capability.data_width, "rdata")
    _bits(value.rresp, 2, "rresp")
    for name in (
        "awready", "wready", "bvalid", "arready", "rvalid", "resetn",
    ):
        if not isinstance(getattr(value, name), bool):
            raise InputValidationError(f"AXI-Lite {name} must be boolean")


def _bits(value: object, width: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << width:
        raise InputValidationError(f"AXI-Lite {name} must be an unsigned {width}-bit integer")
