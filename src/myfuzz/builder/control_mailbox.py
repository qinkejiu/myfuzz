"""Bit-level RawBits v3 to CPU-visible control mailbox backend."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib

from .contracts import ControlPlaneIRV1, canonical_json
from .input_model import InputValidationError
from .rawbits_v3 import RawBitsV3Layout


@dataclass(frozen=True)
class ControlMailboxField:
    name: str
    raw_offset: int
    width: int
    register_offset: int


@dataclass(frozen=True)
class ControlMailboxABI:
    control_plane_digest: str
    rawbits_layout_digest: str
    raw_width: int
    fields: tuple[ControlMailboxField, ...]
    digest: str
    schema: str = "myfuzz.control-mailbox-abi/v1"


def build_control_mailbox_abi(
    control: ControlPlaneIRV1, layout: RawBitsV3Layout,
) -> ControlMailboxABI:
    if layout.digest == "" or control.digest == "":
        raise InputValidationError("control mailbox requires sealed control/layout contracts")
    control_fields = {str(item["name"]): int(item["width"]) for item in control.fields}
    layout_fields = {item.name: item for item in layout.fields}
    if set(control_fields) != set(layout_fields):
        raise InputValidationError("control plane and RawBits layout field sets differ")
    fields = []
    for index, name in enumerate(sorted(control_fields)):
        field = layout_fields[name]
        if field.width != control_fields[name]:
            raise InputValidationError(f"control field {name} width differs from RawBits layout")
        if field.width > 32:
            raise InputValidationError(f"control field {name} exceeds one mailbox word")
        fields.append(ControlMailboxField(name, field.offset, field.width, 0x10 + index * 4))
    payload = {
        "schema": "myfuzz.control-mailbox-abi/v1",
        "control_plane_digest": control.digest,
        "rawbits_layout_digest": layout.digest,
        "raw_width": layout.cycle_width,
        "fields": [asdict(item) for item in fields],
    }
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    return ControlMailboxABI(control.digest, layout.digest, layout.cycle_width, tuple(fields), digest)


def emit_control_mailbox(abi: ControlMailboxABI, *, module_name: str = "myfuzz_control_mailbox_v1") -> str:
    if not module_name.isidentifier():
        raise InputValidationError("control mailbox module_name must be a Verilog identifier")
    if abi.raw_width <= 0:
        raise InputValidationError("control mailbox raw width must be positive")
    capture = []
    reads = ["        32'h0: s_rdata<=active;", "        32'h4: s_rdata<=status_reg;",
             "        32'h8: s_rdata<=result_reg;", "        32'hc: s_rdata<=sequence_reg;"]
    for index, field in enumerate(abi.fields):
        capture.append(f"        fields[{index}]<='0; fields[{index}][{field.width-1}:0]<=raw_bits_i[{field.raw_offset} +: {field.width}];")
        reads.append(f"        32'h{field.register_offset:x}: s_rdata<=fields[{index}];")
    return f"""module {module_name} (
  input logic clk, input logic resetn,
  input logic [{abi.raw_width-1}:0] raw_bits_i, input logic start_i,
  output logic accepted_o, output logic done_o, output logic active_o,
  output logic [31:0] status_o, output logic [31:0] result_o,
  input logic [31:0] s_awaddr, input logic s_awvalid, output logic s_awready,
  input logic [31:0] s_wdata, input logic [3:0] s_wstrb, input logic s_wvalid, output logic s_wready,
  output logic [1:0] s_bresp, output logic s_bvalid, input logic s_bready,
  input logic [31:0] s_araddr, input logic s_arvalid, output logic s_arready,
  output logic [31:0] s_rdata, output logic [1:0] s_rresp, output logic s_rvalid, input logic s_rready
);
  logic active, aw_hold, w_hold;
  logic [31:0] status_reg, result_reg, sequence_reg, awaddr_hold, wdata_hold;
  logic [3:0] wstrb_hold;
  logic [31:0] fields [0:{len(abi.fields)-1}];
  logic [31:0] selected_awaddr, selected_wdata;
  integer i;
  assign active_o=active; assign status_o=status_reg; assign result_o=result_reg;
  always_comb begin
    s_awready=!aw_hold && !s_bvalid && !s_rvalid;
    s_wready=!w_hold && !s_bvalid && !s_rvalid;
    s_arready=!aw_hold && !w_hold && !s_bvalid && !s_rvalid && !(s_awvalid || s_wvalid);
  end
  always_ff @(posedge clk or negedge resetn) begin
    if (!resetn) begin
      active<=0; accepted_o<=0; done_o<=0; status_reg<=0; result_reg<=0; sequence_reg<=0;
      aw_hold<=0; w_hold<=0; s_bvalid<=0; s_bresp<=0; s_rvalid<=0; s_rdata<=0; s_rresp<=0;
      for (i=0;i<{len(abi.fields)};i=i+1) fields[i]<=0;
    end else begin
      accepted_o<=0; done_o<=0;
      if (start_i && !active) begin
        active<=1; accepted_o<=1; status_reg<=0; result_reg<=0; sequence_reg<=sequence_reg+1;
{chr(10).join(capture)}
      end
      if (s_bvalid && s_bready) s_bvalid<=0;
      if (s_rvalid && s_rready) s_rvalid<=0;
      if (s_awready && s_awvalid) begin aw_hold<=1; awaddr_hold<=s_awaddr; end
      if (s_wready && s_wvalid) begin w_hold<=1; wdata_hold<=s_wdata; wstrb_hold<=s_wstrb; end
      if (!s_bvalid && (aw_hold || (s_awready && s_awvalid)) &&
          (w_hold || (s_wready && s_wvalid))) begin
        selected_awaddr=aw_hold ? awaddr_hold : s_awaddr;
        selected_wdata=w_hold ? wdata_hold : s_wdata;
        s_bresp<=2'b00;
        if (selected_awaddr == 32'h4 && (w_hold ? wstrb_hold : s_wstrb) == 4'hf) begin
          status_reg<=selected_wdata; active<=0; done_o<=1;
        end else if (selected_awaddr == 32'h8 && (w_hold ? wstrb_hold : s_wstrb) == 4'hf)
          result_reg<=selected_wdata;
        else s_bresp<=2'b10;
        aw_hold<=0; w_hold<=0; s_bvalid<=1;
      end
      if (s_arready && s_arvalid) begin
        s_rdata<=0; s_rresp<=2'b00;
        case (s_araddr)
{chr(10).join(reads)}
          default: begin s_rdata<=0; s_rresp<=2'b10; end
        endcase
        s_rvalid<=1;
      end
    end
  end
endmodule
"""
