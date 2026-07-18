"""RTL backend for addressable generated system-service storage."""

from __future__ import annotations

from .input_model import InputValidationError


def emit_system_service_target(
    *, module_name: str, size: int, read_only: bool = False,
) -> str:
    if not module_name.isidentifier():
        raise InputValidationError("system service module_name must be a Verilog identifier")
    if size < 4 or size % 4:
        raise InputValidationError("system service size must be a positive multiple of four bytes")
    words = size // 4
    return f"""module {module_name} #(
  parameter HEX_FILE=""
) (
  input logic clk, input logic resetn,
  input logic [31:0] s_awaddr, input logic s_awvalid, output logic s_awready,
  input logic [31:0] s_wdata, input logic [3:0] s_wstrb,
  input logic s_wvalid, output logic s_wready,
  output logic [1:0] s_bresp, output logic s_bvalid, input logic s_bready,
  input logic [31:0] s_araddr, input logic s_arvalid, output logic s_arready,
  output logic [31:0] s_rdata, output logic [1:0] s_rresp,
  output logic s_rvalid, input logic s_rready
);
  localparam integer WORDS={words};
  localparam logic READ_ONLY={1 if read_only else 0};
  logic [31:0] storage [0:WORDS-1];
  logic aw_hold, w_hold;
  logic [31:0] awaddr_hold, wdata_hold;
  logic [3:0] wstrb_hold;
  logic [31:0] selected_wdata;
  logic [3:0] selected_wstrb;
  integer i, write_index, read_index;

  initial begin
    for (i=0; i<WORDS; i=i+1) storage[i]='0;
    if (HEX_FILE != "") $readmemh(HEX_FILE, storage);
  end

  always_comb begin
    s_awready=!aw_hold && !s_bvalid && !s_rvalid;
    s_wready=!w_hold && !s_bvalid && !s_rvalid;
    s_arready=!aw_hold && !w_hold && !s_bvalid && !s_rvalid && !(s_awvalid || s_wvalid);
  end

  always_ff @(posedge clk or negedge resetn) begin
    if (!resetn) begin
      aw_hold<=0; w_hold<=0; s_bvalid<=0; s_bresp<=0;
      s_rvalid<=0; s_rdata<=0; s_rresp<=0;
    end else begin
      if (s_bvalid && s_bready) s_bvalid<=0;
      if (s_rvalid && s_rready) s_rvalid<=0;
      if (s_awready && s_awvalid) begin aw_hold<=1; awaddr_hold<=s_awaddr; end
      if (s_wready && s_wvalid) begin w_hold<=1; wdata_hold<=s_wdata; wstrb_hold<=s_wstrb; end
      if (!s_bvalid && (aw_hold || (s_awready && s_awvalid)) &&
          (w_hold || (s_wready && s_wvalid))) begin
        write_index=(aw_hold ? awaddr_hold : s_awaddr) >> 2;
        selected_wdata=w_hold ? wdata_hold : s_wdata;
        selected_wstrb=w_hold ? wstrb_hold : s_wstrb;
        s_bresp<=2'b00;
        if (READ_ONLY || write_index < 0 || write_index >= WORDS) s_bresp<=2'b10;
        else begin
          if (selected_wstrb[0]) storage[write_index][7:0] <= selected_wdata[7:0];
          if (selected_wstrb[1]) storage[write_index][15:8] <= selected_wdata[15:8];
          if (selected_wstrb[2]) storage[write_index][23:16] <= selected_wdata[23:16];
          if (selected_wstrb[3]) storage[write_index][31:24] <= selected_wdata[31:24];
        end
        aw_hold<=0; w_hold<=0; s_bvalid<=1;
      end
      if (s_arready && s_arvalid) begin
        read_index=s_araddr >> 2; s_rresp<=2'b00;
        if (read_index < 0 || read_index >= WORDS) begin s_rdata<=0; s_rresp<=2'b10; end
        else s_rdata<=storage[read_index];
        s_rvalid<=1;
      end
    end
  end
endmodule
"""
