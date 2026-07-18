"""Generated bounded reset-domain controller service."""

from __future__ import annotations

import re

from .input_model import InputValidationError


def emit_reset_controller(
    *, module_name: str = "myfuzz_reset_controller_v1", domain_count: int,
    protected_mask: int = 0, assert_cycles: int = 2,
) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module_name):
        raise InputValidationError("reset controller module_name must be a Verilog identifier")
    if domain_count <= 0 or domain_count > 32 or assert_cycles <= 0:
        raise InputValidationError("reset controller domain count/cycles are out of range")
    if protected_mask < 0 or protected_mask >= 1 << domain_count:
        raise InputValidationError("reset controller protected mask exceeds domain count")
    select_width = max(1, (domain_count - 1).bit_length())
    return f"""module {module_name} (
  input logic clk,input logic resetn,input logic request_start,
  input logic [{select_width-1}:0] request_domain,
  output logic [{domain_count-1}:0] reset_active,
  output logic request_busy,output logic request_done,output logic request_error,
  output logic [31:0] epoch,
  input logic [31:0] s_awaddr,input logic s_awvalid,output logic s_awready,
  input logic [31:0] s_wdata,input logic [3:0] s_wstrb,input logic s_wvalid,output logic s_wready,
  output logic [1:0] s_bresp,output logic s_bvalid,input logic s_bready,
  input logic [31:0] s_araddr,input logic s_arvalid,output logic s_arready,
  output logic [31:0] s_rdata,output logic [1:0] s_rresp,output logic s_rvalid,input logic s_rready
);
  localparam logic [{domain_count-1}:0] PROTECTED_MASK={domain_count}'h{protected_mask:x};
  integer remaining;
  assign s_awready=!s_bvalid&&!s_rvalid;
  assign s_wready=!s_bvalid&&!s_rvalid;
  assign s_arready=!s_bvalid&&!s_rvalid&&!(s_awvalid||s_wvalid);
  always_ff @(posedge clk or negedge resetn) begin
    if(!resetn)begin reset_active<=0;request_busy<=0;request_done<=0;request_error<=0;
      epoch<=0;remaining<=0;s_bvalid<=0;s_bresp<=0;s_rvalid<=0;s_rdata<=0;s_rresp<=0;end
    else begin
      request_done<=0;request_error<=0;
      if(request_busy)begin
        if(remaining<=1)begin reset_active<=0;request_busy<=0;request_done<=1;epoch<=epoch+1;remaining<=0;end
        else remaining<=remaining-1;
      end else if(request_start)begin
        if(request_domain>={domain_count}||PROTECTED_MASK[request_domain])begin
          request_done<=1;request_error<=1;
        end else begin
          reset_active<=({domain_count}'b1<<request_domain);request_busy<=1;remaining<={assert_cycles};
        end
      end
      if(s_bvalid&&s_bready)s_bvalid<=0;
      if(s_rvalid&&s_rready)s_rvalid<=0;
      if(!s_bvalid&&s_awvalid&&s_wvalid)begin s_bvalid<=1;s_bresp<=2'b10;end
      if(s_arready&&s_arvalid)begin
        s_rdata<=0;s_rresp<=0;
        case(s_araddr)
          32'h0:s_rdata<=request_busy;
          32'h4:s_rdata<=reset_active;
          32'h8:s_rdata<=epoch;
          default:begin s_rdata<=0;s_rresp<=2'b10;end
        endcase
        s_rvalid<=1;
      end
    end
  end
endmodule
"""
