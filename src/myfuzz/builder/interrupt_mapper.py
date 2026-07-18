"""Generated pending/claim/complete interrupt mapper service."""

from __future__ import annotations

import re

from .input_model import InputValidationError


def emit_interrupt_mapper(*, module_name: str = "myfuzz_interrupt_mapper_v1", width: int = 32) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module_name):
        raise InputValidationError("interrupt mapper module_name must be a Verilog identifier")
    if width <= 0 or width > 32:
        raise InputValidationError("interrupt mapper width must be between 1 and 32")
    return f"""module {module_name} (
  input logic clk,input logic resetn,input logic [{width-1}:0] irq_sources,
  output logic [{width-1}:0] cpu_irq,
  input logic [31:0] s_awaddr,input logic s_awvalid,output logic s_awready,
  input logic [31:0] s_wdata,input logic [3:0] s_wstrb,input logic s_wvalid,output logic s_wready,
  output logic [1:0] s_bresp,output logic s_bvalid,input logic s_bready,
  input logic [31:0] s_araddr,input logic s_arvalid,output logic s_arready,
  output logic [31:0] s_rdata,output logic [1:0] s_rresp,output logic s_rvalid,input logic s_rready
);
  logic [{width-1}:0] pending;
  logic aw_hold,w_hold;logic [31:0] awaddr_hold,wdata_hold;
  logic [3:0] wstrb_hold;logic [31:0] selected_awaddr,selected_wdata;
  integer i;logic found;logic [31:0] claim_value;
  assign cpu_irq=pending;
  always_comb begin
    s_awready=!aw_hold&&!s_bvalid&&!s_rvalid;
    s_wready=!w_hold&&!s_bvalid&&!s_rvalid;
    s_arready=!aw_hold&&!w_hold&&!s_bvalid&&!s_rvalid&&!(s_awvalid||s_wvalid);
    found=0;claim_value=0;
    for(i=0;i<{width};i=i+1) if(pending[i]&&!found) begin claim_value=i+1;found=1;end
  end
  always_ff @(posedge clk or negedge resetn) begin
    if(!resetn) begin pending<=0;aw_hold<=0;w_hold<=0;s_bvalid<=0;s_bresp<=0;
      s_rvalid<=0;s_rdata<=0;s_rresp<=0;awaddr_hold<=0;wdata_hold<=0;wstrb_hold<=0;end
    else begin
      pending<=pending|irq_sources;
      if(s_bvalid&&s_bready)s_bvalid<=0;
      if(s_rvalid&&s_rready)s_rvalid<=0;
      if(s_awready&&s_awvalid)begin aw_hold<=1;awaddr_hold<=s_awaddr;end
      if(s_wready&&s_wvalid)begin w_hold<=1;wdata_hold<=s_wdata;wstrb_hold<=s_wstrb;end
      if(!s_bvalid&&(aw_hold||(s_awready&&s_awvalid))&&(w_hold||(s_wready&&s_wvalid)))begin
        selected_awaddr=aw_hold?awaddr_hold:s_awaddr;
        selected_wdata=w_hold?wdata_hold:s_wdata;
        s_bresp<=0;
        if(selected_awaddr==32'h8&&(w_hold?wstrb_hold:s_wstrb)==4'hf)
          pending<=(pending&~selected_wdata[{width-1}:0])|irq_sources;
        else s_bresp<=2'b10;
        aw_hold<=0;w_hold<=0;s_bvalid<=1;
      end
      if(s_arready&&s_arvalid)begin
        s_rdata<=0;s_rresp<=0;
        case(s_araddr)
          32'h0:s_rdata<=pending;
          32'h4:s_rdata<=claim_value;
          default:begin s_rdata<=0;s_rresp<=2'b10;end
        endcase
        s_rvalid<=1;
      end
    end
  end
endmodule
"""
