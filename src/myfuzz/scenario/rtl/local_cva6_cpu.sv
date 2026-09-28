`default_nettype none

// CVA6 alone: its local AXI4 adapter/backend is real RTL; host serves beats.
module local_cva6_cpu (
  input logic clk, reset,
  input logic [1:0] irq,
  output logic req_valid,
  input logic req_ready,
  output logic req_write,
  output logic [63:0] req_addr, req_wdata,
  output logic [7:0] req_be,
  output logic rsp_ready,
  input logic rsp_valid,
  input logic [63:0] rsp_rdata,
  input logic rsp_error
);
  soc_cva6_beat_core u_cpu (
    .clk_i(clk), .reset_i(reset), .irq_i(irq),
    .unified_req_valid_o(req_valid), .unified_req_ready_i(req_ready),
    .unified_write_o(req_write), .unified_addr_o(req_addr),
    .unified_wdata_o(req_wdata), .unified_be_o(req_be),
    .unified_rsp_ready_o(rsp_ready), .unified_rsp_valid_i(rsp_valid),
    .unified_rdata_i(rsp_rdata), .unified_error_i(rsp_error), .flush_o()
  );
endmodule

`default_nettype wire
