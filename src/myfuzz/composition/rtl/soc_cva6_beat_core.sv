`default_nettype none
// Source-backed CVA6 beat initiator core.
//
// Real CVA6 (pinned flattened closure, compiler-proven packed AXI4 boundary)
// with the generic AXI4 beat adapter.  The packed container slices below are
// the compiler-proven coordinates from the official interface description and
// are the only place this boundary is spelled out.  No behavioural CPU is
// present.
//
// MYFUZZ_CORE_DEPENDENCIES: src/myfuzz/protocols/rtl/processor_memory_backend.sv src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv
module soc_cva6_beat_core #(
  parameter longint BOOT_ADDR = 64'h0000_0000_8000_0000,
  parameter string TARGET_CFG = "cv64a6_imafdc_sv39",
  parameter integer CVA6CfgMmuOn = 1,
  parameter integer CVA6CfgCacheEn = 1,
  parameter integer CVA6CfgFpuEn = 1
) (
  input  logic         clk_i,
  input  logic         reset_i,
  input  logic [1:0]   irq_i,
  output logic         unified_req_valid_o,
  input  logic         unified_req_ready_i,
  output logic         unified_write_o,
  output logic [63:0]  unified_addr_o,
  output logic [63:0]  unified_wdata_o,
  output logic [7:0]   unified_be_o,
  output logic         unified_rsp_ready_o,
  input  logic         unified_rsp_valid_i,
  input  logic [63:0]  unified_rdata_i,
  input  logic         unified_error_i,
  output logic         flush_o
);
  wire reset_n = ~reset_i;
  logic [469:0] noc_req;
  logic [209:0] noc_resp;

  cva6 u_cva6 (
      .boot_addr_i(BOOT_ADDR),
      .clk_i(clk_i),
      .debug_req_i(1'b0),
      .hart_id_i(64'd0),
      .ipi_i(1'b0),
      .irq_i(irq_i),
      .noc_req_o(noc_req),
      .noc_resp_i(noc_resp),
      .rst_ni(reset_n),
      .time_irq_i(1'b0)
  );

  logic adapter_req_valid, adapter_req_ready, adapter_write;
  logic [63:0] adapter_addr, adapter_wdata;
  logic [7:0] adapter_be;
  logic adapter_rsp_valid, adapter_rsp_ready, adapter_error;
  logic [63:0] adapter_rdata;

  axi4_processor_memory_adapter #(
      .ADDRESS_WIDTH(64), .DATA_WIDTH(64), .ID_WIDTH(4), .USER_WIDTH(64)
  ) u_axi_adapter (
      .clk_i(clk_i), .rst_ni(reset_n),
      .araddr_i(noc_req[158:95]),
      .arburst_i(noc_req[83:82]), .arcache_i(noc_req[80:77]),
      .arid_i(noc_req[162:159]), .arlen_i(noc_req[94:87]),
      .arlock_i(noc_req[81]), .arprot_i(noc_req[76:74]),
      .arqos_i(noc_req[73:70]), .arready_o(noc_resp[208]),
      .arregion_i(noc_req[69:66]), .arsize_i(noc_req[86:84]),
      .aruser_i(noc_req[65:2]), .arvalid_i(noc_req[1]),
      .awaddr_i(noc_req[465:402]), .awatop_i(noc_req[372:367]),
      .awburst_i(noc_req[390:389]), .awcache_i(noc_req[387:384]),
      .awid_i(noc_req[469:466]), .awlen_i(noc_req[401:394]),
      .awlock_i(noc_req[388]), .awprot_i(noc_req[383:381]),
      .awqos_i(noc_req[380:377]), .awready_o(noc_resp[209]),
      .awregion_i(noc_req[376:373]), .awsize_i(noc_req[393:391]),
      .awuser_i(noc_req[366:303]), .awvalid_i(noc_req[302]),
      .bid_o(noc_resp[205:202]), .bready_i(noc_req[163]),
      .bresp_o(noc_resp[201:200]), .buser_o(noc_resp[199:136]),
      .bvalid_o(noc_resp[206]), .rdata_o(noc_resp[130:67]),
      .rid_o(noc_resp[134:131]), .rlast_o(noc_resp[64]),
      .rready_i(noc_req[0]), .rresp_o(noc_resp[66:65]),
      .ruser_o(noc_resp[63:0]), .rvalid_o(noc_resp[135]),
      .wdata_i(noc_req[301:238]), .wlast_i(noc_req[229]),
      .wready_o(noc_resp[207]), .wstrb_i(noc_req[237:230]),
      .wuser_i(noc_req[228:165]), .wvalid_i(noc_req[164]),
      .req_valid_o(adapter_req_valid), .req_ready_i(adapter_req_ready),
      .req_write_o(adapter_write), .req_addr_o(adapter_addr),
      .req_wdata_o(adapter_wdata), .req_be_o(adapter_be),
      .rsp_valid_i(adapter_rsp_valid), .rsp_ready_o(adapter_rsp_ready),
      .rsp_rdata_i(adapter_rdata), .rsp_error_i(adapter_error)
  );

  logic backend_req_valid, backend_req_ready, backend_write;
  logic [63:0] backend_addr, backend_wdata;
  logic [7:0] backend_be;
  logic backend_rsp_valid, backend_rsp_ready, backend_error;
  logic [63:0] backend_rdata;
  logic target_req_valid, target_req_ready, target_write;
  logic [63:0] target_addr, target_wdata;
  logic [7:0] target_be;
  logic target_rsp_valid, target_rsp_ready, target_error;
  logic [63:0] target_rdata;
  logic target_flush;

  assign backend_req_valid = adapter_req_valid;
  assign backend_write = adapter_write;
  assign backend_addr = adapter_addr;
  assign backend_wdata = adapter_wdata;
  assign backend_be = adapter_be;
  assign adapter_req_ready = backend_req_ready;
  assign adapter_rsp_valid = backend_rsp_valid;
  assign adapter_rdata = backend_rdata;
  assign adapter_error = backend_error;
  assign backend_rsp_ready = adapter_rsp_ready;

  myfuzz_processor_memory_backend #(
      .ADDRESS_WIDTH(64), .DATA_WIDTH(64), .MAX_WAIT_CYCLES(64)
  ) u_backend (
      .clk_i(clk_i), .rst_ni(reset_n), .req_valid_i(backend_req_valid),
      .req_ready_o(backend_req_ready), .req_write_i(backend_write),
      .req_addr_i(backend_addr), .req_wdata_i(backend_wdata),
      .req_be_i(backend_be), .req_mapped_i(1'b1),
      .rsp_valid_o(backend_rsp_valid), .rsp_ready_i(backend_rsp_ready),
      .rsp_rdata_o(backend_rdata), .rsp_error_o(backend_error),
      .cancel_valid_i(1'b0), .cancel_ready_o(), .target_flush_o(target_flush),
      .target_req_valid_o(target_req_valid),
      .target_req_ready_i(target_req_ready),
      .target_write_o(target_write), .target_addr_o(target_addr),
      .target_wdata_o(target_wdata), .target_be_o(target_be),
      .target_rsp_valid_i(target_rsp_valid),
      .target_rsp_ready_o(target_rsp_ready),
      .target_rdata_i(target_rdata), .target_error_i(target_error)
  );

  // Hold the fabric completion for one explicit response stage so the target
  // data is stable across the arbiter WAIT_RSP->RESPOND transition and a
  // same-edge NBA race cannot hand the CPU a stale word.
  logic rsp_hold_valid, rsp_hold_error;
  logic [63:0] rsp_hold_data;

  assign unified_req_valid_o = target_req_valid;
  assign unified_write_o = target_write;
  assign unified_addr_o = target_addr;
  assign unified_wdata_o = target_wdata;
  assign unified_be_o = target_be;
  assign target_req_ready = unified_req_ready_i;
  // The backend consumes the held response; the fabric may only present a new
  // response while no hold is pending.  The held payload must be forwarded with
  // the held valid: driving target_rsp_valid from rsp_hold_valid while leaving
  // target_rdata/target_error undriven hands the AXI adapter a response with no
  // data, and the core then never executes the instruction it fetched.
  assign target_rsp_valid = rsp_hold_valid;
  assign target_rdata = rsp_hold_data;
  assign target_error = rsp_hold_error;
  assign unified_rsp_ready_o = !rsp_hold_valid;
  assign flush_o = reset_i | target_flush;

  always_ff @(posedge clk_i or posedge reset_i) begin
    if (reset_i) begin
      rsp_hold_valid <= 1'b0;
      rsp_hold_data <= '0;
      rsp_hold_error <= 1'b0;
    end else if (rsp_hold_valid) begin
      if (target_rsp_ready)
        rsp_hold_valid <= 1'b0;
    end else if (unified_rsp_valid_i) begin
      rsp_hold_valid <= 1'b1;
      rsp_hold_data <= unified_rdata_i;
      rsp_hold_error <= unified_error_i;
    end
  end
endmodule
`default_nettype wire
