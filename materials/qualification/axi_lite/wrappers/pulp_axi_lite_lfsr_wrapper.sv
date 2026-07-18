// SPDX-License-Identifier: SHL-0.51
`include "axi/typedef.svh"

module pulp_axi_lite_lfsr_wrapper (
  input  logic        clk,
  input  logic        resetn,
  input  logic        s_awvalid,
  output logic        s_awready,
  input  logic [31:0] s_awaddr,
  input  logic        s_wvalid,
  output logic        s_wready,
  input  logic [31:0] s_wdata,
  input  logic [3:0]  s_wstrb,
  output logic        s_bvalid,
  input  logic        s_bready,
  output logic [1:0]  s_bresp,
  input  logic        s_arvalid,
  output logic        s_arready,
  input  logic [31:0] s_araddr,
  output logic        s_rvalid,
  input  logic        s_rready,
  output logic [31:0] s_rdata,
  output logic [1:0]  s_rresp
);
  typedef logic [31:0] addr_t;
  typedef logic [31:0] data_t;
  typedef logic [3:0] strb_t;
  `AXI_LITE_TYPEDEF_ALL(q_axil, addr_t, data_t, strb_t)

  q_axil_req_t req;
  q_axil_resp_t rsp;

  assign req.aw = '{addr: s_awaddr, prot: 3'b000};
  assign req.aw_valid = s_awvalid;
  assign req.w = '{data: s_wdata, strb: s_wstrb};
  assign req.w_valid = s_wvalid;
  assign req.b_ready = s_bready;
  assign req.ar = '{addr: s_araddr, prot: 3'b000};
  assign req.ar_valid = s_arvalid;
  assign req.r_ready = s_rready;
  assign s_awready = rsp.aw_ready;
  assign s_wready = rsp.w_ready;
  assign s_bvalid = rsp.b_valid;
  assign s_bresp = rsp.b.resp;
  assign s_arready = rsp.ar_ready;
  assign s_rvalid = rsp.r_valid;
  assign s_rdata = rsp.r.data;
  assign s_rresp = rsp.r.resp;

  axi_lite_lfsr #(
    .DataWidth(32),
    .axi_lite_req_t(q_axil_req_t),
    .axi_lite_rsp_t(q_axil_resp_t)
  ) i_lfsr (
    .clk_i(clk),
    .rst_ni(resetn),
    .testmode_i(1'b0),
    .req_i(req),
    .rsp_o(rsp),
    .w_ser_data_i(1'b0),
    .w_ser_data_o(),
    .w_ser_en_i(1'b0),
    .r_ser_data_i(1'b0),
    .r_ser_data_o(),
    .r_ser_en_i(1'b0)
  );
endmodule
