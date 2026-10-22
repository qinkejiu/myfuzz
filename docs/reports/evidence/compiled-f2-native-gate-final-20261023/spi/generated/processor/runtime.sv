module local_runtime_processor (
  input logic [0:0] clk,
  input logic [0:0] reset,
  output logic [0:0] rt_lh_p_0_0_0,
  output logic [14:0] rt_lh_p_2_14_0,
  output logic [5:0] rt_lh_p_4_5_0,
  output logic [95:0] rt_lh_p_5_95_0,
  output logic [0:0] rt_lh_p_6_0_0,
  output logic [0:0] rt_lh_p_11_0_0,
  output logic [0:0] rt_lh_p_20_0_0,
  output logic [0:0] rt_lh_p_21_0_0,
  output logic [0:0] rt_lh_p_23_0_0,
  output logic [0:0] rt_lh_p_33_0_0,
  input logic [0:0] rt_lh_p_34_11_11,
  output logic [4:0] rt_lh_p_35_4_0,
  output logic [0:0] trace_obi_d_req,
  output logic [31:0] trace_obi_d_addr,
  output logic [0:0] trace_obi_d_gnt,
  output logic [0:0] trace_obi_d_rvalid,
  output logic [31:0] trace_obi_d_rdata,
  output logic [0:0] trace_obi_d_we,
  output logic [31:0] trace_obi_d_wdata,
  output logic [3:0] trace_obi_d_be,
  output logic [0:0] d_req_valid,
  input logic [0:0] d_req_ready,
  output logic [0:0] d_req_write,
  output logic [31:0] d_req_addr,
  output logic [31:0] d_req_wdata,
  output logic [3:0] d_req_be,
  input logic [0:0] d_rsp_valid,
  output logic [0:0] d_rsp_ready,
  input logic [31:0] d_rsp_rdata,
  input logic [0:0] d_rsp_error,
  output logic [0:0] trace_obi_i_req,
  output logic [31:0] trace_obi_i_addr,
  output logic [0:0] trace_obi_i_gnt,
  output logic [0:0] trace_obi_i_rvalid,
  output logic [31:0] trace_obi_i_rdata,
  output logic [0:0] i_req_valid,
  input logic [0:0] i_req_ready,
  output logic [0:0] i_req_write,
  output logic [31:0] i_req_addr,
  output logic [31:0] i_req_wdata,
  output logic [3:0] i_req_be,
  input logic [0:0] i_rsp_valid,
  output logic [0:0] i_rsp_ready,
  input logic [31:0] i_rsp_rdata,
  input logic [0:0] i_rsp_error
);
  logic [31:0] link_lh_p_12_31_0;
  logic [3:0] link_lh_p_13_3_0;
  logic [0:0] link_lh_p_14_0_0;
  logic [31:0] link_lh_p_15_31_0;
  logic [0:0] link_lh_p_16_0_0;
  logic [0:0] link_lh_p_17_0_0;
  logic [31:0] link_lh_p_18_31_0;
  logic [0:0] link_lh_p_19_0_0;
  logic [31:0] link_lh_p_28_31_0;
  logic [0:0] link_lh_p_29_0_0;
  logic [31:0] link_lh_p_30_31_0;
  logic [0:0] link_lh_p_31_0_0;
  logic [0:0] link_lh_p_32_0_0;
  logic unused_d_error;
  logic unused_i_error;
  assign trace_obi_d_req = link_lh_p_16_0_0;
  assign trace_obi_d_addr = link_lh_p_12_31_0;
  assign trace_obi_d_gnt = link_lh_p_14_0_0;
  assign trace_obi_d_rvalid = link_lh_p_17_0_0;
  assign trace_obi_d_rdata = link_lh_p_15_31_0;
  assign trace_obi_d_we = link_lh_p_19_0_0;
  assign trace_obi_d_wdata = link_lh_p_18_31_0;
  assign trace_obi_d_be = link_lh_p_13_3_0;
  assign trace_obi_i_req = link_lh_p_31_0_0;
  assign trace_obi_i_addr = link_lh_p_28_31_0;
  assign trace_obi_i_gnt = link_lh_p_29_0_0;
  assign trace_obi_i_rvalid = link_lh_p_32_0_0;
  assign trace_obi_i_rdata = link_lh_p_30_31_0;
  local_processor u_component (
    .clk(clk),
    .reset(reset),
    .lh_p_0_0_0(rt_lh_p_0_0_0),
    .lh_p_2_14_0(rt_lh_p_2_14_0),
    .lh_p_4_5_0(rt_lh_p_4_5_0),
    .lh_p_5_95_0(rt_lh_p_5_95_0),
    .lh_p_6_0_0(rt_lh_p_6_0_0),
    .lh_p_11_0_0(rt_lh_p_11_0_0),
    .lh_p_12_31_0(link_lh_p_12_31_0),
    .lh_p_13_3_0(link_lh_p_13_3_0),
    .lh_p_14_0_0(link_lh_p_14_0_0),
    .lh_p_15_31_0(link_lh_p_15_31_0),
    .lh_p_16_0_0(link_lh_p_16_0_0),
    .lh_p_17_0_0(link_lh_p_17_0_0),
    .lh_p_18_31_0(link_lh_p_18_31_0),
    .lh_p_19_0_0(link_lh_p_19_0_0),
    .lh_p_20_0_0(rt_lh_p_20_0_0),
    .lh_p_21_0_0(rt_lh_p_21_0_0),
    .lh_p_23_0_0(rt_lh_p_23_0_0),
    .lh_p_28_31_0(link_lh_p_28_31_0),
    .lh_p_29_0_0(link_lh_p_29_0_0),
    .lh_p_30_31_0(link_lh_p_30_31_0),
    .lh_p_31_0_0(link_lh_p_31_0_0),
    .lh_p_32_0_0(link_lh_p_32_0_0),
    .lh_p_33_0_0(rt_lh_p_33_0_0),
    .lh_p_34_11_11(rt_lh_p_34_11_11),
    .lh_p_35_4_0(rt_lh_p_35_4_0)
  );
  obi_processor_memory_adapter #(
    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .READ_ONLY(0),
    .HAS_BE(1), .HAS_ERROR(0)
  ) u_adapter_d (
    .clk_i(clk),
    .rst_ni(~reset),
    .req_i(link_lh_p_16_0_0),
    .gnt_o(link_lh_p_14_0_0),
    .addr_i(link_lh_p_12_31_0),
    .we_i(link_lh_p_19_0_0),
    .wdata_i(link_lh_p_18_31_0),
    .be_i(link_lh_p_13_3_0),
    .rvalid_o(link_lh_p_17_0_0),
    .rdata_o(link_lh_p_15_31_0),
    .error_o(unused_d_error),
    .req_valid_o(d_req_valid),
    .req_ready_i(d_req_ready),
    .req_write_o(d_req_write),
    .req_addr_o(d_req_addr),
    .req_wdata_o(d_req_wdata),
    .req_be_o(d_req_be),
    .rsp_valid_i(d_rsp_valid),
    .rsp_ready_o(d_rsp_ready),
    .rsp_rdata_i(d_rsp_rdata),
    .rsp_error_i(d_rsp_error)
  );
  obi_processor_memory_adapter #(
    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .READ_ONLY(1),
    .HAS_BE(0), .HAS_ERROR(0)
  ) u_adapter_i (
    .clk_i(clk),
    .rst_ni(~reset),
    .req_i(link_lh_p_31_0_0),
    .gnt_o(link_lh_p_29_0_0),
    .addr_i(link_lh_p_28_31_0),
    .we_i(1'b0),
    .wdata_i(32'b0),
    .be_i(4'b1111),
    .rvalid_o(link_lh_p_32_0_0),
    .rdata_o(link_lh_p_30_31_0),
    .error_o(unused_i_error),
    .req_valid_o(i_req_valid),
    .req_ready_i(i_req_ready),
    .req_write_o(i_req_write),
    .req_addr_o(i_req_addr),
    .req_wdata_o(i_req_wdata),
    .req_be_o(i_req_be),
    .rsp_valid_i(i_rsp_valid),
    .rsp_ready_o(i_rsp_ready),
    .rsp_rdata_i(i_rsp_rdata),
    .rsp_error_i(i_rsp_error)
  );
endmodule
