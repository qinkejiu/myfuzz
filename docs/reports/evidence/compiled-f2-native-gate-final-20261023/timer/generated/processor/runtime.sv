module local_runtime_processor (
  input logic [0:0] clk,
  input logic [0:0] reset,
  output logic [0:0] rt_lh_p_0_0_0,
  output logic [0:0] rt_lh_p_1_0_0,
  output logic [0:0] rt_lh_p_2_0_0,
  output logic [0:0] rt_lh_p_6_0_0,
  output logic [159:0] rt_lh_p_7_159_0,
  output logic [31:0] rt_lh_p_9_31_0,
  output logic [3:0] rt_lh_p_11_3_0,
  output logic [0:0] rt_lh_p_17_0_0,
  output logic [0:0] rt_lh_p_20_0_0,
  output logic [6:0] rt_lh_p_21_6_0,
  output logic [6:0] rt_lh_p_22_6_0,
  output logic [31:0] rt_lh_p_24_31_0,
  output logic [0:0] rt_lh_p_26_0_0,
  output logic [0:0] rt_lh_p_28_0_0,
  output logic [31:0] rt_lh_p_32_31_0,
  output logic [0:0] rt_lh_p_38_0_0,
  input logic [0:0] rt_lh_p_40_0_0,
  output logic [3:0] rt_lh_p_45_3_0,
  output logic [1:0] rt_lh_p_48_1_0,
  output logic [1:0] rt_lh_p_50_1_0,
  output logic [0:0] rt_lh_p_56_0_0,
  output logic [31:0] rt_lh_p_59_31_0,
  output logic [0:0] rt_lh_p_64_0_0,
  output logic [0:0] probe_irq_masked_pre,
  output logic [0:0] probe_irq_taken_pre,
  output logic [0:0] trace_obi_d_req,
  output logic [31:0] trace_obi_d_addr,
  output logic [0:0] trace_obi_d_gnt,
  output logic [0:0] trace_obi_d_rvalid,
  output logic [31:0] trace_obi_d_rdata,
  output logic [0:0] trace_obi_d_error,
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
  output logic [0:0] trace_obi_i_error,
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
  logic [31:0] link_lh_p_8_31_0;
  logic [3:0] link_lh_p_10_3_0;
  logic [0:0] link_lh_p_12_0_0;
  logic [0:0] link_lh_p_13_0_0;
  logic [31:0] link_lh_p_14_31_0;
  logic [0:0] link_lh_p_16_0_0;
  logic [0:0] link_lh_p_18_0_0;
  logic [31:0] link_lh_p_23_31_0;
  logic [0:0] link_lh_p_25_0_0;
  logic [31:0] link_lh_p_31_31_0;
  logic [0:0] link_lh_p_33_0_0;
  logic [0:0] link_lh_p_34_0_0;
  logic [31:0] link_lh_p_35_31_0;
  logic [0:0] link_lh_p_37_0_0;
  logic [0:0] link_lh_p_39_0_0;
  assign probe_irq_masked_pre = ~u_component.u_dut.u_ibex_core.cs_registers_i.mie_q.irq_external | ((u_component.u_dut.u_ibex_core.cs_registers_i.priv_lvl_q == 2'b11) & ~u_component.u_dut.u_ibex_core.csr_mstatus_mie);
  assign probe_irq_taken_pre = u_component.u_dut.u_ibex_core.id_stage_i.controller_i.pc_set_o & u_component.u_dut.u_ibex_core.id_stage_i.controller_i.csr_save_cause_o & (u_component.u_dut.u_ibex_core.id_stage_i.controller_i.exc_pc_mux_o == ibex_pkg::EXC_PC_IRQ) & (u_component.u_dut.u_ibex_core.id_stage_i.controller_i.exc_cause_o == ibex_pkg::ExcCauseIrqExternalM);
  assign trace_obi_d_req = link_lh_p_16_0_0;
  assign trace_obi_d_addr = link_lh_p_8_31_0;
  assign trace_obi_d_gnt = link_lh_p_13_0_0;
  assign trace_obi_d_rvalid = link_lh_p_18_0_0;
  assign trace_obi_d_rdata = link_lh_p_14_31_0;
  assign trace_obi_d_error = link_lh_p_12_0_0;
  assign trace_obi_d_we = link_lh_p_25_0_0;
  assign trace_obi_d_wdata = link_lh_p_23_31_0;
  assign trace_obi_d_be = link_lh_p_10_3_0;
  assign trace_obi_i_req = link_lh_p_37_0_0;
  assign trace_obi_i_addr = link_lh_p_31_31_0;
  assign trace_obi_i_gnt = link_lh_p_34_0_0;
  assign trace_obi_i_rvalid = link_lh_p_39_0_0;
  assign trace_obi_i_rdata = link_lh_p_35_31_0;
  assign trace_obi_i_error = link_lh_p_33_0_0;
  local_processor u_component (
    .clk(clk),
    .reset(reset),
    .lh_p_0_0_0(rt_lh_p_0_0_0),
    .lh_p_1_0_0(rt_lh_p_1_0_0),
    .lh_p_2_0_0(rt_lh_p_2_0_0),
    .lh_p_6_0_0(rt_lh_p_6_0_0),
    .lh_p_7_159_0(rt_lh_p_7_159_0),
    .lh_p_8_31_0(link_lh_p_8_31_0),
    .lh_p_9_31_0(rt_lh_p_9_31_0),
    .lh_p_10_3_0(link_lh_p_10_3_0),
    .lh_p_11_3_0(rt_lh_p_11_3_0),
    .lh_p_12_0_0(link_lh_p_12_0_0),
    .lh_p_13_0_0(link_lh_p_13_0_0),
    .lh_p_14_31_0(link_lh_p_14_31_0),
    .lh_p_16_0_0(link_lh_p_16_0_0),
    .lh_p_17_0_0(rt_lh_p_17_0_0),
    .lh_p_18_0_0(link_lh_p_18_0_0),
    .lh_p_20_0_0(rt_lh_p_20_0_0),
    .lh_p_21_6_0(rt_lh_p_21_6_0),
    .lh_p_22_6_0(rt_lh_p_22_6_0),
    .lh_p_23_31_0(link_lh_p_23_31_0),
    .lh_p_24_31_0(rt_lh_p_24_31_0),
    .lh_p_25_0_0(link_lh_p_25_0_0),
    .lh_p_26_0_0(rt_lh_p_26_0_0),
    .lh_p_28_0_0(rt_lh_p_28_0_0),
    .lh_p_31_31_0(link_lh_p_31_31_0),
    .lh_p_32_31_0(rt_lh_p_32_31_0),
    .lh_p_33_0_0(link_lh_p_33_0_0),
    .lh_p_34_0_0(link_lh_p_34_0_0),
    .lh_p_35_31_0(link_lh_p_35_31_0),
    .lh_p_37_0_0(link_lh_p_37_0_0),
    .lh_p_38_0_0(rt_lh_p_38_0_0),
    .lh_p_39_0_0(link_lh_p_39_0_0),
    .lh_p_40_0_0(rt_lh_p_40_0_0),
    .lh_p_45_3_0(rt_lh_p_45_3_0),
    .lh_p_48_1_0(rt_lh_p_48_1_0),
    .lh_p_50_1_0(rt_lh_p_50_1_0),
    .lh_p_56_0_0(rt_lh_p_56_0_0),
    .lh_p_59_31_0(rt_lh_p_59_31_0),
    .lh_p_64_0_0(rt_lh_p_64_0_0)
  );
  obi_processor_memory_adapter #(
    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .READ_ONLY(0),
    .HAS_BE(1), .HAS_ERROR(1)
  ) u_adapter_d (
    .clk_i(clk),
    .rst_ni(~reset),
    .req_i(link_lh_p_16_0_0),
    .gnt_o(link_lh_p_13_0_0),
    .addr_i(link_lh_p_8_31_0),
    .we_i(link_lh_p_25_0_0),
    .wdata_i(link_lh_p_23_31_0),
    .be_i(link_lh_p_10_3_0),
    .rvalid_o(link_lh_p_18_0_0),
    .rdata_o(link_lh_p_14_31_0),
    .error_o(link_lh_p_12_0_0),
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
    .HAS_BE(0), .HAS_ERROR(1)
  ) u_adapter_i (
    .clk_i(clk),
    .rst_ni(~reset),
    .req_i(link_lh_p_37_0_0),
    .gnt_o(link_lh_p_34_0_0),
    .addr_i(link_lh_p_31_31_0),
    .we_i(1'b0),
    .wdata_i(32'b0),
    .be_i(4'b1111),
    .rvalid_o(link_lh_p_39_0_0),
    .rdata_o(link_lh_p_35_31_0),
    .error_o(link_lh_p_33_0_0),
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
