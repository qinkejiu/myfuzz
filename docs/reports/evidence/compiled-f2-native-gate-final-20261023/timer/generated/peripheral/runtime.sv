module local_runtime_peripheral (
  input logic [0:0] clk,
  input logic [0:0] reset,
  output logic [3:0] rt_lh_p_10_3_0,
  output logic [11:0] trace_paddr,
  output logic [0:0] trace_psel,
  output logic [0:0] trace_penable,
  output logic [0:0] trace_pwrite,
  output logic [31:0] trace_pwdata,
  output logic [0:0] trace_pready,
  output logic [31:0] trace_prdata,
  output logic [0:0] trace_pslverr,
  input logic [0:0] reg_req_valid,
  output logic [0:0] reg_req_ready,
  input logic [0:0] reg_req_write,
  input logic [31:0] reg_req_addr,
  input logic [31:0] reg_req_wdata,
  input logic [3:0] reg_req_be,
  output logic [0:0] reg_rsp_valid,
  input logic [0:0] reg_rsp_ready,
  output logic [31:0] reg_rsp_rdata,
  output logic [0:0] reg_rsp_error,
  output logic [31:0] storage_value,
  output logic [0:0] storage_reset,
  output logic [11:0] storage_paddr,
  output logic [0:0] storage_psel,
  output logic [0:0] storage_penable,
  output logic [0:0] storage_pwrite,
  output logic [31:0] storage_pwdata,
  output logic [31:0] storage_prdata,
  output logic [0:0] storage_pready,
  output logic [0:0] storage_pslverr
);
  logic [11:0] link_lh_p_2_11_0;
  logic [0:0] link_lh_p_3_0_0;
  logic [31:0] link_lh_p_4_31_0;
  logic [0:0] link_lh_p_5_0_0;
  logic [0:0] link_lh_p_6_0_0;
  logic [0:0] link_lh_p_7_0_0;
  logic [31:0] link_lh_p_8_31_0;
  logic [0:0] link_lh_p_9_0_0;
  logic [31:0] apb_paddr;
  logic [3:0] unused_pstrb;
  assign trace_paddr = link_lh_p_2_11_0;
  assign trace_psel = link_lh_p_6_0_0;
  assign trace_penable = link_lh_p_3_0_0;
  assign trace_pwrite = link_lh_p_9_0_0;
  assign trace_pwdata = link_lh_p_8_31_0;
  assign trace_pready = link_lh_p_5_0_0;
  assign trace_prdata = link_lh_p_4_31_0;
  assign trace_pslverr = link_lh_p_7_0_0;
  assign link_lh_p_2_11_0 = apb_paddr[11:0];
  assign storage_value = u_component.u_dut.TIMER_GEN[0].timer_i.regs_q[1];
  assign storage_reset = reset;
  assign storage_paddr = link_lh_p_2_11_0;
  assign storage_psel = link_lh_p_6_0_0;
  assign storage_penable = link_lh_p_3_0_0;
  assign storage_pwrite = link_lh_p_9_0_0;
  assign storage_pwdata = link_lh_p_8_31_0;
  assign storage_prdata = link_lh_p_4_31_0;
  assign storage_pready = link_lh_p_5_0_0;
  assign storage_pslverr = link_lh_p_7_0_0;
  local_peripheral u_component (
    .clk(clk),
    .reset(reset),
    .lh_p_2_11_0(link_lh_p_2_11_0),
    .lh_p_3_0_0(link_lh_p_3_0_0),
    .lh_p_4_31_0(link_lh_p_4_31_0),
    .lh_p_5_0_0(link_lh_p_5_0_0),
    .lh_p_6_0_0(link_lh_p_6_0_0),
    .lh_p_7_0_0(link_lh_p_7_0_0),
    .lh_p_8_31_0(link_lh_p_8_31_0),
    .lh_p_9_0_0(link_lh_p_9_0_0),
    .lh_p_10_3_0(rt_lh_p_10_3_0)
  );
  beat_to_apb #(
    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .HAS_PSTRB(0),
    .SUPPORTS_PARTIAL_WRITE(0), .HAS_PSLVERR(1),
    .MAX_WAIT_CYCLES(16), .WINDOW_BASE(32'd0), .WINDOW_SIZE(4096)
  ) u_adapter_reg (
    .clk(clk),
    .reset(reset),
    .req_valid(reg_req_valid),
    .req_ready(reg_req_ready),
    .write(reg_req_write),
    .addr(reg_req_addr),
    .wdata(reg_req_wdata),
    .be(reg_req_be),
    .rsp_valid(reg_rsp_valid),
    .rsp_ready(reg_rsp_ready),
    .rdata(reg_rsp_rdata),
    .error(reg_rsp_error),
    .paddr(apb_paddr),
    .pstrb(unused_pstrb),
    .penable(link_lh_p_3_0_0),
    .prdata(link_lh_p_4_31_0),
    .pready(link_lh_p_5_0_0),
    .psel(link_lh_p_6_0_0),
    .pslverr(link_lh_p_7_0_0),
    .pwdata(link_lh_p_8_31_0),
    .pwrite(link_lh_p_9_0_0)
  );
endmodule
