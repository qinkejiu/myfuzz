module local_runtime_cpu (
  input logic [0:0] clk,
  input logic [0:0] reset,
  output logic [0:0] rt_lh_p_2_0_0,
  output logic [0:0] rt_lh_p_6_0_0,
  output logic [0:0] rt_lh_p_8_0_0,
  output logic [33:0] cpu_ahb_trace_haddr,
  output logic [2:0] cpu_ahb_trace_hburst,
  output logic [0:0] cpu_ahb_trace_hmastlock,
  output logic [3:0] cpu_ahb_trace_hprot,
  output logic [31:0] cpu_ahb_trace_hrdata,
  output logic [0:0] cpu_ahb_trace_hready,
  output logic [0:0] cpu_ahb_trace_hresp,
  output logic [0:0] cpu_ahb_trace_hsel,
  output logic [2:0] cpu_ahb_trace_hsize,
  output logic [1:0] cpu_ahb_trace_htrans,
  output logic [31:0] cpu_ahb_trace_hwdata,
  output logic [0:0] cpu_ahb_trace_hwrite,
  output logic [3:0] cpu_ahb_trace_hwstrb,
  output logic [0:0] m_req_valid,
  input logic [0:0] m_req_ready,
  output logic [0:0] m_req_write,
  output logic [33:0] m_req_addr,
  output logic [31:0] m_req_wdata,
  output logic [3:0] m_req_be,
  input logic [0:0] m_rsp_valid,
  output logic [0:0] m_rsp_ready,
  input logic [31:0] m_rsp_rdata,
  input logic [0:0] m_rsp_error
);
  logic [33:0] link_lh_p_0_33_0;
  logic [2:0] link_lh_p_1_2_0;
  logic [0:0] link_lh_p_3_0_0;
  logic [3:0] link_lh_p_4_3_0;
  logic [31:0] link_lh_p_5_31_0;
  logic [0:0] link_lh_p_7_0_0;
  logic [0:0] link_lh_p_9_0_0;
  logic [0:0] link_lh_p_10_0_0;
  logic [2:0] link_lh_p_11_2_0;
  logic [1:0] link_lh_p_12_1_0;
  logic [31:0] link_lh_p_13_31_0;
  logic [0:0] link_lh_p_14_0_0;
  logic [3:0] link_lh_p_15_3_0;
  assign cpu_ahb_trace_haddr = link_lh_p_0_33_0;
  assign cpu_ahb_trace_hburst = link_lh_p_1_2_0;
  assign cpu_ahb_trace_hmastlock = link_lh_p_3_0_0;
  assign cpu_ahb_trace_hprot = link_lh_p_4_3_0;
  assign cpu_ahb_trace_hrdata = link_lh_p_5_31_0;
  assign cpu_ahb_trace_hready = link_lh_p_7_0_0;
  assign cpu_ahb_trace_hresp = link_lh_p_9_0_0;
  assign cpu_ahb_trace_hsel = link_lh_p_10_0_0;
  assign cpu_ahb_trace_hsize = link_lh_p_11_2_0;
  assign cpu_ahb_trace_htrans = link_lh_p_12_1_0;
  assign cpu_ahb_trace_hwdata = link_lh_p_13_31_0;
  assign cpu_ahb_trace_hwrite = link_lh_p_14_0_0;
  assign cpu_ahb_trace_hwstrb = link_lh_p_15_3_0;
  local_cpu u_component (
    .clk(clk),
    .reset(reset),
    .lh_p_0_33_0(link_lh_p_0_33_0),
    .lh_p_1_2_0(link_lh_p_1_2_0),
    .lh_p_2_0_0(rt_lh_p_2_0_0),
    .lh_p_3_0_0(link_lh_p_3_0_0),
    .lh_p_4_3_0(link_lh_p_4_3_0),
    .lh_p_5_31_0(link_lh_p_5_31_0),
    .lh_p_6_0_0(rt_lh_p_6_0_0),
    .lh_p_7_0_0(link_lh_p_7_0_0),
    .lh_p_8_0_0(rt_lh_p_8_0_0),
    .lh_p_9_0_0(link_lh_p_9_0_0),
    .lh_p_10_0_0(link_lh_p_10_0_0),
    .lh_p_11_2_0(link_lh_p_11_2_0),
    .lh_p_12_1_0(link_lh_p_12_1_0),
    .lh_p_13_31_0(link_lh_p_13_31_0),
    .lh_p_14_0_0(link_lh_p_14_0_0),
    .lh_p_15_3_0(link_lh_p_15_3_0)
  );
  ahb_lite_memory_target #(
    .ADDRESS_WIDTH(34), .DATA_WIDTH(32),
    .MAX_WAIT_CYCLES(16)
  ) u_ahb_target (
    .clk_i(clk),
    .rst_ni(~reset),
    .req_valid_o(m_req_valid),
    .req_ready_i(m_req_ready),
    .req_write_o(m_req_write),
    .req_addr_o(m_req_addr),
    .req_wdata_o(m_req_wdata),
    .req_be_o(m_req_be),
    .rsp_valid_i(m_rsp_valid),
    .rsp_ready_o(m_rsp_ready),
    .rsp_rdata_i(m_rsp_rdata),
    .rsp_error_i(m_rsp_error),
    .HADDR(link_lh_p_0_33_0),
    .HBURST(link_lh_p_1_2_0),
    .HMASTLOCK(link_lh_p_3_0_0),
    .HPROT(link_lh_p_4_3_0),
    .HRDATAEXT(link_lh_p_5_31_0),
    .HREADYEXT(link_lh_p_7_0_0),
    .HRESPEXT(link_lh_p_9_0_0),
    .HSELEXT(link_lh_p_10_0_0),
    .HSIZE(link_lh_p_11_2_0),
    .HTRANS(link_lh_p_12_1_0),
    .HWDATA(link_lh_p_13_31_0),
    .HWRITE(link_lh_p_14_0_0),
    .HWSTRB(link_lh_p_15_3_0)
  );
endmodule
