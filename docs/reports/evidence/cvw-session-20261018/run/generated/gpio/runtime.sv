module local_runtime_gpio (
  input logic [0:0] clk,
  input logic [0:0] reset,
  output logic [31:0] rt_lh_p_11_31_0,
  input logic [31:0] rt_lh_p_12_31_0,
  output logic [31:0] rt_lh_p_13_31_0,
  output logic [31:0] rt_lh_p_14_31_0,
  output logic [127:0] rt_lh_p_15_127_0,
  output logic [0:0] rt_lh_p_16_0_0,
  input logic [0:0] gpio_req_valid,
  output logic [0:0] gpio_req_ready,
  input logic [0:0] gpio_req_write,
  input logic [31:0] gpio_req_addr,
  input logic [31:0] gpio_req_wdata,
  input logic [3:0] gpio_req_be,
  output logic [0:0] gpio_rsp_valid,
  input logic [0:0] gpio_rsp_ready,
  output logic [31:0] gpio_rsp_rdata,
  output logic [0:0] gpio_rsp_error
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
  assign link_lh_p_2_11_0 = apb_paddr[11:0];
  local_gpio u_component (
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
    .lh_p_11_31_0(rt_lh_p_11_31_0),
    .lh_p_12_31_0(rt_lh_p_12_31_0),
    .lh_p_13_31_0(rt_lh_p_13_31_0),
    .lh_p_14_31_0(rt_lh_p_14_31_0),
    .lh_p_15_127_0(rt_lh_p_15_127_0),
    .lh_p_16_0_0(rt_lh_p_16_0_0)
  );
  beat_to_apb #(
    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .HAS_PSTRB(0),
    .SUPPORTS_PARTIAL_WRITE(0), .HAS_PSLVERR(1),
    .MAX_WAIT_CYCLES(16), .WINDOW_BASE(32'd0), .WINDOW_SIZE(4096)
  ) u_adapter_gpio (
    .clk(clk),
    .reset(reset),
    .req_valid(gpio_req_valid),
    .req_ready(gpio_req_ready),
    .write(gpio_req_write),
    .addr(gpio_req_addr),
    .wdata(gpio_req_wdata),
    .be(gpio_req_be),
    .rsp_valid(gpio_rsp_valid),
    .rsp_ready(gpio_rsp_ready),
    .rdata(gpio_rsp_rdata),
    .error(gpio_rsp_error),
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
