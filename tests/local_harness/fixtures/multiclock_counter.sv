module local_runtime_dual_clock_fixture (
  input  logic        clk,
  input  logic        reset,
  input  logic        clk_aon,
  input  logic        reset_aon,
  output logic [3:0]  irq_o,
  output logic [31:0] core_count_o,
  output logic [31:0] aon_count_o,
  input  logic        timer_req_valid,
  output logic        timer_req_ready,
  input  logic        timer_req_write,
  input  logic [31:0] timer_req_addr,
  input  logic [31:0] timer_req_wdata,
  input  logic [3:0]  timer_req_be,
  output logic        timer_rsp_valid,
  input  logic        timer_rsp_ready,
  output logic [31:0] timer_rsp_rdata,
  output logic        timer_rsp_error,
  output logic        timer_target_stb
);
  always_ff @(posedge clk or posedge reset) begin
    if (reset) core_count_o <= '0;
    else core_count_o <= core_count_o + 1'b1;
  end

  always_ff @(posedge clk_aon or posedge reset_aon) begin
    if (reset_aon) aon_count_o <= '0;
    else aon_count_o <= aon_count_o + 1'b1;
  end

  assign irq_o = 4'b0;
  assign timer_req_ready = 1'b0;
  assign timer_rsp_valid = 1'b0;
  assign timer_rsp_rdata = '0;
  assign timer_rsp_error = 1'b0;
  assign timer_target_stb = 1'b0;
endmodule
