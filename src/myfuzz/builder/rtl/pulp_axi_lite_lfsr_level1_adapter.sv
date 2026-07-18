// SPDX-License-Identifier: SHL-0.51
// The upstream LFSR presents RVALID continuously. Gate it behind one accepted AR
// so the experiment-facing port obeys AXI-Lite transaction ownership.
module pulp_axi_lite_lfsr_level1_adapter (
  input wire clk, input wire resetn,
  input wire s_awvalid, output wire s_awready, input wire [31:0] s_awaddr,
  input wire s_wvalid, output wire s_wready, input wire [31:0] s_wdata,
  input wire [3:0] s_wstrb, output wire s_bvalid, input wire s_bready,
  output wire [1:0] s_bresp,
  input wire s_arvalid, output wire s_arready, input wire [31:0] s_araddr,
  output wire s_rvalid, input wire s_rready, output wire [31:0] s_rdata,
  output wire [1:0] s_rresp
);
  reg read_pending;
  wire raw_arready, raw_rvalid;
  wire raw_rready = read_pending && s_rready;
  wire ar_fire = s_arvalid && s_arready;
  assign s_arready = !read_pending && raw_arready;
  assign s_rvalid = read_pending && raw_rvalid;

  always @(posedge clk or negedge resetn) begin
    if (!resetn) read_pending <= 0;
    else begin
      if (ar_fire) read_pending <= 1;
      if (s_rvalid && s_rready) read_pending <= 0;
    end
  end

  pulp_axi_lite_lfsr_wrapper i_lfsr (
    .clk(clk),.resetn(resetn),.s_awvalid(s_awvalid),.s_awready(s_awready),.s_awaddr(s_awaddr),
    .s_wvalid(s_wvalid),.s_wready(s_wready),.s_wdata(s_wdata),.s_wstrb(s_wstrb),
    .s_bvalid(s_bvalid),.s_bready(s_bready),.s_bresp(s_bresp),
    .s_arvalid(s_arvalid&&!read_pending),.s_arready(raw_arready),.s_araddr(s_araddr),
    .s_rvalid(raw_rvalid),.s_rready(raw_rready),.s_rdata(s_rdata),.s_rresp(s_rresp));
endmodule
