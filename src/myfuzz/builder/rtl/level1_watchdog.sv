// SPDX-License-Identifier: Apache-2.0
module myfuzz_level1_watchdog #(
  parameter [31:0] BASE_ADDR = 32'h1000_1000,
  parameter integer MAX_CYCLES = 1024
) (
  input wire clk, input wire resetn, input wire record_active,
  output reg timeout, output reg [31:0] elapsed_cycles,
  input wire s_awvalid, output wire s_awready, input wire [31:0] s_awaddr,
  input wire s_wvalid, output wire s_wready, input wire [31:0] s_wdata,
  input wire [3:0] s_wstrb, output reg s_bvalid, input wire s_bready,
  output reg [1:0] s_bresp,
  input wire s_arvalid, output wire s_arready, input wire [31:0] s_araddr,
  output reg s_rvalid, input wire s_rready, output reg [31:0] s_rdata,
  output reg [1:0] s_rresp
);
  reg aw_hold, w_hold; reg [31:0] awaddr_hold; reg [3:0] wstrb_hold;
  wire aw_fire=s_awready&&s_awvalid, w_fire=s_wready&&s_wvalid;
  wire write_complete=!s_bvalid&&(aw_hold||aw_fire)&&(w_hold||w_fire);
  wire [31:0] write_address=aw_hold?awaddr_hold:s_awaddr;
  wire [3:0] write_strobe=w_hold?wstrb_hold:s_wstrb;
  wire unused_write_data = ^{s_wdata};
  assign s_awready=resetn&&!s_bvalid&&!aw_hold;
  assign s_wready=resetn&&!s_bvalid&&!w_hold;
  assign s_arready=resetn&&!s_rvalid;
  always @(posedge clk or negedge resetn) begin
    if(!resetn) begin
      timeout<=0; elapsed_cycles<=0; aw_hold<=0; w_hold<=0; awaddr_hold<=0; wstrb_hold<=0;
      s_bvalid<=0; s_bresp<=0; s_rvalid<=0; s_rdata<=0; s_rresp<=0;
    end else begin
      timeout<=0;
      if(!record_active) elapsed_cycles<=0;
      else if(elapsed_cycles < MAX_CYCLES) elapsed_cycles<=elapsed_cycles+1;
      else timeout<=1;
      if(aw_fire) begin aw_hold<=1; awaddr_hold<=s_awaddr; end
      if(w_fire) begin w_hold<=1; wstrb_hold<=s_wstrb; end
      if(s_bvalid&&s_bready) s_bvalid<=0;
      if(write_complete) begin
        aw_hold<=0; w_hold<=0; s_bvalid<=1;
        if(write_address==BASE_ADDR && write_strobe==4'hf) begin elapsed_cycles<=0; s_bresp<=0; end
        else s_bresp<=2'b10;
      end
      if(s_rvalid&&s_rready) s_rvalid<=0;
      if(s_arvalid&&s_arready) begin
        s_rvalid<=1;
        if(s_araddr==BASE_ADDR) begin s_rdata<=elapsed_cycles; s_rresp<=0; end
        else begin s_rdata<=0; s_rresp<=2'b10; end
      end
    end
  end
endmodule
