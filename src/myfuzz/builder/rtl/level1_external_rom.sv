// SPDX-License-Identifier: Apache-2.0
module myfuzz_level1_external_rom #(
  parameter integer WORDS = 256,
  parameter [31:0] BASE_ADDR = 32'h0000_2000,
  parameter HEX_FILE = "level1_rom.hex"
) (
  input wire clk, input wire resetn,
  input wire s_awvalid, output wire s_awready, input wire [31:0] s_awaddr,
  input wire s_wvalid, output wire s_wready, input wire [31:0] s_wdata,
  input wire [3:0] s_wstrb, output reg s_bvalid, input wire s_bready,
  output reg [1:0] s_bresp,
  input wire s_arvalid, output wire s_arready, input wire [31:0] s_araddr,
  output reg s_rvalid, input wire s_rready, output reg [31:0] s_rdata,
  output reg [1:0] s_rresp
);
  reg [31:0] memory [0:WORDS-1];
  reg aw_hold, w_hold;
  wire [31:0] read_index = (s_araddr - BASE_ADDR) >> 2;
  wire read_hit = s_araddr >= BASE_ADDR && read_index < WORDS;
  wire unused_write = ^{s_awaddr, s_wdata, s_wstrb};
  assign s_awready = resetn && !s_bvalid && !aw_hold;
  assign s_wready = resetn && !s_bvalid && !w_hold;
  assign s_arready = resetn && !s_rvalid;

  initial $readmemh(HEX_FILE, memory);

  always @(posedge clk or negedge resetn) begin
    if (!resetn) begin
      s_bvalid <= 1'b0; s_bresp <= 2'b00; aw_hold <= 1'b0; w_hold <= 1'b0;
      s_rvalid <= 1'b0; s_rdata <= 32'b0; s_rresp <= 2'b00;
    end else begin
      if (s_bvalid && s_bready) s_bvalid <= 1'b0;
      if (s_awready && s_awvalid) aw_hold <= 1'b1;
      if (s_wready && s_wvalid) w_hold <= 1'b1;
      if (!s_bvalid && (aw_hold || (s_awready && s_awvalid)) &&
          (w_hold || (s_wready && s_wvalid))) begin
        s_bvalid <= 1'b1; s_bresp <= 2'b10; aw_hold <= 1'b0; w_hold <= 1'b0;
      end
      if (s_rvalid && s_rready) s_rvalid <= 1'b0;
      if (!s_rvalid && s_arvalid) begin
        s_rvalid <= 1'b1;
        if (read_hit) begin s_rdata <= memory[read_index]; s_rresp <= 2'b00; end
        else begin s_rdata <= 32'b0; s_rresp <= 2'b11; end
      end
    end
  end
endmodule
