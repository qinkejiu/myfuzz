// SPDX-License-Identifier: Apache-2.0
// Loads and verifies one generated image through UltraEmbedded's AXI target.
module myfuzz_level1_tcm_loader #(
  parameter integer WORDS = 256,
  parameter [31:0] LOAD_BASE = 32'h0000_2000,
  parameter HEX_FILE = "level1_rom.hex"
) (
  input wire clk, input wire reset,
  input wire start, output reg busy, output reg done, output reg error,
  output reg awvalid, input wire awready, output wire [31:0] awaddr,
  output wire [3:0] awid, output wire [7:0] awlen, output wire [1:0] awburst,
  output reg wvalid, input wire wready, output wire [31:0] wdata,
  output wire [3:0] wstrb, output wire wlast,
  input wire bvalid, output wire bready, input wire [1:0] bresp,
  input wire [3:0] bid,
  output reg arvalid, input wire arready, output wire [31:0] araddr,
  output wire [3:0] arid, output wire [7:0] arlen, output wire [1:0] arburst,
  input wire rvalid, output wire rready, input wire [31:0] rdata,
  input wire [1:0] rresp, input wire [3:0] rid, input wire rlast
);
  localparam IDLE=3'd0, WRITE_SEND=3'd1, WRITE_RESP=3'd2,
             READ_SEND=3'd3, READ_RESP=3'd4, COMPLETE=3'd5;
  reg [2:0] state;
  integer index;
  reg aw_done, w_done;
  reg [31:0] image [0:WORDS-1];
  wire unused_ids = ^{bid, rid, rlast};
  assign awaddr = LOAD_BASE + (index << 2);
  assign awid = 4'b0; assign awlen = 8'b0; assign awburst = 2'b01;
  assign wdata = image[index]; assign wstrb = 4'hf; assign wlast = 1'b1;
  assign bready = state == WRITE_RESP;
  assign araddr = LOAD_BASE + (index << 2);
  assign arid = 4'b0; assign arlen = 8'b0; assign arburst = 2'b01;
  assign rready = state == READ_RESP;

  initial $readmemh(HEX_FILE, image);

  always @(posedge clk or posedge reset) begin
    if (reset) begin
      state <= IDLE; index <= 0; awvalid <= 0; wvalid <= 0; arvalid <= 0;
      aw_done <= 0; w_done <= 0; busy <= 0; done <= 0; error <= 0;
    end else begin
      case (state)
        IDLE: if (start) begin
          index <= 0; awvalid <= 1; wvalid <= 1; aw_done <= 0; w_done <= 0;
          busy <= 1; done <= 0; error <= 0; state <= WRITE_SEND;
        end
        WRITE_SEND: begin
          if (awvalid && awready) begin awvalid <= 0; aw_done <= 1; end
          if (wvalid && wready) begin wvalid <= 0; w_done <= 1; end
          if ((aw_done || (awvalid && awready)) && (w_done || (wvalid && wready)))
            state <= WRITE_RESP;
        end
        WRITE_RESP: if (bvalid) begin
          if (bresp != 2'b00) begin error <= 1; state <= COMPLETE; end
          else if (index == WORDS-1) begin index <= 0; arvalid <= 1; state <= READ_SEND; end
          else begin
            index <= index + 1; awvalid <= 1; wvalid <= 1;
            aw_done <= 0; w_done <= 0; state <= WRITE_SEND;
          end
        end
        READ_SEND: if (arvalid && arready) begin arvalid <= 0; state <= READ_RESP; end
        READ_RESP: if (rvalid) begin
          if (rresp != 2'b00 || rdata != image[index]) begin error <= 1; state <= COMPLETE; end
          else if (index == WORDS-1) state <= COMPLETE;
          else begin index <= index + 1; arvalid <= 1; state <= READ_SEND; end
        end
        COMPLETE: begin busy <= 0; done <= !error; state <= IDLE; end
        default: begin error <= 1; state <= COMPLETE; end
      endcase
    end
  end
endmodule
