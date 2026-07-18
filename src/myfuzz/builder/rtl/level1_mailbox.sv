// SPDX-License-Identifier: Apache-2.0
// Execution-domain MMIO view of the reset-exempt record owner.
module myfuzz_level1_mailbox #(
  parameter [31:0] BASE_ADDR = 32'h1000_0000,
  parameter integer SEQUENCE_WIDTH = 32
) (
  input wire clk, input wire resetn,
  input wire active, input wire [SEQUENCE_WIDTH-1:0] active_sequence,
  input wire [31:0] active_ip_select, input wire active_read_write,
  input wire [31:0] active_offset, input wire [31:0] active_data,
  output reg software_progress, output reg [31:0] software_progress_value,
  output reg protocol_error,
  input wire s_awvalid, output wire s_awready, input wire [31:0] s_awaddr,
  input wire s_wvalid, output wire s_wready, input wire [31:0] s_wdata,
  input wire [3:0] s_wstrb, output reg s_bvalid, input wire s_bready,
  output reg [1:0] s_bresp,
  input wire s_arvalid, output wire s_arready, input wire [31:0] s_araddr,
  output reg s_rvalid, input wire s_rready, output reg [31:0] s_rdata,
  output reg [1:0] s_rresp
);
  reg aw_hold, w_hold;
  reg [31:0] awaddr_hold, wdata_hold;
  reg [3:0] wstrb_hold;
  wire aw_fire = s_awready && s_awvalid;
  wire w_fire = s_wready && s_wvalid;
  wire write_complete = !s_bvalid && (aw_hold || aw_fire) && (w_hold || w_fire);
  wire [31:0] write_address = aw_hold ? awaddr_hold : s_awaddr;
  wire [31:0] write_data = w_hold ? wdata_hold : s_wdata;
  wire [3:0] write_strobe = w_hold ? wstrb_hold : s_wstrb;
  wire [31:0] read_offset = s_araddr - BASE_ADDR;
  wire unused_sequence = ^active_sequence;
  assign s_awready = resetn && !s_bvalid && !aw_hold;
  assign s_wready = resetn && !s_bvalid && !w_hold;
  assign s_arready = resetn && !s_rvalid;

  always @(posedge clk or negedge resetn) begin
    if (!resetn) begin
      software_progress <= 0; software_progress_value <= 0; protocol_error <= 0;
      aw_hold <= 0; w_hold <= 0; awaddr_hold <= 0; wdata_hold <= 0; wstrb_hold <= 0;
      s_bvalid <= 0; s_bresp <= 0; s_rvalid <= 0; s_rdata <= 0; s_rresp <= 0;
    end else begin
      software_progress <= 0;
      if (aw_fire) begin aw_hold <= 1; awaddr_hold <= s_awaddr; end
      if (w_fire) begin w_hold <= 1; wdata_hold <= s_wdata; wstrb_hold <= s_wstrb; end
      if (s_bvalid && s_bready) s_bvalid <= 0;
      if (write_complete) begin
        aw_hold <= 0; w_hold <= 0; s_bvalid <= 1;
        if (write_address == BASE_ADDR + 20 && write_strobe == 4'hf) begin
          software_progress <= 1; software_progress_value <= write_data; s_bresp <= 2'b00;
        end else begin s_bresp <= 2'b10; protocol_error <= 1; end
      end

      if (s_rvalid && s_rready) s_rvalid <= 0;
      if (s_arvalid && s_arready) begin
        s_rvalid <= 1; s_rresp <= 2'b00;
        case (read_offset)
          0: s_rdata <= {31'b0, active};
          4: s_rdata <= active_ip_select;
          8: s_rdata <= {31'b0, active_read_write};
          12: s_rdata <= active_offset;
          16: s_rdata <= active_data;
          20: s_rdata <= software_progress_value;
          default: begin s_rdata <= 0; s_rresp <= 2'b10; protocol_error <= 1; end
        endcase
      end
    end
  end
endmodule
