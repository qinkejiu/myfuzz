// SPDX-License-Identifier: Apache-2.0
module myfuzz_level1_transaction_monitor #(
  parameter integer SEQUENCE_WIDTH = 32,
  parameter integer ROUTE_WIDTH = 8
) (
  input wire clk, input wire resetn,
  input wire record_active, input wire [SEQUENCE_WIDTH-1:0] record_sequence,
  input wire record_read_write, input wire [ROUTE_WIDTH-1:0] expected_route,
  input wire [31:0] expected_address, input wire watchdog_timeout,
  input wire m_awvalid, input wire m_awready, input wire [31:0] m_awaddr,
  input wire m_wvalid, input wire m_wready,
  input wire m_bvalid, input wire m_bready, input wire [1:0] m_bresp,
  input wire m_arvalid, input wire m_arready, input wire [31:0] m_araddr,
  input wire m_rvalid, input wire m_rready, input wire [1:0] m_rresp,
  output reg terminal_valid, output reg terminal_timed_out,
  output reg [SEQUENCE_WIDTH-1:0] terminal_sequence,
  output reg [ROUTE_WIDTH-1:0] terminal_route,
  output reg terminal_read_write, output reg [31:0] terminal_address,
  output reg [1:0] terminal_response, output reg [31:0] terminal_cycles
);
  reg tracking, terminated, aw_seen, w_seen, read_armed;
  reg [SEQUENCE_WIDTH-1:0] tracking_sequence;
  wire new_record = record_active && (!tracking || tracking_sequence != record_sequence);
  wire matching_aw = m_awvalid && m_awready && m_awaddr == expected_address && record_read_write;
  wire matching_w = m_wvalid && m_wready && record_read_write;
  wire matching_ar = m_arvalid && m_arready && m_araddr == expected_address && !record_read_write;
  wire write_armed = (aw_seen || matching_aw) && (w_seen || matching_w);
  wire read_response = (read_armed || matching_ar) && m_rvalid && m_rready;
  wire write_response = write_armed && m_bvalid && m_bready;

  always @(posedge clk or negedge resetn) begin
    if (!resetn) begin
      tracking<=0; terminated<=0; aw_seen<=0; w_seen<=0; read_armed<=0;
      tracking_sequence<=0; terminal_valid<=0; terminal_timed_out<=0;
      terminal_sequence<=0; terminal_route<=0; terminal_read_write<=0;
      terminal_address<=0; terminal_response<=0; terminal_cycles<=0;
    end else begin
      terminal_valid <= 0;
      if (!record_active) begin
        tracking<=0; terminated<=0; aw_seen<=0; w_seen<=0; read_armed<=0;
      end else if (new_record) begin
        tracking<=1; tracking_sequence<=record_sequence; terminated<=0;
        aw_seen<=0; w_seen<=0; read_armed<=0; terminal_cycles<=0;
      end else if (!terminated) begin
        terminal_cycles <= terminal_cycles + 1;
        if (matching_aw) aw_seen <= 1;
        if (matching_w) w_seen <= 1;
        if (matching_ar) read_armed <= 1;
        if (watchdog_timeout || read_response || write_response) begin
          terminal_valid <= 1; terminated <= 1;
          terminal_timed_out <= watchdog_timeout;
          terminal_sequence <= record_sequence; terminal_route <= expected_route;
          terminal_read_write <= record_read_write; terminal_address <= expected_address;
          if (watchdog_timeout) terminal_response <= 2'b00;
          else if (record_read_write) terminal_response <= m_bresp;
          else terminal_response <= m_rresp;
        end
      end
    end
  end
endmodule
