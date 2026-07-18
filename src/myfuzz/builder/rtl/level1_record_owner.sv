// SPDX-License-Identifier: Apache-2.0
// Reset-exempt owner for one transaction-paced RFUZZ record.
module myfuzz_level1_record_owner #(
  parameter integer SEQUENCE_WIDTH = 32,
  parameter integer ROUTE_WIDTH = 8
) (
  input wire clk, input wire resetn, input wire accept_enable,
  input wire record_valid, output wire record_ready,
  input wire [SEQUENCE_WIDTH-1:0] record_sequence,
  input wire [31:0] record_ip_select, input wire record_read_write,
  input wire [31:0] record_offset, input wire [31:0] record_data,
  output reg active, output reg [SEQUENCE_WIDTH-1:0] active_sequence,
  output reg [31:0] active_ip_select, output reg active_read_write,
  output reg [31:0] active_offset, output reg [31:0] active_data,
  input wire raw_terminal_valid, input wire raw_terminal_timed_out,
  input wire [SEQUENCE_WIDTH-1:0] raw_terminal_sequence,
  input wire [ROUTE_WIDTH-1:0] raw_terminal_route,
  input wire raw_terminal_read_write, input wire [31:0] raw_terminal_address,
  input wire [1:0] raw_terminal_response, input wire [31:0] raw_terminal_cycles,
  output reg terminal_valid, input wire terminal_capture_ack,
  output reg terminal_timed_out,
  output reg [SEQUENCE_WIDTH-1:0] terminal_sequence,
  output reg [ROUTE_WIDTH-1:0] terminal_route,
  output reg terminal_read_write, output reg [31:0] terminal_address,
  output reg [1:0] terminal_response, output reg [31:0] terminal_cycles,
  output reg protocol_error
);
  reg slot_busy;
  assign record_ready = accept_enable && !slot_busy;

  always @(posedge clk or negedge resetn) begin
    if (!resetn) begin
      slot_busy <= 0; active <= 0; active_sequence <= 0; active_ip_select <= 0;
      active_read_write <= 0; active_offset <= 0; active_data <= 0;
      terminal_valid <= 0; terminal_timed_out <= 0; terminal_sequence <= 0;
      terminal_route <= 0; terminal_read_write <= 0; terminal_address <= 0;
      terminal_response <= 0; terminal_cycles <= 0; protocol_error <= 0;
    end else begin
      if (record_valid && record_ready) begin
        slot_busy <= 1; active <= 1; active_sequence <= record_sequence;
        active_ip_select <= record_ip_select; active_read_write <= record_read_write;
        active_offset <= record_offset; active_data <= record_data;
      end

      if (raw_terminal_valid) begin
        if (active && !terminal_valid && raw_terminal_sequence == active_sequence) begin
          active <= 0; terminal_valid <= 1;
          terminal_timed_out <= raw_terminal_timed_out;
          terminal_sequence <= raw_terminal_sequence; terminal_route <= raw_terminal_route;
          terminal_read_write <= raw_terminal_read_write;
          terminal_address <= raw_terminal_address;
          terminal_response <= raw_terminal_response; terminal_cycles <= raw_terminal_cycles;
        end else begin
          protocol_error <= 1;
        end
      end

      if (terminal_capture_ack) begin
        if (terminal_valid) begin
          terminal_valid <= 0; slot_busy <= 0;
        end else begin
          protocol_error <= 1;
        end
      end
    end
  end
endmodule
