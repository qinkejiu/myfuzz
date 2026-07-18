// SPDX-License-Identifier: Apache-2.0
// Resets only the execution domain after a captured timeout.
module myfuzz_level1_recovery_controller #(
  parameter integer RESET_CYCLES = 4,
  parameter integer QUIET_CYCLES = 4,
  parameter integer QUARANTINE_LIMIT = 64,
  parameter integer USE_LOADER = 0
) (
  input wire clk, input wire resetn,
  input wire terminal_valid, input wire terminal_timed_out,
  input wire terminal_capture_ack, input wire bus_quiet,
  input wire loader_done, input wire loader_error,
  output reg execution_resetn, output reg cpu_run, output reg loader_start,
  output reg accept_enable, output wire recovering,
  output reg [31:0] restart_count, output reg recovery_error
);
  localparam RESET_DOMAIN=3'd0, WAIT_LOADER=3'd1, QUARANTINE=3'd2,
             RUN=3'd3, FAILED=3'd4;
  reg [2:0] state;
  integer reset_count, quiet_count, quarantine_count;
  assign recovering = state != RUN;

  always @(posedge clk or negedge resetn) begin
    if (!resetn) begin
      state <= RESET_DOMAIN; reset_count <= 0; quiet_count <= 0;
      quarantine_count <= 0; execution_resetn <= 0; cpu_run <= 0;
      loader_start <= 0; accept_enable <= 0; restart_count <= 0;
      recovery_error <= 0;
    end else begin
      loader_start <= 0;
      case (state)
        RESET_DOMAIN: begin
          execution_resetn <= 0; cpu_run <= 0; accept_enable <= 0;
          quiet_count <= 0; quarantine_count <= 0;
          if (reset_count == RESET_CYCLES-1) begin
            reset_count <= 0; execution_resetn <= 1;
            if (USE_LOADER != 0) begin loader_start <= 1; state <= WAIT_LOADER; end
            else state <= QUARANTINE;
          end else reset_count <= reset_count + 1;
        end
        WAIT_LOADER: begin
          if (loader_error) begin recovery_error <= 1; state <= FAILED; end
          else if (loader_done) state <= QUARANTINE;
        end
        QUARANTINE: begin
          if (loader_error || quarantine_count == QUARANTINE_LIMIT-1) begin
            recovery_error <= 1; state <= FAILED;
          end else begin
            quarantine_count <= quarantine_count + 1;
            if (bus_quiet) begin
              if (quiet_count == QUIET_CYCLES-1) begin
                cpu_run <= 1; accept_enable <= 1; state <= RUN;
              end else quiet_count <= quiet_count + 1;
            end else quiet_count <= 0;
          end
        end
        RUN: begin
          if (terminal_valid && terminal_capture_ack && terminal_timed_out) begin
            restart_count <= restart_count + 1; execution_resetn <= 0;
            cpu_run <= 0; accept_enable <= 0; reset_count <= 0;
            state <= RESET_DOMAIN;
          end
        end
        default: begin
          execution_resetn <= 0; cpu_run <= 0; accept_enable <= 0;
          recovery_error <= 1; state <= FAILED;
        end
      endcase
    end
  end
endmodule
