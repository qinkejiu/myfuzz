// Single-outstanding processor-memory beat backend used by source-backed SoCs.
// The module intentionally has no behavioural CPU or peripheral model: it only
// carries one accepted request to the selected real target and propagates the
// target response/error with a bounded timeout and cancellation handshake.
module myfuzz_processor_memory_backend #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input logic clk_i,
    input logic rst_ni,
    input logic req_valid_i,
    output logic req_ready_o,
    input logic req_write_i,
    input logic [ADDRESS_WIDTH-1:0] req_addr_i,
    input logic [DATA_WIDTH-1:0] req_wdata_i,
    input logic [(DATA_WIDTH/8)-1:0] req_be_i,
    input logic req_mapped_i,
    output logic rsp_valid_o,
    input logic rsp_ready_i,
    output logic [DATA_WIDTH-1:0] rsp_rdata_o,
    output logic rsp_error_o,
    input logic cancel_valid_i,
    output logic cancel_ready_o,
    output logic target_flush_o,
    output logic target_req_valid_o,
    input logic target_req_ready_i,
    output logic target_write_o,
    output logic [ADDRESS_WIDTH-1:0] target_addr_o,
    output logic [DATA_WIDTH-1:0] target_wdata_o,
    output logic [(DATA_WIDTH/8)-1:0] target_be_o,
    input logic target_rsp_valid_i,
    output logic target_rsp_ready_o,
    input logic [DATA_WIDTH-1:0] target_rdata_i,
    input logic target_error_i
);
  typedef enum logic [2:0] {IDLE, SEND_TARGET, WAIT_TARGET, RESPOND, FLUSH} state_t;
  state_t state_q;
  logic [ADDRESS_WIDTH-1:0] addr_q;
  logic [DATA_WIDTH-1:0] wdata_q, rdata_q;
  logic [(DATA_WIDTH/8)-1:0] be_q;
  logic write_q, error_q, flush_after_response_q;
  integer unsigned wait_cycles_q;

  initial begin
    if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0 || MAX_WAIT_CYCLES < 1)
      $fatal(1, "invalid processor memory backend parameters");
  end

  assign req_ready_o = rst_ni && state_q == IDLE && !cancel_valid_i;
  assign target_req_valid_o = state_q == SEND_TARGET && !cancel_valid_i;
  assign target_write_o = write_q;
  assign target_addr_o = addr_q;
  assign target_wdata_o = wdata_q;
  assign target_be_o = be_q;
  assign target_rsp_ready_o = state_q == WAIT_TARGET || state_q == FLUSH ||
                              (state_q == SEND_TARGET && target_req_ready_i);
  assign rsp_valid_o = state_q == RESPOND;
  assign rsp_rdata_o = rdata_q;
  assign rsp_error_o = error_q;
  assign target_flush_o = state_q == FLUSH;
  assign cancel_ready_o = cancel_valid_i &&
                          (state_q == IDLE || state_q == SEND_TARGET ||
                           (state_q == RESPOND && !flush_after_response_q) ||
                           state_q == FLUSH);

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      state_q <= IDLE;
      addr_q <= '0;
      wdata_q <= '0;
      be_q <= '0;
      write_q <= 1'b0;
      rdata_q <= '0;
      error_q <= 1'b0;
      flush_after_response_q <= 1'b0;
      wait_cycles_q <= 0;
    end else begin
      case (state_q)
        IDLE: begin
          wait_cycles_q <= 0;
          flush_after_response_q <= 1'b0;
          if (req_valid_i && req_ready_o) begin
            addr_q <= req_addr_i;
            wdata_q <= req_wdata_i;
            be_q <= req_be_i;
            write_q <= req_write_i;
            if (!req_mapped_i) begin
              rdata_q <= '0;
              error_q <= 1'b1;
              state_q <= RESPOND;
            end else begin
              state_q <= SEND_TARGET;
            end
          end
        end
        SEND_TARGET: begin
          if (cancel_valid_i) begin
            state_q <= IDLE;
          end else if (target_req_ready_i) begin
            wait_cycles_q <= 0;
            if (target_rsp_valid_i) begin
              rdata_q <= target_rdata_i;
              error_q <= target_error_i;
              state_q <= RESPOND;
            end else begin
              state_q <= WAIT_TARGET;
            end
          end else if (wait_cycles_q + 1 >= MAX_WAIT_CYCLES) begin
            rdata_q <= '0;
            error_q <= 1'b1;
            state_q <= RESPOND;
          end else begin
            wait_cycles_q <= wait_cycles_q + 1;
          end
        end
        WAIT_TARGET: begin
          if (cancel_valid_i) begin
            state_q <= FLUSH;
          end else if (target_rsp_valid_i) begin
            rdata_q <= target_rdata_i;
            error_q <= target_error_i;
            state_q <= RESPOND;
          end else if (wait_cycles_q + 1 >= MAX_WAIT_CYCLES) begin
            rdata_q <= '0;
            error_q <= 1'b1;
            flush_after_response_q <= 1'b1;
            state_q <= RESPOND;
          end else begin
            wait_cycles_q <= wait_cycles_q + 1;
          end
        end
        RESPOND: begin
          if (cancel_valid_i || rsp_ready_i) begin
            if (flush_after_response_q) state_q <= FLUSH;
            else state_q <= IDLE;
          end
        end
        FLUSH: begin
          flush_after_response_q <= 1'b0;
          state_q <= IDLE;
        end
        default: state_q <= IDLE;
      endcase
    end
  end
endmodule
