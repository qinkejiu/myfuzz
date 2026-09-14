// One-outstanding processor-memory beat to APB3 bridge.
// The bridge drives a real APB target through setup/access phases and keeps the
// response asserted until the upstream beat consumer accepts it.
module processor_apb_bridge #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer APB_ADDR_WIDTH = 12,
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input logic clk_i,
    input logic rst_ni,
    input logic req_valid_i,
    output logic req_ready_o,
    input logic req_write_i,
    input logic [ADDRESS_WIDTH-1:0] req_addr_i,
    input logic [31:0] req_wdata_i,
    input logic [3:0] req_be_i,
    output logic rsp_valid_o,
    input logic rsp_ready_i,
    output logic [31:0] rsp_rdata_o,
    output logic rsp_error_o,
    output logic [APB_ADDR_WIDTH-1:0] paddr_o,
    output logic [31:0] pwdata_o,
    output logic pwrite_o,
    output logic psel_o,
    output logic penable_o,
    input logic [31:0] prdata_i,
    input logic pready_i,
    input logic pslverr_i
);
  typedef enum logic [1:0] {IDLE, SETUP, ACCESS, RESPOND} state_t;
  state_t state_q;
  logic write_q;
  logic [APB_ADDR_WIDTH-1:0] addr_q;
  logic [31:0] wdata_q;
  logic [31:0] rdata_q;
  logic error_q;
  localparam integer WAIT_COUNTER_WIDTH =
      (MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(MAX_WAIT_CYCLES);
  localparam logic [WAIT_COUNTER_WIDTH-1:0] WAIT_TIMEOUT_VALUE =
      WAIT_COUNTER_WIDTH'(MAX_WAIT_CYCLES - 1);
  logic [WAIT_COUNTER_WIDTH-1:0] wait_count_q;

  initial begin
    if (ADDRESS_WIDTH < 1 || APB_ADDR_WIDTH < 1 || MAX_WAIT_CYCLES < 1)
      $fatal(1, "invalid processor APB bridge parameters");
  end

  assign req_ready_o = rst_ni && state_q == IDLE;
  assign rsp_valid_o = state_q == RESPOND;
  assign rsp_rdata_o = rdata_q;
  assign rsp_error_o = error_q;
  assign paddr_o = addr_q;
  assign pwdata_o = wdata_q;
  assign pwrite_o = write_q;
  assign psel_o = (state_q == SETUP) || (state_q == ACCESS);
  assign penable_o = state_q == ACCESS;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      state_q <= IDLE;
      write_q <= 1'b0;
      addr_q <= '0;
      wdata_q <= '0;
      rdata_q <= '0;
      error_q <= 1'b0;
      wait_count_q <= '0;
    end else begin
      case (state_q)
        IDLE: begin
          wait_count_q <= '0;
          if (req_valid_i && req_ready_o) begin
            if (req_write_i && req_be_i != 4'hf) begin
              // APB3 has no byte strobe.  Refuse a partial side-effecting
              // write instead of silently turning it into a full write.
              write_q <= 1'b0;
              rdata_q <= '0;
              error_q <= 1'b1;
              state_q <= RESPOND;
            end else begin
              write_q <= req_write_i;
              // Assignment sizing performs the explicit low-bit truncation
              // (or zero extension) for unusual parameter combinations too;
              // avoid an out-of-range part-select when ADDRESS_WIDTH is
              // narrower than APB_ADDR_WIDTH.
              addr_q <= req_addr_i;
              wdata_q <= req_wdata_i;
              rdata_q <= '0;
              error_q <= 1'b0;
              wait_count_q <= '0;
              state_q <= SETUP;
            end
          end
        end
        SETUP: begin
          wait_count_q <= '0;
          state_q <= ACCESS;
        end
        ACCESS: begin
          if (pready_i) begin
            rdata_q <= write_q ? '0 : prdata_i;
            error_q <= pslverr_i;
            wait_count_q <= '0;
            state_q <= RESPOND;
          end else if (wait_count_q == WAIT_TIMEOUT_VALUE) begin
            // APB has no cancellation handshake.  After the bounded access
            // window, deassert PSEL/PENABLE and complete the beat as an error;
            // this prevents an unresponsive target from occupying the shared
            // SoC fabric forever.
            rdata_q <= '0;
            error_q <= 1'b1;
            wait_count_q <= '0;
            state_q <= RESPOND;
          end else begin
            wait_count_q <= wait_count_q + 1'b1;
          end
        end
        RESPOND: begin
          wait_count_q <= '0;
          if (rsp_ready_i) state_q <= IDLE;
        end
        default: state_q <= IDLE;
      endcase
    end
  end
endmodule
