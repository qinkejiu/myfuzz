module processor_memory_arbiter #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer MAX_WAIT_CYCLES = 16,
    parameter bit INITIATOR0_READ_ONLY = 1'b0,
    parameter bit INITIATOR1_READ_ONLY = 1'b0
) (
    input  logic clk_i,
    input  logic rst_ni,

    input  logic i0_req_valid_i,
    output logic i0_req_ready_o,
    input  logic i0_req_write_i,
    input  logic [ADDRESS_WIDTH-1:0] i0_req_addr_i,
    input  logic [DATA_WIDTH-1:0] i0_req_wdata_i,
    input  logic [(DATA_WIDTH/8)-1:0] i0_req_be_i,
    input  logic i0_req_mapped_i,
    output logic i0_rsp_valid_o,
    input  logic i0_rsp_ready_i,
    output logic [DATA_WIDTH-1:0] i0_rsp_rdata_o,
    output logic i0_rsp_error_o,

    input  logic i1_req_valid_i,
    output logic i1_req_ready_o,
    input  logic i1_req_write_i,
    input  logic [ADDRESS_WIDTH-1:0] i1_req_addr_i,
    input  logic [DATA_WIDTH-1:0] i1_req_wdata_i,
    input  logic [(DATA_WIDTH/8)-1:0] i1_req_be_i,
    input  logic i1_req_mapped_i,
    output logic i1_rsp_valid_o,
    input  logic i1_rsp_ready_i,
    output logic [DATA_WIDTH-1:0] i1_rsp_rdata_o,
    output logic i1_rsp_error_o,

    output logic req_valid_o,
    input  logic req_ready_i,
    output logic req_write_o,
    output logic [ADDRESS_WIDTH-1:0] req_addr_o,
    output logic [DATA_WIDTH-1:0] req_wdata_o,
    output logic [(DATA_WIDTH/8)-1:0] req_be_o,
    input  logic rsp_valid_i,
    output logic rsp_ready_o,
    input  logic [DATA_WIDTH-1:0] rsp_rdata_i,
    input  logic rsp_error_i,
    output logic cancel_valid_o,
    input  logic cancel_ready_i
);
  typedef enum logic [2:0] {RESET_FLUSH, IDLE, SEND, WAIT_RSP, RESPOND, CANCEL} state_t;
  state_t state_q;
  logic owner_q, prefer_i1_q, mapped_q, write_q, cancel_after_response_q;
  logic [ADDRESS_WIDTH-1:0] addr_q;
  logic [DATA_WIDTH-1:0] wdata_q, response_data_q;
  logic [(DATA_WIDTH/8)-1:0] be_q;
  logic response_error_q;
  integer unsigned wait_cycles_q;

  initial begin
    if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0 || MAX_WAIT_CYCLES < 1)
      $fatal(1, "invalid processor_memory_arbiter parameters");
  end

  always_comb begin
    i0_req_ready_o = 1'b0;
    i1_req_ready_o = 1'b0;
    if (state_q == IDLE) begin
      if (i0_req_valid_i && i1_req_valid_i) begin
        if (prefer_i1_q) i1_req_ready_o = 1'b1;
        else i0_req_ready_o = 1'b1;
      end else if (i0_req_valid_i) begin
        i0_req_ready_o = 1'b1;
      end else if (i1_req_valid_i) begin
        i1_req_ready_o = 1'b1;
      end
    end
  end

  assign req_valid_o = (state_q == SEND) && mapped_q &&
                       !(write_q && (owner_q ? INITIATOR1_READ_ONLY : INITIATOR0_READ_ONLY));
  assign req_write_o = write_q;
  assign req_addr_o = addr_q;
  assign req_wdata_o = wdata_q;
  assign req_be_o = be_q;
  assign rsp_ready_o = (state_q == WAIT_RSP) ||
                       ((state_q == SEND) && req_valid_o && req_ready_i) ||
                       (state_q == CANCEL);
  assign cancel_valid_o = (state_q == RESET_FLUSH) || (state_q == CANCEL);

  assign i0_rsp_valid_o = (state_q == RESPOND) && !owner_q;
  assign i1_rsp_valid_o = (state_q == RESPOND) && owner_q;
  assign i0_rsp_rdata_o = response_data_q;
  assign i1_rsp_rdata_o = response_data_q;
  assign i0_rsp_error_o = response_error_q;
  assign i1_rsp_error_o = response_error_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      state_q <= RESET_FLUSH;
      owner_q <= 1'b0;
      prefer_i1_q <= 1'b0;
      mapped_q <= 1'b0;
      write_q <= 1'b0;
      addr_q <= '0;
      wdata_q <= '0;
      be_q <= '0;
      response_data_q <= '0;
      response_error_q <= 1'b0;
      cancel_after_response_q <= 1'b0;
      wait_cycles_q <= 0;
    end else begin
      case (state_q)
        RESET_FLUSH: begin
          if (cancel_ready_i) state_q <= IDLE;
        end
        IDLE: begin
          response_data_q <= '0;
          response_error_q <= 1'b0;
          cancel_after_response_q <= 1'b0;
          wait_cycles_q <= 0;
          if (i0_req_valid_i && i0_req_ready_o) begin
            owner_q <= 1'b0;
            prefer_i1_q <= 1'b1;
            mapped_q <= i0_req_mapped_i;
            write_q <= i0_req_write_i;
            addr_q <= i0_req_addr_i;
            wdata_q <= i0_req_wdata_i;
            be_q <= i0_req_be_i;
            state_q <= SEND;
          end else if (i1_req_valid_i && i1_req_ready_o) begin
            owner_q <= 1'b1;
            prefer_i1_q <= 1'b0;
            mapped_q <= i1_req_mapped_i;
            write_q <= i1_req_write_i;
            addr_q <= i1_req_addr_i;
            wdata_q <= i1_req_wdata_i;
            be_q <= i1_req_be_i;
            state_q <= SEND;
          end
        end
        SEND: begin
          if (!mapped_q || (write_q && (owner_q ? INITIATOR1_READ_ONLY : INITIATOR0_READ_ONLY))) begin
            response_data_q <= '0;
            response_error_q <= 1'b1;
            state_q <= RESPOND;
          end else if (req_valid_o && req_ready_i) begin
            wait_cycles_q <= 0;
            if (rsp_valid_i) begin
              response_data_q <= rsp_rdata_i;
              response_error_q <= rsp_error_i;
              state_q <= RESPOND;
            end else begin
              state_q <= WAIT_RSP;
            end
          end else if (wait_cycles_q + 1 >= MAX_WAIT_CYCLES) begin
            response_data_q <= '0;
            response_error_q <= 1'b1;
            cancel_after_response_q <= 1'b0;
            state_q <= RESPOND;
          end else begin
            wait_cycles_q <= wait_cycles_q + 1;
          end
        end
        WAIT_RSP: begin
          if (rsp_valid_i) begin
            response_data_q <= rsp_rdata_i;
            response_error_q <= rsp_error_i;
            state_q <= RESPOND;
          end else if (wait_cycles_q + 1 >= MAX_WAIT_CYCLES) begin
            response_data_q <= '0;
            response_error_q <= 1'b1;
            cancel_after_response_q <= 1'b1;
            state_q <= RESPOND;
          end else begin
            wait_cycles_q <= wait_cycles_q + 1;
          end
        end
        RESPOND: begin
          if ((!owner_q && i0_rsp_ready_i) || (owner_q && i1_rsp_ready_i)) begin
            if (cancel_after_response_q) state_q <= CANCEL;
            else state_q <= IDLE;
          end
        end
        CANCEL: begin
          if (rsp_valid_i || cancel_ready_i) begin
            cancel_after_response_q <= 1'b0;
            state_q <= IDLE;
          end
        end
        default: state_q <= IDLE;
      endcase
    end
  end
endmodule
