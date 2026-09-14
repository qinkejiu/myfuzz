// One-outstanding processor-memory beat to APB3 bridge.
// The bridge drives a real APB target through setup/access phases and keeps the
// response asserted until the upstream beat consumer accepts it.
module processor_apb_bridge #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer APB_ADDR_WIDTH = 12,
    parameter integer ALLOW_PARTIAL_WRITE = 0
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
  logic [3:0] be_q;
  logic [31:0] rdata_q;
  logic error_q;

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
      be_q <= '0;
      rdata_q <= '0;
      error_q <= 1'b0;
    end else begin
      case (state_q)
        IDLE: begin
          if (req_valid_i && req_ready_o) begin
            if (req_write_i && !ALLOW_PARTIAL_WRITE && req_be_i != 4'hf) begin
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
              // When a target explicitly permits partial writes, disabled
              // lanes are driven as zero because this APB3 bridge has no
              // PSTRB output.  The default PULP APB3 profile rejects them.
              wdata_q <= {
                req_be_i[3] ? req_wdata_i[31:24] : 8'h00,
                req_be_i[2] ? req_wdata_i[23:16] : 8'h00,
                req_be_i[1] ? req_wdata_i[15:8] : 8'h00,
                req_be_i[0] ? req_wdata_i[7:0] : 8'h00
              };
              be_q <= req_be_i;
              rdata_q <= '0;
              error_q <= 1'b0;
              state_q <= SETUP;
            end
          end
        end
        SETUP: state_q <= ACCESS;
        ACCESS: begin
          if (pready_i) begin
            rdata_q <= prdata_i;
            error_q <= pslverr_i;
            state_q <= RESPOND;
          end
        end
        RESPOND: if (rsp_ready_i) state_q <= IDLE;
        default: state_q <= IDLE;
      endcase
    end
  end
endmodule
