// Single outstanding aligned full-word AHB-Lite manager for a register target.
// Address/control are accepted before write data; response is sampled only in
// DATA. HREADYIN is the single-target fabric's HREADYOUT, not an invented ACK.
module ahb_lite_mmio_target #(parameter integer MAX_WAIT_CYCLES=16)(
  input logic clk_i, rst_ni,
  input logic req_valid_i, req_write_i,
  input logic [31:0] req_addr_i, req_wdata_i,
  input logic [3:0] req_be_i,
  output logic req_ready_o, rsp_valid_o,
  input logic rsp_ready_i,
  output logic [31:0] rsp_rdata_o,
  output logic rsp_error_o,
  output logic [31:0] haddr, hwdata,
  output logic hsel, hwrite, hreadyin,
  output logic [1:0] htrans,
  output logic [2:0] hsize,
  input logic hresp, hreadyout,
  input logic [31:0] hrdata
);
  typedef enum logic [1:0] {IDLE, ADDRESS, DATA, RESPONSE} state_t;
  state_t state_q;
  logic [31:0] addr_q, data_q;
  logic write_q;
  integer waits;
  assign req_ready_o = rst_ni && state_q == IDLE;
  assign rsp_valid_o = rst_ni && state_q == RESPONSE;
  assign haddr = addr_q;
  assign hwdata = data_q;
  assign hsel = rst_ni && state_q == ADDRESS;
  assign hwrite = write_q;
  assign htrans = hsel ? 2'b10 : 2'b00;
  assign hsize = 3'b010;
  assign hreadyin = hreadyout;
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      state_q <= IDLE; addr_q <= 0; data_q <= 0; write_q <= 0;
      rsp_rdata_o <= 0; rsp_error_o <= 0; waits <= 0;
    end else case (state_q)
      IDLE: if (req_valid_i) begin
        addr_q <= req_addr_i; data_q <= req_wdata_i; write_q <= req_write_i;
        waits <= 0; rsp_error_o <= 0;
        if (req_addr_i[1:0] != 0 || req_be_i != 4'hf || req_addr_i >= 4096) begin
          rsp_error_o <= 1; rsp_rdata_o <= 0; state_q <= RESPONSE;
        end else state_q <= ADDRESS;
      end
      ADDRESS: if (hreadyout) begin state_q <= DATA; waits <= 0; end
        else if (waits >= MAX_WAIT_CYCLES-1) begin
          rsp_error_o <= 1; rsp_rdata_o <= 0; state_q <= RESPONSE;
        end else waits <= waits+1;
      DATA: if (hreadyout) begin
          rsp_rdata_o <= hrdata; rsp_error_o <= hresp; state_q <= RESPONSE;
        end else if (waits >= MAX_WAIT_CYCLES-1) begin
          rsp_error_o <= 1; rsp_rdata_o <= 0; state_q <= RESPONSE;
        end else waits <= waits+1;
      RESPONSE: if (rsp_ready_i) state_q <= IDLE;
      default: state_q <= IDLE;
    endcase
  end
endmodule
