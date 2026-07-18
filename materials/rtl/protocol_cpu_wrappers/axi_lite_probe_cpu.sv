// Dependency-free AXI-Lite probe CPU master for AutoTop protocol testing.
//
// This is not a software-programmed core. It is a CPU-role protocol initiator
// used to validate that generated AXI-Lite SoCs are not tied to one fixed CPU
// module and port convention.
module axi_lite_probe_cpu #(
  parameter int ACCESS_COUNT = 1,
  parameter logic [32*ACCESS_COUNT-1:0] ACCESS_ADDRS = 32'h0000_0000,
  parameter logic [32*ACCESS_COUNT-1:0] ACCESS_WDATA = 32'h5a00_0000,
  parameter logic [ACCESS_COUNT-1:0] WRITE_ENABLES = {ACCESS_COUNT{1'b1}},
  parameter logic [ACCESS_COUNT-1:0] READ_ENABLES = {ACCESS_COUNT{1'b1}}
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic        trap_o,

  output logic        awvalid_o,
  input  logic        awready_i,
  output logic [31:0] awaddr_o,
  output logic [2:0]  awprot_o,
  output logic        wvalid_o,
  input  logic        wready_i,
  output logic [31:0] wdata_o,
  output logic [3:0]  wstrb_o,
  input  logic        bvalid_i,
  output logic        bready_o,
  input  logic [1:0]  bresp_i,

  output logic        arvalid_o,
  input  logic        arready_i,
  output logic [31:0] araddr_o,
  output logic [2:0]  arprot_o,
  input  logic        rvalid_i,
  output logic        rready_o,
  input  logic [31:0] rdata_i,
  input  logic [1:0]  rresp_i
);
  typedef enum logic [2:0] {
    STATE_WRITE_ADDR,
    STATE_WRITE_RESP,
    STATE_READ_ADDR,
    STATE_READ_RESP,
    STATE_NEXT,
    STATE_DONE
  } state_e;

  state_e state_q;
  int unsigned access_idx_q;
  logic [31:0] current_addr;
  logic [31:0] current_wdata;

  assign current_addr = ACCESS_ADDRS[access_idx_q * 32 +: 32];
  assign current_wdata = ACCESS_WDATA[access_idx_q * 32 +: 32];

  function automatic state_e start_state(input int unsigned idx);
    if (idx >= ACCESS_COUNT) begin
      start_state = STATE_DONE;
    end else if (WRITE_ENABLES[idx]) begin
      start_state = STATE_WRITE_ADDR;
    end else if (READ_ENABLES[idx]) begin
      start_state = STATE_READ_ADDR;
    end else begin
      start_state = STATE_NEXT;
    end
  endfunction

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      access_idx_q <= 0;
      state_q <= start_state(0);
    end else begin
      unique case (state_q)
        STATE_WRITE_ADDR: begin
          if (awvalid_o && awready_i && wvalid_o && wready_i) begin
            state_q <= STATE_WRITE_RESP;
          end
        end
        STATE_WRITE_RESP: begin
          if (bvalid_i && bready_o) begin
            state_q <= READ_ENABLES[access_idx_q] ? STATE_READ_ADDR : STATE_NEXT;
          end
        end
        STATE_READ_ADDR: begin
          if (arvalid_o && arready_i) begin
            state_q <= STATE_READ_RESP;
          end
        end
        STATE_READ_RESP: begin
          if (rvalid_i && rready_o) begin
            state_q <= STATE_NEXT;
          end
        end
        STATE_NEXT: begin
          access_idx_q <= access_idx_q + 1'b1;
          state_q <= start_state(access_idx_q + 1'b1);
        end
        default: begin
          state_q <= STATE_DONE;
        end
      endcase
    end
  end

  assign awvalid_o = state_q == STATE_WRITE_ADDR;
  assign awaddr_o = current_addr;
  assign awprot_o = 3'b000;
  assign wvalid_o = state_q == STATE_WRITE_ADDR;
  assign wdata_o = current_wdata;
  assign wstrb_o = 4'hf;
  assign bready_o = state_q == STATE_WRITE_RESP;

  assign arvalid_o = state_q == STATE_READ_ADDR;
  assign araddr_o = current_addr;
  assign arprot_o = 3'b000;
  assign rready_o = state_q == STATE_READ_RESP;

  assign trap_o = 1'b0;

  logic unused_responses;
  assign unused_responses = ^{bresp_i, rdata_i, rresp_i};
endmodule
