// Generated from source-backed interface annotations. Do not edit.
module generic_composition_top (
    input logic p_383812aaf51f5c02,
    input logic [63:0] p_4cd92fc9a17d34ce,
    input logic [1:0] p_75d018274eec347f,
    input logic p_76a7e203dba8986e,
    input logic p_98965e3be3553707,
    input logic p_bb4e1f746b3702c1,
    input logic p_d845d6b234ff56a9,
    input logic [63:0] p_e036cb8b170a5306
);
  logic [469:0] source_e7cde6a4ffc55876;
  logic [209:0] source_07a9bde03ff39377;
  logic processor_adapter_reset_n;
  logic [1:0] processor_adapter_reset_sync_q;
  always_ff @(posedge p_76a7e203dba8986e or negedge p_98965e3be3553707) begin
    if (!p_98965e3be3553707) processor_adapter_reset_sync_q <= 2'b00;
    else processor_adapter_reset_sync_q <= {processor_adapter_reset_sync_q[0], 1'b1};
  end
  assign processor_adapter_reset_n = processor_adapter_reset_sync_q[1];
  cva6 u_4fc0e2ef899df534 (
        .boot_addr_i(p_e036cb8b170a5306),
        .clk_i(p_76a7e203dba8986e),
        .debug_req_i(p_bb4e1f746b3702c1),
        .hart_id_i(p_4cd92fc9a17d34ce),
        .ipi_i(p_383812aaf51f5c02),
        .irq_i(p_75d018274eec347f),
        .noc_req_o(source_e7cde6a4ffc55876),
        .noc_resp_i(source_07a9bde03ff39377),
        .rst_ni(p_98965e3be3553707),
        .time_irq_i(p_d845d6b234ff56a9)
  );
  logic r_08a25da31160fb91_req_valid;
  logic r_08a25da31160fb91_req_ready;
  logic r_08a25da31160fb91_write;
  logic [63:0] r_08a25da31160fb91_addr;
  logic [63:0] r_08a25da31160fb91_wdata;
  logic [7:0] r_08a25da31160fb91_be;
  logic r_08a25da31160fb91_rsp_valid;
  logic r_08a25da31160fb91_rsp_ready;
  logic [63:0] r_08a25da31160fb91_rdata;
  logic r_08a25da31160fb91_error;
  logic r_08a25da31160fb91_mapped;
  assign r_08a25da31160fb91_mapped = (r_08a25da31160fb91_addr >= 64'h0 && r_08a25da31160fb91_addr < 64'h1000);
  axi4_processor_memory_adapter #(
        .ADDRESS_WIDTH(64),
        .DATA_WIDTH(64),
        .ID_WIDTH(4),
        .USER_WIDTH(64)
  ) u_r_08a25da31160fb91 (
        .clk_i(p_76a7e203dba8986e),
        .rst_ni(processor_adapter_reset_n),
        .araddr_i(source_e7cde6a4ffc55876[158:95]),
        .arburst_i(source_e7cde6a4ffc55876[83:82]),
        .arcache_i(source_e7cde6a4ffc55876[80:77]),
        .arid_i(source_e7cde6a4ffc55876[162:159]),
        .arlen_i(source_e7cde6a4ffc55876[94:87]),
        .arlock_i(source_e7cde6a4ffc55876[81:81]),
        .arprot_i(source_e7cde6a4ffc55876[76:74]),
        .arqos_i(source_e7cde6a4ffc55876[73:70]),
        .arready_o(source_07a9bde03ff39377[208:208]),
        .arregion_i(source_e7cde6a4ffc55876[69:66]),
        .arsize_i(source_e7cde6a4ffc55876[86:84]),
        .aruser_i(source_e7cde6a4ffc55876[65:2]),
        .arvalid_i(source_e7cde6a4ffc55876[1:1]),
        .awaddr_i(source_e7cde6a4ffc55876[465:402]),
        .awatop_i(source_e7cde6a4ffc55876[372:367]),
        .awburst_i(source_e7cde6a4ffc55876[390:389]),
        .awcache_i(source_e7cde6a4ffc55876[387:384]),
        .awid_i(source_e7cde6a4ffc55876[469:466]),
        .awlen_i(source_e7cde6a4ffc55876[401:394]),
        .awlock_i(source_e7cde6a4ffc55876[388:388]),
        .awprot_i(source_e7cde6a4ffc55876[383:381]),
        .awqos_i(source_e7cde6a4ffc55876[380:377]),
        .awready_o(source_07a9bde03ff39377[209:209]),
        .awregion_i(source_e7cde6a4ffc55876[376:373]),
        .awsize_i(source_e7cde6a4ffc55876[393:391]),
        .awuser_i(source_e7cde6a4ffc55876[366:303]),
        .awvalid_i(source_e7cde6a4ffc55876[302:302]),
        .bid_o(source_07a9bde03ff39377[205:202]),
        .bready_i(source_e7cde6a4ffc55876[163:163]),
        .bresp_o(source_07a9bde03ff39377[201:200]),
        .buser_o(source_07a9bde03ff39377[199:136]),
        .bvalid_o(source_07a9bde03ff39377[206:206]),
        .rdata_o(source_07a9bde03ff39377[130:67]),
        .rid_o(source_07a9bde03ff39377[134:131]),
        .rlast_o(source_07a9bde03ff39377[64:64]),
        .rready_i(source_e7cde6a4ffc55876[0:0]),
        .rresp_o(source_07a9bde03ff39377[66:65]),
        .ruser_o(source_07a9bde03ff39377[63:0]),
        .rvalid_o(source_07a9bde03ff39377[135:135]),
        .wdata_i(source_e7cde6a4ffc55876[301:238]),
        .wlast_i(source_e7cde6a4ffc55876[229:229]),
        .wready_o(source_07a9bde03ff39377[207:207]),
        .wstrb_i(source_e7cde6a4ffc55876[237:230]),
        .wuser_i(source_e7cde6a4ffc55876[228:165]),
        .wvalid_i(source_e7cde6a4ffc55876[164:164]),
        .req_valid_o(r_08a25da31160fb91_req_valid),
        .req_ready_i(r_08a25da31160fb91_req_ready),
        .req_write_o(r_08a25da31160fb91_write),
        .req_addr_o(r_08a25da31160fb91_addr),
        .req_wdata_o(r_08a25da31160fb91_wdata),
        .req_be_o(r_08a25da31160fb91_be),
        .rsp_valid_i(r_08a25da31160fb91_rsp_valid),
        .rsp_ready_o(r_08a25da31160fb91_rsp_ready),
        .rsp_rdata_i(r_08a25da31160fb91_rdata),
        .rsp_error_i(r_08a25da31160fb91_error)
  );
  logic backend_req_valid;
  logic backend_req_ready;
  logic backend_write;
  logic [63:0] backend_addr;
  logic [63:0] backend_wdata;
  logic [7:0] backend_be;
  logic backend_rsp_valid;
  logic backend_rsp_ready;
  logic [63:0] backend_rdata;
  logic backend_error;
  logic backend_cancel_valid;
  logic backend_cancel_ready;
  logic processor_backend_reset_n;
  assign processor_backend_reset_n = p_98965e3be3553707;
  assign backend_req_valid = r_08a25da31160fb91_req_valid;
  assign backend_write = r_08a25da31160fb91_write;
  assign backend_addr = r_08a25da31160fb91_addr;
  assign backend_wdata = r_08a25da31160fb91_wdata;
  assign backend_be = r_08a25da31160fb91_be;
  assign backend_rsp_ready = r_08a25da31160fb91_rsp_ready;
  assign r_08a25da31160fb91_req_ready = backend_req_ready;
  assign r_08a25da31160fb91_rsp_valid = backend_rsp_valid;
  assign r_08a25da31160fb91_rdata = backend_rdata;
  assign r_08a25da31160fb91_error = backend_error;
  assign backend_cancel_valid = 1'b0;
  logic backend_target_req_valid;
  logic backend_target_req_ready;
  logic backend_target_write;
  logic [63:0] backend_target_addr;
  logic [63:0] backend_target_wdata;
  logic [7:0] backend_target_be;
  logic backend_target_rsp_valid;
  logic backend_target_rsp_ready;
  logic [63:0] backend_target_rdata;
  logic backend_target_error;
  logic backend_target_flush;
  logic c_b6e969160e7b57d2_select;
  assign c_b6e969160e7b57d2_select = backend_target_addr >= 64'h0 && backend_target_addr < 64'h1000;
  logic c_b6e969160e7b57d2_req_valid;
  logic c_b6e969160e7b57d2_req_ready;
  logic c_b6e969160e7b57d2_write;
  logic [63:0] c_b6e969160e7b57d2_addr;
  logic [63:0] c_b6e969160e7b57d2_wdata;
  logic [7:0] c_b6e969160e7b57d2_be;
  logic c_b6e969160e7b57d2_rsp_valid;
  logic c_b6e969160e7b57d2_rsp_ready;
  logic [63:0] c_b6e969160e7b57d2_rdata;
  logic c_b6e969160e7b57d2_error;
  assign c_b6e969160e7b57d2_req_valid = backend_target_req_valid && c_b6e969160e7b57d2_select;
  assign c_b6e969160e7b57d2_write = backend_target_write;
  assign c_b6e969160e7b57d2_addr = backend_target_addr;
  assign c_b6e969160e7b57d2_wdata = backend_target_wdata;
  assign c_b6e969160e7b57d2_be = backend_target_be;
  assign c_b6e969160e7b57d2_rsp_ready = backend_target_rsp_ready && c_b6e969160e7b57d2_select;
  logic c_b6e969160e7b57d2_reset_n;
  assign c_b6e969160e7b57d2_reset_n = p_98965e3be3553707;
  logic c_b6e969160e7b57d2_flush_reset;
  assign c_b6e969160e7b57d2_flush_reset = c_b6e969160e7b57d2_reset_n && !(backend_target_flush && c_b6e969160e7b57d2_select);
  riscv_boot_memory_64 u_c_b6e969160e7b57d2 (
        .req_valid(c_b6e969160e7b57d2_req_valid),
        .req_ready(c_b6e969160e7b57d2_req_ready),
        .write(c_b6e969160e7b57d2_write),
        .addr(c_b6e969160e7b57d2_addr),
        .wdata(c_b6e969160e7b57d2_wdata),
        .be(c_b6e969160e7b57d2_be),
        .rsp_valid(c_b6e969160e7b57d2_rsp_valid),
        .rsp_ready(c_b6e969160e7b57d2_rsp_ready),
        .rdata(c_b6e969160e7b57d2_rdata),
        .error(c_b6e969160e7b57d2_error),
        .clock(p_76a7e203dba8986e),
        .reset(c_b6e969160e7b57d2_flush_reset)
  );
  assign backend_target_req_ready = (c_b6e969160e7b57d2_select && c_b6e969160e7b57d2_req_ready);
  assign backend_target_rsp_valid = (c_b6e969160e7b57d2_select && c_b6e969160e7b57d2_rsp_valid);
  assign backend_target_rdata = ((c_b6e969160e7b57d2_select && c_b6e969160e7b57d2_rsp_valid) ? c_b6e969160e7b57d2_rdata : '0);
  assign backend_target_error = ((c_b6e969160e7b57d2_select && c_b6e969160e7b57d2_rsp_valid) && c_b6e969160e7b57d2_error);
  myfuzz_processor_memory_backend u_processor_memory_backend (
        .clk_i(p_76a7e203dba8986e),
        .rst_ni(processor_backend_reset_n),
        .req_valid_i(backend_req_valid),
        .req_ready_o(backend_req_ready),
        .req_write_i(backend_write),
        .req_addr_i(backend_addr),
        .req_wdata_i(backend_wdata),
        .req_be_i(backend_be),
        .req_mapped_i(r_08a25da31160fb91_mapped),
        .rsp_valid_o(backend_rsp_valid),
        .rsp_ready_i(backend_rsp_ready),
        .rsp_rdata_o(backend_rdata),
        .rsp_error_o(backend_error),
        .cancel_valid_i(backend_cancel_valid),
        .cancel_ready_o(backend_cancel_ready),
        .target_flush_o(backend_target_flush),
        .target_req_valid_o(backend_target_req_valid),
        .target_req_ready_i(backend_target_req_ready),
        .target_write_o(backend_target_write),
        .target_addr_o(backend_target_addr),
        .target_wdata_o(backend_target_wdata),
        .target_be_o(backend_target_be),
        .target_rsp_valid_i(backend_target_rsp_valid),
        .target_rsp_ready_o(backend_target_rsp_ready),
        .target_rdata_i(backend_target_rdata),
        .target_error_i(backend_target_error)
  );
endmodule

module myfuzz_processor_memory_backend (
    input logic clk_i, input logic rst_ni,
    input logic req_valid_i, output logic req_ready_o,
    input logic req_write_i, input logic [63:0] req_addr_i,
    input logic [63:0] req_wdata_i,
    input logic [7:0] req_be_i, input logic req_mapped_i,
    output logic rsp_valid_o, input logic rsp_ready_i,
    output logic [63:0] rsp_rdata_o, output logic rsp_error_o,
    input logic cancel_valid_i, output logic cancel_ready_o,
    output logic target_flush_o,
    output logic target_req_valid_o, input logic target_req_ready_i,
    output logic target_write_o, output logic [63:0] target_addr_o,
    output logic [63:0] target_wdata_o,
    output logic [7:0] target_be_o,
    input logic target_rsp_valid_i, output logic target_rsp_ready_o,
    input logic [63:0] target_rdata_i, input logic target_error_i
);
  localparam integer MAX_WAIT_CYCLES = 16;
  typedef enum logic [2:0] {IDLE, SEND_TARGET, WAIT_TARGET, RESPOND, FLUSH} state_t;
  state_t state_q;
  logic [63:0] addr_q;
  logic [63:0] wdata_q, rdata_q;
  logic [7:0] be_q;
  logic write_q, error_q, flush_after_response_q;
  integer unsigned wait_cycles_q;
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
      state_q <= IDLE; addr_q <= '0; wdata_q <= '0; be_q <= '0;
      write_q <= 1'b0; rdata_q <= '0; error_q <= 1'b0;
      flush_after_response_q <= 1'b0; wait_cycles_q <= 0;
    end else begin
      case (state_q)
        IDLE: begin
          wait_cycles_q <= 0; flush_after_response_q <= 1'b0;
          if (req_valid_i && req_ready_o) begin
            addr_q <= req_addr_i; wdata_q <= req_wdata_i; be_q <= req_be_i;
            write_q <= req_write_i;
            if (!req_mapped_i) begin
              rdata_q <= '0; error_q <= 1'b1; state_q <= RESPOND;
            end else state_q <= SEND_TARGET;
          end
        end
        SEND_TARGET: begin
          if (cancel_valid_i) state_q <= IDLE;
          else if (target_req_ready_i) begin
            wait_cycles_q <= 0;
            if (target_rsp_valid_i) begin
              rdata_q <= target_rdata_i; error_q <= target_error_i;
              state_q <= RESPOND;
            end else state_q <= WAIT_TARGET;
          end else if (wait_cycles_q + 1 >= MAX_WAIT_CYCLES) begin
            rdata_q <= '0; error_q <= 1'b1; state_q <= RESPOND;
          end else begin
            wait_cycles_q <= wait_cycles_q + 1;
          end
        end
        WAIT_TARGET: begin
          if (cancel_valid_i) begin
            state_q <= FLUSH;
          end
          else if (target_rsp_valid_i) begin
            rdata_q <= target_rdata_i; error_q <= target_error_i;
            state_q <= RESPOND;
          end else if (wait_cycles_q + 1 >= MAX_WAIT_CYCLES) begin
            rdata_q <= '0; error_q <= 1'b1;
            flush_after_response_q <= 1'b1; state_q <= RESPOND;
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
          flush_after_response_q <= 1'b0; state_q <= IDLE;
        end
        default: state_q <= IDLE;
      endcase
    end
  end
endmodule
