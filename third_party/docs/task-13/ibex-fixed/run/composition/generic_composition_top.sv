// Generated from source-backed interface annotations. Do not edit.
module generic_composition_top (
    input logic p_0b3b30ccc88cc021,
    input logic p_1675d0ea821ed0fd,
    input logic p_44698aa8b04e6752,
    input logic p_48ce350cb465138b,
    input logic [31:0] p_4cd92fc9a17d34ce,
    input logic p_619e912101197846,
    input logic p_61aae37a0aca31e4,
    input logic [63:0] p_682f0ad4e3b9f3f9,
    input logic [3:0] p_6d17b9b611052f86,
    input logic [127:0] p_75cfcb7c955f748d,
    input logic p_76a7e203dba8986e,
    input logic [6:0] p_771fdce65f7e4270,
    input logic p_80240ac4c2da1227,
    input logic p_88de547440c710d0,
    input logic p_8a541c272dc7de03,
    input logic p_98965e3be3553707,
    input logic p_afe51855e2886000,
    input logic [3:0] p_b39e50b36d56f511,
    input logic p_b8a7cd262410caf5,
    input logic p_bb4e1f746b3702c1,
    input logic [6:0] p_c3bbc328aab2d3f0,
    input logic [31:0] p_e036cb8b170a5306,
    input logic [31:0] p_edbf1bb5dce303cf,
    input logic [14:0] p_ee300435f6caa83b,
    input logic [3:0] p_f0679b70d3982ecf,
    input logic [6:0] p_f77659d1ab76abfa,
    input logic [31:0] p_f81fe4356c222350
);
  logic [31:0] source_a0991ba5f96e7e0d;
  logic [3:0] source_c279fe70b912e3ec;
  logic source_4ab7bf607b064559;
  logic source_2d51b82a338cada1;
  logic [31:0] source_d79ab177f30f6f7d;
  logic source_8be4ca8dfba4edbc;
  logic source_5ffab7270e47daa6;
  logic [31:0] source_3db89f9f4dce4518;
  logic source_121d35a8d047d67a;
  logic [31:0] source_01808038df35b80c;
  logic source_0bd9de920986cf5c;
  logic source_7eb8f2c180e4b7db;
  logic [31:0] source_31e8a548777c1311;
  logic source_2ea8d72e701f4651;
  logic source_c8a5f75bcd336b47;
  logic processor_adapter_reset_n;
  logic [1:0] processor_adapter_reset_sync_q;
  always_ff @(posedge p_76a7e203dba8986e or negedge p_98965e3be3553707) begin
    if (!p_98965e3be3553707) processor_adapter_reset_sync_q <= 2'b00;
    else processor_adapter_reset_sync_q <= {processor_adapter_reset_sync_q[0], 1'b1};
  end
  assign processor_adapter_reset_n = processor_adapter_reset_sync_q[1];
  ibex_top #(
        .ICache(0),
        .PMPEnable(0),
        .RV32E(0),
        .SecureIbex(0)
  ) u_cb4b96b2f48423b1 (
        .boot_addr_i(p_e036cb8b170a5306),
        .cheriot_enable_i(p_b39e50b36d56f511),
        .clk_i(p_76a7e203dba8986e),
        .data_addr_o(source_a0991ba5f96e7e0d),
        .data_be_o(source_c279fe70b912e3ec),
        .data_err_i(source_4ab7bf607b064559),
        .data_gnt_i(source_2d51b82a338cada1),
        .data_rdata_i(source_d79ab177f30f6f7d),
        .data_rdata_intg_i(p_f77659d1ab76abfa),
        .data_req_o(source_8be4ca8dfba4edbc),
        .data_rvalid_i(source_5ffab7270e47daa6),
        .data_tag_i(p_619e912101197846),
        .data_wdata_o(source_3db89f9f4dce4518),
        .data_we_o(source_121d35a8d047d67a),
        .debug_req_i(p_bb4e1f746b3702c1),
        .fetch_enable_i(p_6d17b9b611052f86),
        .hart_id_i(p_4cd92fc9a17d34ce),
        .instr_addr_o(source_01808038df35b80c),
        .instr_err_i(source_0bd9de920986cf5c),
        .instr_gnt_i(source_7eb8f2c180e4b7db),
        .instr_rdata_i(source_31e8a548777c1311),
        .instr_rdata_intg_i(p_c3bbc328aab2d3f0),
        .instr_req_o(source_2ea8d72e701f4651),
        .instr_rvalid_i(source_c8a5f75bcd336b47),
        .irq_external_i(p_b8a7cd262410caf5),
        .irq_fast_i(p_ee300435f6caa83b),
        .irq_nm_i(p_afe51855e2886000),
        .irq_software_i(p_88de547440c710d0),
        .irq_timer_i(p_1675d0ea821ed0fd),
        .mcounteren_writable_i(p_f0679b70d3982ecf),
        .rst_ni(p_98965e3be3553707),
        .scan_rst_ni(p_44698aa8b04e6752),
        .scramble_key_i(p_75cfcb7c955f748d),
        .scramble_key_valid_i(p_8a541c272dc7de03),
        .scramble_nonce_i(p_682f0ad4e3b9f3f9),
        .test_en_i(p_61aae37a0aca31e4),
        .trvk_heap_base_addr_i(p_edbf1bb5dce303cf),
        .trvk_revbm_err_i(p_0b3b30ccc88cc021),
        .trvk_revbm_gnt_i(p_48ce350cb465138b),
        .trvk_revbm_rdata_i(p_f81fe4356c222350),
        .trvk_revbm_rdata_intg_i(p_771fdce65f7e4270),
        .trvk_revbm_rvalid_i(p_80240ac4c2da1227)
  );
  logic r_7c73d284941f1ad4_req_valid;
  logic r_7c73d284941f1ad4_req_ready;
  logic r_7c73d284941f1ad4_write;
  logic [31:0] r_7c73d284941f1ad4_addr;
  logic [31:0] r_7c73d284941f1ad4_wdata;
  logic [3:0] r_7c73d284941f1ad4_be;
  logic r_7c73d284941f1ad4_rsp_valid;
  logic r_7c73d284941f1ad4_rsp_ready;
  logic [31:0] r_7c73d284941f1ad4_rdata;
  logic r_7c73d284941f1ad4_error;
  logic r_7c73d284941f1ad4_mapped;
  assign r_7c73d284941f1ad4_mapped = (r_7c73d284941f1ad4_addr >= 32'h0 && r_7c73d284941f1ad4_addr < 32'h1000);
  obi_processor_memory_adapter #(
        .ADDRESS_WIDTH(32),
        .DATA_WIDTH(32),
        .HAS_BE(1),
        .HAS_ERROR(1),
        .READ_ONLY(0)
  ) u_r_7c73d284941f1ad4 (
        .clk_i(p_76a7e203dba8986e),
        .rst_ni(processor_adapter_reset_n),
        .addr_i(source_a0991ba5f96e7e0d),
        .be_i(source_c279fe70b912e3ec),
        .error_o(source_4ab7bf607b064559),
        .gnt_o(source_2d51b82a338cada1),
        .rdata_o(source_d79ab177f30f6f7d),
        .req_i(source_8be4ca8dfba4edbc),
        .rvalid_o(source_5ffab7270e47daa6),
        .wdata_i(source_3db89f9f4dce4518),
        .we_i(source_121d35a8d047d67a),
        .req_valid_o(r_7c73d284941f1ad4_req_valid),
        .req_ready_i(r_7c73d284941f1ad4_req_ready),
        .req_write_o(r_7c73d284941f1ad4_write),
        .req_addr_o(r_7c73d284941f1ad4_addr),
        .req_wdata_o(r_7c73d284941f1ad4_wdata),
        .req_be_o(r_7c73d284941f1ad4_be),
        .rsp_valid_i(r_7c73d284941f1ad4_rsp_valid),
        .rsp_ready_o(r_7c73d284941f1ad4_rsp_ready),
        .rsp_rdata_i(r_7c73d284941f1ad4_rdata),
        .rsp_error_i(r_7c73d284941f1ad4_error)
  );
  logic r_059f4844376642ae_req_valid;
  logic r_059f4844376642ae_req_ready;
  logic r_059f4844376642ae_write;
  logic [31:0] r_059f4844376642ae_addr;
  logic [31:0] r_059f4844376642ae_wdata;
  logic [3:0] r_059f4844376642ae_be;
  logic r_059f4844376642ae_rsp_valid;
  logic r_059f4844376642ae_rsp_ready;
  logic [31:0] r_059f4844376642ae_rdata;
  logic r_059f4844376642ae_error;
  logic r_059f4844376642ae_mapped;
  assign r_059f4844376642ae_mapped = (r_059f4844376642ae_addr >= 32'h0 && r_059f4844376642ae_addr < 32'h1000);
  obi_processor_memory_adapter #(
        .ADDRESS_WIDTH(32),
        .DATA_WIDTH(32),
        .HAS_BE(0),
        .HAS_ERROR(1),
        .READ_ONLY(1)
  ) u_r_059f4844376642ae (
        .clk_i(p_76a7e203dba8986e),
        .rst_ni(processor_adapter_reset_n),
        .addr_i(source_01808038df35b80c),
        .error_o(source_0bd9de920986cf5c),
        .gnt_o(source_7eb8f2c180e4b7db),
        .rdata_o(source_31e8a548777c1311),
        .req_i(source_2ea8d72e701f4651),
        .rvalid_o(source_c8a5f75bcd336b47),
        .req_valid_o(r_059f4844376642ae_req_valid),
        .req_ready_i(r_059f4844376642ae_req_ready),
        .req_write_o(r_059f4844376642ae_write),
        .req_addr_o(r_059f4844376642ae_addr),
        .req_wdata_o(r_059f4844376642ae_wdata),
        .req_be_o(r_059f4844376642ae_be),
        .rsp_valid_i(r_059f4844376642ae_rsp_valid),
        .rsp_ready_o(r_059f4844376642ae_rsp_ready),
        .rsp_rdata_i(r_059f4844376642ae_rdata),
        .rsp_error_i(r_059f4844376642ae_error)
  );
  logic backend_req_valid;
  logic backend_req_ready;
  logic backend_write;
  logic [31:0] backend_addr;
  logic [31:0] backend_wdata;
  logic [3:0] backend_be;
  logic backend_rsp_valid;
  logic backend_rsp_ready;
  logic [31:0] backend_rdata;
  logic backend_error;
  logic backend_cancel_valid;
  logic backend_cancel_ready;
  logic processor_backend_reset_n;
  assign processor_backend_reset_n = p_98965e3be3553707;
  logic processor_arbiter_reset_n;
  assign processor_arbiter_reset_n = p_98965e3be3553707;
  processor_memory_arbiter #(
        .ADDRESS_WIDTH(32), .DATA_WIDTH(32),
        .MAX_WAIT_CYCLES(16),
        .INITIATOR0_READ_ONLY(0), .INITIATOR1_READ_ONLY(1)
  ) u_processor_backend_arbiter (
        .clk_i(p_76a7e203dba8986e),
        .rst_ni(processor_arbiter_reset_n),
        .i0_req_valid_i(r_7c73d284941f1ad4_req_valid),
        .i0_req_ready_o(r_7c73d284941f1ad4_req_ready),
        .i0_req_write_i(r_7c73d284941f1ad4_write),
        .i0_req_addr_i(r_7c73d284941f1ad4_addr),
        .i0_req_wdata_i(r_7c73d284941f1ad4_wdata),
        .i0_req_be_i(r_7c73d284941f1ad4_be),
        .i0_req_mapped_i(r_7c73d284941f1ad4_mapped),
        .i0_rsp_valid_o(r_7c73d284941f1ad4_rsp_valid),
        .i0_rsp_ready_i(r_7c73d284941f1ad4_rsp_ready),
        .i0_rsp_rdata_o(r_7c73d284941f1ad4_rdata),
        .i0_rsp_error_o(r_7c73d284941f1ad4_error),
        .i1_req_valid_i(r_059f4844376642ae_req_valid),
        .i1_req_ready_o(r_059f4844376642ae_req_ready),
        .i1_req_write_i(r_059f4844376642ae_write),
        .i1_req_addr_i(r_059f4844376642ae_addr),
        .i1_req_wdata_i(r_059f4844376642ae_wdata),
        .i1_req_be_i(r_059f4844376642ae_be),
        .i1_req_mapped_i(r_059f4844376642ae_mapped),
        .i1_rsp_valid_o(r_059f4844376642ae_rsp_valid),
        .i1_rsp_ready_i(r_059f4844376642ae_rsp_ready),
        .i1_rsp_rdata_o(r_059f4844376642ae_rdata),
        .i1_rsp_error_o(r_059f4844376642ae_error),
        .req_valid_o(backend_req_valid),
        .req_ready_i(backend_req_ready),
        .req_write_o(backend_write),
        .req_addr_o(backend_addr),
        .req_wdata_o(backend_wdata),
        .req_be_o(backend_be),
        .rsp_valid_i(backend_rsp_valid),
        .rsp_ready_o(backend_rsp_ready),
        .rsp_rdata_i(backend_rdata),
        .rsp_error_i(backend_error),
        .cancel_valid_o(backend_cancel_valid),
        .cancel_ready_i(backend_cancel_ready)
  );
  logic backend_mapped;
  assign backend_mapped = (backend_addr >= 32'h0 && backend_addr < 32'h1000);
  logic backend_target_req_valid;
  logic backend_target_req_ready;
  logic backend_target_write;
  logic [31:0] backend_target_addr;
  logic [31:0] backend_target_wdata;
  logic [3:0] backend_target_be;
  logic backend_target_rsp_valid;
  logic backend_target_rsp_ready;
  logic [31:0] backend_target_rdata;
  logic backend_target_error;
  logic backend_target_flush;
  logic c_b6e969160e7b57d2_select;
  assign c_b6e969160e7b57d2_select = backend_target_addr >= 32'h0 && backend_target_addr < 32'h1000;
  logic c_b6e969160e7b57d2_req_valid;
  logic c_b6e969160e7b57d2_req_ready;
  logic c_b6e969160e7b57d2_write;
  logic [31:0] c_b6e969160e7b57d2_addr;
  logic [31:0] c_b6e969160e7b57d2_wdata;
  logic [3:0] c_b6e969160e7b57d2_be;
  logic c_b6e969160e7b57d2_rsp_valid;
  logic c_b6e969160e7b57d2_rsp_ready;
  logic [31:0] c_b6e969160e7b57d2_rdata;
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
  riscv_boot_memory_32 u_c_b6e969160e7b57d2 (
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
        .req_mapped_i(backend_mapped),
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
    input logic req_write_i, input logic [31:0] req_addr_i,
    input logic [31:0] req_wdata_i,
    input logic [3:0] req_be_i, input logic req_mapped_i,
    output logic rsp_valid_o, input logic rsp_ready_i,
    output logic [31:0] rsp_rdata_o, output logic rsp_error_o,
    input logic cancel_valid_i, output logic cancel_ready_o,
    output logic target_flush_o,
    output logic target_req_valid_o, input logic target_req_ready_i,
    output logic target_write_o, output logic [31:0] target_addr_o,
    output logic [31:0] target_wdata_o,
    output logic [3:0] target_be_o,
    input logic target_rsp_valid_i, output logic target_rsp_ready_o,
    input logic [31:0] target_rdata_i, input logic target_error_i
);
  localparam integer MAX_WAIT_CYCLES = 16;
  typedef enum logic [2:0] {IDLE, SEND_TARGET, WAIT_TARGET, RESPOND, FLUSH} state_t;
  state_t state_q;
  logic [31:0] addr_q;
  logic [31:0] wdata_q, rdata_q;
  logic [3:0] be_q;
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
