`default_nettype none
// Source-backed Ibex beat initiator core.
//
// Real Ibex (pinned closure) with one OBI adapter per CPU memory endpoint.
// The instruction endpoint is read-only; both endpoints expose the
// processor-memory-beat contract to the generated SoC fabric.  There is no
// behavioural CPU or memory model in this module.  The parent decides how the
// endpoints are arbitrated and decoded.
//
// MYFUZZ_CORE_DEPENDENCIES: src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv
module soc_ibex_beat_core #(
  parameter integer BOOT_ADDR = 32'h0001_0000,
  parameter integer PMPEnable = 0,
  parameter integer RV32E = 0,
  parameter integer ICache = 0,
  parameter integer SecureIbex = 0
) (
  input  logic        clk_i,
  input  logic        reset_i,
  input  logic [1:0]  irq_i,
  output logic        instr_req_valid_o,
  input  logic        instr_req_ready_i,
  output logic        instr_write_o,
  output logic [31:0] instr_addr_o,
  output logic [31:0] instr_wdata_o,
  output logic [3:0]  instr_be_o,
  input  logic        instr_rsp_valid_i,
  output logic        instr_rsp_ready_o,
  input  logic [31:0] instr_rdata_i,
  input  logic        instr_error_i,
  output logic        data_req_valid_o,
  input  logic        data_req_ready_i,
  output logic        data_write_o,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  output logic [3:0]  data_be_o,
  input  logic        data_rsp_valid_i,
  output logic        data_rsp_ready_o,
  input  logic [31:0] data_rdata_i,
  input  logic        data_error_i,
  output logic        flush_o
);
  wire reset_n = ~reset_i;

  logic data_req, data_gnt, data_rvalid, data_we, data_err, data_tag;
  logic [3:0] data_be;
  logic [31:0] data_addr, data_wdata, data_rdata;
  logic instr_req, instr_gnt, instr_rvalid, instr_err;
  logic [31:0] instr_addr, instr_rdata;

  ibex_top #(
      .ICache(ICache),
      .PMPEnable(PMPEnable),
      .RV32E(RV32E),
      .SecureIbex(SecureIbex)
  ) u_ibex (
      .clk_i(clk_i),
      .rst_ni(reset_n),
      .test_en_i(1'b0),
      .cheriot_enable_i(ibex_pkg::IbexMuBiOff),
      .hart_id_i(32'd0),
      .boot_addr_i(BOOT_ADDR[31:0]),
      .trvk_heap_base_addr_i(32'd0),
      .instr_req_o(instr_req),
      .instr_gnt_i(instr_gnt),
      .instr_rvalid_i(instr_rvalid),
      .instr_addr_o(instr_addr),
      .instr_rdata_i(instr_rdata),
      .instr_rdata_intg_i(7'd0),
      .instr_err_i(instr_err),
      .data_req_o(data_req),
      .data_gnt_i(data_gnt),
      .data_rvalid_i(data_rvalid),
      .data_we_o(data_we),
      .data_be_o(data_be),
      .data_addr_o(data_addr),
      .data_wdata_o(data_wdata),
      .data_wdata_intg_o(),
      .data_tag_o(data_tag),
      .data_rdata_i(data_rdata),
      .data_rdata_intg_i(7'd0),
      .data_tag_i(1'b0),
      .data_err_i(data_err),
      .trvk_revbm_req_o(),
      .trvk_revbm_gnt_i(1'b0),
      .trvk_revbm_rvalid_i(1'b0),
      .trvk_revbm_addr_o(),
      .trvk_revbm_rdata_i(32'd0),
      .trvk_revbm_rdata_intg_i(7'd0),
      .trvk_revbm_err_i(1'b0),
      .irq_software_i(1'b0),
      .irq_timer_i(1'b0),
      .irq_external_i(irq_i[0]),
      .irq_fast_i(15'd0),
      .irq_nm_i(1'b0),
      .scramble_key_valid_i(1'b0),
      .scramble_key_i(128'd0),
      .scramble_nonce_i(64'd0),
      .debug_req_i(1'b0),
      .fetch_enable_i(ibex_pkg::IbexMuBiOn),
      .mcounteren_writable_i(ibex_pkg::IbexMuBiOn),
      .scan_rst_ni(reset_n)
  );

  obi_processor_memory_adapter #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .HAS_BE(0), .HAS_ERROR(1), .READ_ONLY(1)
  ) u_instr_adapter (
      .clk_i(clk_i), .rst_ni(reset_n), .req_i(instr_req), .gnt_o(instr_gnt),
      .addr_i(instr_addr), .we_i(1'b0), .wdata_i(32'd0), .be_i(4'hf),
      .rvalid_o(instr_rvalid), .rdata_o(instr_rdata), .error_o(instr_err),
      .req_valid_o(instr_req_valid_o), .req_ready_i(instr_req_ready_i),
      .req_write_o(instr_write_o), .req_addr_o(instr_addr_o),
      .req_wdata_o(instr_wdata_o), .req_be_o(instr_be_o),
      .rsp_valid_i(instr_rsp_valid_i), .rsp_ready_o(instr_rsp_ready_o),
      .rsp_rdata_i(instr_rdata_i), .rsp_error_i(instr_error_i)
  );

  obi_processor_memory_adapter #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .HAS_BE(1), .HAS_ERROR(1), .READ_ONLY(0)
  ) u_data_adapter (
      .clk_i(clk_i), .rst_ni(reset_n), .req_i(data_req), .gnt_o(data_gnt),
      .addr_i(data_addr), .we_i(data_we), .wdata_i(data_wdata), .be_i(data_be),
      .rvalid_o(data_rvalid), .rdata_o(data_rdata), .error_o(data_err),
      .req_valid_o(data_req_valid_o), .req_ready_i(data_req_ready_i),
      .req_write_o(data_write_o), .req_addr_o(data_addr_o),
      .req_wdata_o(data_wdata_o), .req_be_o(data_be_o),
      .rsp_valid_i(data_rsp_valid_i), .rsp_ready_o(data_rsp_ready_o),
      .rsp_rdata_i(data_rdata_i), .rsp_error_i(data_error_i)
  );

  logic unused_ibex;
  assign unused_ibex = data_tag;
  // Ibex has no memory-flush pin; the harness memory flush is the test reset
  // the parent applies.  flush_o stays explicit so every CPU core exposes the
  // same harness contract.
  assign flush_o = 1'b0;
endmodule
`default_nettype wire
