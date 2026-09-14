// Source-backed Ibex + PULP APB GPIO/SPI acceptance harness.
//
// This is deliberately a composition wrapper, not a CPU/peripheral model:
// Ibex, the OBI adapters, processor arbiter, N-source SoC arbiter/router,
// boot/RAM targets, APB bridges and the pinned PULP IP are all real RTL.
// The generated renderer enables this module only for an explicit real build.
module soc_ibex_pulp_core (
    input logic clk_i,
    input logic reset_i,
    input logic stim_offer_i,
    input logic [2:0] stim_target_selector_i,
    input logic [31:0] stim_offset_i,
    input logic stim_write_i,
    input logic [31:0] stim_wdata_i,
    input logic [3:0] stim_be_i,
    input logic [7:0] gpio_in_i,
    input logic spi_sck_i,
    input logic spi_cs_i,
    input logic irq_claim_i,
    input logic irq_complete_i,
    output logic [31:0] gpio_out_o,
    output logic [31:0] gpio_dir_o,
    output logic gpio_irq_o,
    output logic spi_clk_o,
    output logic spi_cs0_o,
    output logic spi_sdo0_o,
    output logic cpu_irq_o,
    output logic cpu_mmio_transaction_o,
    output logic fuzz_mmio_transaction_o,
    output logic [31:0] cpu_transaction_count_o,
    output logic [31:0] fuzz_transaction_count_o,
    output logic [31:0] cpu_completion_count_o,
    output logic [31:0] fuzz_completion_count_o,
    output logic fabric_protocol_error_o
);
  localparam logic [31:0] ROM_BASE  = 32'h0001_0000;
  localparam logic [31:0] ROM_SIZE  = 32'h0000_8000;
  localparam logic [31:0] RAM_BASE  = 32'h8000_0000;
  localparam logic [31:0] RAM_SIZE  = 32'h0001_0000;
  localparam logic [31:0] GPIO_BASE = 32'h4000_0000;
  localparam logic [31:0] SPI_BASE  = 32'h4000_1000;
  localparam logic [31:0] PERIPH_SIZE = 32'h0000_1000;

  wire reset_n = ~reset_i;

  // Ibex OBI boundary.
  logic data_req, data_gnt, data_rvalid, data_we, data_err, data_tag;
  logic [3:0] data_be;
  logic [31:0] data_addr, data_wdata, data_rdata;
  logic instr_req, instr_gnt, instr_rvalid, instr_err;
  logic [31:0] instr_addr, instr_rdata;

  logic proc_i0_req_valid, proc_i0_req_ready, proc_i0_write;
  logic [31:0] proc_i0_addr, proc_i0_wdata;
  logic [3:0] proc_i0_be;
  logic proc_i0_rsp_valid, proc_i0_rsp_ready, proc_i0_error;
  logic [31:0] proc_i0_rdata;
  logic proc_i1_req_valid, proc_i1_req_ready, proc_i1_write;
  logic [31:0] proc_i1_addr, proc_i1_wdata;
  logic [3:0] proc_i1_be;
  logic proc_i1_rsp_valid, proc_i1_rsp_ready, proc_i1_error;
  logic [31:0] proc_i1_rdata;
  logic proc_i0_mapped, proc_i1_mapped;

  assign proc_i0_mapped =
      ((proc_i0_addr >= ROM_BASE) && (proc_i0_addr < ROM_BASE + ROM_SIZE)) ||
      ((proc_i0_addr >= RAM_BASE) && (proc_i0_addr < RAM_BASE + RAM_SIZE)) ||
      ((proc_i0_addr >= GPIO_BASE) && (proc_i0_addr < GPIO_BASE + PERIPH_SIZE)) ||
      ((proc_i0_addr >= SPI_BASE) && (proc_i0_addr < SPI_BASE + PERIPH_SIZE));
  assign proc_i1_mapped =
      ((proc_i1_addr >= ROM_BASE) && (proc_i1_addr < ROM_BASE + ROM_SIZE)) ||
      ((proc_i1_addr >= RAM_BASE) && (proc_i1_addr < RAM_BASE + RAM_SIZE));

  ibex_top #(
      .ICache(0),
      .PMPEnable(0),
      .RV32E(0),
      .SecureIbex(0)
  ) u_ibex (
      .clk_i(clk_i),
      .rst_ni(reset_n),
      .test_en_i(1'b0),
      .cheriot_enable_i(ibex_pkg::IbexMuBiOff),
      .hart_id_i(32'd0),
      .boot_addr_i(ROM_BASE),
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
      .irq_external_i(cpu_irq_o),
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
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .HAS_BE(1), .HAS_ERROR(1), .READ_ONLY(0)
  ) u_data_adapter (
      .clk_i(clk_i), .rst_ni(reset_n), .req_i(data_req), .gnt_o(data_gnt),
      .addr_i(data_addr), .we_i(data_we), .wdata_i(data_wdata), .be_i(data_be),
      .rvalid_o(data_rvalid), .rdata_o(data_rdata), .error_o(data_err),
      .req_valid_o(proc_i0_req_valid), .req_ready_i(proc_i0_req_ready),
      .req_write_o(proc_i0_write), .req_addr_o(proc_i0_addr),
      .req_wdata_o(proc_i0_wdata), .req_be_o(proc_i0_be),
      .rsp_valid_i(proc_i0_rsp_valid), .rsp_ready_o(proc_i0_rsp_ready),
      .rsp_rdata_i(proc_i0_rdata), .rsp_error_i(proc_i0_error)
  );

  obi_processor_memory_adapter #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .HAS_BE(0), .HAS_ERROR(1), .READ_ONLY(1)
  ) u_instr_adapter (
      .clk_i(clk_i), .rst_ni(reset_n), .req_i(instr_req), .gnt_o(instr_gnt),
      .addr_i(instr_addr), .we_i(1'b0), .wdata_i(32'd0), .be_i(4'hf),
      .rvalid_o(instr_rvalid), .rdata_o(instr_rdata), .error_o(instr_err),
      .req_valid_o(proc_i1_req_valid), .req_ready_i(proc_i1_req_ready),
      .req_write_o(proc_i1_write), .req_addr_o(proc_i1_addr),
      .req_wdata_o(proc_i1_wdata), .req_be_o(proc_i1_be),
      .rsp_valid_i(proc_i1_rsp_valid), .rsp_ready_o(proc_i1_rsp_ready),
      .rsp_rdata_i(proc_i1_rdata), .rsp_error_i(proc_i1_error)
  );

  logic cpu_backend_req_valid, cpu_backend_req_ready, cpu_backend_write;
  logic [31:0] cpu_backend_addr, cpu_backend_wdata;
  logic [3:0] cpu_backend_be;
  logic cpu_backend_rsp_valid, cpu_backend_rsp_ready, cpu_backend_error;
  logic [31:0] cpu_backend_rdata;
  logic cpu_backend_cancel_valid, cpu_backend_cancel_ready;
  logic cpu_backend_flush;
  logic cpu_target_req_valid, cpu_target_req_ready, cpu_target_write;
  logic [31:0] cpu_target_addr, cpu_target_wdata;
  logic [3:0] cpu_target_be;
  logic cpu_target_rsp_valid, cpu_target_rsp_ready, cpu_target_error;
  logic [31:0] cpu_target_rdata;

  processor_memory_arbiter #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .MAX_WAIT_CYCLES(64),
      .INITIATOR0_READ_ONLY(0), .INITIATOR1_READ_ONLY(1)
  ) u_processor_arbiter (
      .clk_i(clk_i), .rst_ni(reset_n),
      .i0_req_valid_i(proc_i0_req_valid), .i0_req_ready_o(proc_i0_req_ready),
      .i0_req_write_i(proc_i0_write), .i0_req_addr_i(proc_i0_addr),
      .i0_req_wdata_i(proc_i0_wdata), .i0_req_be_i(proc_i0_be),
      .i0_req_mapped_i(proc_i0_mapped), .i0_rsp_valid_o(proc_i0_rsp_valid),
      .i0_rsp_ready_i(proc_i0_rsp_ready), .i0_rsp_rdata_o(proc_i0_rdata),
      .i0_rsp_error_o(proc_i0_error),
      .i1_req_valid_i(proc_i1_req_valid), .i1_req_ready_o(proc_i1_req_ready),
      .i1_req_write_i(proc_i1_write), .i1_req_addr_i(proc_i1_addr),
      .i1_req_wdata_i(proc_i1_wdata), .i1_req_be_i(proc_i1_be),
      .i1_req_mapped_i(proc_i1_mapped), .i1_rsp_valid_o(proc_i1_rsp_valid),
      .i1_rsp_ready_i(proc_i1_rsp_ready), .i1_rsp_rdata_o(proc_i1_rdata),
      .i1_rsp_error_o(proc_i1_error),
      .req_valid_o(cpu_backend_req_valid), .req_ready_i(cpu_backend_req_ready),
      .req_write_o(cpu_backend_write), .req_addr_o(cpu_backend_addr),
      .req_wdata_o(cpu_backend_wdata), .req_be_o(cpu_backend_be),
      .rsp_valid_i(cpu_backend_rsp_valid), .rsp_ready_o(cpu_backend_rsp_ready),
      .rsp_rdata_i(cpu_backend_rdata), .rsp_error_i(cpu_backend_error),
      .cancel_valid_o(cpu_backend_cancel_valid), .cancel_ready_i(cpu_backend_cancel_ready)
  );

  myfuzz_processor_memory_backend #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .MAX_WAIT_CYCLES(64)
  ) u_cpu_backend (
      .clk_i(clk_i), .rst_ni(reset_n), .req_valid_i(cpu_backend_req_valid),
      .req_ready_o(cpu_backend_req_ready), .req_write_i(cpu_backend_write),
      .req_addr_i(cpu_backend_addr), .req_wdata_i(cpu_backend_wdata),
      .req_be_i(cpu_backend_be), .req_mapped_i(1'b1),
      .rsp_valid_o(cpu_backend_rsp_valid), .rsp_ready_i(cpu_backend_rsp_ready),
      .rsp_rdata_o(cpu_backend_rdata), .rsp_error_o(cpu_backend_error),
      .cancel_valid_i(cpu_backend_cancel_valid), .cancel_ready_o(cpu_backend_cancel_ready),
      .target_flush_o(cpu_backend_flush), .target_req_valid_o(cpu_target_req_valid),
      .target_req_ready_i(cpu_target_req_ready), .target_write_o(cpu_target_write),
      .target_addr_o(cpu_target_addr), .target_wdata_o(cpu_target_wdata),
      .target_be_o(cpu_target_be), .target_rsp_valid_i(cpu_target_rsp_valid),
      .target_rsp_ready_o(cpu_target_rsp_ready), .target_rdata_i(cpu_target_rdata),
      .target_error_i(cpu_target_error)
  );

  // The fuzz MMIO master is a second real source on the same target fabric.
  logic fuzz_req_valid, fuzz_req_ready, fuzz_write;
  logic [31:0] fuzz_addr, fuzz_wdata;
  logic [3:0] fuzz_be;
  logic fuzz_rsp_valid, fuzz_rsp_ready, fuzz_error;
  logic [31:0] fuzz_rdata;
  logic [31:0] fuzz_busy_drop, fuzz_error_count, fuzz_completion_count;
  logic [3:0] fuzz_error_code;
  fuzz_mmio_master #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .SELECTOR_WIDTH(3),
      .SELECTOR_INVALID(3'd4), .NUM_WINDOWS(4), .ADDRESS_STRATEGY(1),
      .WINDOW_BASE({32'h4000_1000, 32'h4000_0000, 32'h8000_0000, 32'h0001_0000}),
      .WINDOW_SIZE({32'h0000_1000, 32'h0000_1000, 32'h0001_0000, 32'h0000_8000})
  ) u_fuzz_mmio (
      .clk(clk_i), .reset(reset_i), .stim_offer(stim_offer_i),
      .stim_target_selector(stim_target_selector_i), .stim_offset(stim_offset_i),
      .stim_write(stim_write_i), .stim_wdata(stim_wdata_i), .stim_be(stim_be_i),
      .req_valid(fuzz_req_valid), .req_ready(fuzz_req_ready), .write(fuzz_write),
      .addr(fuzz_addr), .wdata(fuzz_wdata), .be(fuzz_be), .rsp_valid(fuzz_rsp_valid),
      .rsp_ready(fuzz_rsp_ready), .rdata(fuzz_rdata), .error(fuzz_error),
      .busy_drop_count(fuzz_busy_drop), .error_count(fuzz_error_count),
      .completion_count(fuzz_completion_count), .error_code(fuzz_error_code)
  );

  logic [1:0] source_req_valid, source_req_ready, source_write;
  logic [1:0][31:0] source_addr, source_wdata;
  logic [1:0][3:0] source_be;
  logic [1:0] source_rsp_valid, source_rsp_ready, source_error;
  logic [1:0][31:0] source_rdata;
  logic [1:0] source_instr;
  logic fabric_req_valid, fabric_req_ready, fabric_write, fabric_instr;
  logic [31:0] fabric_addr, fabric_wdata;
  logic [3:0] fabric_be;
  logic fabric_rsp_valid, fabric_rsp_ready, fabric_error;
  logic [31:0] fabric_rdata;
  logic [0:0] fabric_source_id, fabric_rsp_source_id;
  logic [7:0] fabric_transaction_id, fabric_rsp_transaction_id;
  logic fabric_protocol_error;

  assign source_req_valid[0] = cpu_target_req_valid;
  assign source_req_valid[1] = fuzz_req_valid;
  assign source_write[0] = cpu_target_write;
  assign source_write[1] = fuzz_write;
  assign source_addr[0] = cpu_target_addr;
  assign source_addr[1] = fuzz_addr;
  assign source_wdata[0] = cpu_target_wdata;
  assign source_wdata[1] = fuzz_wdata;
  assign source_be[0] = cpu_target_be;
  assign source_be[1] = fuzz_be;
  assign source_instr = 2'b00;
  assign cpu_target_req_ready = source_req_ready[0];
  assign fuzz_req_ready = source_req_ready[1];
  assign cpu_target_rsp_valid = source_rsp_valid[0];
  assign cpu_target_rdata = source_rdata[0];
  assign cpu_target_error = source_error[0];
  assign source_rsp_ready[0] = cpu_target_rsp_ready;
  assign fuzz_rsp_valid = source_rsp_valid[1];
  assign fuzz_rdata = source_rdata[1];
  assign fuzz_error = source_error[1];
  assign source_rsp_ready[1] = fuzz_rsp_ready;

  soc_arbiter #(
      .NUM_SOURCES(2), .ADDRESS_WIDTH(32), .DATA_WIDTH(32),
      .SOURCE_ID_WIDTH(1), .TRANSACTION_ID_WIDTH(8)
  ) u_soc_arbiter (
      .clk(clk_i), .reset(reset_i), .s_req_valid(source_req_valid),
      .s_req_ready(source_req_ready), .s_write(source_write), .s_addr(source_addr),
      .s_wdata(source_wdata), .s_be(source_be), .s_instr(source_instr),
      .s_rsp_valid(source_rsp_valid), .s_rsp_ready(source_rsp_ready),
      .s_rdata(source_rdata), .s_error(source_error), .req_valid(fabric_req_valid),
      .req_ready(fabric_req_ready), .write(fabric_write), .addr(fabric_addr),
      .wdata(fabric_wdata), .be(fabric_be), .instr(fabric_instr),
      .source_id(fabric_source_id), .transaction_id(fabric_transaction_id),
      .rsp_valid(fabric_rsp_valid), .rsp_ready(fabric_rsp_ready),
      .rdata(fabric_rdata), .error(fabric_error), .rsp_source_id(fabric_rsp_source_id),
      .rsp_transaction_id(fabric_rsp_transaction_id),
      .protocol_error(fabric_protocol_error)
  );

  localparam logic [127:0] WINDOW_BASES = {
      SPI_BASE, GPIO_BASE, RAM_BASE, ROM_BASE
  };
  localparam logic [127:0] WINDOW_SIZES = {
      PERIPH_SIZE, PERIPH_SIZE, RAM_SIZE, ROM_SIZE
  };
  localparam logic [127:0] WINDOW_TARGET_BASES = 128'd0;
  localparam logic [7:0] WINDOW_TARGETS = {2'd3, 2'd2, 2'd1, 2'd0};

  logic [3:0] target_req_valid, target_req_ready, target_write;
  logic [3:0][31:0] target_addr, target_wdata;
  logic [3:0][3:0] target_be;
  logic [3:0] target_rsp_valid, target_rsp_ready, target_error;
  logic [3:0][31:0] target_rdata;
  logic [1:0] selected_target;
  logic target_stale_pending;

  soc_router #(
      .RESET_CLEARS_TARGETS(1'b1), .NUM_TARGETS(4), .ADDRESS_WIDTH(32),
      .DATA_WIDTH(32), .SOURCE_ID_WIDTH(1), .NUM_SOURCES(2),
      .TRANSACTION_ID_WIDTH(8), .TARGET_ID_WIDTH(2), .MAX_WINDOWS(4),
      .NUM_WINDOWS(4), .WINDOW_BASE(WINDOW_BASES),
      .WINDOW_TARGET_BASE(WINDOW_TARGET_BASES), .WINDOW_SIZE(WINDOW_SIZES),
      .WINDOW_TARGET(WINDOW_TARGETS), .WINDOW_EXECUTABLE(4'b0011),
      .WINDOW_READABLE(4'b1111), .WINDOW_WRITABLE(4'b1110),
      .WINDOW_SOURCE_MASK(8'hff)
  ) u_soc_router (
      .clk(clk_i), .reset(reset_i), .req_valid(fabric_req_valid),
      .req_ready(fabric_req_ready), .write(fabric_write), .addr(fabric_addr),
      .wdata(fabric_wdata), .be(fabric_be), .instr(fabric_instr),
      .source_id(fabric_source_id), .transaction_id(fabric_transaction_id),
      .rsp_valid(fabric_rsp_valid), .rsp_ready(fabric_rsp_ready),
      .rdata(fabric_rdata), .error(fabric_error),
      .rsp_source_id(fabric_rsp_source_id), .rsp_transaction_id(fabric_rsp_transaction_id),
      .t_req_valid(target_req_valid), .t_req_ready(target_req_ready),
      .t_write(target_write), .t_addr(target_addr), .t_wdata(target_wdata),
      .t_be(target_be), .t_rsp_valid(target_rsp_valid), .t_rsp_ready(target_rsp_ready),
      .t_rdata(target_rdata), .t_error(target_error), .selected_target(selected_target),
      .stale_pending(target_stale_pending)
  );

  logic rom_flush, ram_flush;
  assign rom_flush = reset_i | cpu_backend_flush;
  assign ram_flush = reset_i | cpu_backend_flush;
  riscv_boot_memory_32 #(.BASE_ADDR(0), .BYTES(32768), .LOAD_IMAGE(1)) u_rom (
      .clock(clk_i), .reset(reset_n), .flush(rom_flush), .req_valid(target_req_valid[0]),
      .req_ready(target_req_ready[0]), .write(target_write[0]), .addr(target_addr[0]),
      .wdata(target_wdata[0]), .be(target_be[0]), .rsp_valid(target_rsp_valid[0]),
      .rsp_ready(target_rsp_ready[0]), .rdata(target_rdata[0]), .error(target_error[0])
  );
  riscv_boot_memory_32 #(.BASE_ADDR(0), .BYTES(65536), .LOAD_IMAGE(0)) u_ram (
      .clock(clk_i), .reset(reset_n), .flush(ram_flush), .req_valid(target_req_valid[1]),
      .req_ready(target_req_ready[1]), .write(target_write[1]), .addr(target_addr[1]),
      .wdata(target_wdata[1]), .be(target_be[1]), .rsp_valid(target_rsp_valid[1]),
      .rsp_ready(target_rsp_ready[1]), .rdata(target_rdata[1]), .error(target_error[1])
  );

  logic gpio_req_ready, gpio_req_valid, gpio_rsp_valid, gpio_rsp_ready, gpio_error;
  logic [31:0] gpio_req_addr, gpio_req_wdata, gpio_rsp_rdata;
  logic [3:0] gpio_req_be;
  logic [11:0] gpio_paddr;
  logic [31:0] gpio_pwdata, gpio_prdata;
  logic gpio_pwrite, gpio_psel, gpio_penable, gpio_pready, gpio_pslverr;
  logic [7:0] gpio_out, gpio_dir;
  logic [7:0] gpio_in_sync;
  logic [7:0][3:0] gpio_padcfg;

  processor_apb_bridge u_gpio_bridge (
      .clk_i(clk_i), .rst_ni(reset_n), .req_valid_i(target_req_valid[2]),
      .req_ready_o(target_req_ready[2]), .req_write_i(target_write[2]),
      .req_addr_i(target_addr[2]), .req_wdata_i(target_wdata[2]), .req_be_i(target_be[2]),
      .rsp_valid_o(target_rsp_valid[2]), .rsp_ready_i(target_rsp_ready[2]),
      .rsp_rdata_o(target_rdata[2]), .rsp_error_o(target_error[2]), .paddr_o(gpio_paddr),
      .pwdata_o(gpio_pwdata), .pwrite_o(gpio_pwrite), .psel_o(gpio_psel),
      .penable_o(gpio_penable), .prdata_i(gpio_prdata), .pready_i(gpio_pready),
      .pslverr_i(gpio_pslverr)
  );
  apb_gpio #(.APB_ADDR_WIDTH(12), .PAD_NUM(8), .NBIT_PADCFG(4)) u_gpio (
      .HCLK(clk_i), .HRESETn(reset_n), .dft_cg_enable_i(1'b1), .PADDR(gpio_paddr),
      .PWDATA(gpio_pwdata), .PWRITE(gpio_pwrite), .PSEL(gpio_psel),
      .PENABLE(gpio_penable), .PRDATA(gpio_prdata), .PREADY(gpio_pready),
      .PSLVERR(gpio_pslverr), .gpio_in(gpio_in_i), .gpio_in_sync(gpio_in_sync),
      .gpio_out(gpio_out), .gpio_dir(gpio_dir), .gpio_padcfg(gpio_padcfg),
      .interrupt(gpio_irq_o)
  );
  assign gpio_out_o = {24'd0, gpio_out};
  assign gpio_dir_o = {24'd0, gpio_dir};

  logic spi_paddr_valid;
  logic [11:0] spi_paddr;
  logic [31:0] spi_pwdata, spi_prdata;
  logic spi_pwrite, spi_psel, spi_penable, spi_pready, spi_pslverr;
  logic [1:0] spi_events;
  logic spi_clk, spi_csn0, spi_sdo0;
  logic spi_sdo1, spi_sdo2, spi_sdo3;
  logic spi_mode;
  processor_apb_bridge u_spi_bridge (
      .clk_i(clk_i), .rst_ni(reset_n), .req_valid_i(target_req_valid[3]),
      .req_ready_o(target_req_ready[3]), .req_write_i(target_write[3]),
      .req_addr_i(target_addr[3]), .req_wdata_i(target_wdata[3]), .req_be_i(target_be[3]),
      .rsp_valid_o(target_rsp_valid[3]), .rsp_ready_i(target_rsp_ready[3]),
      .rsp_rdata_o(target_rdata[3]), .rsp_error_o(target_error[3]), .paddr_o(spi_paddr),
      .pwdata_o(spi_pwdata), .pwrite_o(spi_pwrite), .psel_o(spi_psel),
      .penable_o(spi_penable), .prdata_i(spi_prdata), .pready_i(spi_pready),
      .pslverr_i(spi_pslverr)
  );
  apb_spi_master #(.BUFFER_DEPTH(10), .APB_ADDR_WIDTH(12)) u_spi (
      .HCLK(clk_i), .HRESETn(reset_n), .PADDR(spi_paddr), .PWDATA(spi_pwdata),
      .PWRITE(spi_pwrite), .PSEL(spi_psel), .PENABLE(spi_penable),
      .PRDATA(spi_prdata), .PREADY(spi_pready), .PSLVERR(spi_pslverr),
      .events_o(spi_events), .spi_clk(spi_clk), .spi_csn0(spi_csn0),
      .spi_csn1(), .spi_csn2(), .spi_csn3(), .spi_mode(), .spi_sdo0(spi_sdo0),
      .spi_sdo1(spi_sdo1), .spi_sdo2(spi_sdo2), .spi_sdo3(spi_sdo3),
      .spi_sdi0(1'b0), .spi_sdi1(1'b0), .spi_sdi2(1'b0), .spi_sdi3(1'b0)
  );
  assign spi_clk_o = spi_clk;
  assign spi_cs0_o = spi_csn0;
  assign spi_sdo0_o = spi_sdo0;

  // Real peripheral interrupt sources are routed into Ibex's external IRQ.
  logic [2:0] irq_pending, irq_in_service, irq_sources;
  logic irq_claim_valid;
  logic [1:0] irq_claim_id;
  logic [11:0] irq_priority = {3{4'd1}};
  assign irq_sources = {1'b0, |spi_events, gpio_irq_o};
  soc_irq_router #(.NUM_SOURCES(3), .SOURCE_ID_WIDTH(2), .PRIORITY_WIDTH(4)) u_irq_router (
      .source_i(irq_sources), .enable_i(3'b111), .edge_mode_i(3'b111),
      .clear_i(3'b000), .claim_i(irq_claim_i), .complete_i(irq_complete_i),
      .priority_i(irq_priority), .clk_i(clk_i), .reset_i(reset_i),
      .irq_o(cpu_irq_o), .pending_o(irq_pending), .in_service_o(irq_in_service),
      .claim_valid_o(irq_claim_valid), .claim_id_o(irq_claim_id)
  );

  assign cpu_mmio_transaction_o = source_req_valid[0] && source_req_ready[0];
  assign fuzz_mmio_transaction_o = source_req_valid[1] && source_req_ready[1];
  assign fabric_protocol_error_o = fabric_protocol_error;
  always_ff @(posedge clk_i or posedge reset_i) begin
    if (reset_i) begin
      cpu_transaction_count_o <= 32'd0;
      fuzz_transaction_count_o <= 32'd0;
      cpu_completion_count_o <= 32'd0;
      fuzz_completion_count_o <= 32'd0;
    end else begin
      if (cpu_mmio_transaction_o) cpu_transaction_count_o <= cpu_transaction_count_o + 1'b1;
      if (fuzz_mmio_transaction_o) fuzz_transaction_count_o <= fuzz_transaction_count_o + 1'b1;
      if (source_rsp_valid[0] && source_rsp_ready[0]) cpu_completion_count_o <= cpu_completion_count_o + 1'b1;
      if (source_rsp_valid[1] && source_rsp_ready[1]) fuzz_completion_count_o <= fuzz_completion_count_o + 1'b1;
    end
  end
endmodule
