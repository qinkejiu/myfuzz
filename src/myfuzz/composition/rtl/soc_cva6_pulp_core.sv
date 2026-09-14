`default_nettype none

// Source-backed CVA6 + PULP APB GPIO/SPI acceptance harness.
//
// The CPU is the pinned CVA6 top with its compiler-proven packed AXI4
// boundary.  Its requests pass through the generic AXI beat adapter,
// single-source arbiter, address router, and 64-to-32 width adapters before
// reaching the real PULP peripherals.  There is no behavioural CPU or
// peripheral substitute in this wrapper.
module soc_cva6_pulp_core (
    input logic clk_i,
    input logic reset_i,
    output logic [31:0] gpio_out_o,
    output logic [31:0] gpio_dir_o,
    output logic gpio_irq_o,
    output logic spi_clk_o,
    output logic spi_cs0_o,
    output logic spi_sdo0_o,
    output logic cpu_mmio_transaction_o,
    output logic [31:0] cpu_transaction_count_o,
    output logic [31:0] cpu_completion_count_o,
    output logic fabric_protocol_error_o
);
  localparam logic [63:0] RAM_BASE = 64'h0000_0000_8000_0000;
  localparam logic [63:0] RAM_SIZE = 64'h0000_0000_0001_0000;
  localparam logic [63:0] GPIO_BASE = 64'h0000_0000_4000_0000;
  localparam logic [63:0] SPI_BASE = 64'h0000_0000_4000_1000;
  localparam logic [63:0] PERIPH_SIZE = 64'h0000_0000_0000_1000;
  wire reset_n = ~reset_i;
  logic spi_irq;

  logic [469:0] noc_req;
  logic [209:0] noc_resp;

  // CVA6's official interface is a packed AXI4 request/response container.
  // These slices are the compiler-proven coordinates from the pinned source
  // description; they are kept explicit at this one physical boundary.
  cva6 u_cva6 (
      .boot_addr_i(RAM_BASE),
      .clk_i(clk_i),
      .debug_req_i(1'b0),
      .hart_id_i(64'd0),
      .ipi_i(1'b0),
      .irq_i({spi_irq, gpio_irq_o}),
      .noc_req_o(noc_req),
      .noc_resp_i(noc_resp),
      .rst_ni(reset_n),
      .time_irq_i(1'b0)
  );

  logic adapter_req_valid, adapter_req_ready, adapter_write;
  logic [63:0] adapter_addr, adapter_wdata;
  logic [7:0] adapter_be;
  logic adapter_rsp_valid, adapter_rsp_ready, adapter_error;
  logic [63:0] adapter_rdata;

  axi4_processor_memory_adapter #(
      .ADDRESS_WIDTH(64), .DATA_WIDTH(64), .ID_WIDTH(4), .USER_WIDTH(64)
  ) u_axi_adapter (
      .clk_i(clk_i), .rst_ni(reset_n),
      .araddr_i(noc_req[158:95]),
      .arburst_i(noc_req[83:82]), .arcache_i(noc_req[80:77]),
      .arid_i(noc_req[162:159]), .arlen_i(noc_req[94:87]),
      .arlock_i(noc_req[81]), .arprot_i(noc_req[76:74]),
      .arqos_i(noc_req[73:70]), .arready_o(noc_resp[208]),
      .arregion_i(noc_req[69:66]), .arsize_i(noc_req[86:84]),
      .aruser_i(noc_req[65:2]), .arvalid_i(noc_req[1]),
      .awaddr_i(noc_req[465:402]), .awatop_i(noc_req[372:367]),
      .awburst_i(noc_req[390:389]), .awcache_i(noc_req[387:384]),
      .awid_i(noc_req[469:466]), .awlen_i(noc_req[401:394]),
      .awlock_i(noc_req[388]), .awprot_i(noc_req[383:381]),
      .awqos_i(noc_req[380:377]), .awready_o(noc_resp[209]),
      .awregion_i(noc_req[376:373]), .awsize_i(noc_req[393:391]),
      .awuser_i(noc_req[366:303]), .awvalid_i(noc_req[302]),
      .bid_o(noc_resp[205:202]), .bready_i(noc_req[163]),
      .bresp_o(noc_resp[201:200]), .buser_o(noc_resp[199:136]),
      .bvalid_o(noc_resp[206]), .rdata_o(noc_resp[130:67]),
      .rid_o(noc_resp[134:131]), .rlast_o(noc_resp[64]),
      .rready_i(noc_req[0]), .rresp_o(noc_resp[66:65]),
      .ruser_o(noc_resp[63:0]), .rvalid_o(noc_resp[135]),
      .wdata_i(noc_req[301:238]), .wlast_i(noc_req[229]),
      .wready_o(noc_resp[207]), .wstrb_i(noc_req[237:230]),
      .wuser_i(noc_req[228:165]), .wvalid_i(noc_req[164]),
      .req_valid_o(adapter_req_valid), .req_ready_i(adapter_req_ready),
      .req_write_o(adapter_write), .req_addr_o(adapter_addr),
      .req_wdata_o(adapter_wdata), .req_be_o(adapter_be),
      .rsp_valid_i(adapter_rsp_valid), .rsp_ready_o(adapter_rsp_ready),
      .rsp_rdata_i(adapter_rdata), .rsp_error_i(adapter_error)
  );

  logic backend_req_valid, backend_req_ready, backend_write;
  logic [63:0] backend_addr, backend_wdata;
  logic [7:0] backend_be;
  logic backend_rsp_valid, backend_rsp_ready, backend_error;
  logic [63:0] backend_rdata;
  logic backend_target_req_valid, backend_target_req_ready, backend_target_write;
  logic [63:0] backend_target_addr, backend_target_wdata;
  logic [7:0] backend_target_be;
  logic backend_target_rsp_valid, backend_target_rsp_ready, backend_target_error;
  logic [63:0] backend_target_rdata;
  logic backend_target_flush;

  assign backend_req_valid = adapter_req_valid;
  assign backend_write = adapter_write;
  assign backend_addr = adapter_addr;
  assign backend_wdata = adapter_wdata;
  assign backend_be = adapter_be;
  assign adapter_req_ready = backend_req_ready;
  assign adapter_rsp_valid = backend_rsp_valid;
  assign adapter_rdata = backend_rdata;
  assign adapter_error = backend_error;
  assign backend_rsp_ready = adapter_rsp_ready;

  myfuzz_processor_memory_backend #(
      .ADDRESS_WIDTH(64), .DATA_WIDTH(64), .MAX_WAIT_CYCLES(64)
  ) u_backend (
      .clk_i(clk_i), .rst_ni(reset_n), .req_valid_i(backend_req_valid),
      .req_ready_o(backend_req_ready), .req_write_i(backend_write),
      .req_addr_i(backend_addr), .req_wdata_i(backend_wdata),
      .req_be_i(backend_be), .req_mapped_i(1'b1),
      .rsp_valid_o(backend_rsp_valid), .rsp_ready_i(backend_rsp_ready),
      .rsp_rdata_o(backend_rdata), .rsp_error_o(backend_error),
      .cancel_valid_i(1'b0), .cancel_ready_o(), .target_flush_o(backend_target_flush),
      .target_req_valid_o(backend_target_req_valid),
      .target_req_ready_i(backend_target_req_ready),
      .target_write_o(backend_target_write), .target_addr_o(backend_target_addr),
      .target_wdata_o(backend_target_wdata), .target_be_o(backend_target_be),
      .target_rsp_valid_i(backend_target_rsp_valid),
      .target_rsp_ready_o(backend_target_rsp_ready),
      .target_rdata_i(backend_target_rdata), .target_error_i(backend_target_error)
  );

  logic [0:0] source_req_valid, source_req_ready, source_write;
  logic [0:0][63:0] source_addr, source_wdata;
  logic [0:0][7:0] source_be;
  logic [0:0] source_rsp_valid, source_rsp_ready, source_error;
  logic [0:0][63:0] source_rdata;
  logic source_rsp_hold_valid, source_rsp_hold_error;
  logic [63:0] source_rsp_hold_data;
  logic [0:0] source_instr;
  logic fabric_req_valid, fabric_req_ready, fabric_write, fabric_instr;
  logic [63:0] fabric_addr, fabric_wdata;
  logic [7:0] fabric_be;
  logic fabric_rsp_valid, fabric_rsp_ready, fabric_error;
  logic [63:0] fabric_rdata;
  logic [0:0] fabric_source_id, fabric_rsp_source_id;
  logic [7:0] fabric_transaction_id, fabric_rsp_transaction_id;
  logic fabric_protocol_error;

  assign source_req_valid[0] = backend_target_req_valid;
  assign source_write[0] = backend_target_write;
  assign source_addr[0] = backend_target_addr;
  assign source_wdata[0] = backend_target_wdata;
  assign source_be[0] = backend_target_be;
  assign source_instr[0] = 1'b0;
  assign backend_target_req_ready = source_req_ready[0];
  // Hold the arbiter completion for one explicit response stage.  This keeps
  // the target data stable across the arbiter's WAIT_RSP->RESPOND transition
  // and prevents a same-edge NBA race from handing the backend a stale word.
  assign source_rsp_ready[0] = !source_rsp_hold_valid;
  assign backend_target_rsp_valid = source_rsp_hold_valid;
  assign backend_target_rdata = source_rsp_hold_data;
  assign backend_target_error = source_rsp_hold_error;
  always_ff @(posedge clk_i or posedge reset_i) begin
    if (reset_i) begin
      source_rsp_hold_valid <= 1'b0;
      source_rsp_hold_data <= '0;
      source_rsp_hold_error <= 1'b0;
    end else if (source_rsp_hold_valid) begin
      if (backend_target_rsp_ready)
        source_rsp_hold_valid <= 1'b0;
    end else if (source_rsp_valid[0]) begin
      source_rsp_hold_valid <= 1'b1;
      source_rsp_hold_data <= source_rdata[0];
      source_rsp_hold_error <= source_error[0];
    end
  end

  soc_arbiter #(
      .NUM_SOURCES(1), .ADDRESS_WIDTH(64), .DATA_WIDTH(64),
      .SOURCE_ID_WIDTH(1), .TRANSACTION_ID_WIDTH(8)
  ) u_soc_arbiter (
      .clk(clk_i), .reset(reset_i), .s_req_valid(source_req_valid),
      .s_req_ready(source_req_ready), .s_write(source_write),
      .s_addr(source_addr), .s_wdata(source_wdata), .s_be(source_be),
      .s_instr(source_instr), .s_rsp_valid(source_rsp_valid),
      .s_rsp_ready(source_rsp_ready), .s_rdata(source_rdata),
      .s_error(source_error), .req_valid(fabric_req_valid),
      .req_ready(fabric_req_ready), .write(fabric_write), .addr(fabric_addr),
      .wdata(fabric_wdata), .be(fabric_be), .instr(fabric_instr),
      .source_id(fabric_source_id), .transaction_id(fabric_transaction_id),
      .rsp_valid(fabric_rsp_valid), .rsp_ready(fabric_rsp_ready),
      .rdata(fabric_rdata), .error(fabric_error),
      .rsp_source_id(fabric_rsp_source_id),
      .rsp_transaction_id(fabric_rsp_transaction_id),
      .protocol_error(fabric_protocol_error)
  );

  localparam logic [191:0] WINDOW_BASES = {SPI_BASE, GPIO_BASE, RAM_BASE};
  localparam logic [191:0] WINDOW_SIZES = {PERIPH_SIZE, PERIPH_SIZE, RAM_SIZE};
  localparam logic [191:0] WINDOW_TARGET_BASES = {64'd0, 64'd0, RAM_BASE};
  localparam logic [5:0] WINDOW_TARGETS = {2'd2, 2'd1, 2'd0};

  logic [2:0] target_req_valid, target_req_ready, target_write;
  logic [2:0][63:0] target_addr, target_wdata;
  logic [2:0][7:0] target_be;
  logic [2:0] target_rsp_valid, target_rsp_ready, target_error;
  logic [2:0][63:0] target_rdata;
  logic [1:0] selected_target;

  soc_router #(
      .RESET_CLEARS_TARGETS(1'b1), .NUM_TARGETS(3), .ADDRESS_WIDTH(64),
      .DATA_WIDTH(64), .SOURCE_ID_WIDTH(1), .NUM_SOURCES(1),
      .TRANSACTION_ID_WIDTH(8), .TARGET_ID_WIDTH(2), .MAX_WINDOWS(3),
      .NUM_WINDOWS(3), .WINDOW_BASE(WINDOW_BASES),
      .WINDOW_TARGET_BASE(WINDOW_TARGET_BASES), .WINDOW_SIZE(WINDOW_SIZES),
      .WINDOW_TARGET(WINDOW_TARGETS), .WINDOW_EXECUTABLE(3'b001),
      .WINDOW_READABLE(3'b111), .WINDOW_WRITABLE(3'b111),
      .WINDOW_SOURCE_MASK(3'b111)
  ) u_soc_router (
      .clk(clk_i), .reset(reset_i), .req_valid(fabric_req_valid),
      .req_ready(fabric_req_ready), .write(fabric_write), .addr(fabric_addr),
      .wdata(fabric_wdata), .be(fabric_be), .instr(fabric_instr),
      .source_id(fabric_source_id), .transaction_id(fabric_transaction_id),
      .rsp_valid(fabric_rsp_valid), .rsp_ready(fabric_rsp_ready),
      .rdata(fabric_rdata), .error(fabric_error),
      .rsp_source_id(fabric_rsp_source_id),
      .rsp_transaction_id(fabric_rsp_transaction_id),
      .t_req_valid(target_req_valid), .t_req_ready(target_req_ready),
      .t_write(target_write), .t_addr(target_addr), .t_wdata(target_wdata),
      .t_be(target_be), .t_rsp_valid(target_rsp_valid),
      .t_rsp_ready(target_rsp_ready), .t_rdata(target_rdata),
      .t_error(target_error), .selected_target(selected_target),
      .stale_pending()
  );

  logic memory_flush;
  assign memory_flush = reset_i | backend_target_flush;
  riscv_boot_memory_64 #(
      .BASE_ADDR(RAM_BASE), .BYTES(65536), .LOAD_IMAGE(1)
  ) u_memory (
      .clock(clk_i), .reset(reset_n), .flush(memory_flush),
      .req_valid(target_req_valid[0]), .req_ready(target_req_ready[0]),
      .write(target_write[0]), .addr(target_addr[0]),
      .wdata(target_wdata[0]), .be(target_be[0]),
      .rsp_valid(target_rsp_valid[0]), .rsp_ready(target_rsp_ready[0]),
      .rdata(target_rdata[0]), .error(target_error[0])
  );

  // PULP GPIO behind the generic 64-to-32 lane adapter and APB3 bridge.
  logic gpio64_req_valid, gpio64_req_ready, gpio64_write;
  logic [63:0] gpio64_addr, gpio64_wdata, gpio64_rdata;
  logic [7:0] gpio64_be;
  logic gpio64_rsp_valid, gpio64_rsp_ready, gpio64_error;
  logic gpio32_req_valid, gpio32_req_ready, gpio32_write;
  logic [63:0] gpio32_addr;
  logic [31:0] gpio32_wdata, gpio32_rdata;
  logic [3:0] gpio32_be;
  logic gpio32_rsp_valid, gpio32_rsp_ready, gpio32_error;
  logic [11:0] gpio_paddr;
  logic [31:0] gpio_pwdata, gpio_prdata;
  logic gpio_pwrite, gpio_psel, gpio_penable, gpio_pready, gpio_pslverr;
  logic [7:0] gpio_out, gpio_dir, gpio_in_sync;
  logic [7:0][3:0] gpio_padcfg;

  mmio_width_adapter #(
      .RESET_CLEARS_TARGETS(1'b1), .ADDRESS_WIDTH(64), .DATA_WIDTH(64),
      .PERIPHERAL_DATA_WIDTH(32)
  ) u_gpio_width (
      .clk(clk_i), .reset(reset_i), .req_valid(target_req_valid[1]),
      .req_ready(target_req_ready[1]), .write(target_write[1]),
      .addr(target_addr[1]), .wdata(target_wdata[1]), .be(target_be[1]),
      .rsp_valid(target_rsp_valid[1]), .rsp_ready(target_rsp_ready[1]),
      .rdata(target_rdata[1]), .error(target_error[1]),
      .p_req_valid(gpio64_req_valid), .p_req_ready(gpio64_req_ready),
      .p_write(gpio64_write), .p_addr(gpio64_addr), .p_wdata(gpio64_wdata),
      .p_be(gpio64_be), .p_rsp_valid(gpio64_rsp_valid),
      .p_rsp_ready(gpio64_rsp_ready), .p_rdata(gpio64_rdata),
      .p_error(gpio64_error), .stale_pending()
  );
  assign gpio32_req_valid = gpio64_req_valid;
  assign gpio64_req_ready = gpio32_req_ready;
  assign gpio32_write = gpio64_write;
  assign gpio32_addr = gpio64_addr;
  assign gpio32_wdata = gpio64_wdata;
  assign gpio32_be = gpio64_be;
  assign gpio64_rsp_valid = gpio32_rsp_valid;
  assign gpio32_rsp_ready = gpio64_rsp_ready;
  assign gpio64_rdata = gpio32_rdata;
  assign gpio64_error = gpio32_error;

  processor_apb_bridge #(.ADDRESS_WIDTH(64), .APB_ADDR_WIDTH(12)) u_gpio_bridge (
      .clk_i(clk_i), .rst_ni(reset_n), .req_valid_i(gpio32_req_valid),
      .req_ready_o(gpio32_req_ready), .req_write_i(gpio32_write),
      .req_addr_i(gpio32_addr), .req_wdata_i(gpio32_wdata), .req_be_i(gpio32_be),
      .rsp_valid_o(gpio32_rsp_valid), .rsp_ready_i(gpio32_rsp_ready),
      .rsp_rdata_o(gpio32_rdata), .rsp_error_o(gpio32_error),
      .paddr_o(gpio_paddr), .pwdata_o(gpio_pwdata), .pwrite_o(gpio_pwrite),
      .psel_o(gpio_psel), .penable_o(gpio_penable), .prdata_i(gpio_prdata),
      .pready_i(gpio_pready), .pslverr_i(gpio_pslverr)
  );
  apb_gpio #(.APB_ADDR_WIDTH(12), .PAD_NUM(8), .NBIT_PADCFG(4)) u_gpio (
      .HCLK(clk_i), .HRESETn(reset_n), .dft_cg_enable_i(1'b1),
      .PADDR(gpio_paddr), .PWDATA(gpio_pwdata), .PWRITE(gpio_pwrite),
      .PSEL(gpio_psel), .PENABLE(gpio_penable), .PRDATA(gpio_prdata),
      .PREADY(gpio_pready), .PSLVERR(gpio_pslverr), .gpio_in(8'd0),
      .gpio_in_sync(gpio_in_sync), .gpio_out(gpio_out), .gpio_dir(gpio_dir),
      .gpio_padcfg(gpio_padcfg), .interrupt(gpio_irq_o)
  );
  assign gpio_out_o = {24'd0, gpio_out};
  assign gpio_dir_o = {24'd0, gpio_dir};

  // PULP SPI behind the same lane/APB path.
  logic spi64_req_valid, spi64_req_ready, spi64_write;
  logic [63:0] spi64_addr, spi64_wdata, spi64_rdata;
  logic [7:0] spi64_be;
  logic spi64_rsp_valid, spi64_rsp_ready, spi64_error;
  logic spi32_req_valid, spi32_req_ready, spi32_write;
  logic [63:0] spi32_addr;
  logic [31:0] spi32_wdata, spi32_rdata;
  logic [3:0] spi32_be;
  logic spi32_rsp_valid, spi32_rsp_ready, spi32_error;
  logic [11:0] spi_paddr;
  logic [31:0] spi_pwdata, spi_prdata;
  logic spi_pwrite, spi_psel, spi_penable, spi_pready, spi_pslverr;
  logic [1:0] spi_events;
  logic spi_clk, spi_csn0, spi_sdo0;
  mmio_width_adapter #(
      .RESET_CLEARS_TARGETS(1'b1), .ADDRESS_WIDTH(64), .DATA_WIDTH(64),
      .PERIPHERAL_DATA_WIDTH(32)
  ) u_spi_width (
      .clk(clk_i), .reset(reset_i), .req_valid(target_req_valid[2]),
      .req_ready(target_req_ready[2]), .write(target_write[2]),
      .addr(target_addr[2]), .wdata(target_wdata[2]), .be(target_be[2]),
      .rsp_valid(target_rsp_valid[2]), .rsp_ready(target_rsp_ready[2]),
      .rdata(target_rdata[2]), .error(target_error[2]),
      .p_req_valid(spi64_req_valid), .p_req_ready(spi64_req_ready),
      .p_write(spi64_write), .p_addr(spi64_addr), .p_wdata(spi64_wdata),
      .p_be(spi64_be), .p_rsp_valid(spi64_rsp_valid),
      .p_rsp_ready(spi64_rsp_ready), .p_rdata(spi64_rdata),
      .p_error(spi64_error), .stale_pending()
  );
  assign spi32_req_valid = spi64_req_valid;
  assign spi64_req_ready = spi32_req_ready;
  assign spi32_write = spi64_write;
  assign spi32_addr = spi64_addr;
  assign spi32_wdata = spi64_wdata;
  assign spi32_be = spi64_be;
  assign spi64_rsp_valid = spi32_rsp_valid;
  assign spi32_rsp_ready = spi64_rsp_ready;
  assign spi64_rdata = spi32_rdata;
  assign spi64_error = spi32_error;

  processor_apb_bridge #(.ADDRESS_WIDTH(64), .APB_ADDR_WIDTH(12)) u_spi_bridge (
      .clk_i(clk_i), .rst_ni(reset_n), .req_valid_i(spi32_req_valid),
      .req_ready_o(spi32_req_ready), .req_write_i(spi32_write),
      .req_addr_i(spi32_addr), .req_wdata_i(spi32_wdata), .req_be_i(spi32_be),
      .rsp_valid_o(spi32_rsp_valid), .rsp_ready_i(spi32_rsp_ready),
      .rsp_rdata_o(spi32_rdata), .rsp_error_o(spi32_error),
      .paddr_o(spi_paddr), .pwdata_o(spi_pwdata), .pwrite_o(spi_pwrite),
      .psel_o(spi_psel), .penable_o(spi_penable), .prdata_i(spi_prdata),
      .pready_i(spi_pready), .pslverr_i(spi_pslverr)
  );
  apb_spi_master #(.BUFFER_DEPTH(10), .APB_ADDR_WIDTH(12)) u_spi (
      .HCLK(clk_i), .HRESETn(reset_n), .PADDR(spi_paddr), .PWDATA(spi_pwdata),
      .PWRITE(spi_pwrite), .PSEL(spi_psel), .PENABLE(spi_penable),
      .PRDATA(spi_prdata), .PREADY(spi_pready), .PSLVERR(spi_pslverr),
      .events_o(spi_events), .spi_clk(spi_clk), .spi_csn0(spi_csn0),
      .spi_csn1(), .spi_csn2(), .spi_csn3(), .spi_mode(),
      .spi_sdo0(spi_sdo0), .spi_sdo1(), .spi_sdo2(), .spi_sdo3(),
      .spi_sdi0(1'b0), .spi_sdi1(1'b0), .spi_sdi2(1'b0), .spi_sdi3(1'b0)
  );
  assign spi_irq = |spi_events;
  assign spi_clk_o = spi_clk;
  assign spi_cs0_o = spi_csn0;
  assign spi_sdo0_o = spi_sdo0;

  assign cpu_mmio_transaction_o = source_req_valid[0] && source_req_ready[0];
  assign fabric_protocol_error_o = fabric_protocol_error;
  always_ff @(posedge clk_i or posedge reset_i) begin
    if (reset_i) begin
      cpu_transaction_count_o <= 32'd0;
      cpu_completion_count_o <= 32'd0;
    end else begin
      if (cpu_mmio_transaction_o)
        cpu_transaction_count_o <= cpu_transaction_count_o + 1'b1;
      if (source_rsp_valid[0] && source_rsp_ready[0])
        cpu_completion_count_o <= cpu_completion_count_o + 1'b1;
    end
  end
endmodule

`default_nettype wire
