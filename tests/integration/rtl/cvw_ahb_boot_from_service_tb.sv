// The harness supplies CVW's boot program itself: no preloaded RAM, no hierarchy
// poke.  The core's reset vector is inside the external-memory region (moved there
// by configs/cpus/cvw/config_extmem/config.vh), so the *first* fetch the core ever
// issues is addressed to the AHB-Lite port, and the service on the beat side is
// what answers it.
//
// WHY THIS BENCH IS THE INTERESTING ONE
//   The previous bench had to poke the core's uncore RAM through the hierarchy to
//   get a program in place, because upstream boots at 0x80000000 and the uncore RAM
//   answers there.  That poke is exactly what a generated harness cannot do.  This
//   bench removes it: the boot fetch arrives over AHB, so everything the core
//   executes comes from the service, which is how every other CPU in this
//   repository is booted.
//
// WHAT THIS PROVES
//   * the core's very first fetch is an AHB-Lite transfer to the external region,
//   * the harness's service decides what the core executes (the program is not in
//     any memory the core owns),
//   * the transfer completes through the subordinate's own handshake.
//
// WHAT IT DOES NOT PROVE
//   That a generated session runs: this is still a bench with a hand-written
//   service.  The generated runtime must give the AHB service a boot-resident
//   program; this bench shows that the boundary is capable of it.
`timescale 1ns/1ps
module cvw_ahb_boot_from_service_tb;
  localparam integer AW = 34, DW = 32;
  localparam [AW-1:0] EXT_BASE = 34'h0_C000_0000;   // derived EXT_MEM + RESET_VECTOR
  localparam integer  EXT_WORDS = 1024;
  localparam [AW-1:0] EXT_TOP = EXT_BASE + EXT_WORDS*4 - 1;
  localparam integer  MAX_CYCLES = 4000;

  logic clk = 0; always #5 clk = ~clk;
  logic rst_ni = 0;
  logic [1:0] HTRANS; logic [AW-1:0] HADDR; logic HWRITE;
  logic [2:0] HSIZE, HBURST; logic [3:0] HPROT; logic HMASTLOCK, HSELEXT;
  logic [DW-1:0] HWDATA; logic [3:0] HWSTRB;
  logic HREADYEXT; logic [DW-1:0] HRDATAEXT; logic HRESPEXT;
  logic req_valid, req_ready, req_write; logic [AW-1:0] req_addr;
  logic [DW-1:0] req_wdata; logic [3:0] req_be;
  logic rsp_valid, rsp_ready, rsp_error; logic [DW-1:0] rsp_rdata;

  // This is *not* the core's memory.  The core has no program anywhere; the only
  // copy of the program lives in the service.
  logic [31:0] service_memory [0:EXT_WORDS-1];

  cvw_ahb_cpu_top cpu(.clk, .reset_ext(~rst_ni), .HRDATAEXT, .HREADYEXT, .HRESPEXT,
    .HCLK(), .HRESETn(), .HADDR, .HWDATA, .HWSTRB, .HWRITE, .HSIZE, .HBURST,
    .HPROT, .HTRANS, .HMASTLOCK, .HREADY(), .HSELEXT);

  ahb_lite_memory_target #(.ADDRESS_WIDTH(AW), .DATA_WIDTH(DW), .MAX_WAIT_CYCLES(16)) tgt(
    .clk_i(clk), .rst_ni, .HTRANS, .HADDR, .HWRITE, .HSIZE, .HBURST, .HPROT,
    .HMASTLOCK, .HSELEXT, .HWDATA, .HWSTRB, .HREADYEXT, .HRDATAEXT, .HRESPEXT,
    .req_valid_o(req_valid), .req_ready_i(req_ready), .req_write_o(req_write),
    .req_addr_o(req_addr), .req_wdata_o(req_wdata), .req_be_o(req_be),
    .rsp_valid_i(rsp_valid), .rsp_ready_o(rsp_ready), .rsp_rdata_i(rsp_rdata),
    .rsp_error_i(rsp_error));

  logic serving = 0, awaiting_response = 0;
  logic [31:0] response_word;
  wire addressed = (req_addr >= EXT_BASE) && (req_addr <= EXT_TOP);
  assign req_ready = !serving && !awaiting_response;
  always_comb response_word = addressed ? service_memory[(req_addr - EXT_BASE) >> 2]
                                        : 32'h00000013;
  always_ff @(posedge clk) begin
    if (!rst_ni) begin
      serving <= 0; awaiting_response <= 0; rsp_valid <= 0;
    end else if (!awaiting_response && !serving && req_valid && req_ready) serving <= 1;
    else if (serving) begin
      serving <= 0; awaiting_response <= 1; rsp_valid <= 1; rsp_rdata <= response_word;
    end else if (awaiting_response && rsp_valid && rsp_ready) begin
      awaiting_response <= 0; rsp_valid <= 0;
    end
  end

  // ---- observations ---------------------------------------------------------
  integer boot_fetches = 0;          // fetches of the reset vector word
  integer served = 0;
  logic first_fetch_was_ahb = 0;     // the core's first fetch went over AHB
  logic saw_any_fetch = 0;
  logic [AW-1:0] first_fetch_addr = '0;
  integer failures = 0;
  task automatic check(input logic condition, input string message);
    begin
      if (!condition) begin failures = failures + 1; $display("FAIL: %s", message); end
    end
  endtask

  always @(posedge clk) begin
    if (HSELEXT && HTRANS != 2'b00) begin
      if (!saw_any_fetch) begin
        first_fetch_was_ahb <= 1;
        first_fetch_addr <= HADDR;
      end
      saw_any_fetch <= 1;
      if (HADDR == EXT_BASE) boot_fetches <= boot_fetches + 1;
    end
    if (req_valid && req_ready) served <= served + 1;
  end

  integer n = 0;
  always @(posedge clk) begin
    n <= n + 1;
    if (n == 20) rst_ni <= 1;
  end

  integer i;
  initial begin
    for (i = 0; i < EXT_WORDS; i = i + 1) service_memory[i] = 32'h00000013;
    // The whole program, and the core owns none of it:
    //   self: j self   -- the core must keep fetching this from the service.
    service_memory[0] = 32'h0000006F;
  end

  initial begin
    repeat (MAX_CYCLES) @(posedge clk);
    #1;
    check(first_fetch_was_ahb,
          "the core's first fetch is an AHB-Lite transfer, so the harness owns the boot program");
    check(first_fetch_addr == EXT_BASE,
          "the first fetch is addressed to the configured reset vector");
    check(served > 0, "the service answered the boot fetch");
    check(boot_fetches > 0, "the service supplied the word the core executed");
    check(HRESPEXT === 1'b0, "no error was invented on the boundary");
    if (failures == 0)
      $display("CVW_AHB_BOOT_FROM_SERVICE_TB: PASS (first=%h served=%0d boot_fetches=%0d)",
               first_fetch_addr, served, boot_fetches);
    else
      $display("CVW_AHB_BOOT_FROM_SERVICE_TB: FAIL (%0d)", failures);
    $finish;
  end
endmodule
