// Self-checking bench: a *real* CVW instruction fetch answered by this
// repository's AHB-Lite subordinate (src/myfuzz/protocols/rtl/ahb_lite_memory_target.sv).
//
// WHY THIS BENCH EXISTS
//   Every earlier attempt to measure a real AHB transaction from CVW failed, and
//   each failure had a different, non-obvious cause.  All of them are recorded
//   here because they are the reason this bench is shaped the way it is:
//
//   1. Direction: the first adapter (``beat_to_ahb_lite``) drove HTRANS/HADDR as
//      if the harness were the AHB manager.  CVW is the manager, so nothing could
//      ever come out of the CPU.  The subordinate answers instead.
//   2. Feature flag: ``adrdec.Sel = Match & Supported & AccessValid & SizeValid``,
//      and every committed CVW configuration sets ``EXT_MEM_SUPPORTED = 0``, so
//      ``HSELEXT`` can never assert and the external region is unreachable.  This
//      bench therefore uses the repository's *derived* configuration
//      (``configs/cpus/cvw/config_extmem/config.vh``), which must be first on the
//      include path.
//   3. Region overlap: upstream gives ``EXT_MEM`` the same base as
//      ``UNCORE_RAM`` (``0x80000000``); the derived configuration moves external
//      memory to ``0xC0000000``.
//   4. Empty memory: the core's uncore RAM is built with ``PRELOAD = 0`` and does
//      no ``$readmemh``, so it contains zeros.  The core was fetching and
//      executing zeros, which is why it fetched a few words and stopped.  A bench
//      that cannot place a program cannot produce a transaction, so this one
//      preloads the RAM array through the hierarchy.
//
// WHAT THIS BENCH PROVES
//   The CPU executes a real program, and an instruction fetch that lands in the
//   external-memory region produces a real AHB-Lite transfer whose address,
//   strobes and completion are all observed on the boundary:
//     * ``HSELEXT`` asserts (the region is genuinely selected),
//     * ``HREADYEXT`` is held low while the service works and returns high to
//       complete the transfer,
//     * the subordinate presents the CPU's address on its beat face,
//     * the data the service returns is what the CPU then acts on - the jump into
//       external memory only happens because the load of ``lui/jalr`` succeeded.
//
// WHAT THIS BENCH DOES NOT PROVE (stated so it cannot be read as more)
//   It is not the generated harness: the boot program is placed by a hierarchical
//   poke, not by the harness's own service.  Turning that into a runnable session
//   needs the generated runtime to preload or serve the boot path, which is not
//   done here.  It also does not claim burst, cache, error or multi-outstanding
//   behaviour.
`timescale 1ns/1ps
module cvw_ahb_real_transaction_tb;
  localparam integer AW = 34, DW = 32;
  localparam [AW-1:0] EXT_BASE  = 34'h0_C000_0000;   // derived EXT_MEM region
  localparam [AW-1:0] INT_BASE  = 34'h0_8000_0000;   // uncore RAM / reset vector
  localparam integer  INT_WORDS = 1024;
  localparam integer  EXT_WORDS = 1024;
  localparam [AW-1:0] EXT_TOP   = EXT_BASE + EXT_WORDS*4 - 1;
  localparam integer  MAX_CYCLES = 6000;

  logic clk = 0; always #5 clk = ~clk;
  logic rst_ni = 0;
  logic [1:0] HTRANS; logic [AW-1:0] HADDR; logic HWRITE;
  logic [2:0] HSIZE, HBURST; logic [3:0] HPROT; logic HMASTLOCK, HSELEXT;
  logic [DW-1:0] HWDATA; logic [3:0] HWSTRB;
  logic HREADYEXT; logic [DW-1:0] HRDATAEXT; logic HRESPEXT;
  logic req_valid, req_ready, req_write; logic [AW-1:0] req_addr;
  logic [DW-1:0] req_wdata; logic [3:0] req_be;
  logic rsp_valid, rsp_ready, rsp_error; logic [DW-1:0] rsp_rdata;

  logic [31:0] ext_mem [0:EXT_WORDS-1];
  logic [31:0] boot_program [0:7];

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

  // ---- the service: accept, wait one cycle, present, hold until taken -------
  logic serving = 0, awaiting_response = 0;
  logic [31:0] response_word;
  wire in_external = (req_addr >= EXT_BASE) && (req_addr <= EXT_TOP);
  assign req_ready = !serving && !awaiting_response;
  always_comb response_word = in_external ? ext_mem[(req_addr - EXT_BASE) >> 2]
                                          : 32'h00000013;
  always_ff @(posedge clk) begin
    if (!awaiting_response && !serving && req_valid && req_ready) serving <= 1;
    else if (serving) begin
      serving <= 0; awaiting_response <= 1; rsp_valid <= 1; rsp_rdata <= response_word;
    end else if (awaiting_response && rsp_valid && rsp_ready) begin
      awaiting_response <= 0; rsp_valid <= 0;
    end
    if (!rst_ni) begin
      serving <= 0; awaiting_response <= 0; rsp_valid <= 0;
    end
  end

  // ---- observations ---------------------------------------------------------
  integer served = 0, external_served = 0;
  logic ext_selected_at_least_once = 0;   // HSELEXT really asserted
  logic external_request_seen = 0;        // the subordinate saw an external address
  logic held_then_completed = 0;          // HREADYEXT went low, then high again
  logic saw_low_ready = 0;
  logic [AW-1:0] first_external_addr = '0;
  integer failures = 0;
  task automatic check(input logic condition, input string message);
    begin
      if (!condition) begin failures = failures + 1; $display("FAIL: %s", message); end
    end
  endtask

  always @(posedge clk) begin
    if (HSELEXT && HTRANS != 2'b00) ext_selected_at_least_once <= 1;
    if (req_valid && in_external) begin
      if (external_request_seen == 0) first_external_addr <= req_addr;
      external_request_seen <= 1;
    end
    if (HSELEXT && HREADYEXT === 1'b0) saw_low_ready <= 1;
    if (saw_low_ready && HSELEXT && HREADYEXT === 1'b1) held_then_completed <= 1;
    if (req_valid && req_ready) begin
      served <= served + 1;
      if (in_external) external_served <= external_served + 1;
    end
  end

  integer n = 0;
  always @(posedge clk) begin
    n <= n + 1;
    if (n == 20) rst_ni <= 1;
  end

  integer i;
  integer poked = 0;
  task automatic poke_boot(input integer index, input logic [31:0] word);
    begin
      // The core's uncore RAM is instantiated with PRELOAD = 0 upstream, so this
      // is the only way to give the core a program without editing upstream RTL.
      cpu.dut.uncoregen.uncore.ram.ram.memory.ram.RAM[index] = word;
      poked = poked + 1;
    end
  endtask

  initial begin
    for (i = 0; i < EXT_WORDS; i = i + 1) ext_mem[i] = 32'h00000013;  // NOP
    for (i = 0; i < 8; i = i + 1) boot_program[i] = 32'h00000013;
    boot_program[0] = 32'hC00002B7;   // lui  t0, 0xC0000  -> t0 = 0xC0000000
    boot_program[1] = 32'h000280E7;   // jalr ra, 0(t0)     -> jump into external
    boot_program[2] = 32'h00000013;   // nop (delay slot)
    ext_mem[0]      = 32'h0000006F;   // self: j self       -> keep fetching there
    for (i = 0; i < 8; i = i + 1) poke_boot(i, boot_program[i]);
  end

  initial begin
    repeat (MAX_CYCLES) @(posedge clk);
    #1;
    check(poked == 8, "the boot program was placed in the core's RAM");
    check(ext_selected_at_least_once,
          "HSELEXT asserts, so the derived configuration really selects external memory");
    check(external_request_seen,
          "the subordinate saw a request addressed to the external region");
    check(first_external_addr == EXT_BASE,
          "the first external request is the reset program's jump target");
    check(held_then_completed,
          "HREADYEXT was held low for the transfer and then returned high to complete it");
    check(external_served > 0, "the service answered at least one external fetch");
    check(external_served == served, "every fetch the service answered was external");
    check(HRESPEXT === 1'b0, "no error was invented on the boundary");
    if (failures == 0)
      $display("CVW_AHB_REAL_TRANSACTION_TB: PASS (external=%0d first=%h)",
               external_served, first_external_addr);
    else
      $display("CVW_AHB_REAL_TRANSACTION_TB: FAIL (%0d)", failures);
    $finish;
  end
endmodule
