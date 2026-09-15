// Real-hardware-evidence testbench: a real ZipCPU Wishbone master executing a
// real program through the project's Wishbone CPU-side adapter.
//
//   real ZipCPU (zipwb, third_party/soc-zipcpu/rtl/core/zipwb.v)
//     -> src/myfuzz/protocols/rtl/wishbone_processor_memory_adapter.sv
//     -> src/myfuzz/protocols/rtl/processor_memory_backend.sv
//     -> the beat-level RAM responder that lives at the bottom of this file
//
// The CPU is a *source* core, not a model: it fetches, decodes and executes the
// program in $zipcpu_boot_image (see tests/integration/zipcpu_boot_image.py) and
// the only clock domain is the one driven here.  The pass criterion is the RAM
// array content the program is written to produce:
//
//   ram[0x200] == 0x0000beef   (an LDI immediate, stored)
//   ram[0x204] == 0x0000bef0   (loaded back from 0x200, ADDed 1, stored again)
//
// The second word can only exist if the CPU really completed an instruction
// fetch, an LDI, a store, a load, an ALU op and a second store through the
// adapter and the backend, so a "the CPU never ran" pass is impossible.
//
//   iverilog -g2012 -s soc_zipcpu_wishbone_tb -o tb.vvp <zipcpu closure> \
//            src/myfuzz/protocols/rtl/wishbone_processor_memory_adapter.sv \
//            src/myfuzz/protocols/rtl/processor_memory_backend.sv \
//            tests/integration/rtl/soc_zipcpu_wishbone_tb.sv
//   vvp tb.vvp +zipcpu_boot_image=tests/fixtures/soc_zipcpu_wishbone_boot.hex
//
// Success prints exactly one machine checkable line:
//   SOC_ZIPCPU_WISHBONE_REAL_OK stores=2 data=0000beef0000bef0 ...
// Every failure path (watchdog timeout, o_break, wrong RAM contents, an err_o
// response, a response without a request, an ack without a response, a stuck
// stall_o, a transfer whose address changes while its termination is held) ends
// in $fatal, so a hung or misbehaving CPU fails instead of hanging.

`timescale 1ns / 1ps

module soc_zipcpu_wishbone_tb;

    // ------------------------------------------------------------------
    // Sizing constants.  These mirror tests/integration/zipcpu_boot_image.py.
    // ------------------------------------------------------------------
    // ADDRESS_WIDTH is 30, not 32, on purpose.  zipwb's RESET_ADDRESS is a
    // [31:0] parameter but zipcore.v:134 takes
    //     localparam [(AW-1):0] RESET_BUS_ADDRESS = RESET_ADDRESS[AW+1:2];
    // so AW=32 selects RESET_ADDRESS[33:2], whose two top bits do not exist and
    // come back as X.  The X lands in the CPU's program counter and the core
    // stops making progress (observed: three fetches, then a dead bus).  With
    // AW=30 the select is RESET_ADDRESS[31:2] and {o_wb_addr, 2'b00} is exactly
    // the 32-bit byte address the adapter wants.
    localparam integer AW              = 30;
    localparam [31:0]  RESET_ADDRESS   = 32'h0000_0100;
    localparam integer MEM_WORDS       = 1024;         // image is zero padded to this
    localparam integer MEM_INDEX_BITS  = 10;           // $clog2(MEM_WORDS)

    localparam [31:0]  STORE_A_ADDR    = 32'h0000_0200;
    localparam [31:0]  STORE_B_ADDR    = 32'h0000_0204;
    localparam [31:0]  EXPECT_A        = 32'h0000_beef;
    localparam [31:0]  EXPECT_B        = 32'h0000_bef0;

    localparam integer RESET_CYCLES     = 8;
    localparam integer WATCHDOG_CYCLES  = 20000;
    localparam integer SETTLE_CYCLES    = 64;          // quiet window after the last store
    localparam integer MAX_STALL_RUN    = 64;          // stall_o must never be stuck
    localparam integer TRACE_DEPTH      = 16;

    // ------------------------------------------------------------------
    // Clock and reset
    // ------------------------------------------------------------------
    logic clk;
    initial clk = 1'b0;
    always #5 clk = ~clk;

    logic rst_ni;        // adapter + backend: synchronous, active low
    logic cpu_reset;     // ZipCPU: synchronous, active high

    // ------------------------------------------------------------------
    // CPU debug/idle inputs
    // ------------------------------------------------------------------
    logic        i_halt;
    logic        i_interrupt;
    logic        i_clear_cache;
    logic        i_cpu_clken;
    logic [4:0]  i_dbg_wreg;
    logic        i_dbg_we;
    logic [31:0] i_dbg_data;
    logic [4:0]  i_dbg_rreg;

    // ------------------------------------------------------------------
    // Interconnect nets (declared up front: Icarus elaborates in source order)
    // ------------------------------------------------------------------
    // CPU-side Wishbone -> beat adapter (frozen project RTL)
    wire        adp_stall, adp_ack, adp_err;
    wire [31:0] adp_dat_r;
    wire        adp_req_valid, adp_req_write, adp_req_ready;
    wire [31:0] adp_req_addr, adp_req_wdata;
    wire [3:0]  adp_req_be;
    wire        adp_rsp_valid, adp_rsp_ready, adp_rsp_error;
    wire [31:0] adp_rsp_rdata;

    // beat backend (frozen project RTL)
    wire        bck_req_ready, bck_rsp_valid, bck_rsp_error;
    wire [31:0] bck_rsp_rdata;
    wire        bck_cancel_ready, bck_flush;
    wire        tgt_req_valid, tgt_write, tgt_rsp_ready;
    wire [31:0] tgt_addr, tgt_wdata;
    wire [3:0]  tgt_be;

    // beat-level RAM responder (target side of the backend)
    logic        ram_rsp_valid;
    logic [31:0] ram_rsp_rdata;
    logic        ram_rsp_error;
    logic        tgt_req_ready;
    logic [31:0] ram [0:MEM_WORDS-1];

    // ------------------------------------------------------------------
    // Real ZipCPU as a Wishbone master
    // ------------------------------------------------------------------
    // Note: zipwb's o_halted is !o_dbg_stall (zipwb.v:305), i.e. "the debug port
    // is ready", not "the HALT instruction was executed".  This testbench does
    // not use it as a pass signal: termination is proven by the RAM content plus
    // the bus quiescence window instead.
    wire        o_dbg_stall;
    wire        o_halted;
    wire [31:0] o_dbg_reg;
    wire [2:0]  o_dbg_cc;
    wire        o_break;
    wire        wb_gbl_cyc, wb_gbl_stb;
    wire        wb_lcl_cyc, wb_lcl_stb;
    wire        wb_we;
    wire [AW-1:0] wb_addr;      // WORD address: RESET_BUS_ADDRESS = RESET_ADDRESS[AW+1:2]
    wire [31:0] wb_data;
    wire [3:0]  wb_sel;
    wire        o_op_stall, o_pf_stall, o_i_count;
    wire [31:0] o_debug;
    wire        o_prof_stb;
    wire [AW+1:0] o_prof_addr;
    wire [31:0] o_prof_ticks;

    zipwb #(
        .RESET_ADDRESS   (RESET_ADDRESS),
        .ADDRESS_WIDTH   (AW),
        .OPT_LGICACHE    (0),              // no I-cache: every fetch is a bus transfer
        .OPT_LGDCACHE    (0),              // no D-cache: every load/store is a bus transfer
        .OPT_SIM         (1'b1),
        .OPT_START_HALTED(1'b1),           // released by deasserting i_halt
        .OPT_PIPELINED   (1'b0),           // classic (non pipelined) Wishbone master
        .WITH_LOCAL_BUS  (1'b0)            // single bus: global only
    ) u_cpu (
        .i_clk         (clk),
        .i_reset       (cpu_reset),
        .i_interrupt   (i_interrupt),
        .i_cpu_clken   (i_cpu_clken),
        .i_halt        (i_halt),
        .i_clear_cache (i_clear_cache),
        .i_dbg_wreg    (i_dbg_wreg),
        .i_dbg_we      (i_dbg_we),
        .i_dbg_data    (i_dbg_data),
        .i_dbg_rreg    (i_dbg_rreg),
        .o_dbg_stall   (o_dbg_stall),
        .o_halted      (o_halted),
        .o_dbg_reg     (o_dbg_reg),
        .o_dbg_cc      (o_dbg_cc),
        .o_break       (o_break),
        .o_wb_gbl_cyc  (wb_gbl_cyc),
        .o_wb_gbl_stb  (wb_gbl_stb),
        .o_wb_lcl_cyc  (wb_lcl_cyc),
        .o_wb_lcl_stb  (wb_lcl_stb),
        .o_wb_we       (wb_we),
        .o_wb_addr     (wb_addr),
        .o_wb_data     (wb_data),
        .o_wb_sel      (wb_sel),
        .i_wb_stall    (adp_stall),
        .i_wb_ack      (adp_ack),
        .i_wb_data     (adp_dat_r),
        .i_wb_err      (adp_err),
        .o_op_stall    (o_op_stall),
        .o_pf_stall    (o_pf_stall),
        .o_i_count     (o_i_count),
        .o_debug       (o_debug),
        .o_prof_stb    (o_prof_stb),
        .o_prof_addr   (o_prof_addr),
        .o_prof_ticks  (o_prof_ticks)
    );

    // The ZipCPU splits its Wishbone master into a global and a local channel.
    // WITH_LOCAL_BUS=0 keeps the local channel quiet, but both are combined here
    // so the adapter sees one classic bus either way.
    wire cpu_cyc = wb_gbl_cyc | wb_lcl_cyc;
    wire cpu_stb = wb_gbl_stb | wb_lcl_stb;

    // o_wb_addr is a WORD address (zipcore.v:134
    //   localparam [(AW-1):0] RESET_BUS_ADDRESS = RESET_ADDRESS[AW+1:2];)
    // while the adapter wants a BYTE address, hence the two zero bits.  With
    // AW=30 this expression is exactly 32 bits wide.
    wire [AW+1:0] cpu_byte_addr = {wb_addr, 2'b00};

    // ------------------------------------------------------------------
    // CPU-side Wishbone -> beat adapter (frozen project RTL)
    // ------------------------------------------------------------------
    wishbone_processor_memory_adapter #(
        .ADDRESS_WIDTH(32),
        .DATA_WIDTH   (32),
        .READ_ONLY    (0),
        .HAS_SEL      (1)
    ) u_adapter (
        .clk_i        (clk),
        .rst_ni       (rst_ni),
        .cyc_i        (cpu_cyc),
        .stb_i        (cpu_stb),
        .we_i         (wb_we),
        .adr_i        (cpu_byte_addr),
        .dat_w_i      (wb_data),
        .sel_i        (wb_sel),
        .stall_o      (adp_stall),
        .ack_o        (adp_ack),
        .err_o        (adp_err),
        .dat_r_o      (adp_dat_r),
        .req_valid_o  (adp_req_valid),
        .req_ready_i  (adp_req_ready),
        .req_write_o  (adp_req_write),
        .req_addr_o   (adp_req_addr),
        .req_wdata_o  (adp_req_wdata),
        .req_be_o     (adp_req_be),
        .rsp_valid_i  (adp_rsp_valid),
        .rsp_ready_o  (adp_rsp_ready),
        .rsp_rdata_i  (adp_rsp_rdata),
        .rsp_error_i  (adp_rsp_error)
    );

    // ------------------------------------------------------------------
    // beat backend (frozen project RTL)
    // ------------------------------------------------------------------
    myfuzz_processor_memory_backend #(
        .ADDRESS_WIDTH (32),
        .DATA_WIDTH    (32),
        .MAX_WAIT_CYCLES(16)
    ) u_backend (
        .clk_i             (clk),
        .rst_ni            (rst_ni),
        .req_valid_i       (adp_req_valid),
        .req_ready_o       (bck_req_ready),
        .req_write_i       (adp_req_write),
        .req_addr_i        (adp_req_addr),
        .req_wdata_i       (adp_req_wdata),
        .req_be_i          (adp_req_be),
        .req_mapped_i      (1'b1),        // every address the CPU uses is mapped
        .rsp_valid_o       (bck_rsp_valid),
        .rsp_ready_i       (adp_rsp_ready),
        .rsp_rdata_o       (bck_rsp_rdata),
        .rsp_error_o       (bck_rsp_error),
        .cancel_valid_i    (1'b0),
        .cancel_ready_o    (bck_cancel_ready),
        .target_flush_o    (bck_flush),
        .target_req_valid_o(tgt_req_valid),
        .target_req_ready_i(tgt_req_ready),
        .target_write_o    (tgt_write),
        .target_addr_o     (tgt_addr),
        .target_wdata_o    (tgt_wdata),
        .target_be_o       (tgt_be),
        .target_rsp_valid_i(ram_rsp_valid),
        .target_rsp_ready_o(tgt_rsp_ready),
        .target_rdata_i    (ram_rsp_rdata),
        .target_error_i    (ram_rsp_error)
    );

    assign adp_req_ready = bck_req_ready;
    assign adp_rsp_valid = bck_rsp_valid;
    assign adp_rsp_rdata = bck_rsp_rdata;
    assign adp_rsp_error = bck_rsp_error;

    // ------------------------------------------------------------------
    // Beat-level RAM responder -- the target side of the backend.
    // One outstanding request, one cycle of registered response latency.
    // ------------------------------------------------------------------
    integer      write_count;
    integer      read_count;          // every read the backend made (fetches + loads)
    integer      read_trace_count;    // how many of them are recorded below
    logic [31:0] store_addr_q [0:TRACE_DEPTH-1];
    logic [31:0] store_data_q [0:TRACE_DEPTH-1];
    logic [3:0]  store_be_q   [0:TRACE_DEPTH-1];
    logic [31:0] read_addr_q [0:TRACE_DEPTH-1];

    // A response can only be produced once, and only for a request we accepted.
    logic        tgt_busy;

    wire tgt_fire     = tgt_req_valid && tgt_req_ready;
    wire tgt_rsp_fire = ram_rsp_valid && tgt_rsp_ready;
    wire [31:0] tgt_word_index = tgt_addr >> 2;

    integer bi;
    integer ri;

    // ------------------------------------------------------------------
    // Boot image.  Zeroing the whole array first is what keeps an uninitialised
    // fetch from returning X, and it must happen in the same initial block as
    // the load: separate initial blocks have no defined order at time 0.
    // ------------------------------------------------------------------
    reg [8*512-1:0] boot_image_path;
    initial begin
        for (ri = 0; ri < MEM_WORDS; ri = ri + 1)
            ram[ri] = 32'h0000_0000;
        if (!$value$plusargs("zipcpu_boot_image=%s", boot_image_path))
            boot_image_path = "tests/fixtures/soc_zipcpu_wishbone_boot.hex";
        $readmemh(boot_image_path, ram);
        // The image must really contain the program, otherwise the CPU would
        // execute zeroes and this test would be measuring nothing.
        if (ram[RESET_ADDRESS >> 2] !== 32'h0e00_0200) begin
            $fatal(1, "boot image %0s does not hold the expected program at %08x (got %08x)",
                   boot_image_path, RESET_ADDRESS, ram[RESET_ADDRESS >> 2]);
        end
        // Anti-vacuity: the words the program is supposed to produce must start
        // cleared, so the only way they can hold the expected values at the end
        // is that the real CPU wrote them through the adapter and the backend.
        if (ram[STORE_A_ADDR >> 2] !== 32'h0 || ram[STORE_B_ADDR >> 2] !== 32'h0) begin
            $fatal(1, "boot image preloads the expected store results; the pass check would be vacuous");
        end
    end

    always_ff @(posedge clk) begin
        if (!rst_ni) begin
            ram_rsp_valid      <= 1'b0;
            ram_rsp_rdata      <= 32'h0;
            ram_rsp_error      <= 1'b0;
            tgt_busy           <= 1'b0;
            tgt_req_ready      <= 1'b0;
            write_count        <= 0;
            read_count         <= 0;
            read_trace_count        <= 0;
        end else begin
            tgt_req_ready <= !tgt_busy && !ram_rsp_valid;

            if (tgt_rsp_fire) begin
                ram_rsp_valid <= 1'b0;
                tgt_busy      <= 1'b0;
            end

            if (tgt_fire) begin
                // The backend must never hand us a request while we already own one.
                if (tgt_busy || ram_rsp_valid) begin
                    $fatal(1, "RAM: request accepted while a request was already in flight");
                end
                if (tgt_word_index >= MEM_WORDS) begin
                    $fatal(1, "RAM: out-of-range byte address %08x from the CPU", tgt_addr);
                end
                tgt_busy      <= 1'b1;
                ram_rsp_valid <= 1'b1;
                ram_rsp_error <= 1'b0;
                if (tgt_write) begin
                    for (bi = 0; bi < 4; bi = bi + 1)
                        if (tgt_be[bi])
                            ram[tgt_word_index[MEM_INDEX_BITS-1:0]][8*bi +: 8]
                                <= tgt_wdata[8*bi +: 8];
                    if (write_count < TRACE_DEPTH) begin
                        store_addr_q[write_count] <= tgt_addr;
                        store_data_q[write_count] <= tgt_wdata;
                        store_be_q[write_count]   <= tgt_be;
                    end
                    write_count <= write_count + 1;
                end else begin
                    ram_rsp_rdata <= ram[tgt_word_index[MEM_INDEX_BITS-1:0]];
                    read_count    <= read_count + 1;
                    if (read_trace_count < TRACE_DEPTH) begin
                        read_addr_q[read_trace_count] <= tgt_addr;
                    end
                    read_trace_count <= read_trace_count + 1;
                end
            end
        end
    end

    // ------------------------------------------------------------------
    // Adapter / backend contract checkers
    // ------------------------------------------------------------------
    integer ack_rises;
    integer rsp_accepted;
    integer stall_run;
    integer violations;
    logic   req_outstanding;
    logic   ack_q;
    logic   transfer_active_q;
    logic [31:0] held_addr_q;
    logic [31:0] held_wdata_q;
    logic [3:0]  held_be_q;

    always_ff @(posedge clk) begin
        if (!rst_ni) begin
            ack_rises        <= 0;
            rsp_accepted     <= 0;
            stall_run        <= 0;
            violations       <= 0;
            req_outstanding  <= 1'b0;
            ack_q            <= 1'b0;
            transfer_active_q<= 1'b0;
            held_addr_q      <= 32'h0;
            held_wdata_q     <= 32'h0;
            held_be_q        <= 4'h0;
        end else begin
            ack_q <= adp_ack;

            // (0) The CPU's address bus must never carry X.  This is the first
            // thing that breaks if the CPU's ADDRESS_WIDTH and RESET_ADDRESS
            // disagree (see the AW comment above).
            if ((cpu_cyc || cpu_stb) && (^cpu_byte_addr === 1'bx)) begin
                violations <= violations + 1;
                $display("SOC_ZIPCPU_WISHBONE_VIOLATION CPU address bus contains X at cycle %0d: %b",
                         $time, cpu_byte_addr);
            end

            // (1) No response for a request never issued.
            if (adp_rsp_valid && !req_outstanding) begin
                violations <= violations + 1;
                $display("SOC_ZIPCPU_WISHBONE_VIOLATION response with no outstanding request at cycle %0d", $time);
            end
            if (adp_req_valid && adp_req_ready) begin
                req_outstanding <= 1'b1;
            end
            if (adp_rsp_valid && adp_rsp_ready) begin
                req_outstanding <= 1'b0;
                rsp_accepted    <= rsp_accepted + 1;
            end

            // (2) No ack without a completed backend response.
            if (adp_ack && !ack_q) begin
                ack_rises <= ack_rises + 1;
                if (ack_rises >= rsp_accepted) begin
                    violations <= violations + 1;
                    $display("SOC_ZIPCPU_WISHBONE_VIOLATION ack_o without a completed backend response at cycle %0d", $time);
                end
            end

            // (3) A response must never carry an error on this path.
            if (adp_err) begin
                violations <= violations + 1;
                $display("SOC_ZIPCPU_WISHBONE_VIOLATION adapter err_o asserted at cycle %0d", $time);
            end
            if (adp_rsp_valid && adp_rsp_error) begin
                violations <= violations + 1;
                $display("SOC_ZIPCPU_WISHBONE_VIOLATION backend response with rsp_error set at cycle %0d", $time);
            end

            // (4) stall_o must not be stuck.
            if (adp_stall) begin
                stall_run <= stall_run + 1;
                if (stall_run + 1 >= MAX_STALL_RUN) begin
                    $fatal(1, "adapter stall_o asserted for %0d consecutive cycles (stuck)", stall_run + 1);
                end
            end else begin
                stall_run <= 0;
            end

            // (5) A held termination means the transfer is not over: the master
            // must keep address/data/select stable until it drops STB.
            if (adp_ack) begin
                if (transfer_active_q &&
                    ((held_addr_q !== cpu_byte_addr) ||
                     (held_wdata_q !== wb_data) ||
                     (held_be_q !== wb_sel))) begin
                    violations <= violations + 1;
                    $display("SOC_ZIPCPU_WISHBONE_VIOLATION transfer changed while ack_o was held (cycle %0d): %08x->%08x",
                             $time, held_addr_q, cpu_byte_addr);
                end
                transfer_active_q <= 1'b1;
                held_addr_q       <= cpu_byte_addr;
                held_wdata_q      <= wb_data;
                held_be_q         <= wb_sel;
            end else begin
                transfer_active_q <= 1'b0;
            end
        end
    end

    // ------------------------------------------------------------------
    // Stimulus + pass/fail
    // ------------------------------------------------------------------
    integer cycles;
    integer settle;
    logic   ram_ok;

    assign ram_ok = (ram[STORE_A_ADDR >> 2] === EXPECT_A) &&
                    (ram[STORE_B_ADDR >> 2] === EXPECT_B);

    initial begin
        i_halt        = 1'b1;
        i_interrupt   = 1'b0;
        i_clear_cache = 1'b0;
        i_cpu_clken   = 1'b1;
        i_dbg_wreg    = 5'h0;
        i_dbg_we      = 1'b0;
        i_dbg_data    = 32'h0;
        i_dbg_rreg    = 5'h0;
        rst_ni        = 1'b0;
        cpu_reset     = 1'b1;

        repeat (RESET_CYCLES) @(posedge clk);
        rst_ni = 1'b1;
        repeat (2) @(posedge clk);
        cpu_reset = 1'b0;
        @(posedge clk);
        i_halt = 1'b0;         // release the start-halted real CPU

        settle = 0;
        for (cycles = 0; cycles < WATCHDOG_CYCLES; cycles = cycles + 1) begin
            @(posedge clk);

            if (o_break) begin
                $fatal(1, "ZipCPU asserted o_break at cycle %0d: the program trapped (bad encoding or illegal instruction)",
                       cycles);
            end
            if (violations != 0) begin
                $fatal(1, "adapter/backend contract violation(s): %0d (see SOC_ZIPCPU_WISHBONE_VIOLATION lines)", violations);
            end

            if (ram_ok && !(adp_req_valid && adp_req_ready)) begin
                // The pass criterion is: both program produced words are in RAM
                // *and* the CPU has stopped asking the bus for anything for
                // SETTLE_CYCLES in a row.  The quiescence half is what proves the
                // program terminated (the HALT put the core to sleep) instead of
                // the CPU merely being mid-flight when we looked; it is also why
                // a late or repeated store cannot slip past unnoticed.
                settle = settle + 1;
                if (settle >= SETTLE_CYCLES) begin
                    if (write_count != 2) begin
                        $fatal(1, "RAM is correct but the CPU issued %0d writes (expected exactly 2)", write_count);
                    end
                    if (read_count == 0) begin
                        $fatal(1, "RAM is correct but the backend never saw a read: the CPU did not fetch");
                    end
                    $display("SOC_ZIPCPU_WISHBONE_REAL_OK stores=%0d data=%08x%08x cycles=%0d reads=%0d quiet=%0d",
                             write_count,
                             ram[STORE_A_ADDR >> 2], ram[STORE_B_ADDR >> 2],
                             cycles + 1, read_count, settle);
                    for (bi = 0; bi < write_count && bi < TRACE_DEPTH; bi = bi + 1)
                        $display("SOC_ZIPCPU_WISHBONE_TRACE store[%0d] addr=%08x data=%08x be=%b",
                                 bi, store_addr_q[bi], store_data_q[bi], store_be_q[bi]);
                    for (bi = 0; bi < read_trace_count && bi < TRACE_DEPTH; bi = bi + 1)
                        $display("SOC_ZIPCPU_WISHBONE_TRACE read[%0d] addr=%08x", bi, read_addr_q[bi]);
                    $finish;
                end
            end else begin
                settle = 0;
            end
        end

        $display("SOC_ZIPCPU_WISHBONE_TIMEOUT after %0d cycles: ram[%08x]=%08x (want %08x) ram[%08x]=%08x (want %08x) writes=%0d reads=%0d halted=%0b break=%0b",
                 WATCHDOG_CYCLES, STORE_A_ADDR, ram[STORE_A_ADDR >> 2], EXPECT_A,
                 STORE_B_ADDR, ram[STORE_B_ADDR >> 2], EXPECT_B,
                 write_count, read_count, o_halted, o_break);
        for (bi = 0; bi < write_count && bi < TRACE_DEPTH; bi = bi + 1)
            $display("SOC_ZIPCPU_WISHBONE_TRACE store[%0d] addr=%08x data=%08x be=%b",
                     bi, store_addr_q[bi], store_data_q[bi], store_be_q[bi]);
        for (bi = 0; bi < read_trace_count && bi < TRACE_DEPTH; bi = bi + 1)
            $display("SOC_ZIPCPU_WISHBONE_TRACE read[%0d] addr=%08x", bi, read_addr_q[bi]);
        $fatal(1, "watchdog expired: the real ZipCPU did not complete the program");
    end

endmodule
