`timescale 1ns/1ps
//
// Real PicoRV32 (AXI4-Lite master) end-to-end through the new AXI4-Lite
// CPU-side adapter:
//
//   picorv32_axi -> axi4_lite_processor_memory_adapter
//                -> myfuzz_processor_memory_backend
//                -> soc_cpu_beat_ram
//
// This is the counterpart of soc_picorv32_wishbone_tb.sv: the same core, the
// same committed boot image and the same RAM model, so the only difference
// between the two runs is the initiator protocol in front of the adapter.
//
// What the bench refuses to accept:
//   - a CPU that hangs (cycle watchdog),
//   - a retired instruction stream that diverges from the committed boot image
//     (word and PC compared on every retirement, trap and illegal instruction
//     included), so "the program really ran" is not inferred from side effects,
//   - an error response for an in-range access, on either the AXI response
//     channel or the beat backend,
//   - RAM contents that only a widened byte enable could have produced: the
//     byte and halfword stores are checked as whole words, so an adapter that
//     turned a 1-byte store into a 4-byte store fails here,
//   - a mismatch between the number of stores the CPU reports retiring and the
//     number of writes that actually reached memory (no invented, no dropped
//     writes).
//
// The AXI4-Lite master here has no BRESP/RRESP inputs (PicoRV32 ignores the
// response codes), so the response signals are wired into the bench and checked
// there instead of being dropped.
module soc_picorv32_axilite_tb;
    localparam integer MEM_WORDS      = 2048;
    localparam integer PROGRAM_WORDS  = 64;
    localparam integer PROGRAM_LENGTH = 17;      // instructions in soc_picorv32_boot.hex
    localparam integer CYCLE_LIMIT    = 200000;
    localparam integer MARKER_WORD    = 1020;    // 0x0ff0 / 4

    logic clk = 1'b0;
    always #5 clk = ~clk;
    logic rst_n = 1'b0;

    // CPU <-> adapter
    logic        awvalid, awready, wvalid, wready, bvalid, bready;
    logic        arvalid, arready, rvalid, rready;
    logic [31:0] awaddr, wdata, araddr, rdata;
    logic [2:0]  awprot, arprot;
    logic [3:0]  wstrb;
    logic [1:0]  bresp, rresp;
    logic        cpu_trap;

    // adapter <-> backend
    logic        req_valid, req_ready, req_write, rsp_valid, rsp_ready, rsp_error;
    logic [31:0] req_addr, req_wdata, rsp_rdata;
    logic [3:0]  req_be;

    // backend <-> RAM
    logic        tgt_req_valid, tgt_req_ready, tgt_req_write;
    logic [31:0] tgt_req_addr, tgt_req_wdata;
    logic [3:0]  tgt_req_be;
    logic        tgt_rsp_valid, tgt_rsp_ready, tgt_rsp_error;
    logic [31:0] tgt_rsp_rdata;
    logic        target_flush;

    // CPU retirement trace (RVFI) and its checker
    logic        rvfi_valid, rvfi_trap;
    logic [31:0] rvfi_insn, rvfi_pc_rdata;
    logic [3:0]  rvfi_mem_wmask, rvfi_mem_rmask;
    logic [31:0] rvfi_retired, rvfi_stores, rvfi_loads;
    logic        rvfi_mismatch;

    picorv32_axi #(
        .ENABLE_COUNTERS(1),
        .ENABLE_COUNTERS64(1),
        .ENABLE_REGS_16_31(1),
        .ENABLE_REGS_DUALPORT(1),
        .COMPRESSED_ISA(0),
        .CATCH_MISALIGN(1),
        .CATCH_ILLINSN(1),
        .ENABLE_MUL(0),
        .ENABLE_DIV(0),
        .ENABLE_IRQ(0),
        .REGS_INIT_ZERO(1),
        .PROGADDR_RESET(32'h0000_0000),
        .PROGADDR_IRQ(32'h0000_0010),
        .STACKADDR(32'h0000_0ff0)
    ) cpu (
        .clk(clk),
        .resetn(rst_n),
        .trap(cpu_trap),
        .mem_axi_awvalid(awvalid), .mem_axi_awready(awready),
        .mem_axi_awaddr(awaddr),   .mem_axi_awprot(awprot),
        .mem_axi_wvalid(wvalid),   .mem_axi_wready(wready),
        .mem_axi_wdata(wdata),     .mem_axi_wstrb(wstrb),
        .mem_axi_bvalid(bvalid),   .mem_axi_bready(bready),
        .mem_axi_arvalid(arvalid), .mem_axi_arready(arready),
        .mem_axi_araddr(araddr),   .mem_axi_arprot(arprot),
        .mem_axi_rvalid(rvalid),   .mem_axi_rready(rready),
        .mem_axi_rdata(rdata),
        .pcpi_wr(1'b0), .pcpi_rd(32'h0), .pcpi_wait(1'b0), .pcpi_ready(1'b0),
        .irq(32'h0),
        .rvfi_valid(rvfi_valid), .rvfi_insn(rvfi_insn), .rvfi_trap(rvfi_trap),
        .rvfi_pc_rdata(rvfi_pc_rdata),
        .rvfi_mem_wmask(rvfi_mem_wmask), .rvfi_mem_rmask(rvfi_mem_rmask)
    );

    // The adapter under test.  Its AXI4-Lite side faces the CPU, its beat side
    // faces the generic backend, exactly as it is instantiated by the renderer.
    axi4_lite_processor_memory_adapter #(
        .ADDRESS_WIDTH(32),
        .DATA_WIDTH(32)
    ) adapter (
        .clk_i(clk),
        .rst_ni(rst_n),
        .awaddr_i(awaddr), .awprot_i(awprot), .awvalid_i(awvalid), .awready_o(awready),
        .wdata_i(wdata),   .wstrb_i(wstrb),   .wvalid_i(wvalid),   .wready_o(wready),
        .bresp_o(bresp),   .bvalid_o(bvalid), .bready_i(bready),
        .araddr_i(araddr), .arprot_i(arprot), .arvalid_i(arvalid), .arready_o(arready),
        .rdata_o(rdata),   .rresp_o(rresp),   .rvalid_o(rvalid),   .rready_i(rready),
        .req_valid_o(req_valid), .req_ready_i(req_ready), .req_write_o(req_write),
        .req_addr_o(req_addr),   .req_wdata_o(req_wdata), .req_be_o(req_be),
        .rsp_valid_i(rsp_valid), .rsp_ready_o(rsp_ready),
        .rsp_rdata_i(rsp_rdata), .rsp_error_i(rsp_error)
    );

    myfuzz_processor_memory_backend #(
        .ADDRESS_WIDTH(32),
        .DATA_WIDTH(32),
        .MAX_WAIT_CYCLES(64)
    ) backend (
        .clk_i(clk),
        .rst_ni(rst_n),
        .req_valid_i(req_valid), .req_ready_o(req_ready), .req_write_i(req_write),
        .req_addr_i(req_addr),   .req_wdata_i(req_wdata), .req_be_i(req_be),
        .req_mapped_i(1'b1),
        .rsp_valid_o(rsp_valid), .rsp_ready_i(rsp_ready),
        .rsp_rdata_o(rsp_rdata), .rsp_error_o(rsp_error),
        .cancel_valid_i(1'b0),   .cancel_ready_o(),
        .target_flush_o(target_flush),
        .target_req_valid_o(tgt_req_valid), .target_req_ready_i(tgt_req_ready),
        .target_write_o(tgt_req_write),
        .target_addr_o(tgt_req_addr), .target_wdata_o(tgt_req_wdata),
        .target_be_o(tgt_req_be),
        .target_rsp_valid_i(tgt_rsp_valid), .target_rsp_ready_o(tgt_rsp_ready),
        .target_rdata_i(tgt_rsp_rdata),     .target_error_i(tgt_rsp_error)
    );

    soc_cpu_beat_ram #(
        .ADDRESS_WIDTH(32),
        .DATA_WIDTH(32),
        .MEM_WORDS(MEM_WORDS)
    ) ram (
        .clk_i(clk),
        .rst_ni(rst_n),
        .target_req_valid_i(tgt_req_valid), .target_req_ready_o(tgt_req_ready),
        .target_req_write_i(tgt_req_write),
        .target_req_addr_i(tgt_req_addr),   .target_req_wdata_i(tgt_req_wdata),
        .target_req_be_i(tgt_req_be),
        .target_rsp_valid_o(tgt_rsp_valid), .target_rsp_ready_i(tgt_rsp_ready),
        .target_rsp_rdata_o(tgt_rsp_rdata), .target_rsp_error_o(tgt_rsp_error)
    );

    soc_cpu_rvfi_checker #(
        .PROGRAM_WORDS(PROGRAM_WORDS),
        .ADDRESS_WIDTH(32)
    ) rvfi (
        .clk_i(clk),
        .rst_ni(rst_n),
        .program_length_i(PROGRAM_LENGTH),
        .rvfi_valid_i(rvfi_valid), .rvfi_insn_i(rvfi_insn),
        .rvfi_pc_rdata_i(rvfi_pc_rdata), .rvfi_trap_i(rvfi_trap),
        .rvfi_mem_wmask_i(rvfi_mem_wmask), .rvfi_mem_rmask_i(rvfi_mem_rmask),
        .retired_o(rvfi_retired), .stores_o(rvfi_stores), .loads_o(rvfi_loads),
        .mismatch_o(rvfi_mismatch)
    );

    string  boot_image_path;
    integer cycles    = 0;
    integer responses = 0;
    logic   done      = 1'b0;
    integer i;

    task automatic fail(input string message);
        begin
            $display("SOC_PICORV32_AXILITE_FAIL %0s cycles=%0d retired=%0d stores=%0d loads=%0d responses=%0d ram_writes=%0d ram_reads=%0d",
                     message, cycles, rvfi_retired, rvfi_stores, rvfi_loads,
                     responses, ram.write_count_q, ram.read_count_q);
            $fatal(1, "soc_picorv32_axilite_tb: %0s", message);
        end
    endtask

    task automatic check_word(input integer index, input [31:0] expected,
                              input string label);
        begin
            if (ram.mem[index] !== expected) begin
                $display("SOC_PICORV32_AXILITE_FAIL %0s mem[%0d]=%08x expected=%08x",
                         label, index, ram.mem[index], expected);
                $fatal(1, "soc_picorv32_axilite_tb: %0s", label);
            end
        end
    endtask

    initial begin
        rst_n = 1'b0;
        if (!$value$plusargs("boot_image=%s", boot_image_path)) begin
            $display("SOC_PICORV32_AXILITE_FAIL missing +boot_image=<path>");
            $fatal(1, "soc_picorv32_axilite_tb: no boot image");
        end
        for (i = 0; i < MEM_WORDS; i = i + 1)
            ram.mem[i] = 32'h0;
        $readmemh(boot_image_path, ram.mem);
        $readmemh(boot_image_path, rvfi.image);
        repeat (8) @(posedge clk);
        rst_n = 1'b1;
    end

    always @(posedge clk) begin
        if (rst_n) begin
            cycles <= cycles + 1;
            if (cycles > CYCLE_LIMIT)
                fail("cycle watchdog expired");
            if (cpu_trap)
                fail("cpu asserted trap");
            if (rvfi_mismatch)
                fail("retired instruction stream diverged from the boot image");
            if (bvalid && bresp != 2'b00)
                fail("AXI write response was not OKAY");
            if (rvalid && rresp != 2'b00)
                fail("AXI read response was not OKAY");
            if (rsp_valid && rsp_error)
                fail("beat backend returned an error for an in-range address");
            if (bvalid && bready)
                responses <= responses + 1;
            if (rvalid && rready)
                responses <= responses + 1;

            // The marker store is the last access of the program, so once the
            // whole image has retired every earlier store is already visible.
            if (!done && rvfi_retired >= PROGRAM_LENGTH && ram.mem[MARKER_WORD] === 32'h1) begin
                done <= 1'b1;
                if (ram.write_count_q != rvfi_stores) begin
                    $display("SOC_PICORV32_AXILITE_FAIL write accounting: ram_writes=%0d cpu_stores=%0d",
                             ram.write_count_q, rvfi_stores);
                    $fatal(1, "soc_picorv32_axilite_tb: write accounting");
                end
                check_word(64,  32'h5a5a5a5a, "full-word store at 0x100");
                check_word(65,  32'h000000a5, "full-word store at 0x104");
                check_word(66,  32'h000000a5, "byte store at 0x108 must not widen to a word");
                check_word(67,  32'h000000a5, "halfword store at 0x10c must not widen to a word");
                check_word(68,  32'h5a5a5a5a, "load-back store at 0x110");
                check_word(69,  32'h000000a5, "halfword load-back store at 0x114");
                check_word(MARKER_WORD, 32'h00000001, "completion marker at 0xff0");
                $display("SOC_PICORV32_AXILITE_REAL_OK retired=%0d stores=%0d loads=%0d responses=%0d ram_writes=%0d ram_reads=%0d cycles=%0d data=%08x",
                         rvfi_retired, rvfi_stores, rvfi_loads, responses,
                         ram.write_count_q, ram.read_count_q, cycles, ram.mem[64]);
                $finish;
            end
        end
    end
endmodule
