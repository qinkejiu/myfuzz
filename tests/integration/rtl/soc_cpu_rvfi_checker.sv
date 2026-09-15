// Retired-instruction checker for the real PicoRV32 protocol benches.
//
// PicoRV32 exposes an RVFI (RISC-V Formal Interface) trace, so the benches do
// not have to infer "the program ran" from side effects.  This module compares
// every retired instruction against the committed boot image, word for word and
// program counter for program counter, counts the memory operations the CPU
// itself reports, and flags the first divergence.
//
// The self-jumping terminator at the end of the program retires over and over
// while the testbench drains, so instructions past the end of the image are
// compared against that final jump instead of against an out-of-range entry.
//
// Ports are plain vectors rather than integers on purpose: Icarus accepts
// neither "input integer" ports nor continuous assignment to an integer.
module soc_cpu_rvfi_checker #(
    parameter integer PROGRAM_WORDS = 64,
    parameter integer ADDRESS_WIDTH = 32
) (
    input  logic                      clk_i,
    input  logic                      rst_ni,
    input  logic [31:0]               program_length_i,
    input  logic                      rvfi_valid_i,
    input  logic [31:0]               rvfi_insn_i,
    input  logic [ADDRESS_WIDTH-1:0]  rvfi_pc_rdata_i,
    input  logic                      rvfi_trap_i,
    input  logic [3:0]                rvfi_mem_wmask_i,
    input  logic [3:0]                rvfi_mem_rmask_i,
    output logic [31:0]               retired_o,
    output logic [31:0]               stores_o,
    output logic [31:0]               loads_o,
    output logic                      mismatch_o
);
    logic [31:0] image [0:PROGRAM_WORDS-1];

    logic [31:0] retired_q;
    logic [31:0] stores_q;
    logic [31:0] loads_q;
    logic        mismatch_q;

    logic [31:0] index;
    logic [31:0] expected_insn;
    logic [ADDRESS_WIDTH-1:0] expected_pc;

    assign index = (retired_q < program_length_i) ? retired_q : (program_length_i - 1);
    assign expected_insn = image[index];
    assign expected_pc = index * 4;

    assign retired_o = retired_q;
    assign stores_o = stores_q;
    assign loads_o = loads_q;
    assign mismatch_o = mismatch_q;

    initial begin
        if (PROGRAM_WORDS < 1)
            $fatal(1, "soc_cpu_rvfi_checker: PROGRAM_WORDS must be positive");
    end

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            retired_q <= 32'd0;
            stores_q <= 32'd0;
            loads_q <= 32'd0;
            mismatch_q <= 1'b0;
        end else if (program_length_i == 32'd0) begin
            mismatch_q <= 1'b1;
        end else if (rvfi_valid_i) begin
            if (rvfi_insn_i !== expected_insn) begin
                mismatch_q <= 1'b1;
                $display("SOC_CPU_RVFI_INSN_MISMATCH retired=%0d pc=%08x insn=%08x expected=%08x",
                         retired_q, rvfi_pc_rdata_i, rvfi_insn_i, expected_insn);
            end
            if (rvfi_pc_rdata_i !== expected_pc) begin
                mismatch_q <= 1'b1;
                $display("SOC_CPU_RVFI_PC_MISMATCH retired=%0d pc=%08x expected=%08x",
                         retired_q, rvfi_pc_rdata_i, expected_pc);
            end
            if (rvfi_trap_i) begin
                mismatch_q <= 1'b1;
                $display("SOC_CPU_RVFI_TRAP retired=%0d pc=%08x insn=%08x",
                         retired_q, rvfi_pc_rdata_i, rvfi_insn_i);
            end
            retired_q <= retired_q + 32'd1;
            if (|rvfi_mem_wmask_i)
                stores_q <= stores_q + 32'd1;
            if (|rvfi_mem_rmask_i)
                loads_q <= loads_q + 32'd1;
        end
    end
endmodule
