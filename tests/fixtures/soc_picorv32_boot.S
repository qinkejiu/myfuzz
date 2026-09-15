/*
 * RV32I boot program for the real PicoRV32 protocol benches.
 *
 * It is bus agnostic on purpose: the same image drives picorv32_axi
 * (AXI4-Lite, see soc_picorv32_axilite_tb.sv) and picorv32_wb (classic
 * Wishbone, see soc_picorv32_wishbone_tb.sv) so the two runs differ only in
 * the initiator protocol in front of the adapter under test.
 *
 * What it proves, once the two store words below are visible in the RAM
 * behind the adapter:
 *   - instruction fetch works through the adapter (the program ran at all),
 *   - a full-word store (wstrb/sel = 1111) reaches memory,
 *   - a byte store (0001) and a halfword store (0011) reach the right lanes,
 *     so the byte-enable path is not silently widened,
 *   - a word load and a halfword load return the stored data, so the read
 *     path is not decoupled from the write path,
 *   - the final marker store only happens after the load-back completed.
 *
 * The image is assembled with the RISC-V toolchain inside clang, not by hand:
 *   clang --target=riscv32 -march=rv32i -mabi=ilp32 -nostdlib -fuse-ld=lld \
 *         -Wl,-Ttext=0 -Wl,--no-relax -o boot.elf boot.S
 * and tests/integration/test_soc_real_picorv32.py regenerates
 * soc_picorv32_boot.hex from this file and fails if the two disagree.
 *
 * Memory map (byte addresses, word index = address/4):
 *   0x000        program (18 instructions, ends in a self jump)
 *   0x100        full-word store 0x5a5a5a5a
 *   0x104        full-word store 0x000000a5
 *   0x108        byte store 0xa5            -> only lane 0 may change
 *   0x10c        halfword store 0x00a5      -> only lanes 0..1 may change
 *   0x110        load-back of 0x100         -> proves the read path
 *   0x114        halfword load of 0x10c     -> proves the read path
 *   0xff0        completion marker (1)
 */
    .section .text
    .globl _start
_start:
    li   t0, 0x100              /* data base */
    li   t1, 0x5a5a5a5a
    sw   t1, 0(t0)              /* 0x100: full word      (sel/wstrb 1111) */
    li   t2, 0x000000a5
    sw   t2, 4(t0)              /* 0x104: full word      (sel/wstrb 1111) */
    sb   t2, 8(t0)              /* 0x108: byte store     (sel/wstrb 0001) */
    sh   t2, 12(t0)             /* 0x10c: halfword store (sel/wstrb 0011) */
    lw   t3, 0(t0)              /* read back 0x100 */
    sw   t3, 16(t0)             /* 0x110: read data, not a re-materialised constant */
    lh   t4, 12(t0)             /* read back the halfword */
    sw   t4, 20(t0)             /* 0x114 */
    li   t5, 0xff0              /* completion marker address */
    li   t6, 1
    sw   t6, 0(t5)              /* 0xff0: last access of the program */
done:
    j    done                   /* PicoRV32 has no halt: spin after the marker */
