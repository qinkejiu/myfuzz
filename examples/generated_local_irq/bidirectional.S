/* RV32I, no compressed instructions. RAM persists throughout four ISR calls.
 * s0=A, s1=B, s2=RAM. A[7:0] -> B[7:0]; external -> B[15:8].
 * Each bank has seven payload bits and one rising-edge strobe.
 */
.option norvc
.section .text
.globl _start
_start:
  li s0, 0x40001000
  li s1, 0x40000000
  li s2, 0x20000
  li t0, 5
  sw t0, 0(s2)
  sw zero, 4(s2)
  li t0, 0xffff
  sw t0, 0(s0)
  sw t0, 4(s1)
  li t0, 0x8080
  sw t0, 0x18(s1)
  li t0, 0x40004000 /* packed 2-bit rising types for pins 7 and 15 */
  sw t0, 0x1c(s1)
  sw zero, 0x20(s1)
  la t0, vectors
  ori t0, t0, 1
  csrw mtvec, t0
  li t0, 0x800
  csrw mie, t0
  csrsi mstatus, 8
  li t0, 0x81
  sw t0, 0x0c(s0)
wait_first:
  lw a0, 4(s2)
  li a1, 1
  bne a0, a1, wait_first
  lw a2, 0x0c(s0)
  andi a2, a2, -129
  sw a2, 0x0c(s0)
  li a0, 20
settle_low:
  addi a0, a0, -1
  bnez a0, settle_low
  andi a2, a2, -256
  li t0, 0x82
  or a2, a2, t0
  sw a2, 0x0c(s0)
idle:
  j idle
.balign 256
vectors:
.rept 32
  j isr
.endr
isr:
  lw t1, 0x08(s1)
  lw t0, 0x24(s1)
  lw t4, 4(s2)
  slli t5, t4, 2
  add t5, t5, s2
  sw t0, 32(t5)
  sw t1, 64(t5)
  andi t2, t0, 0x80
  beqz t2, external_bank
  andi t2, t1, 0x7f
  j accumulate
external_bank:
  srli t2, t1, 8
  andi t2, t2, 0x7f
accumulate:
  lw t3, 0(s2)
  add t3, t3, t2
  sw t3, 0(s2)
  sw t3, 96(t5)
  slli t3, t3, 8
  lw t6, 0x0c(s0)
  andi t6, t6, 0xff
  or t3, t3, t6
  sw t3, 0x0c(s0)
  addi t4, t4, 1
  sw t4, 4(s2)
  mret
