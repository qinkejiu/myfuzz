  .section .text
  .globl _start
_start:
  lui   t0, 0x40000
  li    t1, 0x5a
  sw    t1, 0x0c(t0)
1:
  j     1b
