.section .text
.globl _start
_start:
  li t0, 1024
  li t1, 1611516670
  sw t1, 0(t0)
1:
  j 1b
