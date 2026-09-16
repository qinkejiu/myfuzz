.section .text
.globl _start
_start:
    lui t0, 0x80000
    lui t1, 0x80020
    lui t2, 0x80010
    lui t3, 0x80030
    li a0, 0x55

loop:
    sw a0, 0(t0)
    lw a1, 0(t0)
    sw a0, 4(t1)
    lw a2, 0(t1)
    sw a0, 8(t1)
    lw a3, 0(t2)
    lw a4, 8(t2)
    sw a0, 0(t3)
    lw a5, 0(t3)
    xori a0, a0, 0xff
    add a0, a0, a1
    xor a0, a0, a2
    j loop
