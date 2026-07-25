.section .text
.globl _start
_start:
    li t0, 0x40000000
    li t1, 0x40010000
    li t2, 0x40020000

    # Enable both UART directions with a small baud-rate increment.
    li t3, 0x00030001
    sw t3, 0x10(t0)

    # Drive all GPIOs, then alternate their output value in the loop.
    li t3, -1
    sw t3, 0x20(t1)
    li a0, 0x55
    sw a0, 0x14(t1)

    # Configure and start the timer; interrupts remain masked in the core.
    li t3, 0x00010000
    sw t3, 0x10c(t2)
    li t3, 1
    sw t3, 0x100(t2)
    sw t3, 0x4(t2)

loop:
    sw a0, 0x1c(t0)
    lw a1, 0x14(t0)
    lw a2, 0x18(t0)

    sw a0, 0x14(t1)
    lw a3, 0x10(t1)
    sw a3, 0x8(t1)

    lw a4, 0x110(t2)
    sw a4, 0x118(t2)
    lw a5, 0x104(t2)
    sw a5, 0x104(t2)

    xor a0, a0, a1
    xor a0, a0, a2
    xor a0, a0, a3
    add a0, a0, a4
    xori a0, a0, 0xff
    j loop
