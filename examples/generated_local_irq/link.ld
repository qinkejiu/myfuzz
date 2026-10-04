ENTRY(_start)
SECTIONS { . = 0x10000; .text : { *(.text*) } /DISCARD/ : { *(.comment) *(.riscv.attributes) } }
