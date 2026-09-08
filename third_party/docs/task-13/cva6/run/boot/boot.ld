ENTRY(_start)
SECTIONS {
  . = 0x80;
  .text : { *(.text*) }
  /DISCARD/ : { *(.comment) *(.riscv.attributes) }
}
