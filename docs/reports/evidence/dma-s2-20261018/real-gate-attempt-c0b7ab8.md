# S2 real gate attempt on frozen snapshot c0b7ab8: failed, fixed, re-queued

**This file is a failure record, not passing evidence.**

- increment: P8 S2
- snapshot: `c0b7ab8`
- gate: `MYFUZZ_DMA_DESCRIPTOR_REAL=1 ... test_dma_uart_descriptor_real.py`
- first case: `RX_TO_RAM len=1`; the push-depth, nested CPU-pop, RAM-commit and
  IRQ-order fixes are passed
- failure:

```
RuntimeError: ISR PC 0x10464 lacks exactly one real retirement
```

## Root cause: the case slice was sealed at the COMPLETED write

The real ISR journal at the end of the case was:

- `isr_counter_load=0x1045c` retired (eid 22912);
- `0x10460 addi` retired (eid 22928);
- `COMPLETED` `memory_write` eid 22934 (value 1) appeared;
- the `0x10464 sw` retirement and MRET were **not yet journaled** when the case
  was sealed.

`DescriptorBoot` broke out of the poll loop as soon as it saw the COMPLETED
write, so the slice ended before the store retirement and the certifier could
not find the real retirement at 0x10464.

## Fix (hard requirement on the real store retirement)

After the unique, correct-value COMPLETED write, `_execute_case` keeps advancing
poll rounds for a bounded number (`COMPLETION_ROUNDS=64`) until the real
retirement of the ISR counter store (`isr_counter_load + 8`) is in the journal;
it also captures MRET (`isr_counter_load + 12`) and a return to the main loop
(`MAIN <= pc < ISR`) when they appear. Failure semantics are kept:

- a wrong-valued or duplicate COMPLETED write fails immediately;
- if the store retirement is still missing after the bound, the case fails with
  `CPU ISR counter store retirement is missing after COMPLETED`.

The batch template now budgets `3 * COMPLETION_ROUNDS` extra steps per case.

Tests: the fake boot now emits store retire → MRET retire → main-loop retire
after COMPLETED; the positive asserts all three PCs are inside the sealed case
slice; negatives cover a COMPLETED write without its retirement (bounded hard
failure) and a wrong COMPLETED value (immediate failure). 66 software tests
pass.

## Status

The fixed gate is re-queued. All five attempts are failure records; there is no
S2 real-RTL passing evidence and P8 does not pass.
