# S2 real gate attempt on frozen snapshot 73eb811: failed, fixed, re-queued

**This file is a failure record, not passing evidence.**

- increment: P8 S2
- snapshot: `73eb811`
- gate: `MYFUZZ_DMA_DESCRIPTOR_REAL=1 ... test_dma_uart_descriptor_real.py`
- first case: `RX_TO_RAM len=1`; the push-depth, nested CPU-pop and RAM-commit
  fixes are passed
- failure:

```
RuntimeError: DMA completion/IRQ/CPU take order is incomplete
```

## Real journal order (from the live run)

- DMA completion IRQ edge `dma_edge.event_id=19619`, `native_tick=196`
- bound source window start `source_start.event_id=19622`, `source_tick=196`
- real CPU external take `cpu_external_irq_taken.event_id=19653`,
  `cpu_tick=182`
- bound CPU take `cpu_irq_taken.event_id=19655`

The source window opens before the CPU samples the external interrupt line, so
`source_start` precedes `cpu_external_irq_taken`. The old assertion used
`irq_edge < external < start < take`, which is the opposite of the journal.

## Fix (ordering corrected, every join kept)

The order assertion is now

```
last_write < irq_edge < source_start < external < take
```

The identity/tick joins are unchanged and still mandatory:

- `source_start.source_event_id == cpu_irq_taken.source_event_id`;
- `cpu_irq_taken.cpu_tick == cpu_external_irq_taken.local_tick`;
- `source_start.source_tick == dma_edge.native_local_tick`.

Tests: the synthetic journal now uses the real order (irq edge → source window
start → external take → bound take) and a positive pins the four strictly
increasing event ids; negatives reject external before start, take before
external, a mismatched source tick and a mismatched take identity. 64 software
tests pass.

## Status

The fixed gate is re-queued. All four attempts are failure records; there is
no S2 real-RTL passing evidence and P8 does not pass.
