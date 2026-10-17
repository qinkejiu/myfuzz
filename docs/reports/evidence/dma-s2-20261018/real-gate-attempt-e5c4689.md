# S2 real gate attempt on frozen snapshot e5c4689: failed, fixed, re-queued

**This file is a failure record, not passing evidence.**

- increment: P8 S2
- snapshot: `e5c4689`
- gate: `MYFUZZ_DMA_DESCRIPTOR_REAL=1 ... test_dma_uart_descriptor_real.py`
- failure in a later case (`command_count=11279`, `case_start=23086`):

```
RuntimeError: CPU must pop exactly ... (4 pops; top_level=4, nested=1)
```

Four pops were expected, five were counted.

## Root cause: a late top-level copy crosses the case boundary

The previous case's fourth CPU access had only the nested
`mmio_delivery.target_uart_access` (no event_id, counted by access_id). Its
top-level `uart_rdata_access` external event was journaled late and landed in
the **next** case's slice. The per-case merge deduplicates by `access_id` only
inside one slice, so the same access was counted twice: four top-level copies
(three of the current case plus the late previous-case copy) and one nested
copy of the current case = five.

## Fix (boot-level cross-case dedupe, count assertion unchanged)

1. `DescriptorBoot` keeps `settled_access_ids`, the CPU access ids already
   counted in earlier cases; the replay keeps the same set over the same case
   order.
2. `certify_descriptor_case` accepts `settled_access_ids` and filters already
   counted CPU pops and their late nested deliveries; the count stays
   `4` for RX and `4+len` for RAM/TX.
3. Each successful case's `cpu_pop_access_ids` joins the set; the evidence
   records both `cpu_pop_access_ids` (counted here) and
   `settled_cpu_access_ids` (late copies filtered from this slice).
4. A CPU pop without a real `access_id` fails immediately (never guessed), so
   cross-case dedupe always has a real identity.

Tests: a nested-only fourth access plus a late top-level event with the same
access id in the next case yields five pops without the settled set (failure)
and remains four with it, with the late id recorded in
`settled_cpu_access_ids`; a late nested delivery variant is covered too.
68 software tests pass.

## Status

The fixed gate is re-queued. All six attempts are failure records; there is no
S2 real-RTL passing evidence and P8 does not pass.
