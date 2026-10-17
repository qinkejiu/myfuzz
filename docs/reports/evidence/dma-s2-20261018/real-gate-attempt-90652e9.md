# S2 real gate attempt on frozen snapshot 90652e9: failed, fixed, re-queued

**This file is a failure record, not passing evidence.**

- increment: P8 S2
- snapshot: `90652e9` (parent `8dd3e70`), cache reused
- gate: `MYFUZZ_DMA_DESCRIPTOR_REAL=1 ... test_dma_uart_descriptor_real.py`
- first case: `RX_TO_RAM len=1`; the push-depth fix from the first attempt is
  passed (real push ticks 0,1,2,3,4)
- failure:

```
RuntimeError: CPU must pop exactly the descriptor and drained payload bytes
```

## Root cause: one real CPU pop lives only in the nested delivery object

The four CPU `RDATA` reads of the first case are recorded as three top-level
`uart_rdata_access` events (tx7/tx9/tx11, event_id 18476/18621/18766) plus one
nested copy only: tx13 (`read_value=90`) exists inside the CPU
`mmio_delivery` event 18849 as `target_uart_access`
(`kind='uart_rdata_access'`, `status='observed'`, `read_capture` present, no
`event_id`). `extract_case_witnesses` counted only top-level rows, so the
certifier saw 3 pops instead of 4.

## Fix (no downgrade, no host counting)

`_merge_cpu_pops` now accepts both real shapes:

1. top-level `uart_rdata_access` with `source_transaction.channel_id='data'`;
2. CPU `mmio_delivery` (`device_id='uart'`, `offset=0x18`, `write=false`)
   `target_uart_access` with `kind='uart_rdata_access'`;
3. deduplicated by the real `access_id`, so one routed access is counted once;
   a nested-only pop is anchored at the delivery's `event_id` and sorted with
   the other pops;
4. a nested copy without a real `access_id` is ignored rather than guessed,
   which leaves the count short and fails certification with the top_level /
   nested counts in the message;
5. the count assertion is unchanged: `4 + len` (4 for RX, 4+len for RAM/TX);
   `fifo.pops[].source` records `top_level` or `nested`.

Tests: the synthetic journal now carries both copies for every CPU pop (the
default positive asserts 4 CPU pops with source `top_level`, proving dedupe by
access id), a new positive has only the fourth nested copy (sources
`top_level,top_level,top_level,nested`), and two negatives remove both copies or
the nested access id. 54 software tests pass.

## Status

The fixed gate is re-queued. Both attempts are failure records; there is no S2
real-RTL passing evidence and P8 does not pass.
