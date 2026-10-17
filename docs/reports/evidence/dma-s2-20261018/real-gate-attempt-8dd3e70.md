# S2 real gate attempt on frozen snapshot 8dd3e70: failed, fixed, re-queued

**This file is a failure record, not passing evidence.**

- increment: P8 S2
- snapshot: `8dd3e70f48d7694309a86a92506b716769b4e032`
- gate: `MYFUZZ_DMA_DESCRIPTOR_REAL=1 ... test_dma_uart_descriptor_real.py`
- first case: `RX_TO_RAM`, `len=1`, `source_count=5`, 4793 commands, `case_start=185`
- failure:

```
RuntimeError: UART RX FIFO push lacks a real depth
dma_uart_descriptor_runtime.py:571 (old push_depths read the push-tick post depth and required >=1)
```

## Root cause: real sampling semantics, not a missing field

The pinned `uart_tick_observation` samples `post` at the push strobe tick while
the real RX FIFO depth counter still shows the **pre-push** occupancy; the live
S2 probe log (`attempt1-push-probes.log` in the main-session evidence directory)
shows `PRE_DEPTH == POST_DEPTH` on every push: **0,1,2,3,4** (`event_id`
3595/7062/10521/13988/17447, `local_tick` 851/1717/2581/3447/4311). The pushed
byte is `post.probe_uart_fifo_data`, and the depth increment appears on the next
tick sample. This matches the already-saved S1 continuous journal: event 3587
(`local_tick` 851) is the push tick with `post{depth=0, data=90, wvalid=1,
wready=1}`, and event 3591 (`local_tick` 852) is the next tick with
`post{depth=1, head=90, rvalid=1}`.

No S2 journal bundle was saved from the failed attempt (the gate aborts before
`descriptor.json.gz`), so the values above are the live-run values reported by
the main session plus the equivalent saved S1 sample.

## Fix (assertions kept, no host counting)

`_push_depth_chain` now reads only real journal probes:

1. every push tick has `post.wvalid==1 && post.wready==1` and
   `post.probe_uart_fifo_data == declared byte`;
2. the push-tick depth stream is exactly `0..n-1` (`n = 4 + len`), and
   `depth_before[-1] + 1 == n`;
3. the immediately following real tick sample must not be another push and must
   show `post.probe_uart_fifo_depth == depth_before + 1`;
4. adjacent push chains stay contiguous.

New negatives lock the fields: stalled depth, wrong push data, missing following
sample, depth gap, depth repeat, non-empty FIFO at case start (shifted 0..n-1)
and a missing push all fail.

## Status

The fixed gate is **re-queued** on a frozen snapshot. Until it passes there is
no S2 real-RTL evidence and P8 does not pass.
