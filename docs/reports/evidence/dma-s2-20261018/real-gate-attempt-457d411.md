# S2 real gate attempt on frozen snapshot 457d411: failed, fixed, re-queued

**This file is a failure record, not passing evidence.**

- increment: P8 S2
- snapshot: `457d411` (its parent `53a9b7b` is the P7 I3 commit, so the build
  identity differs from the previous attempt)
- gate: `MYFUZZ_DMA_DESCRIPTOR_REAL=1 ... test_dma_uart_descriptor_real.py`
- first case: `RX_TO_RAM len=1`; the push-depth and nested CPU-pop fixes are
  passed
- failure:

```
RuntimeError: DMA RAM commit is not the accepted write beat effect
```

## Real journal order (from the live run)

One transferred word is recorded as **read beat → memory commit → write beat**:

- DMA read beat `dma_edge.event_id=19530`
- DMA `memory_write` commit `event_id=19591`, address `143360`, value `90`,
  version `(0, 7)`
- DMA write beat `dma_edge.event_id=19592`

The old certifier required `write_event_id < commit_event_id`, which is the
opposite of the real journal (the memory service commits before the master edge
event is appended; the S1 notes already warned that commits can precede
retirement/edge events).

## Fix (order assertion kept, tightened to the real interval)

Per transferred word the commit must lie inside its own real read interval:

- `read_event_id < commit_event_id`;
- if another word follows, `commit_event_id < next_beat.read_event_id`;
- for the last word the interval is closed by the existing ordering
  `last_write < irq_edge < external < source_start < take`;
- address, payload value and present/strictly-increasing `version` assertions
  are unchanged; the error message is now
  `DMA RAM commit is not inside its accepted read beat interval`.

Tests: the synthetic journal gained a `commit_before_write=True` real shape
(read → commit → write) used by a positive for len=2 and len=1; negatives lock
a commit before its own read, a commit after the next read, a wrong commit
value and a repeated version. 59 software tests pass.

## Status

The fixed gate is re-queued. All three attempts are failure records; there is
no S2 real-RTL passing evidence and P8 does not pass.
