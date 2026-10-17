# P8 S2 evidence: external serial descriptor, three directions, multi-word FIFO

## Status: first real gate attempt failed, fixed, re-queued

This directory contains **software-only** evidence plus one failure record
(`real-gate-attempt-8dd3e70.md`). The first attempted real gate on frozen
snapshot `8dd3e70` failed on the real UART push-depth sampling semantics (the
push strobe tick carries the pre-push occupancy, 0..n-1; the +1 appears on the
next tick). The certifier now enforces exactly that and the gate is re-queued
on a frozen snapshot. No passing native evidence exists yet and no RTL
observation is claimed here.

The queued gate (see `.superpowers/sdd/p8-s2-descriptor-report.md` section 8):

```sh
MYFUZZ_DMA_DESCRIPTOR_REAL=1 \
MYFUZZ_DMA_DESCRIPTOR_CACHE=<cache> \
MYFUZZ_DMA_DESCRIPTOR_EVIDENCE=<evidence> \
PYTHONPATH=src timeout 1800 python3 -m pytest -xq \
  tests/integration/test_dma_uart_descriptor_real.py
```

Expected result: `1 passed` with six real cases (each direction at least once,
at least two multi-word cases) and an equal fresh full-prefix replay.

## Files

| file | what it is |
| --- | --- |
| `descriptor-program.json` | recomputed fixed firmware layout, direction control words, declared windows and the six declared DMA programs (software only) |
| `generate_software_evidence.py` | read-only generator for `descriptor-program.json` |
| `software-descriptor-unit.txt` | `51 passed` for `tests/integration/test_dma_uart_descriptor.py` |
| `software-focused-gate.txt` | `71 passed, 4 skipped` for the design §6.2 list plus both new files |
| `software-search-regression.txt` | `30 passed` for the unchanged S1b search software tests |
| `real-gate-attempt-8dd3e70.md` | failure record: real push depths 0..4, root cause, fix and re-queue |
| `manifest.json` | digests, claims, deviations, failure attempt and the queued gate description |

## What is *not* claimed

- `fifo_origin` remains `unknown` and every case is `source_authority=incomplete`.
- No `AdmissionRegistry` / `OwnershipMap` / `RuntimeEdgeIndex` /
  `UartConsumptionTracker` acceptance (S4).
- No invalid-descriptor / real CPU error-ISR observation (S3).
- No TX journal event: the S2 gate uses the real UART peer's serial capture (S4
  moves it into the journal).
- P8 is not passed by this increment.
