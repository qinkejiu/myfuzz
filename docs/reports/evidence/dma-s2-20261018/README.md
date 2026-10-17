# P8 S2 evidence: external serial descriptor, three directions, multi-word FIFO

## Status: real RTL gate queued, not run

This directory contains **software-only** evidence. No native Verilator build
was started and no RTL observation is claimed here. The S2 real gate is queued
until the source tree is frozen, because the S1/P7 gates share the same build
cache and a concurrent source change would shift the build identity of a gate
that has not been re-baselined.

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
| `software-descriptor-unit.txt` | `44 passed` for `tests/integration/test_dma_uart_descriptor.py` |
| `software-focused-gate.txt` | `64 passed, 4 skipped` for the design §6.2 list plus both new files |
| `software-search-regression.txt` | `30 passed` for the unchanged S1b search software tests |
| `manifest.json` | digests, claims, deviations and the queued gate description |

## What is *not* claimed

- `fifo_origin` remains `unknown` and every case is `source_authority=incomplete`.
- No `AdmissionRegistry` / `OwnershipMap` / `RuntimeEdgeIndex` /
  `UartConsumptionTracker` acceptance (S4).
- No invalid-descriptor / real CPU error-ISR observation (S3).
- No TX journal event: the S2 gate uses the real UART peer's serial capture (S4
  moves it into the journal).
- P8 is not passed by this increment.
