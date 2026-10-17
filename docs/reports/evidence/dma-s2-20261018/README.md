# P8 S2 evidence: external serial descriptor, three directions, multi-word FIFO

## Status: three real gate attempts failed, all fixed, re-queued

This directory contains **software-only** evidence plus three failure records
(`real-gate-attempt-8dd3e70.md`, `real-gate-attempt-90652e9.md`,
`real-gate-attempt-457d411.md`).

- Attempt 1 (`8dd3e70`) failed on the real UART push-depth sampling semantics:
  the push strobe tick carries the pre-push occupancy (0..n-1) and the +1
  appears on the next tick.
- Attempt 2 (`90652e9`, cache reused) passed the depth check and failed on a CPU
  RDATA pop that exists only as the nested
  `mmio_delivery.target_uart_access` (no top-level `uart_rdata_access`); the
  certifier now merges both real shapes by `access_id`.
- Attempt 3 (`457d411`) passed both previous fixes and failed on the real RAM
  commit order: read beat → memory commit → write beat. The certifier now
  anchors each commit inside its own read interval
  (`read < commit < next_read`; the last word is closed by the IRQ order).

Both fixes keep the assertions and never count host events. The gate is
re-queued on a frozen snapshot; no passing native evidence exists yet and no
RTL observation is claimed here.

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
| `software-descriptor-unit.txt` | `59 passed` for `tests/integration/test_dma_uart_descriptor.py` |
| `software-focused-gate.txt` | `79 passed, 4 skipped` for the design §6.2 list plus both new files |
| `software-search-regression.txt` | `30 passed` for the unchanged S1b search software tests |
| `real-gate-attempt-8dd3e70.md` | failure 1: real push depths 0..4, root cause, fix and re-queue |
| `real-gate-attempt-90652e9.md` | failure 2: nested-only CPU pop (mmio delivery 18849), root cause, fix and re-queue |
| `real-gate-attempt-457d411.md` | failure 3: real read→commit→write order, root cause, fix and re-queue |
| `manifest.json` | digests, claims, deviations, failure attempt and the queued gate description |

## What is *not* claimed

- `fifo_origin` remains `unknown` and every case is `source_authority=incomplete`.
- No `AdmissionRegistry` / `OwnershipMap` / `RuntimeEdgeIndex` /
  `UartConsumptionTracker` acceptance (S4).
- No invalid-descriptor / real CPU error-ISR observation (S3).
- No TX journal event: the S2 gate uses the real UART peer's serial capture (S4
  moves it into the journal).
- P8 is not passed by this increment.
