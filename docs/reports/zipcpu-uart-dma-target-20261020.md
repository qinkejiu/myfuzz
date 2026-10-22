# ZipCPU `wbdmac` → `wbuart` TXREG DMA target

**Status:** Bounded local positive, fresh replay, host route admission refusal,
and offline evidence audit passed on 2026-10-20.

## Scope

This slice admits one 32-bit word from the host `PersistentMemory` service,
through the generated ZipCPU `wbdmac` session, to the generated `wbuart`
TXREG at `0x4000300c`. The accepted window is 16 bytes; only offset `0x0c`,
full-word byte enable `0xf`, and values `0..255` are accepted. Before DMA, the
UART is configured with SETUP value 25. The observed TX pin is decoded as one
8N1 byte with 25 local clocks per bit.

The route compiler pins the exact DMA session, memory service/resource,
`MasterTargetWindow`, UART session/provider identity, and one-beat source
admission. The provider issues the bounded local target Wishbone access and
joins its request, the real `wbuart` ACK output sampled in the native trace,
and the decoded TX byte to the DMA write key and provider access ID. Wishbone
is observed through passive generated trace taps; the taps do not alter bus
behavior. The key is supplied by the normal DMA dispatcher; route admission
checks its read/write stream continuity.

## Evidence

The opt-in native gate passed: **1 passed in 43.38s**. It observed a RAM read
from `0x10100` returning `0x41`, then a DMA write of `0x41` to TXREG
`0x4000300c`. The provider receipt ties that write to the Wishbone request at
local tick 13 and sampled DUT ACK output at tick 15. The same access ID joins
the decoded serial byte `0x41`; the frame starts at tick 15 and decodes at tick
252.

The fresh descriptor has a different execution identity and matches the
original after execution-specific identifiers are normalized. The host route
admission refusal, after observing a real DMA master Wishbone write request,
records the unselected destination `0x40003010`, its payload, pre-backend
values, tick, and typed transaction key. Route admission refused before
provider invocation: provider call count was zero, UART local ticks stayed at
6, and no serial output was added. This is not a DMA bus error response and
does not claim the DMA made no earlier source RAM read.

The independent saved-evidence audit passed and wrote
[`independent-audit.json`](evidence/zipcpu-uart-dma-20261020-local-attempt3/independent-audit.json).
It checks that the RAM read and TXREG write keys share an execution, testcase,
source, epoch and channel, with adjacent sequence numbers. Its script is
preserved alongside the raw evidence. The three compressed native artifacts
were SHA-256 checked by the audit. The exact native command and exit result are in
[`run-receipt.json`](evidence/zipcpu-uart-dma-20261020-local-attempt3/run-receipt.json).
The native gate decodes the physical TX pin online; the saved descriptor stores
the decoded byte but not raw TX samples for an independent offline re-decode.

| Attempt | Result | Preserved record |
| --- | --- | --- |
| 1 | Failed before native process startup: provider saw ambiguous `cyc` bus export. | [attempt1](evidence/zipcpu-uart-dma-20261020-local-attempt1/failure.json) |
| 2 | Failed before native process startup: TX pin disposition was `external`, not the assumed `functional`. | [attempt2](evidence/zipcpu-uart-dma-20261020-local-attempt2/failure.json) |
| 3 | Native gate passed; independent evidence audit passed. | [attempt3 evidence](evidence/zipcpu-uart-dma-20261020-local-attempt3/) |

Scoped provider/trace/route regression result: **65 passed** across
`test_wishbone_uart_dma_target_provider.py`,
`test_wishbone_uart_trace_renderer.py`, and
`test_zipcpu_uart_dma_paths.py`.

## Capability boundary

This result establishes one local transaction-level route with declared and
topology-bound identities, one runtime-observed transfer, fresh replay, and
one host route admission refusal after observing a native DMA request. The
compiled topology still reports
`runtime_causality_verified=false` and `resource_versions_verified=false`.
Observing the target's native ACK output is not evidence of a physical
Wishbone bridge or a shared SoC clock. This work does not establish CPU consumption, decode or
retirement; UART RXREG→RAM; arbitrary Wishbone DMA; multiple-beat DMA; a remote
gate; P7 F6; P6/P7/P8 completion; or completion of the six-CPU/four-IP objective.

## Reproduction

From the repository root:

```sh
PYTHONPATH=src pytest -q \
  tests/local_harness/test_wishbone_uart_dma_target_provider.py \
  tests/local_harness/test_wishbone_uart_trace_renderer.py \
  tests/scenario/test_zipcpu_uart_dma_paths.py

MYFUZZ_DMA_ZIPCPU_UART_REAL=1 \
MYFUZZ_DMA_ZIPCPU_UART_EVIDENCE=docs/reports/evidence/zipcpu-uart-dma-20261020-local-attempt3 \
MYFUZZ_DMA_ZIPCPU_UART_CACHE=/tmp/myfuzz-zipcpu-uart-dma-20261020-attempt3-cache \
PYTHONPATH=src pytest -q tests/integration/test_dma_zipcpu_uart_real.py

PYTHONPATH=src python3 \
  docs/reports/evidence/zipcpu-uart-dma-20261020-local-attempt3/independent-audit.py
```

The local gate used the repository's existing generated RTL toolchain/cache.
No remote server was accessed for this slice.
