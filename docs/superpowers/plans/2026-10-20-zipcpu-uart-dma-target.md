# ZipCPU UART TXREG DMA target implementation plan

Spec: [ZipCPU UART TXREG DMA target adapter](../specs/2026-10-20-zipcpu-uart-dma-target-design.md)

## Task ownership

- Provider implementation: `src/myfuzz/local_harness/wishbone_uart_session.py`
  and `tests/local_harness/test_wishbone_uart_dma_target_provider.py`.
- Route compiler: new `src/myfuzz/scenario/zipcpu_uart_dma_paths.py` and
  `tests/scenario/test_zipcpu_uart_dma_paths.py`.
- Native integration/evidence/docs: new
  `tests/integration/test_dma_zipcpu_uart_real.py`, evidence directory under
  `docs/reports/evidence/`, new report, and progress/index/runtime docs.

## Tasks

- [x] Add failing provider tests for exact identity/context, native Wishbone
  request and ACK, 8N1 TX byte, value/offset/byte-enable refusal, and poison
  after an uncertain post-command result.
- [x] Implement provider identity and keyed TXREG write completion on
  `GeneratedWishboneUartSession`; retain the measured native bus and serial
  witnesses with one access ID and source key.
- [x] Add immutable one-beat RAM→TXREG admission and a prepared/compiled route
  bound to the current DMA, memory service/resource, target window and UART
  provider identity.
- [x] Add route compiler and admission tests for exact topology, selected
  source/value, full-word-only window and unselected destination.
- [x] Add an opt-in real/fresh/refusal gate. Configure SETUP 25 before DMA;
  verify the provider-issued target Wishbone request, sampled DUT ACK output,
  and decoded serial byte; capture the host route admission refusal after a
  native DMA request, including raw pins, ticks, typed key, provider invocation
  count and serial output count.
- [x] Run scoped provider/route regressions and the native gate; save exact
  commands/results and run an offline independent evidence join.
- [x] Write the report and update `docs/CURRENT_PROGRESS.md`,
  `docs/LOCAL_HARNESS_RUNTIME.md`, `docs/reports/README.md`, and the shared DMA
  route follow-up status.

## Execution constraints

- Follow `agent.md`; this slice is local, and any later remote writes stay under
  `/root/fanzehui/**`.
- The worktree is shared and dirty. Do not clean/reset/stage/commit, overwrite
  unrelated edits, or reuse previous attempt evidence.
- Keep the acceptance scope to one low-byte RAM word and one TXREG write. Do
  not include RXREG→RAM, CPU bus consumption, a physical bus bridge, or generic
  Wishbone DMA support.
- A provider callback that issued the target command but cannot establish ACK
  and serial output is uncertain and poisons further callbacks for that case.

## Status

Implemented and locally accepted for the bounded route in
[the 2026-10-20 report](../../reports/zipcpu-uart-dma-target-20261020.md).
Attempt3 native gate and independent saved-evidence audit passed. Attempts1/2
remain preserved as pre-start failures. The route compiler's
`runtime_causality_verified` and `resource_versions_verified` fields remain
false; this result does not claim a physical bridge, CPU consumption/retirement,
generic Wishbone DMA, or phase completion.
