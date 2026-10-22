# P7 D4 ZipCPU UART Wishbone Admission Plan

> Use the repository's test-first workflow; retain existing worktree changes.

**Goal:** Admit one generated ZipCPU `wbuart` Wishbone target into D4 topology binding using its existing versioned provider and typed DMA path.

**Architecture:** Add the exact `GeneratedWishboneUartSession` provider predicate to the closed target admission. Generate D2/D3 route rows for a RAM read and UART TXREG write, prepare the existing typed graph without mutating the runner, then let D4 perform the first live bind. Keep `compile_zipcpu_uart_dma_runtime_paths(...)` behavior intact for callers that want immediate topology binding and admission installation.

**Limits:** Only `uart.bus`, Wishbone classic, `target.wishbone` v1 `word-addressed-registered-ack`, full-word TXREG offset 12, accepted values 0..255, provider startup setup value 25, and the pinned 8N1 TX identity. F6 stays unsupported. No native or remote gate in this software slice.

## Task 1: Add a generated D2/D3 and typed-path fixture

- [x] Generate route rows for a DMA read from persistent RAM and write to ZipCPU UART TXREG.
- [x] Use `target.wishbone` v1 `word-addressed-registered-ack` and a test-only capability sidecar for `uart.bus`; do not imply a shipped sidecar.
- [x] Add `prepare_zipcpu_uart_dma_runtime_paths(...)` to build the existing typed graph without binding or installing admission; the integration fixture starts no native process.
- [x] Assert D2/D3 preserves route/binding rows, selects the expected target template, keeps F6 unsupported, and emits no DMA transfer edge.
- [x] Confirm each provider-method shadow negative with the real binder; it rejects before the prepared live bind.

## Task 2: Enforce the exact Wishbone UART target contract

- [x] Validate exact session class and refuse instance shadowing of all seven provider identity/mechanics methods, including `_dma_exact_document`.
- [x] Validate `_validate_provider_identity(...)` against the generated artifact, then require component `zipcpu_uart`, artifact kind `wishbone_uart`, endpoint `uart.bus`, protocol `wishbone@classic`, and the actual target artifact's template selection.
- [x] Restrict policy to write-only TXREG offset 12, `byte_enable == 15`, no readable offsets, writable offsets `(12,)`, and `range(0, 256)`.
- [x] Require `target.wishbone` v1 `word-addressed-registered-ack` and one 32-bit `TXREG` register at offset 12 with `rw` access.
- [x] Verify the positive binds the exact prepared object once in the D4 binder call; existing OTI and PULP paths remain admitted.

## Task 3: Add hostile negatives and update records

- [x] Reject provider shadow/identity drift, subclass/lookalike, wrong artifact/profile, non-Wishbone/unadapted endpoint, wrong template, read route, wrong offset, partial byte enable, wrong accepted values, subwindow, and different live target window.
- [x] Spy that provider/static target refusal does not call `PreparedRuntimePathContract.bind`; a changed live window is refused by the prepared binder.
- [x] Recheck provider method implementations and canonical identity during topology validation; post-bind method and identity drift are refused.
- [x] Run the focused D2/D3/D4 and route/replay reader software gate plus syntax and diff checks.
- [x] Record exact counts and maintain the boundary that prior native DMA evidence is separate, F6 is unsupported, and this slice runs no native/remote gate.

## Completion record

Completed 2026-10-20. The two focused ZipCPU D4 integration cases plus the existing ZipCPU runtime-path tests passed **37 tests**; the D4/topology/replay joint gate passed **186 tests and 30 subtests in 206.37s**. `py_compile` and `git diff --check` are included in the final report. See [implementation report](../../reports/p7-d4-zipcpu-uart-wishbone-admission-20261020.md) and [design](../specs/2026-10-20-p7-d4-zipcpu-uart-wishbone-admission-design.md).
