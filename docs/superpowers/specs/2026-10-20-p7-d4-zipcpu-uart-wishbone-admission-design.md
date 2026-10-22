# P7 D4 ZipCPU UART Wishbone TXREG Admission Design

Date: 2026-10-20

## Goal

Add the generated ZipCPU `wbuart` Wishbone target as a bounded D4 live DMA topology binding positive. This is the next independent bus protocol after the PULP GPIO APB3 target. It must consume the exact D2/D3 route rows and the existing ZipCPU UART typed runtime path.

## Admission contract

Only exact `GeneratedWishboneUartSession` instances backed by the generated `zipcpu_uart` profile are candidates. Validate the existing versioned provider identity through the strict `_validate_provider_identity` consumer in `zipcpu_uart_dma_paths.py`; it binds the provider to the actual artifact digest, instance, Wishbone role map, TX pin, startup setup write, and 8N1 timing. Reject session instance shadows of provider identity/mechanics methods before reading that identity.

The accepted target is the adapted `uart.bus` endpoint with protocol `('wishbone', 'classic')` and D2 template `target.wishbone` v1 `word-addressed-registered-ack`. The route is restricted to write-only TXREG offset 12, full-word byte enable 15, and accepted byte values `range(0, 256)`. The artifact must identify `component_id == 'zipcpu_uart'`, `kind == 'wishbone_uart'`, a 16-byte address window, and a 32-bit `TXREG` register at offset 12 with `rw` access.

The existing `PreparedRuntimePathContract.bind` remains the authority for matching the exact typed route and live `MasterTargetWindow`. The positive must bind the same prepared object once inside D4 and preserve D2/D3 route/binding rows. F6 remains `unsupported` and D2/D3 compilation adds no native DMA transfer edge.

`prepare_zipcpu_uart_dma_runtime_paths(...)` exposes construction of this existing typed graph without binding the Runner or installing beat admission. D4 uses that preparation path so the D4 binder owns the first live bind. The existing `compile_zipcpu_uart_dma_runtime_paths(...)` keeps its immediate bind-and-install behavior for runtime consumers.

## Refusals

Reject provider method shadowing or identity drift, wrong session/profile/artifact, an unadapted or non-Wishbone endpoint, a different template, read access, other offsets, partial byte enable, accepted values outside the byte range, a changed address window, or a different live target window. Provider and static artifact/template refusal must happen before the prepared live bind. Live route/window mismatches remain subject to the existing prepared binder.

## Verification boundary

The software gate covers generated D2 -> D3 -> D4 composition, the real generated ZipCPU UART artifact and provider, the existing typed RAM-read/DMA-write/TXREG graph, same-object binding, exact provider identity, and hostile negatives. It does not run a native/build/remote gate. Previously archived native ZipCPU DMA evidence remains separate; this slice does not claim a physical Wishbone bridge, CPU consumption/retirement, arbitrary Wishbone target support, multiword transfer, F6, or full P6/P7/P8 completion.
