# Protocol-Neutral DMA Route Admission Design

Date: 2026-10-21

## Goal

Reuse one D4 admission implementation to join native DMA beats to exact D2/D3-bound route identities across different target bus protocols. Apply it to the existing PULP APB3 PADOUT path and the ZipCPU Wishbone UART TXREG path.

## Design

Add `DmaMasterRouteAdmission` in `src/myfuzz/scenario/dma_route_admission.py`. It receives a protocol-specific beat policy, one topology-bound D4 credential, a path ID, and the exact selected read and write `DmaMasterRouteContract` objects. For each beat, it resolves the route by operation, asks the bound topology to match the full route and transaction identity, validates every returned match field, then delegates device/value/sequence rules to the beat policy. It records a route match only after both checks succeed. A response is accepted only for a transaction key whose beat already has an exact route match, and is then delegated to the beat policy.

The generic layer owns no protocol templates, register offsets, payload semantics, or target side effects. PULP and ZipCPU retain their current exact beat policies and native target providers. `begin_case()` clears route evidence and resets the selected policy. The current compiler helpers and their existing bind-and-install behavior remain compatible. The native D4 path instead prepares routes, binds the same prepared object exactly once, installs the generic admission, and preserves existing fresh replay and wrong-offset refusal checks.

## Evidence and boundaries

Unit tests cover exact read/write route matching, refusal before policy state changes, response-key association, and per-case clearing. The PULP native gate remains a regression oracle for APB3. The ZipCPU native gate adds D4 binding to its real Wishbone DMA-to-TXREG transfer, checks RAM read and UART request/ACK/effect/serial-byte joins, performs a fresh replay, and refuses an unselected TXREG offset before provider dispatch.

F6 remains unsupported. This establishes software topology binding and selected route consumption; it does not claim a physical Wishbone-to-APB bridge, CPU programming or retirement, arbitrary target support, multiword DMA, or P7/P6/P8 completion.
