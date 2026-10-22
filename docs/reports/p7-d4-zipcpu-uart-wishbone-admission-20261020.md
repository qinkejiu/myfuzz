# P7 D4 ZipCPU UART Wishbone TXREG Admission

Date: 2026-10-20

## Result

The D4 live topology binder admits one bounded ZipCPU `wbuart` target: exact generated `GeneratedWishboneUartSession`, adapted endpoint `uart.bus` on Wishbone classic, and D2 target template `target.wishbone` v1 `word-addressed-registered-ack`. The generated artifact must be `zipcpu_uart` / `wishbone_uart` with a 16-byte window and one 32-bit `TXREG` register at offset 12 with `rw` access.

Admission calls the existing strict `_validate_provider_identity` only after rejecting instance shadows of provider identity and all provider mechanics methods, including `_dma_exact_document`. It snapshots method implementations and canonical provider identity; every later topology validation rechecks both, so replacing a provider method after binding invalidates the credential. The provider identity binds the artifact digest, instance, Wishbone role map, TX pin, SETUP value 25 and 8N1 timing. The route accepts only write-only TXREG offset 12, full-word byte enable 15, and values `range(0, 256)`. The existing prepared binder remains responsible for the live `MasterTargetWindow` and typed route identity.

`prepare_zipcpu_uart_dma_runtime_paths(...)` now constructs the existing typed RAM-read / DMA-write / TXREG graph without binding the runner or installing runtime admission. This separates preparation from the default `compile_zipcpu_uart_dma_runtime_paths(...)` behavior, which continues to bind and install admission. D4 receives the prepared graph and performs its first live bind, exactly once, so a positive D4 bind does not collide with a validator installed during fixture construction.

The generated D2/D3 rows and target template are preserved. The positive D4 test reuses the same `PreparedRuntimePathContract` object and yields a `topology_bound` credential. D2/D3 still reports F6 `unsupported` and adds no `DMA_MASTER_TRANSFER` edge to either its dependency graph or runtime path contract.

## Refusal coverage

Software coverage checks changed target-template identity, provider startup identity drift, shadowing each of the seven provider identity/mechanics methods before bind, and unsupported TXREG operation/offset/value policies. Post-bind provider method or identity drift makes `validate_topology()` refuse with `dma-binding-topology-changed`; restoring the original method and startup identity restores validation. A changed live master target window is rejected by the prepared binder after its one attempted bind. Static provider/template refusals occur before `PreparedRuntimePathContract.bind`.

The generated UART test capability is a test-only D2/D3 sidecar. It is not a shipped capability sidecar or an additional runtime assertion.

## Verification boundary

Focused verification passed: the two ZipCPU D4 integration cases plus `tests/scenario/test_zipcpu_uart_dma_paths.py`, **37 passed**. The full D4/topology/replay software gate passed **186 tests and 30 subtests in 206.37s**:

```text
PYTHONPATH=src python3 -m pytest -q \
  tests/local_harness/test_dma_artifact_endpoint_links.py \
  tests/scenario/test_dma_intent_topology_binding.py \
  tests/scenario/test_runtime_path_contract.py \
  tests/integration/test_dma_intent_binding_replay.py \
  tests/integration/test_dma_master_route_replay_readers.py \
  tests/integration/test_p7b_p7c_dma_route_intent.py \
  tests/integration/test_route_intent_reader_boundaries.py --tb=short
```

This slice did not run a native, build, or remote gate. The separate local ZipCPU DMA evidence remains in [the ZipCPU UART DMA target report](zipcpu-uart-dma-target-20261020.md); this admission result does not claim a physical Wishbone bridge, CPU DMA configuration/consumption/retirement, UART RX-to-RAM, multiword transfer, arbitrary Wishbone target support, F6, or full P6/P7/P8 completion.
