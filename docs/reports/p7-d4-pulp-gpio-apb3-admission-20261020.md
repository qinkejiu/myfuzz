# P7 D4 PULP GPIO APB3 PADOUT Admission

Date: 2026-10-20

## Result

The D4 live DMA topology binder now admits one bounded PULP target path: generated `pulp_gpio_causal_local` GPIO, endpoint `gpio.bus` on APB3, and write-only `PADOUT` at offset 12. Admission requires the exact `GeneratedPulpGpioSession`, the existing code-sealed GPIO producer, the pinned `pulp_gpio_observation_contract`, provider identity `pulp_gpio_dma_target_provider.v1` / `dma_master_target_access.v1` / `pulp_gpio_padout_apb3.v1`, and D2 target template `target.apb3` v1 `full-word`.

The route policy is restricted to `write`, `permissions == ('write',)`, `byte_enable == 15`, no readable offsets, and writable offsets `(12,)`. The actual profile must expose one 32-bit `PADOUT` register at offset 12 with `rw` access. The target endpoint must be adapted and declare protocol `('apb', '3')`. Provider method shadowing is refused by `check_producer(session)` before the provider identity is read. The existing prepared binder remains responsible for the live `MasterTargetWindow` and typed route identity.

The generated PULP route was carried through D2 and D3 and bound into the existing RAM-read / DMA-write typed graph. The positive case preserves the route and template rows, reuses the same `PreparedRuntimePathContract` object, and calls its `bind` method once. The private `RuntimeEdgeIndex` validates against the compilation and reuses this exact prepared object; a graph-construction spy confirms it does not deserialize a replacement graph. Before reuse, the index recomputes the prepared graph/path selections against the immutable document and checks all cached source records. A negative mutates a source ID in the in-memory cache while leaving the saved bytes alone; the index refuses it. F6 remains `unsupported`, and D2/D3 compilation still adds no `DMA_MASTER_TRANSFER` runtime edge.

After binding, `match_dma_master_route(...)` rechecks the live topology and PULP provider seal before every query. The generated case matches the exact RAM read and PADOUT write, while another offset and an unaccepted write value return no match. A post-bind provider method shadow refuses with `dma-binding-topology-changed`. These are route-fit checks only: they do not join an accepted native request, target effect, or response.

## Refusal coverage

The software tests reject a subclass/lookalike session, missing or shadowed/altered provider method, wrong D2 template, wrong endpoint, non-APB3 endpoint, unadapted endpoint, read route, wrong offset, partial byte enable, changed artifact observation document, target subwindow, and a different live master target window. A binder spy verifies that provider refusal occurs before `PreparedRuntimePathContract.bind`.

The changed artifact observation document fails the existing artifact integrity comparison before the PULP-specific contract comparison. Altered provider methods are refused by the producer seal before comparing returned identity fields; the exact provider identity is checked on the successful generated session.

## Verification boundary

The full joint software gate was rerun on 2026-10-20 with the route-intent/replay suites plus `tests/scenario/test_runtime_edge_index.py`: **209 passed, 61 subtests passed in 250.50 seconds**. It includes the route-fit lookup, no-replacement-graph regression, and the prepared-cache tampering negative. An independent code review found no Critical or Important issue. Provider method mutation and artifact-document mutation are refused at their earlier seal/integrity checks; the tests and statements above preserve that order.

This slice did not run a native/build/remote gate. The separate local PULP native DMA evidence remains in [the PULP DMA target report](pulp-apb3-dma-target-20261020.md); this D4 change does not upgrade that evidence or assert a physical Wishbone-to-APB bridge, CPU DMA configuration/consumption/retirement, multiword DMA, generic F6, or full P6/P7/P8 completion. Other target providers remain separate work.
