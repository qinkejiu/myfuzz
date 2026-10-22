# P7-C compiled F6 result handed to Caliptra D4

Date: 2026-10-21
Status: bounded implementation and native acceptance complete.

## Result

The Caliptra SHA256 native gate now carries the exact `compiled_paths.v1`
result from D3 into the existing D4 topology bind. The handoff stores the full
compiler result and static D4 declaration, checks their route and binding
identities, and calls the existing live topology binder once with the same
`PreparedRuntimePathContract` object. Positive, independent fresh, and
wrong-route refusal runs retain the complete bound handoff in their evidence.

P7-C F6 remains `unsupported` with reason
`dma-route-live-topology-binding-required`. The compiler result contains no
`DMA_MASTER_TRANSFER` rule/edge and no `dma_master_route` runtime contract or
DMA route list. This work proves that D4 consumed the exact static refusal
result; it does not enable static F6 execution.

The validator now checks closed compiler and wiring shapes, canonical wiring
digests, exact route IDs, the explicit null runtime identity, and equality of
the root F6 refusal with its single `reason.missing` row. It round-trips both
dependency graph and runtime path contract schemas, refusing DMA transfer
rules/edges and runtime DMA routes. D4 route links form a complete unique
policy bijection. Caliptra, PULP, and ZipCPU read/write route selection uses
the declared operation rather than tuple order.

## Verification

The final focused software gate was:

```bash
PYTHONPATH=src pytest -q \
  tests/scenario/test_compiled_f6_dma_handoff.py \
  tests/scenario/test_dma_intent_topology_binding.py \
  tests/scenario/test_dma_route_admission.py \
  tests/integration/test_p7b_p7c_dma_route_intent.py::test_d4_route_mapping_is_policy_unique_and_name_independent \
  tests/integration/test_p7b_p7c_dma_route_intent.py::test_caliptra_ahb_d2_d3_route_binds_existing_typed_topology \
  tests/integration/test_dma_caliptra_sha256_real.py \
  tests/integration/test_dma_pulp_gpio_real.py \
  tests/integration/test_dma_zipcpu_uart_real.py
```

Result: **109 passed, 4 skipped in 30.32s**. The four opt-in native tests in
the three protocol test files were skipped in this software-only run. After
adding the canonical dependency-graph v2 compatibility case, the handoff and
route-order regression tests were rerun: **26 passed in 0.39s**.

The final native gate used a new cache and refreshed the evidence directory:

```bash
PYTHONPATH=src \
MYFUZZ_DMA_CALIPTRA_REAL=1 \
MYFUZZ_DMA_CALIPTRA_CACHE=/tmp/myfuzz-caliptra-f6-handoff-cache-selfcontained-20261021 \
MYFUZZ_DMA_CALIPTRA_EVIDENCE=docs/reports/evidence/p7-f6-compiled-dma-handoff-20261021 \
pytest -q tests/integration/test_dma_caliptra_sha256_real.py
```

Result: **1 passed in 78.60s**. A separate evidence check verified the
compile-request digest, compiled-result and wrapper hashes, static F6 refusal,
absence of runtime DMA routes, exact prepared-object bind count, normalized
fresh equality, and the provider-before-refusal boundary described below.

## Evidence

The directory
[`p7-f6-compiled-dma-handoff-20261021/`](evidence/p7-f6-compiled-dma-handoff-20261021/)
contains four gzip JSON run/request records, a separate gzip input manifest,
and the raw D3 request inputs:

- `compile-request.json.gz` preserves the exact D3 request so it can be loaded
  with the same identity after its referenced inputs are restored.
- `compile-inputs/` contains byte-exact copies of the generated wiring contract
  and both test-capability sidecars. `compile-input-manifest.json.gz` records
  each original absolute path, archive path, byte length, and SHA256; restore
  these files to their recorded paths before replaying the unchanged request.
- `descriptor.json.gz` records the positive native DMA run and full D4
  handoff.
- `fresh.json.gz` records a separately recompiled D3 result and fresh native
  run.
- `native-refusal.json.gz` records the in-window `CTRL+4` route refusal and
  pre-provider observations.

Identity values from this run:

| Identity | SHA256 |
|---|---|
| D3 compile request | `sha256:e913b94098c7d43d55645b0381c994b2fd8b09a1a0a0dd4b328f5426d77a749f` |
| Complete `compiled_paths.v1` | `95538e6bab266f5d858c5bf943233c487de418838019c463b440e0c2a633af58` |
| Compiled F6 handoff | `b718529bdf1b9d1c70d755f1674152dae2ccfb9fd2299dd75af2ee3a2ba2ebc5` |
| Bound handoff | `434d117fda9665cd234555e3437de02cd8aeb814027a14e1ec89320cbf81d8fd` |

The positive run joins route `(0,0)` as a RAM read at `0x10100` and route
`(2,0)` as a Caliptra `CTRL` write at `0x40002010`. Both records show one bind
of the exact prepared graph. The `abc` SHA256 known answer matches; the fresh
compile request produces the same compiler, handoff, and bound-handoff
identities, while the native execution IDs differ and the normalized evidence
matches.

The refusal run observes a native request to `0x40002014` when the selected
route is `0x40002010`. D4 rejects it with
`DMA route match does not exactly match the selected route` before a Caliptra
provider event. The saved provider event list and rejected-key RAM
write/commit list are both empty; AHB local ticks remain 68.

## Limits

This is a transaction-level ZipCPU Wishbone DMA to Caliptra AHB-Lite target
composition through the existing software admission layer. It does not prove
a physical Wishbone-to-AHB bridge, CPU DMA programming or consumption,
instruction retirement, completion IRQ/ISR, arbitrary F6 execution, or P7-E.
P6, P7, P8, and the six-CPU/four-IP aggregate objective remain open.
