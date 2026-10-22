# P7-D4 Caliptra AHB-Lite route consumption

This slice adds Caliptra SHA256 as a third native target protocol consuming the existing `DmaMasterRouteAdmission`, following PULP APB3 and ZipCPU Wishbone. It keeps the existing Caliptra beat policy as the target-specific layer and leaves D2/D3 F6 disabled.

## Fixture and D4 binding

The native fixture creates a generated Ibex CPU owner and a generated ZipCPU DMA artifact with its endpoint-link document. Both sessions share one `PersistentMemory` object. D2, D3, the prepared route, and live RAM use base `0x10000`, size `0x20000`; the DMA source word is at `0x10100`. A generated Caliptra SHA256 AHB-Lite session provides the target window.

The fixture prepares the typed paths, builds the D4 declaration from the prepared object and generated endpoint links, and binds that exact object once. The saved binding tier is `topology_bound`; `bind_count` is 1 and `same_prepared_object` is true. The generic D4 admission wraps the existing one-word Caliptra policy using the bound RAM-read and Caliptra CTRL-write routes. A test-only observer records only completions accepted by the base policy.

## Positive run and fresh replay

The final native command was:

```bash
PYTHONPATH=src \
MYFUZZ_DMA_CALIPTRA_REAL=1 \
MYFUZZ_DMA_CALIPTRA_CACHE=/tmp/myfuzz-caliptra-d4-cache-20261021 \
MYFUZZ_DMA_CALIPTRA_EVIDENCE=docs/reports/evidence/p7-d4-caliptra-generic-route-consumption-20261021 \
pytest -q tests/integration/test_dma_caliptra_sha256_real.py
```

It passed with **1 passed in 92.11s** after the focused software gate. The focused command was:

```bash
PYTHONPATH=src pytest -q \
  tests/scenario/test_caliptra_sha256_dma_paths.py \
  tests/scenario/test_dma_route_admission.py \
  tests/integration/test_p7b_p7c_dma_route_intent.py
```

It passed with **41 passed in 285.41s**. The focused software gate also preserves the Caliptra D2/D3 F6 `unsupported` assertions and verifies that no `DMA_MASTER_TRANSFER` edge is added.

The positive descriptor records these D4 route matches and runtime route hashes:

| D4 edge | Operation | Address | Runtime route SHA256 | Transaction source sequence |
| --- | --- | --- | --- | ---: |
| `(0, 0)` | read | `0x10100` | `71c91f132c503f473857ba810bac2886f6992f4f5e794ebe43e290a74a594292` | 1 |
| `(2, 0)` | write | `0x40002010` | `da5ba3f32bb773e110fb473cdc34f4127bd2b168d01f0f60441c375224838542` | 2 |

For the RAM read, the typed route-match key joins to the DMA accepted beat, one `memory_read`, a successful Caliptra policy completion (`rdata=5`, `error=0`, state `expect_write`), and the successful native Wishbone response. For the CTRL write, a distinct key joins the accepted beat and route match to one Caliptra AHB provider receipt, the observed request/data response and effect (`CTRL`, offset `0x10`, full-word value `5`), the accepted policy completion (`rdata=0`, `error=0`, state `complete`), and the successful native Wishbone response.

The Caliptra status read was `3`; the digest was `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`, matching SHA256 of `abc`. The independent fresh run used different DMA and Caliptra execution IDs. The saved descriptor and fresh record compare equal after execution-ID normalization.

## In-window refusal

The native refusal record captures a `STEP_WB_DMA` pre-backend request to `CTRL+4` at `0x40002014` with value `5`. D4 rejects it with the exact error `DMA route match does not exactly match the selected route`. The only retained route match and policy completion are the preceding RAM read; policy state remains `expect_write`.

The rejected write's typed transaction key is recorded. No `memory_write` or `memory_write_commit` event exists under that key, no Caliptra provider receipt was issued, and AHB local ticks stayed at `68`. RAM preload and SHA block setup precede the refusal observation and are outside this rejected-write side-effect statement.

## Evidence and scope

Saved files are in [the Caliptra native evidence directory](evidence/p7-d4-caliptra-generic-route-consumption-20261021/):

- `descriptor.json.gz` — positive D4 binding, route matches, keyed service and response joins, provider receipt, status and digest.
- `fresh.json.gz` — independent positive execution for normalized comparison.
- `native-refusal.json.gz` — native `CTRL+4` request, exact matcher refusal, retained read evidence, rejected key, provider count, and AHB ticks.

Independent read-only review approved the native implementation and saved evidence with no Critical, Important, or Minor findings. Syntax compilation also passed for both changed integration test files.

This is bounded transaction-level composition of an independent native Wishbone DMA process with a generated Caliptra AHB-Lite process. It does not establish a physical Wishbone-to-AHB bridge, CPU DMA programming or CPU consumption/retirement, multiword transfer, arbitrary AHB support, F6, P7-E, or full P6/P7/P8 or six-CPU/four-IP completion.
