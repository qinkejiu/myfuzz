# P7 D4 PULP GPIO Native Route Consumption

Date: 2026-10-21

## Result

The PULP GPIO D4 topology credential now gates the real native one-word DMA
path. Preparation is separate from binding: the compatibility
`compile_pulp_gpio_dma_runtime_paths(...)` entry point still binds once and
installs its existing admission, while the native fixture prepares one typed
graph, lets D4 bind that exact object once, and installs a composite admission
that checks the D4 route before the existing beat policy advances.

The live run used D2/D3 wiring with RAM base `0x10000`, size `0x20000`, GPIO
base `0x40001000`, size `0x1000`, and PADOUT offset `0x0c`. The source word at
`0x10100` was `0x5aa55aa5`; the selected destination was `0x4000100c`. The D3
route digest was `14d4512ddbf629d1637135bf0ce8aeb45e6e175208d0792dc5e323f5670e778f`.
The D4 document reports tier `topology_bound` and identity SHA256
`49b5dfcad5450a41ec4225c19fba2acafd9ba2530062714f460b8e61bd144d1a`.

Each native session recorded `bind_count == 1` and
`same_prepared_object == true`. The RAM read matched D4 edge `(0, 0)` and
transaction key `execution_id=6c6ffeb6a4994b8889a9aae30fb832e7; testcase_id=pulp-dma-single-word; source_component=dma; source_epoch=0; channel_id=dma-memory; source_sequence=1`;
that key joined to exactly one MemoryService read of `0x5aa55aa5` and a native
read response with the same value and `error == 0`. The PADOUT write matched
edge `(2, 0)` and its distinct key had the same fields with
`source_sequence=2`; it joined to the PULP target-provider/APB3 receipt, the
observed PADOUT effect `gpio-access:gpio:0:1`, and a native write response
with `error == 0`. The one-word admission also requires the write value to
equal the successful RAM read response.

The independent fresh run matched the normalized reference exactly. Both
positive runs ended with admission state `complete`. In the negative run, a
native request to `0x40001010` was refused after the permitted RAM read but
before a write-route match or GPIO provider/APB activity. PADOUT remained zero
and admission remained at `expect_write`.

## Verification

The complete opt-in native file passed **2 tests in 116.38 seconds**:

```bash
PYTHONPATH=src MYFUZZ_DMA_PULP_REAL=1 \
MYFUZZ_DMA_PULP_CACHE=/tmp/myfuzz-pulp-d4-native-cache-20261021 \
MYFUZZ_DMA_PULP_EVIDENCE=docs/reports/evidence/p7-d4-pulp-native-route-consumption-20261021 \
timeout 1800 python3 -m pytest -xq tests/integration/test_dma_pulp_gpio_real.py
```

The joint software regression passed **236 tests and 61 subtests in 343.76
seconds** with:

```bash
PYTHONPATH=src python3 -m pytest -q \
  tests/local_harness/test_dma_artifact_endpoint_links.py \
  tests/scenario/test_dma_intent_topology_binding.py \
  tests/scenario/test_runtime_path_contract.py \
  tests/scenario/test_runtime_edge_index.py \
  tests/integration/test_dma_intent_binding_replay.py \
  tests/integration/test_dma_master_route_replay_readers.py \
  tests/integration/test_p7b_p7c_dma_route_intent.py \
  tests/integration/test_route_intent_reader_boundaries.py \
  tests/scenario/test_pulp_gpio_dma_paths.py --tb=short
```

It covered artifact links, D4 topology/replay, route-index readers, D2/D3
composition, and the PULP path preparation/compatibility API. `py_compile` and
`git diff --check` exited 0; the scoped trailing-whitespace scan passed for all
11 source/spec/plan/report/index files.

Evidence is in
[`evidence/p7-d4-pulp-native-route-consumption-20261021/`](evidence/p7-d4-pulp-native-route-consumption-20261021/):
`reference.json.gz`, `fresh.json.gz`, `comparison.json`,
`unselected-offset-refusal.json.gz`, and `manifest.json`. The normalized
reference and fresh SHA256 values are both
`1b8654ff9aacabbc6ba80309d9b5e3cc4b6b6ea321590c38091c5f1eb2dc56ae`.
An independent read-only code review found no concrete correctness issue.

## Scope

This is transaction-level composition of separate native Wishbone DMA and
PULP GPIO/APB3 processes. It does not claim a physical Wishbone-to-APB bridge,
CPU DMA programming or retirement, a multiword transfer, generic F6
execution, or completion of P7-E. The D2/D3 F6 row remains `unsupported` and
the compiler gains no `DMA_MASTER_TRANSFER` edge from this slice. P6, P7, P8,
and the six-CPU/four-IP objective remain open.
