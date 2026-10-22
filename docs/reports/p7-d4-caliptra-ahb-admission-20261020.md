# P7 D4 Caliptra SHA256 AHB-Lite CTRL Admission

Date: 2026-10-20

## Result

The D4 live topology binder now admits one bounded Caliptra target: the exact generated `GeneratedAhbLiteRegisterSession`, artifact profile `caliptra_sha256`, artifact kind `ahb_lite_register_observe`, adapted `sha256.bus` AHB-Lite v1 endpoint, and D2 template `target.ahb-lite` v1 `full-word-single`. The only permitted target operation is a write-only full-word write to `CTRL` at offset 16 with value 5 and byte enable 15, inside the exact 4 KiB target window.

Admission checks the generated provider identity and its artifact digest, the CTRL register layout, the exact AHB trace schema and role widths, and the complete D2 request policy. Trace roles map only to their corresponding `trace_<role>` signal. Provider methods are resolved through the class MRO; instance shadows are refused. The topology guard snapshots and rechecks method owners, callable implementations and code objects, canonical provider identity, and stable target configuration. This catches both method replacement and in-place `__code__` changes after binding.

`prepare_caliptra_sha256_dma_runtime_paths(...)` builds the existing typed RAM-read / DMA-write / SHA CTRL graph without binding a runner or installing admission. D4 reuses that same `PreparedRuntimePathContract` object and calls `bind` exactly once. Static/provider/template refusals happen before that call; a changed live `MasterTargetWindow` is rejected by the prepared binder during its single attempted bind. The positive result has credential tier `topology_bound`.

The generated artifact request carries the exact `sha256.bus` target policy in its plan tuning, while the current generated executor document does not expose that policy in `protocol_templates`. The binder therefore recomputes the contract and selection from the pinned artifact request plus endpoint/profile and compares it with the D2 binding. This admission does not change the runtime renderer.

The D2/D3 route and template rows remain preserved. F6 remains `unsupported`, and neither the D2/D3 dependency graph nor the runtime path contract gains a `DMA_MASTER_TRANSFER` edge.

## Refusal coverage

Tests refuse subclass/lookalike sessions; shadows of each guarded method; wrong artifact component, kind, instance or window; missing or changed provider identity; wrong trace protocol, role, mapping or width; an unadapted or wrong endpoint; an unsupported target template; read access; wrong offset, byte enable or value; and a route subwindow. Post-bind method shadowing, in-place code replacement, provider identity drift, and stable configuration drift all invalidate topology validation; restoring the original implementation and values restores validation.

Static, provider and template refusals are proven to occur before `PreparedRuntimePathContract.bind`. The live-window mismatch is checked by the prepared binder after exactly one bind attempt.

## Verification boundary

The focused Caliptra software gate passed **14 tests in 37.42s**. After the code-review fixes, the joint D4/topology/replay gate passed **200 tests and 30 subtests in 255.53s**:

```text
PYTHONPATH=src python3 -m pytest -q \
  tests/local_harness/test_dma_artifact_endpoint_links.py \
  tests/scenario/test_dma_intent_topology_binding.py \
  tests/scenario/test_runtime_path_contract.py \
  tests/scenario/test_caliptra_sha256_dma_paths.py \
  tests/integration/test_dma_intent_binding_replay.py \
  tests/integration/test_dma_master_route_replay_readers.py \
  tests/integration/test_p7b_p7c_dma_route_intent.py \
  tests/integration/test_route_intent_reader_boundaries.py --tb=short
```

The independent read-only review's two findings—same-function `__code__` mutation and aliased trace signal mappings—were fixed and covered before the final joint gate. `py_compile` passed for the four changed Python source/test files, and the scoped trailing-whitespace scan passed.

This slice did not run a native, build, or remote gate. The separate [Caliptra native DMA report](caliptra-ahb-dma-target-20261020.md) remains independent evidence. D4 `topology_bound` does not itself prove a SHA digest, a physical Wishbone-to-AHB bridge, CPU consumption or retirement, IRQ behavior, arbitrary AHB support, F6 execution, or completion of P6/P7/P8 and the six-CPU/four-IP objective.
