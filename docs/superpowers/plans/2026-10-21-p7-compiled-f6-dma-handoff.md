# P7 compiled F6 DMA handoff implementation plan

> **Status:** bounded implementation and acceptance complete; see [result report](../../reports/p7-f6-compiled-dma-handoff-20261021.md). Preserve the shared dirty worktree; no staging, commit, reset, cleanup, or remote work was performed.

**Goal:** Bind the exact P7-C F6 compilation result to the existing live D4 DMA route credential without making static F6 executable.

**Architecture:** Add a closed digest-bound handoff wrapper for the complete `compiled_paths.v1` document and the existing detached DMA binding declaration. Bind the wrapper through the current D4 topology binder exactly once, then retain it in the existing Caliptra native evidence; all beat admission and target behavior remain in current code.

**Tech Stack:** Python 3 frozen dataclasses, canonical JSON/SHA256, `compiled_paths.v1`, `PreparedDmaIntentBinding`, `BoundDmaIntentTopology`, `DmaMasterRouteAdmission`, pytest, generated native Caliptra AHB-Lite fixture.

## Global Constraints

- Keep `compiled_paths.v1` F6 `unsupported` with reason `dma-route-live-topology-binding-required`.
- Emit no static `DMA_MASTER_TRANSFER` edge and no live endpoint/target identity from P7-C.
- Route matching is a full explicit bijection; never select by name, address, order, or first master.
- Keep the existing PULP APB3, ZipCPU Wishbone, and Caliptra AHB-Lite route behavior and target-specific beat policies unchanged.
- Preserve every unrelated dirty/untracked file; do not stage, commit, reset, clean, or run remote work.
- Do not claim CPU programming/retirement, completion IRQ/ISR, a physical Wishbone-to-AHB bridge, arbitrary F6, P7-E, or full P6/P7/P8 completion.

---

## File map

| File | Responsibility |
|---|---|
| `src/myfuzz/scenario/compiled_f6_dma_handoff.py` | Closed immutable compiled-F6 / D4-binding evidence wrappers and validators |
| `tests/scenario/test_compiled_f6_dma_handoff.py` | Detached schema, digest, route-set, and refusal tests |
| `tests/integration/test_dma_caliptra_sha256_real.py` | Pass the exact P7-C compiled result into D4 and retain handoff in native evidence |
| `docs/reports/p7-f6-compiled-dma-handoff-20261021.md` | Final bounded result, command identities, evidence and limitations |
| `docs/CURRENT_PROGRESS.md`, `docs/reports/README.md`, `docs/superpowers/plans/README.md` | Current status and evidence indexes |

## Task 1: immutable compiled F6 handoff

**Files:** create `src/myfuzz/scenario/compiled_f6_dma_handoff.py` and `tests/scenario/test_compiled_f6_dma_handoff.py`.

**Interfaces:** consume a `Mapping[str, object]` returned by `compile_paths(request)` plus an existing `PreparedDmaIntentBinding`; produce `CompiledF6DmaHandoff` with `document()` and `identity_sha256`. Invalid input raises `CompiledF6DmaHandoffError(ValueError)` with stable `code` and JSON `pointer` attributes.

- [x] Add exact static-refusal acceptance coverage. Synthetic schema tests cover detached validation; the Caliptra integration passes the mapping from the real D2/D3 `compile_paths` call with its matching declaration.
- [x] Add route/binding digest mismatch negatives with stable handoff refusal codes and pointers.
- [x] Reject executable F6, non-null or missing runtime identity, wrong refusal, and route-set mismatch before Runner binding.
- [x] Reject unknown wrapper keys, malformed nested containers, and incorrect compiler, declaration, handoff, and bound-wrapper digests.
- [x] Reject malformed compiler graph schemas, hidden DMA rules/edges/routes, reason-summary mismatch, and wiring-section identity drift; preserve a canonical v2 dependency-graph positive case.
- [x] Implement frozen `CompiledF6DmaHandoff`, strict `prepare_compiled_f6_dma_handoff(compiled_paths, declaration)`, and canonical JSON/SHA256 identities.
- [x] Copy and canonicalize the complete compiler document; compare ordered F6 route IDs and declaration route links.
- [x] Recompute the static route and binding digests from embedded wiring; compare them with the compiler identity and exact declaration.
- [x] Verify detached handoff documents, unchanged caller values, schema negatives, and the actual compiler-to-D4 integration in final software gates.

## Task 2: live bind wrapper with one prepared graph

**Files:** extend `src/myfuzz/scenario/compiled_f6_dma_handoff.py` and its tests.

**Interfaces:** consume `CompiledF6DmaHandoff`, actual Runner, and generation-issued `artifact_links`; produce `BoundCompiledF6DmaHandoff` wrapping the existing `BoundDmaIntentTopology`. Its closed document is `bound_compiled_f6_dma_handoff.v1` with `compiled_f6_handoff`, `topology_binding`, and `identity_sha256` alongside `schema_version`.

- [x] Spy on `PreparedRuntimePathContract.bind` in the real generated-endpoint Caliptra fixture; assert one call with the declaration's retained prepared object.
- [x] Reuse the existing binder's Runner, artifact-link, endpoint, and target checks before effects; retain its drift refusal coverage.
- [x] Tamper with compiled-path, declaration, route, topology, and outer-wrapper hashes; require bound-reader refusal.
- [x] Implement the wrapper by delegating once to `bind_dma_intent_topology(...)`, without constructing another prepared graph.
- [x] Revalidate both embedded handoff identity and the existing live topology guard in `BoundCompiledF6DmaHandoff.validate_topology()`.
- [x] Verify the bound document retains the exact compiler digest and `topology_bound` credential.

## Task 3: Caliptra native consumer and evidence

**Files:** modify `tests/integration/test_dma_caliptra_sha256_real.py` and add `docs/reports/evidence/p7-f6-compiled-dma-handoff-20261021/` outputs through the existing opt-in gate.

- [x] Return the actual `compiled_paths.v1` result from `_native_d3_wiring`; check F6 reason and route digest before Runner creation.
- [x] Bind positive, wrong-route refusal, and fresh runs from that exact compiled result; fresh reloads the saved request and recompiles independently.
- [x] Record the full compiled-F6 handoff, compiler digests, one-bind proof, typed route matches, provider receipts, responses, and target effects.
- [x] Preserve the exact compile request and byte-identical generated wiring/test-capability inputs with original paths and hashes for replay.
- [x] Preserve `CTRL+4` refusal before AHB provider dispatch and prove the rejected key has no memory write or commit.
- [x] Compare original and independent fresh evidence after execution-ID normalization; require equal compiled handoff, route, and semantic identities.
- [x] Run the focused software command:

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

Result: 109 passed, 4 skipped in 30.32 seconds. After adding the canonical dependency-graph v2 compatibility case, the handoff and route-order regression tests were rerun: 26 passed in 0.39 seconds. The four opt-in native protocol tests were skipped in this software-only run.

- [x] Run the native gate with a fresh task-specific cache; save compile request, positive, fresh, and refusal evidence:

```bash
PYTHONPATH=src \
MYFUZZ_DMA_CALIPTRA_REAL=1 \
MYFUZZ_DMA_CALIPTRA_CACHE=/tmp/myfuzz-caliptra-f6-handoff-cache-selfcontained-20261021 \
MYFUZZ_DMA_CALIPTRA_EVIDENCE=docs/reports/evidence/p7-f6-compiled-dma-handoff-20261021 \
pytest -q tests/integration/test_dma_caliptra_sha256_real.py
```

Expected: positive transfer, fresh match, and in-window refusal pass in the same bounded real gate; the D3 status remains static unsupported in both saved records.

## Task 4: report, review, and indexes

**Files:** create `docs/reports/p7-f6-compiled-dma-handoff-20261021.md`; update `docs/CURRENT_PROGRESS.md`, `docs/reports/README.md`, and this plan's index entry.

- [x] Record command lines/exits, exact D3 request/compiler/bound identities, route keys, fresh comparison, refusal ordering, and evidence paths in the report.
- [x] State that P7-C F6 remains unsupported with no static DMA route; the slice only hands the exact compiled refusal to the D4 live bind.
- [x] Complete independent read-only reviews, resolve the schema and route-order findings, and rerun affected software/native gates.
- [x] Run final scoped `git diff --check` and verify every added report/index link resolves.
- [x] Preserve unrelated dirty/untracked files; do not stage or commit.

## Completion criteria

The exact P7-C F6 document is present in both the D4 binding and saved native evidence; a keyed positive run, fresh match, and pre-provider wrong-route refusal remain proven; static F6 is still unsupported; and all source/report boundaries match the evidence. This plan does not close P6, P7-E, P8, or the six-CPU/four-IP aggregate goal.
