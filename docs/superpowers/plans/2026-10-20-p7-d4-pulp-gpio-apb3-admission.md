# P7 D4 PULP GPIO APB3 Admission Implementation Plan

> **For agentic workers:** Use the repository's test-first workflow. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admit one generated PULP GPIO APB3 PADOUT target into D4 topology binding under its pinned provider and observation contract.

**Architecture:** Extend the existing closed target-admission predicate in `dma_intent_topology_binding.py`. Exercise the real D2/D3 generator, a real generated PULP artifact, and the existing PULP typed DMA route; retain the already-prepared graph object and let `PreparedRuntimePathContract.bind` validate the live `MasterTargetWindow`.

**Tech Stack:** Python 3.12, pytest, local harness artifact generator, D2/D3 compiled path API, `PreparedRuntimePathContract`.

## Global Constraints

- Only exact `GeneratedPulpGpioSession` plus `pulp_gpio_causal_local` is admitted.
- Provider/API/profile identities are `pulp_gpio_dma_target_provider.v1`, `dma_master_target_access.v1`, and `pulp_gpio_padout_apb3.v1`.
- Only `target.apb3` v1 `full-word` and full-word PADOUT writes at offset 12 are admitted.
- Keep D2/D3 behavior and P7-C F6 `unsupported` unchanged.
- Do not run a native or remote gate in this software-only slice.
- Do not stage, commit, reset, or clean the shared worktree.

---

### Task 1: Add the D2/D3 PULP integration fixture and observe RED

**Files:**
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py`
- Read: `src/myfuzz/scenario/pulp_gpio_dma_paths.py`
- Read: `tests/scenario/test_dma_intent_topology_binding.py`

**Interfaces:**
- Reuse `generate_harness_set`, `load_path_compile_request`, and `compile_paths` to create the PULP D2/D3 rows.
- Reuse the existing generated DMA artifact-link fixture and generate a real `pulp_gpio_causal_local` runtime artifact.
- Construct the existing typed PULP RAM-read / GPIO-write graph using the same `RULES`, `RuntimeNode`, and `RuntimeEdgeContract` declarations as `pulp_gpio_dma_paths.py`; derive route identities from the actual memory service, DMA session, and `MasterTargetWindow`.

- [x] Add a test that first asserts the D2/D3 output preserves both route rows and selects `target.apb3` v1 `full-word` for `gpio.bus`.
- [x] Assert the D2/D3 F6 row remains `unsupported` and has no DMA transfer edge.
- [x] Prepare the generated route declaration and call D4 binding with the actual PULP artifact; before implementation, observe `dma-binding-target-unsupported` at the PULP target.

Run: `PYTHONPATH=src python3 -m pytest -q tests/integration/test_p7b_p7c_dma_route_intent.py::test_pulp_apb3_d2_d3_route_binds_existing_typed_topology --tb=short`

Expected RED: the generated artifact and declaration load successfully; D4 rejects the exact PULP session with `dma-binding-target-unsupported` because PULP is not in the closed target allowlist.

### Task 2: Add the exact PULP provider admission

**Files:**
- Modify: `src/myfuzz/scenario/dma_intent_topology_binding.py`
- Test: `tests/integration/test_p7b_p7c_dma_route_intent.py`

**Interfaces:**
- Extend `_target_binding(wiring, intent, session, pointer)`.
- Keep existing OTI and Wishbone UART branches unchanged.
- Use `GeneratedPulpGpioSession.dma_master_target_provider_identity_document()` and `pulp_gpio_observation_contract()` as the registered identity source.

- [x] Admit only `type(session) is GeneratedPulpGpioSession` after exact generated-artifact validation; check the code-sealed GPIO producer to reject instance method shadowing before reading provider identity.
- [x] Require profile component `pulp_gpio_causal_local`, artifact kind `apb_gpio`, pinned observation contract, and adapted APB3 `gpio.bus`.
- [x] Require provider/API/profile identity exactly, plus D2 `target.apb3` v1 `full-word`.
- [x] Require write-only route policy, `byte_enable == 15`, no readable offsets, exactly writable offset `(12,)`, and a 32-bit `PADOUT` register at offset 12 with write permission.
- [x] Run the RED test and the focused existing D4 target tests.

Run: `PYTHONPATH=src python3 -m pytest -q tests/integration/test_p7b_p7c_dma_route_intent.py::test_pulp_apb3_d2_d3_route_binds_existing_typed_topology tests/integration/test_p7b_p7c_dma_route_intent.py::test_d2_d3_route_binds_existing_typed_topology_and_keeps_f6_closed tests/integration/test_p7b_p7c_dma_route_intent.py::test_live_peripheral_target_and_window_identity --tb=short`

Expected: all selected tests pass; the PULP positive binds the same prepared object exactly once and the existing target tests retain their behavior.

### Task 3: Add hostile negatives and update the status record

**Files:**
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py`
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/reports/README.md`
- Create: `docs/reports/p7-d4-pulp-gpio-apb3-admission-20261020.md`
- Modify: `docs/superpowers/plans/README.md`

**Interfaces:**
- Keep negative cases on generated PULP artifacts; do not mutate a valid artifact and rehash its identity.
- Use fresh fixtures per mutation so each refusal identifies one changed admission fact.

- [x] Add refusals for lookalike/subclass session, missing or shadowed/altered provider method, artifact observation-document tampering, wrong APB3 template, wrong endpoint protocol/adaptation, read access, another offset, partial byte enable, and target subwindow/live-window mismatch.
- [x] Add a spy proving provider refusal does not reach prepared graph bind; preserve the exact original prepared object and one bind call in the positive.
- [x] Run the Task 1 integration test, focused D4 tests, and the existing route/replay reader regression gate.
- [x] Record the final software counts and explicitly keep F6, native, remote, six-CPU/four-IP acceptance, and P6/P7/P8 claims open.

### Task 4: Expose guarded route-fit lookups from the bound credential

**Files:**
- Modify: `src/myfuzz/scenario/dma_intent_topology_binding.py`
- Modify: `src/myfuzz/scenario/runtime_edge_index.py`
- Modify: `src/myfuzz/scenario/runtime_path_contract.py`
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py`
- Modify: `tests/scenario/test_runtime_edge_index.py`
- Update: this plan and the D4 PULP report

- [x] Add an exact RAM-read and PADOUT-write lookup to the generated PULP D4 positive; reject another offset and an unaccepted write value.
- [x] Observe RED because `BoundDmaIntentTopology` did not expose a route matcher; implement a private `RuntimeEdgeIndex` validated against the existing compilation and exact already-bound prepared object. Recompute and compare its graph/path/source caches; avoid deserializing a second graph.
- [x] Revalidate topology before each lookup; snapshot and recheck the code-sealed PULP provider plus exact provider identity so instance method shadowing after bind refuses.
- [x] Add a RED/GREEN cache-tampering negative for the reusable prepared object; run the full RuntimeEdgeIndex module and independent review.
- [x] Keep the result a route-fit identity only; accepted request, target effect, and native response joins remain caller-owned, and F6 remains unsupported.
- [x] Re-run the complete route-intent and replay-reader software gate; record the exact result below.

## Completion record

The joint software gate, including `test_runtime_edge_index.py`, passed **209 tests and 61 subtests in 250.50 seconds**. The graph-construction spy confirms the binder reuses the exact prepared object without constructing a replacement runtime graph; the cache-tampering negative confirms stale source-owner records are refused. This slice did not run native/build/remote tests; the report is [p7-d4-pulp-gpio-apb3-admission-20261020.md](../../reports/p7-d4-pulp-gpio-apb3-admission-20261020.md).

Run: `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_dma_artifact_endpoint_links.py tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_runtime_path_contract.py tests/scenario/test_runtime_edge_index.py tests/integration/test_dma_intent_binding_replay.py tests/integration/test_dma_master_route_replay_readers.py tests/integration/test_p7b_p7c_dma_route_intent.py tests/integration/test_route_intent_reader_boundaries.py --tb=short`

Expected: the complete software gate passes; the report lists the observed count and states that no native or remote execution occurred.
