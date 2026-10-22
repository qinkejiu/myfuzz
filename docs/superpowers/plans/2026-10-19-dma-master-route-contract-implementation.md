# Versioned DMA Master Route Contract Implementation Plan

> **Execution:** Use `subagent-driven-development`; keep each task on the files listed below and review each task before merging its result. The user has already approved the shared route design and requested parallel agents.

**Goal:** Add a versioned, fail-closed DMA master route contract and migrate the existing OpenTitan UART RX FIFO → ZipCPU wbdmac → RAM S4 path to it, while keeping old v1 evidence readable and P7 F6 unsupported.

**Architecture:** Keep `runtime_path_contract.v1` byte-compatible when it has no DMA routes. Contracts that declare routes serialize as v2 and bind each route to a selected typed graph edge. Compile the route against the exact live DMA endpoint, `MasterTargetWindow` or `PersistentMemory`, and selected Runner topology. For each beat, join the accepted native request, real target operation, and single native response by one exact `TransactionKey`; pair the separate UART read and RAM write keys by measured order and exact value. Saved plan/replay readers preserve route declarations rather than dropping them.

**Initial scope:** First consumer only: existing OpenTitan UART S4. The initial delivery did not include PULP, ZipCPU UART, or Caliptra target adapters. Follow-up local DMA route consumers are tracked in their own plans/reports; they do not close P6/P7/P8 or complete the six-CPU adaptation objective.

## Global constraints

- Follow `/home/qinkejiu/myfuzz/agent.md`. Do not write remote project, cache, operation, or evidence files outside `/root/fanzehui/**`; the jump host is connect-only.
- Keep work local until the software gates are reviewed. For a later real S4 run, create a new operation/evidence directory under `/root/fanzehui/myfuzz/`; do not alter the frozen P6 Attempt10 r10 controller or its files.
- Do not clean, reset, stage, or commit the shared dirty worktree. Preserve all existing user changes. Do not stage unrelated files.
- Preserve v1 serialized bytes and historical identities. V1 readers remain supported; a v1-only reader must refuse a v2 contract rather than discard a route.
- Preserve actual S3 target-error transactions and their no-side-effect/error-response evidence. A denied/error beat never counts as a successful transfer.
- Recheck frozen topology before each selected case admission and immediately before each DMA beat can touch a target.
- Keep P7 PathWiring/D3 F6 unsupported with `dma-master-route-undeclared` in this slice.
- A route declaration or topology compile is not a runtime transfer claim. Keep declared, topology-bound, runtime-observed, and replay-verified as separate capability states.

## Expected route contract API

Implementer task 1 owns this API; other tasks may code against it and coordinate if a detail needs adjustment:

- `RuntimePathContract` accepts an optional immutable `dma_master_routes` tuple. No routes serialize to the existing `runtime_path_contract.v1`; one or more routes serialize to strict `runtime_path_contract.v2` with sorted `dma_master_routes`.
- Add frozen `DmaMasterRouteContract(rule_index, prerequisite_index, source_node_id, target_node_id, initiator_component, endpoint_id, endpoint_identity_sha256, target_kind, target_component, target_id, base, size, operation, permissions, byte_enable, readable_offsets, writable_offsets, accepted_write_values, target_identity_sha256)`. It is keyed by the exact dependency edge. Target kind is `peripheral` or `persistent_memory`; its canonical route identity derives from the full declaration.
- Expose `canonical_runtime_identity_sha256(value)`, `persistent_memory_route_identity_document(memory, memory_id, base, size)`, and `MasterTargetWindow.route_identity_document()`. Compiled topology route rows are `{route, route_sha256, endpoint:{component,endpoint_id,identity_sha256}, target:{kind,component,id,base,size,permissions,identity_sha256,identity}}`.
- Add relation `dma_master_route` and graph kind `DMA_MASTER_TRANSFER`; reject any other kind/relation pairing. Bind the route to a selected edge and verify that edge endpoints agree with the declared initiator and target operation. Graph edge direction follows data flow, not bus ownership: UART read result → DMA receive; DMA write payload → target effect.
- Add injective window identity serialization. Encode tuple accepted values in order, and range accepted values as exact `start`, `stop`, and `step`; do not use the legacy `[start, stop - 1]` summary for v2 identity.
- Compiled topology snapshots exact endpoint/session/window or `MemoryService`/`PersistentMemory`/ledger/resource objects and immutable route declaration. `validate_topology()` detects replacement or mutation before admission and before target effect.
- New prepared-path and topology-compilation documents carrying routes use v2 schema labels. Their readers continue accepting v1 and preserve v1 canonical documents.

## Task 1 — Contract v2, route binding, and topology snapshots

**Files:**

- Modify `src/myfuzz/scenario/runtime_path_contract.py`
- Modify `src/myfuzz/scenario/dependency.py`
- Modify `src/myfuzz/local_harness/wishbone_dma_session.py`
- Modify `tests/scenario/test_dependency_mutation.py`
- Modify `tests/scenario/test_runtime_path_contract.py`
- Modify `tests/local_harness/test_wishbone_dma_session.py`

**Work:**

1. Add `DMA_MASTER_TRANSFER` as a closed dependency graph kind, plus strict `DmaMasterRouteContract` validation, stable canonical document forms, v1/v2 parsing, and the `DMA_MASTER_TRANSFER` / `dma_master_route` compatibility rule.
2. Ensure a v2 route references an existing selected graph edge; route initiator and target must match declared components while edge orientation follows data flow. Reject missing, duplicate, unknown, ambiguous, or incompatible route rows.
3. Bind peripheral routes to exactly one live DMA session endpoint and `MasterTargetWindow` whose complete identity, aperture, accepted values, and permissions match. Bind RAM routes to the exact same `PersistentMemory` object as the declared topology and to the same DMA `MemoryService` and ledger.
4. Extend the compiled frozen topology references so `validate_topology()` catches changes to session, endpoint, window tuple/object, endpoint identity, memory service, memory, ledger, region index, or route declaration. Keep the validation before each admission and target effect callable from the runtime path.
5. Add a strict one-time DMA-session route-validator hook, installable before startup and invoked immediately before a target/memory side effect. Task 3 installs the compiled validator; its admission loop checks the same validator before registering each source admission.
6. Emit `prepared_runtime_paths.v2` and `runtime_path_compilation.v2` only when a DMA route is present; preserve existing v1 documents byte-for-byte otherwise. Readers reject unknown v2 keys and never silently drop the route list.
7. Add unit coverage for v1 byte identity; strict v2 round trip; unknown fields; relation mismatch; missing/ambiguous windows; wrong endpoint; wrong memory resource/service/ledger; permissions/aperture mismatch; topology mutation; range-step identity collisions; tuple-versus-range identity; and refusal of a post-start validator replacement.

**Review gate:** inspect canonical v1 output against existing fixtures and confirm every v2 route is included in prepared, compiled, and topology digests.

## Task 2 — Runtime edge index v2 and route-edge lookups

**Files:**

- Modify `src/myfuzz/scenario/runtime_edge_index.py`
- Modify `tests/scenario/test_runtime_edge_index.py`

**Work:**

1. Continue accepting v1 compilation and contract documents. Accept v2 only as a strict matching pair and validate route rows against the selected prepared edge and compiled topology.
2. Emit `runtime_edge_index.v2` when routes exist; include stable route IDs and edge keys in the detached index document.
3. Expose an exact typed route lookup for source/transfer evidence joins. Do not let `dma_master_route` match generic `causal_order`, `event_order`, MMIO, or direct-binding paths.
   The public matcher is `match_dma_master_route(path_id, *, initiator_component, endpoint_id, target_kind, target_component, target_id, base, size, operation, address, byte_enable, transaction_key, value=None)` and returns a detached `DmaMasterRouteMatch` only for a strict selected-edge match.
4. Ensure all topology fields for endpoint/window and RAM resource identity are validated, and v2 digest checks cover them.
5. Add tests for v1 compatibility, v2 valid route, route omitted/tampered, unknown fields, ambiguous routes, wrong selected edge, wrong topology identity, and no causal-order fallback.

**Review gate:** independently compare the index route lookup result against the contract edge key, route digest, and topology digest.

## Task 3 — UART S4 graph and per-beat source/target joins

**Files:**

- Modify `src/myfuzz/scenario/dma_runtime_paths.py`
- Modify `src/myfuzz/scenario/uart_consumption.py`
- Modify `src/myfuzz/integration/dma_uart_descriptor_runtime.py`
- Modify `tests/scenario/test_dma_runtime_paths.py`
- Modify `tests/scenario/test_uart_consumption_dma_master.py`
- Modify `tests/integration/test_dma_source_authority.py`
- Modify `tests/integration/test_dma_prefix_replay.py` only if an existing replay assertion requires the v2 identity

**Work:**

1. Replace the UART route's `causal_order` declaration with explicit UART-read and RAM-write route edges, retaining the separate CPU descriptor-pop → DMA ordering edge and the persistent-memory declaration. Use separate nodes/rules so data-flow direction is explicit: UART FIFO entry → UART master RDATA operation → DMA receive; CPU descriptor pop and DMA receive are both prerequisites to the DMA-pop state; DMA write payload → RAM master-write operation → persistent commit.
2. Emit `dma_runtime_paths.v2` and DMA source-provenance v2 only for the migrated path. The UART route adapter must use the shared route contract and exact compiled route lookup.
3. Preserve one exact `TransactionKey` from each accepted DMA beat through the matching real UART/RAM operation and single response. Read and write use distinct adjacent keys with matching execution/case/source/epoch/channel identity; join the exact read value to the RAM write and real memory version event.
4. Recheck compiled topology immediately before the UART pop and before the RAM mutation. Do not claim service commit authority unless an enabled commit stream is independently joined.
5. Preserve S3 invalid-target behavior: issue the real invalid request, record the native error response, prove the target had no side effect, and issue no success route/transfer certificate.
6. Keep UART source admission, FIFO-retention/pop proof, error ISR evidence, and source-authenticated typed-prefix replay requirements intact.
7. Add focused tests for request/target/response exact-key joins, missing or duplicate response, key mismatch, reordered/mismatched read-write pair, target error/no side effect, missing memory version, mismatched byte, and positive UART→RAM route.

**Review gate:** inspect emitted S4 graph to ensure the bus initiator is recorded separately from data-flow edge direction and CPU FIFO ordering remains a distinct relation.

## Task 4 — Saved-plan and fresh-replay reader compatibility

**Files:**

- Modify `src/myfuzz/scenario/session_runtime.py`
- Modify `src/myfuzz/integration/scenario_rfuzz_live.py`
- Modify `src/myfuzz/integration/scenario_rfuzz.py`
- Modify existing relevant replay tests under `tests/scenario/` and `tests/integration/` without overlapping Task 2 or Task 3 test files

**Work:**

1. Audit every decode, freeze, fresh-normalize, and digest check for prepared paths, compiled topology, and runtime edge index.
2. Accept historical v1 byte forms. For v2, preserve the entire route declaration and v2 identity in saved plans and fresh-run construction; reject route omission or unknown fields.
3. Ensure fresh replay compiles against independent Runner/session/memory/window owners while requiring route declarations, selected edge identities, target window/resource identities, and proof scope to match the saved run.
4. Add regression coverage for historical v1 saved plans and v2 route-bearing positive/negative replay documents.

**Review gate:** enumerate each replay reader and show that a v2 DMA route cannot disappear between saved plan parse, fresh compile, index construction, and replay comparison.

## Task 5 — Local integration, report, and gated remote S4 evidence

**Files:**

- Modify `docs/CURRENT_PROGRESS.md`
- Modify `docs/LOCAL_HARNESS_RUNTIME.md`
- Modify `docs/reports/README.md`
- Create/update `docs/reports/dma-master-route-contract-20261019.md`
- If the reviewed local gates pass, create remote operation/evidence only under `/root/fanzehui/myfuzz/operations/<new-operation>/` and `/root/fanzehui/myfuzz/evidence/<new-evidence>/`

**Work:**

1. Run scoped unit/integration gates from Tasks 1–4, plus the existing S4 native profile check, only after the code review gates are complete.
2. Do not reuse prior S4 evidence as proof for the new v2 route identity. Freeze the new tree/config/tool identity.
3. On the remote server, verify each operation/evidence path is under `/root/fanzehui/myfuzz/` before writing. Run a new native positive S4, a controlled target/route failure, and an independent fresh-prefix replay; preserve all failed attempts.
4. Record declared, topology-bound, runtime-observed, and replay-verified states separately. Do not report P6/P7/P8 completion; explicitly retain P7 F6 as unsupported and the other three IP provider adapters as open.
5. Update progress documents with exact artifacts, commands, exit codes, and limits. Do not alter existing frozen gates or claim decode/retirement/global timing.

## Acceptance evidence checklist

- [x] v1 contract/prepared/compilation/index documents remain canonical and readable.
- [x] v2 route contracts are strict, topology-bound, and included in every digest and replay path.
- [x] Endpoint/window/RAM resource identity and permissions fail closed, including post-compile mutation.
- [x] Per-beat UART and RAM effects join to exact DMA request/response identities; transfer-level keys remain distinct and values match.
- [x] S3 real error/no-side-effect path remains intact and cannot create a successful transfer claim; the new S4 run also exercises two measured illegal target requests.
- [x] New real S4 positive run, controlled failure, and independent fresh replay are reported with fresh identities.
- [x] P7 F6 remains unsupported; PULP, ZipCPU UART, and Caliptra DMA adapters remain explicitly open.

## Follow-up status (2026-10-20)

The initial acceptance checklist above records the 2026-10-19 route-contract
delivery. Since then, PULP APB3 GPIO, Caliptra AHB-Lite, and ZipCPU UART TXREG
each have separate bounded local DMA target implementations and native
reports: [PULP](../../reports/pulp-apb3-dma-target-20261020.md),
[Caliptra](../../reports/caliptra-ahb-dma-target-20261020.md), and
[ZipCPU UART](../../reports/zipcpu-uart-dma-target-20261020.md). The tracked
local target consumers in this follow-up set have passed their bounded gates.
P7 F6 stays unsupported; these results do not assert a physical
interconnect, CPU consumption/retirement, continuous fuzzing or P6/P7/P8
completion.
