# P7-B/P7-C static DMA route intents implementation plan

> **Execution:** Use subagents for independent tasks; preserve all existing shared-worktree changes. Do not stage, clean, reset, or commit.

**Goal:** Carry explicit static DMA master route declarations through P7-B and P7-C while keeping live route identity binding as a later runtime gate.

**Architecture:** Add a closed static `dma_master_route_intent.v1` parser and canonical identity, add `harness_compose.v2` / `wiring_contract.v2` / containing harness-set v2 for route-bearing compositions, and teach P7-C to preserve and validate those rows. Preserve v1 output bytes when no route is present. Keep `RuntimePathContract.v2` and live identity hashes unchanged; F6 remains runtime-unsupported.

## Global constraints

- Follow `/home/qinkejiu/myfuzz/agent.md`; this slice stays local.
- Preserve v1 document bytes and frozen evidence. V1 routes/unknown fields must refuse rather than be ignored.
- Do not infer roles from instance, component, file, protocol, or directory names.
- Resolve endpoint selection from exact declared endpoint IDs, protocol roles, registered template contracts, and explicit route declarations.
- Do not copy static identities into `DmaMasterRouteContract.endpoint_identity_sha256` or `.target_identity_sha256`; only the live Runner binder may derive these.
- A valid static route does not create a runtime graph edge, authorize execution, prove a transfer, or close F6/P7.
- Keep currently declared F6 with no route explicitly `dma-master-route-undeclared`; a validated intent remains `dma-route-live-topology-binding-required` at runtime.

## Task 1 — Static route intent model and tests

Files:

- Create `src/myfuzz/scenario/dma_route_intent.py`.
- Create `tests/scenario/test_dma_route_intent.py`.

Work:

1. Add frozen `DmaMasterRouteIntent` and `parse_dma_master_route_intents(document, pointer=...)` for the closed `dma_master_route_intent.v1` wrapper with the target union, field bounds, permission/offset checks, and no runtime identity fields.
2. Canonicalize rows by `route_id`; expose `DmaMasterRouteIntent.document()`, `identity_sha256`, and `dma_master_route_intents_document(routes)`.
3. Encode accepted values injectively: ordered tuple/list values and exact range `start`/`stop`/`step`.
4. Write tests first and confirm the missing API failures; then implement and run the model tests.

## Task 2 — D2 v2 composition and wiring generation

Files:

- Modify `src/myfuzz/local_harness/harness_set.py`.
- Modify `src/myfuzz/scripts/generate_local_harness_set.py` only if its help/refusal surface needs the new version.
- Modify `tests/local_harness/test_harness_set.py`.

Work:

1. Keep v1 loader/generator output unchanged. Accept strict `harness_compose.v2` only when it carries a nonempty `dma_master_routes` array.
2. Preflight each route's initiator profile/master endpoint, target instance/endpoint or exact memory resource, aperture, permissions, offsets, byte enable, and accepted-value policy before staging/output creation. Resolve from declared endpoint IDs and profile endpoint shape; do not use instance names.
3. Emit `wiring_contract.v2` and `harness_set.v2` with canonical route rows plus a one-to-one `dma_master_route_bindings` section. The input binding explicitly selects registered templates for the route initiator and peripheral target; persistent-memory targets have no target template. V2 CPU/device control rows may explicitly select their control endpoint template. Output fingerprints bind the static profile endpoint or exact memory resource; never label them as live endpoint identities. Retain all existing non-route field values.
4. Add v1 byte-compatibility and v2 route positive/negative tests, including renamed instance identities and no partial output on refusal.

## Task 3 — P7-C strict v2 wiring reader and route preservation

Files:

- Modify `src/myfuzz/scenario/compiled_paths.py`.
- Modify `tests/scenario/test_compiled_paths.py`.
- Modify `tests/integration/test_p7b_to_p7c_chain.py`.

Work:

1. Add immutable `PathWiring.dma_master_routes`; parse `wiring_contract.v2` and `path_wiring.v2` with closed keys while retaining v1 parsing byte-for-byte. Strictly parse and preserve the v2 static binding rows too.
2. Include route sections only for schemas that declare them; do not globally add an absent route section to all v1 identities.
3. Preserve route and static binding rows when request supplements are merged into `PathWiring`; recompute profile-endpoint/resource fingerprints and assert the route digest is unchanged across D2→D3.
4. Verify that any static F6 intent's named mover endpoint is a declared master and is the exact endpoint named by its `transfer` feature operation. Do not infer the first mover/master.
5. Keep route-bearing F6 runtime declaration unsupported with `dma-route-live-topology-binding-required`; keep missing route reason `dma-master-route-undeclared`. Do not emit `DMA_MASTER_TRANSFER` or runtime identity hashes in this slice.

## Task 4 — V2 reader compatibility, integration checks, and report

Files:

- Inspect/update `src/myfuzz/local_harness/generated_artifact_admission.py`.
- Inspect/update `src/myfuzz/scenario/capability_report.py` and `src/myfuzz/local_harness/auto_harness_test.py` where exact versions are checked or route-bearing wiring is read.
- Add focused integration coverage to `tests/integration/test_p7b_to_p7c_chain.py` or a dedicated test.
- Create `docs/reports/p7-d2-d3-static-dma-route-intents-20261020.md`.
- Update `docs/CURRENT_PROGRESS.md`, `docs/reports/README.md`, and plan index.

Work:

1. Inventory version readers; each reader either accepts and preserves v2 or explicitly refuses it. No v1-only reader may silently drop the route array.
2. Test route-bearing D2 output through P7-C supplement merge, while proving F6 has no runtime route and remains unsupported.
3. Run focused software gates, record exact commands/results, update indexes, and preserve current P7/DMA boundaries.

## Completion checklist

- [x] Static model tests pass.
- [x] D2 v1/v2 tests pass; legacy v1 output identity is unchanged.
- [x] D3 route preservation and F6 runtime-unsupported tests pass.
- [x] Relevant v2 readers reject or preserve without dropping route data.
- [x] Focused integration suite passes.
- [x] Report and indexes list exact scope, evidence, and remaining D4/live gaps.
