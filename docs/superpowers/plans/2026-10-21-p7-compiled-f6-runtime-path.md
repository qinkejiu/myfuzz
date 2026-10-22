# P7 compiled F6 runtime path implementation plan

> **Status (2026-10-21):** Task 2 coverage follow-up and Task 3 bounded native gate are complete. The final six-file software gate passed **201 tests, 0 skipped／378.04s**; the local native positive/refusal/fresh gate passed **1 test／73.87s**. Independent code/evidence and final test reviews are APPROVED. Coverage includes a real D3 multi-mover ambiguity refusal, a multi-target route mismatch before graph construction, write-operation and in-aperture source drift, both detached D4 binder spies, and compatibility API delegation. Static/general F6 remains unsupported. Preserve the shared dirty worktree; do not stage, commit, reset, clean, or run remote operations in this documentation slice.

**Goal:** Compile one Caliptra RAM-word-to-`CTRL=5` runtime path from the exact P7-C static refusal, explicit D2/D3 route pairing, and live endpoint topology.

**Architecture:** Add a closed `compiled_f6_runtime_path.v1` after D3 and after a live Runner exists. Generate its graph with the existing dependency/runtime contract types, build the existing route-intent declaration and F6 handoff from that exact prepared graph, and bind the same object once through D4. Keep `compiled_paths.v1` F6 unsupported and edge-free.

**Tech Stack:** Python 3 frozen dataclasses, canonical JSON/SHA256, `DmaMasterRouteIntent`, `DependencyGraph`, `RuntimePathContract`, the current DMA intent binder, Caliptra AHB-Lite native fixture, pytest.

**Design:** [P7 compiled F6 runtime-path spec](../specs/2026-10-21-p7-compiled-f6-runtime-path-design.md).

Task 1 wire-format details are defined in the spec's “exact closed wire
shape” section. It nests the full `compiled_f6_dma_handoff.v1` so its existing
reader can validate the D3 static refusal, compiled digest, wiring identity,
prepared graph/contract and D4 route-link bijection. The outer runtime-path
digest excludes only its own `identity_sha256`; the D3 result digest must use
`compiled_document_sha256()`.

## Global Constraints

- Keep D3 `compiled_paths.v1` F6 `unsupported` with `dma-route-live-topology-binding-required` and null runtime identity.
- Emit no static `DMA_MASTER_TRANSFER` rule/edge; the new versioned artifact is post-live and separate.
- Support only one explicit RAM word-read / Caliptra SHA256 CTRL write pair in this slice.
- Select routes by explicit route ID and operation; never infer them from names, addresses, tuple order, or first-match behavior.
- Reuse the existing `DmaMasterRouteContract`, `RuntimePathContract`, topology binder and beat admission; keep the exact prepared object through one D4 bind.
- Fresh replay rebuilds the runtime artifact and live bind from independent owners; it does not reuse bound credentials.
- Preserve all unrelated dirty/untracked files; no staging, commit, reset, cleanup, or remote work.
- Do not claim CPU programming/retirement, IRQ/ISR, physical bus bridge, multiword DMA, arbitrary F6, P7-E, or overall P6/P7/P8 completion.

## File map

| File | Responsibility |
|---|---|
| `src/myfuzz/scenario/compiled_f6_runtime_path.py` | Closed source/pair descriptors, runtime-path artifact, compiler and one-bind wrapper |
| `src/myfuzz/scenario/caliptra_sha256_dma_paths.py` | Retain target/provider-specific identity extraction and beat policy; delegate graph construction to the runtime compiler |
| `tests/scenario/test_compiled_f6_runtime_path.py` | Descriptor, graph, route bijection, digest and refusal tests |
| `tests/scenario/test_caliptra_sha256_dma_paths.py` | Keep the existing Caliptra route/admission regressions on the shared graph builder |
| `tests/integration/test_dma_caliptra_sha256_real.py` | Prove compiler-produced path, same-object D4 bind, native positive/refusal/fresh evidence |
| `docs/reports/p7-f6-runtime-path-caliptra-20261021.md` | Exact software/native evidence and limits |
| `docs/CURRENT_PROGRESS.md`, `docs/reports/README.md`, `docs/superpowers/plans/README.md` | Index the bounded result and keep F6/global status accurate |

## Task 1: closed descriptors and runtime artifact

**Files:** create `src/myfuzz/scenario/compiled_f6_runtime_path.py` and `tests/scenario/test_compiled_f6_runtime_path.py`.

**Interfaces:**

- `DmaTransferSourceWord.from_document(document)` parses the closed `dma_transfer_source_word.v1` descriptor; `document()` returns a detached canonical JSON value.
- `DmaTransferRoutePair.from_document(document)` parses the closed `dma_transfer_route_pair.v1` pair with `relation="same_word_value"`.
- `CompiledF6RuntimePath.from_document(document)` parses the exact outer keys `schema_version`, `source`, `transfer_pair`, `compiled_f6_handoff`, and `identity_sha256`; `compiled_f6_handoff` is the complete existing `compiled_f6_dma_handoff.v1` document. Its reader validates the embedded D3 identity/static refusal, wiring digests, prepared graph and contract, and complete route-link mapping.
- `CompiledF6RuntimePath.identity_sha256` is SHA256 over sorted-key compact UTF-8 JSON with non-finite numbers rejected, computed after removing only the outer `identity_sha256` key. The nested D3 digest is validated by the existing `compiled_document_sha256()` implementation.
- The exact source keys are `schema_version`, `memory_component`, `resource_id`, `image_id`, `address`, `word_bytes`, `byte_enable`, and `direction`. The reader requires nonempty trimmed identities, a nonnegative four-byte-aligned unsigned-64-bit `address`, `word_bytes=4`, `byte_enable=15`, and `direction="CPU_TO_IP"`. Region membership is checked later against the static read route and live memory.
- The exact route-pair keys are `schema_version`, `read_route_id`, `write_route_id`, and `relation`; IDs are nonempty and distinct, and relation is exactly `same_word_value`.
- The artifact reader requires exactly two D2/D3 route intents: the paired read route targets the source's persistent-memory component/resource and contains its address range; the paired write route is `sha256.bus` on Caliptra instance/device `sha`, operation `write`, byte-enable 15, writable offset `[16]`, and accepted value `[5]`. Both use the same initiator. The D4 declaration maps the read route to edge `(0, 0)` and write route to `(2, 0)`.
- The embedded prepared graph is exactly one source `ram.source_word`, nodes `dma.read_data`, `dma.write_data`, and `sha.ctrl_start_effect`, and three ordered rules: `(0) DMA_MASTER_TRANSFER` from the RAM source to DMA read data, `(1) EVENT_ORDER` from read data to write data, `(2) DMA_MASTER_TRANSFER` from DMA write data to SHA CTRL effect. The runtime contract has `dma_master_route`, `causal_order`, and `dma_master_route` relations at `(0, 0)`, `(1, 0)`, and `(2, 0)` respectively. The selected path is direction `CPU_TO_IP`, target `sha.ctrl_start_effect`, and source `ram.source_word`.
- The detached reader validates the complete typed route policy and canonical route hashes but does not claim the embedded endpoint/target identity hashes are independently authentic. Live preparation derives them from the exact runner endpoint, memory, window and provider; the existing D4 binder and topology guard recompute and compare them against those live owners.

- [x] Write tests for valid source/pair descriptors and reject missing/unknown fields, wrong integer types, unaligned/overflowing addresses, non-four-byte width, non-full byte enable, direction other than `CPU_TO_IP`, duplicate IDs, identical read/write IDs, and any relation other than `same_word_value`. Region membership is not a detached-descriptor check; test it in Task 2 against the route and live memory.
- [x] Write artifact reader tests for outer digest tampering, changed nested D3 digest/identity, changed F6 status/reason, unexpected static DMA edges, malformed prepared graph/runtime contract, route-edge omissions/duplicates, wrong explicit read/write edge mapping, and noncanonical serialized route-link order.
- [x] Run `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py`; confirm intended schema/refusal failures before implementation.
- [x] Implement frozen descriptor/artifact types and strict closed readers; round-trip through the existing `RuntimePathContract` reader and canonical digest helper.
- [x] Rerun the focused command; all accepted schema cases pass and every malformed case fails with a stable refusal code/pointer.

## Task 2: live graph compiler and Caliptra integration

**Files:** modify `src/myfuzz/scenario/compiled_f6_runtime_path.py`, `src/myfuzz/scenario/caliptra_sha256_dma_paths.py`, `tests/scenario/test_compiled_f6_runtime_path.py`, and `tests/integration/test_dma_caliptra_sha256_real.py`.

**Interfaces:**

- `prepare_compiled_f6_runtime_path(compiled_paths, wiring, runner, *, source, transfer_pair, artifact_links)` returns one immutable `CompiledF6RuntimePath` retaining the exact `PreparedRuntimePathContract` used by D4.
- `bind_compiled_f6_runtime_path(path, runner, *, artifact_links)` delegates exactly once to `bind_compiled_f6_dma_handoff(path.handoff, ...)` and returns a bound runtime path that validates the graph, route links and live topology before each route lookup.
- `compiled_paths` is the complete D3 document mapping. `wiring` is the normalized `PathWiring` that produced that document; before graph construction, require its route-intent and binding digests/documents to match `compiled_paths.identity.wiring` and the D3 refusal's route set.
- `CompiledF6RuntimePath.from_document()` returns a detached artifact and must not be bindable. The live preparation factory creates a distinct in-memory prepared instance with a private provenance marker tied by object identity to the retained `PreparedRuntimePathContract`; the bind API rejects deserialized or directly constructed artifacts without that provenance.
- Move the live Caliptra route-facts validation currently in `caliptra_sha256_dma_paths._route_declarations()` into `compiled_f6_runtime_path.py` (or a lower-level module imported by both). Preserve its exact shared `MemoryService`/ledger/`PersistentMemory` owner check, canonical readable RAM region, unique DMA window, registered SHA endpoint object, provider identity and method checks, AHB-Lite trace, and full-word CTRL policy. `caliptra_sha256_dma_paths.py` must delegate to the shared helper; the new module must not import `caliptra_sha256_dma_paths.py`, avoiding a cycle.
- Put the sole Caliptra graph/contract/selection builder in `compiled_f6_runtime_path.py`. Both `prepare_compiled_f6_runtime_path()` and the legacy `prepare_caliptra_sha256_dma_runtime_paths()` call this builder. The runtime compiler builds the `PreparedRuntimePathContract` itself and carries that exact object through `prepare_dma_intent_binding()`, `prepare_compiled_f6_dma_handoff()`, and one D4 bind.

The compiler reads the two static intents by the explicit IDs in
`transfer_pair`; it must not call test helper `_unique_dma_intent_route_map()`
or choose routes by policy-first matching. It builds exactly these route links:
`read_route_id -> (rule_index=0, prerequisite_index=0)` and
`write_route_id -> (rule_index=2, prerequisite_index=0)`, each carrying the
typed runtime-route digest and the existing explicit artifact endpoint-link
record. `prepare_dma_intent_binding()` validates the full static-to-runtime
bijection. Preserve the live checks in
`caliptra_sha256_dma_paths._route_declarations()` for the exact shared memory
service/owner, canonical readable region, DMA window, Caliptra endpoint
object, provider identity, trace, full-word CTRL policy, and artifact owner;
separate those live facts from graph construction. The new compiler must
generate the graph and `PreparedRuntimePathContract` itself, not call the old
manual graph factory and wrap its result. Pass the same prepared object through
`prepare_dma_intent_binding()`, `prepare_compiled_f6_dma_handoff()`, and one
`bind_compiled_f6_dma_handoff()` call. A handoff restored only from serialized
bytes is detached and cannot satisfy the live same-object bind requirement.

- [x] Add synthetic live-runner tests for valid RAM-read→target-write generation, reversed input route-intent tuple order producing the same artifact, missing/extra/duplicate routes, multiple movers/targets, route operation mismatch, source component/resource/address/out-of-region drift, endpoint-link alias/physical-owner mismatch, DMA master endpoint identity drift, target-window/provider identity mismatch, and same-prepared-object one-bind behavior. In the positive spy, prove `bind_compiled_f6_dma_handoff()` is called exactly once and its single `PreparedRuntimePathContract.bind()` receives the same object retained by both the runtime path and handoff.
- [x] Add source/route-binding drift negatives: mutate the D3 route-binding identity, explicit route IDs, read/write operation, RAM owner and address both inside and outside the declared canonical region; each must refuse before live bind. Reversed tuple order must still map the explicit read ID to `(0,0)` and write ID to `(2,0)`.
- [x] Preserve and exercise Caliptra live-fact refusal cases for mismatched shared `MemoryService`/`PersistentMemory`/ledger owners, wrong CPU memory owner, missing/duplicate/unreadable RAM region, invalid DMA target tuple/window, wrong registered SHA endpoint, missing provider methods, provider identity drift, invalid AHB-Lite trace, and `CTRL` byte-enable/readable-offset/writable-offset/accepted-value drift. Exercise artifact-link owner/provider/physical-link mismatches through the D4 bind.
- [x] Add detached-provenance negatives: `from_document(compiler-produced-artifact)` can round-trip but `bind_compiled_f6_runtime_path()` refuses before either D4 binder spy; direct constructors cannot mint bindable provenance.
- [x] Compare supplied `PathWiring` against the full D3 route-intent and binding identity before constructing any runtime object; malformed/mismatched D3 or wiring inputs must fail before topology binding.
- [x] Keep `_route_declarations()` compatible as a delegating alias if current tests/importers use it; preserve current `prepare_caliptra_sha256_dma_runtime_paths()` / `compile_caliptra_sha256_dma_runtime_paths()` callers and prove those compatibility APIs use the single graph builder. Exercise every listed live-owner/provider/trace/window refusal after moving it.
- [x] Replace Caliptra's local `DependencyGraph`/nodes/edges construction with the new compiler; retain only Caliptra provider identity validation and its existing single-word `CTRL=5` beat policy.
- [x] In the integration helper, construct `DmaMasterRouteAdmission` using the explicit `transfer_pair` IDs and their compiled runtime edges; do not use `_select_dma_read_write_routes()` or another policy-first selector.
- [x] For live-fact refusal tests, construct or expose the Runner before any compatibility helper prepares a graph; ensure each source descriptor and D3 wiring use the same RAM region/address being mutated so an earlier fixture rejection cannot mask the intended check.
- [x] Keep `prepare_caliptra_sha256_dma_runtime_paths()` and `compile_caliptra_sha256_dma_runtime_paths()` compatible for their existing software callers, but make them call the same graph builder in `compiled_f6_runtime_path.py`; do not leave a second manual node/rule/edge construction in the Caliptra module. Run `PYTHONPATH=src pytest -q tests/scenario/test_caliptra_sha256_dma_paths.py` after the refactor.
- [x] Keep the static D3 handoff test proving F6 remains unsupported and its static document has no DMA transfer rule/edge or runtime routes.
- [x] Run `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_dma_route_admission.py tests/scenario/test_caliptra_sha256_dma_paths.py tests/integration/test_p7b_p7c_dma_route_intent.py`; final result: 201 passed, 0 skipped, 378.04s.
- [x] Require the actual D3 compiler output and live Caliptra fixture to produce `compiled_f6_runtime_path.v1`; the bound wrapper must contain the same prepared graph object and report one bind.

## Task 3: native positive, refusal, and independent fresh replay

**2026-10-21 progress:** Task 3 local implementation and final code review are
**APPROVED**. After the final evidence-contract change, the focused software
gate passed **196 tests, 0 skipped／336.08s**. After the Task 2 regression
coverage additions, the same six-file gate passed **201 tests, 0 skipped／378.04s**;
the production implementation was unchanged by those test-only additions. The opt-in native gate passed
**1 test／73.87s** in an isolated local cache/evidence directory. An independent
read-only audit of all 27 compressed evidence documents returned **APPROVED**.
The gate covers first positive + separate `CTRL+4` refusal + fresh positive;
it does not rerun the refusal on the fresh Runner. The remote jump host is
reachable but the target returns `No route to host`; the target was untouched.
Exact command, source/result/artifact digests, route joins and limits are in the
[status report](../../reports/p7-f6-runtime-path-caliptra-20261021.md). This
bounded native result does not make static/general F6 supported; P6/P7/P8,
P7-E and the six-CPU/four-IP objective remain open.

Latest SSH preflight (2026-10-21): `jumpserver` was reachable, but the
read-only inner SSH to `root@192.168.5.70` failed with exit 255,
`No route to host`; no target command ran. The local native attempt below was
used to complete this bounded Task 3 gate.
Local read-only feasibility check found the required Verilator/C++/make/ar
tools and 5.1 GiB available RAM; a fresh task-specific evidence/cache path is
available. No local build or native run had started at that check.

**Files:** modify `tests/integration/test_dma_caliptra_sha256_real.py`; write outputs only under `docs/reports/evidence/p7-f6-runtime-path-caliptra-20261021/`.

- [x] Extend the opt-in Caliptra native gate to save the compiler-produced runtime artifact, full D3 result, route pair, D4 handoff/bound wrapper, and the exact prepared-object bind count.
- [x] Invoke the compiler and binder through `_make_pair()` for both the first and fresh positive run; pass each run's own `compiled_paths` and `PathWiring`. Retain the same process-local prepared object from `CompiledF6RuntimePath` through D4.
- [x] Save first/fresh full D3 documents, source and route-pair documents, `compiled_f6_runtime_path.v1`, unbound `compiled_f6_dma_handoff.v1`, bound wrapper, their identity digests, and a per-run bind count / same-object result.
- [x] Require typed transaction evidence that the RAM read returns the declared word and the same value reaches Caliptra `CTRL=5`; preserve the existing SHA256 known-answer assertion.
- [x] Preserve the existing in-window `CTRL+4` refusal before provider dispatch; record zero provider events and no rejected-key effect.
- [x] Make the fresh execution independently rerun D3, rebuild the runtime artifact, build a new handoff, and bind its own new Runner. Require normalized semantic equality and distinct process/session/execution identity.
- [x] Compare versioned D3/runtime-path/handoff identities before any execution normalization. Build a separate event-only semantic projection that normalizes only documented transaction execution fields; do not recursively replace arbitrary `execution_id` keys or substrings in integrity-bound artifacts.
- [x] Record separate first/fresh object and native process identities while both runs are alive; require distinct Runner/session/memory/prepared/handoff objects, distinct native process IDs, and distinct execution IDs. Keep those owner-distinctness fields outside semantic equality.
- [x] Run focused software gates from Task 2 before the native gate.
- [x] Run the opt-in Caliptra native gate with a new task-specific cache and evidence directory; require positive, fresh and refusal branches in one passing invocation.

## Task 4: independent review and documentation

**Files:** create `docs/reports/p7-f6-runtime-path-caliptra-20261021.md`; update current progress and report/plan indexes.

- [x] Record exact commands, exit status, source/result/artifact hashes, route IDs, prepared object bind identity, fresh comparison, and refusal ordering.
- [x] State that static D3 F6 remains unsupported and this artifact only supplies a bounded post-live runtime path for the Caliptra single-word case.
- [x] Obtain independent read-only reviews of the compiler boundary, route/source identity, fresh construction, evidence joins, scope wording, and the Task 2 regression tests; no unresolved concrete findings remain.
- [x] Verify report/index links and run scoped `git diff --check`.
- [x] Preserve unrelated worktree changes and leave the worktree unstaged/uncommitted.

## Completion criteria

The real D3 refusal is consumed by a separately versioned runtime-path compiler; only the explicit RAM-word/Caliptra CTRL pair is accepted; D4 binds the same generated graph exactly once; native positive, pre-provider refusal and independent fresh rebuild/rebind pass; all report boundaries match saved evidence. This does not close static F6, P6, P7-E, P8, or the full six-CPU/four-IP objective.
