# Caliptra Protocol-Neutral DMA Route Consumption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consume the existing D4-bound, protocol-neutral DMA route admission on the real Caliptra SHA256 AHB-Lite target path and preserve positive, fresh, refusal, and topology-binding evidence.

**Architecture:** Keep `CaliptraSha256DmaBeatAdmission` as the one-word Caliptra behavior policy and wrap it with `DmaMasterRouteAdmission` built from the exact D4-bound read and write routes. Build the native fixture from generated CPU and linked DMA artifacts over one shared RAM, prepare D2/D3 using the same RAM aperture, bind the same prepared contract once, then verify native RAM and AHB transactions independently by their typed transaction keys.

**Tech Stack:** Python 3, pytest, generated local CPU/DMA/AHB-Lite sessions, `PersistentMemory`, D2/D3 route-intent compilation, D4 topology binding, gzip JSON evidence.

## Global Constraints

- Keep the D2/D3 route rows and default helper geometry unchanged: RAM defaults remain base `0x1000`, size `0x1000`; ROM base is `max(0x10000, ram_base + ram_size)`.
- For the native fixture, D2 route, D3 wiring, `PersistentMemory`, prepared route, and live RAM geometry all equal base `0x10000`, size `0x20000`; source address remains `0x10100`.
- Bind the exact prepared graph object exactly once per execution; do not call `compile_caliptra_sha256_dma_runtime_paths` in the D4 native fixture because that legacy helper binds and installs policy itself.
- The generated DMA artifact's `endpoint_links_document()` and generated CPU artifact/session must own the exact route identities; all executions use one shared `PersistentMemory` object.
- The selected routes are `(0, 0)` RAM read and `(2, 0)` Caliptra `CTRL` write. `DmaMasterRouteAdmission` runs topology matching before delegating to the existing Caliptra beat policy.
- Join each D4 route match and keyed service completion to the matching native Wishbone response separately; a policy `completed()` callback alone does not prove a native response.
- The native test records Caliptra policy completion callbacks through a test-only subclass that delegates to `CaliptraSha256DmaBeatAdmission.completed()` before serializing the typed key; it does not change production admission behavior or identity.
- The refusal destination is in-window `CTRL+4`. Require the exact failure `DMA route match does not exactly match the selected route`, policy state `expect_write`, only the RAM-read route in admission evidence, no Caliptra provider receipt, and unchanged AHB ticks. Do not mutate or shadow the sealed provider method to count calls.
- Limit the refusal side-effect statement to the rejected DMA write; RAM preload and SHA block setup occur earlier and are outside that assertion.
- Keep F6 `unsupported`, add no D2/D3 DMA transfer edge, and make no claim of a physical Wishbone-to-AHB bridge, CPU programming/retirement, multiword DMA, arbitrary AHB support, P7-E, or full P6/P7/P8 / six-CPU/four-IP completion.
- Save the new native evidence separately from Caliptra attempt7 and prior D4 software-only evidence.

---

### Task 1: Parameterize Caliptra D2/D3 RAM geometry

**Files:**
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py`
- Test: `tests/integration/test_p7b_p7c_dma_route_intent.py`

**Interfaces:**
- `_generate_caliptra_sha256_dma_route_d2_d3(tmp_path: Path, *, ram_base: int = 0x1000, ram_size: int = 0x1000)` returns the same `(d2_wiring, request, compiled)` tuple as today.
- The D2 `route.ram-read`, D2 memory resource `ram`, and D3 wiring retain the exact supplied `ram_base`/`ram_size`; ROM starts at `max(0x10000, ram_base + ram_size)`.

- [x] **Step 1: Add a regression for default and native-sized RAM geometry**

Add a focused test which calls the helper once with defaults and once with `ram_base=0x10000, ram_size=0x20000`. Read D2 resources from `d2_wiring['resources']` and D3 resources from `request.wiring.document['resources']`. Assert that the default D2 route and `ram` resource remain `0x1000/0x1000`; assert that the native D2 route, D2 resource, and D3 resource all use `0x10000/0x20000`; assert ROM starts at `0x30000`; and assert F6 remains `unsupported` with no runtime `DMA_MASTER_TRANSFER` edge in either compiled result.

- [x] **Step 2: Run the focused test and resolve the generated resource schema**

Run: `PYTHONPATH=src pytest -q tests/integration/test_p7b_p7c_dma_route_intent.py -k caliptra_ram_geometry`

The first attempt exposed that generated D2/D3 memory rows are under `resources`, not `memory`; after correcting those field paths, the focused regression passed. The final test checks that native geometry is carried through D2 and D3.

- [x] **Step 3: Parameterize only the helper's existing geometry fields**

Add keyword-only `ram_base` and `ram_size` defaults. Use them in the RAM route row, memory resource row, and ROM base calculation. Preserve all route IDs, endpoint/template fields, defaults, and return shape.

- [x] **Step 4: Re-run the focused geometry regression and D2/D3/D4 Caliptra software gate**

Run: `PYTHONPATH=src pytest -q tests/integration/test_p7b_p7c_dma_route_intent.py -k 'caliptra_ram_geometry or caliptra_ahb_d2_d3_route_binds_existing_typed_topology'`

Expected: PASS; the default route digest inputs remain unchanged and the native geometry compiles without enabling F6.

---

### Task 2: Exercise Caliptra policy through D4 route admission

**Files:**
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py`
- Test: `tests/integration/test_p7b_p7c_dma_route_intent.py`

**Interfaces:**
- Extend `test_caliptra_ahb_d2_d3_route_binds_existing_typed_topology` after it binds the exact `paths.prepared` object and before provider-drift mutations.
- `prepare_caliptra_sha256_dma_runtime_paths(...)` intentionally returns `admission=None`; construct the existing `CaliptraSha256DmaBeatAdmission(image_address=paths.image_address, window=window)` after topology binding, then use that object, `paths.path_id`, the exact `read_route` and `write_route` from `paths.prepared.contract.dma_master_routes`, and the existing `bound`.

- [x] **Step 1: Add a D4 composition regression with keyed read and write completion**

Construct `CaliptraSha256DmaBeatAdmission(image_address=paths.image_address, window=window)`, then construct `DmaMasterRouteAdmission(policy, bound, path_id=paths.path_id, read_route=read_route, write_route=write_route)`. Start a case with two distinct `TransactionKey` objects. Admit the declared source read and complete it with `SHA_CTRL_START_VALUE`; assert `expect_write`. Attempt `completed()` using a different key and assert the generic gate rejects it without changing policy state or route rows. Attempt `CTRL+4` using the write key and exact full-word value; assert the exact error `DMA route match does not exactly match the selected route`, policy state remains `expect_write`, and only `(0, 0)` remains in `route_matches`. Then admit the exact `CTRL` write with `target is window`, complete it using the same key, and assert `complete` plus route keys `(0, 0)` and `(2, 0)`.

- [x] **Step 2: Run the Caliptra D4 software regression**

Run: `PYTHONPATH=src pytest -q tests/integration/test_p7b_p7c_dma_route_intent.py -k caliptra_ahb_d2_d3_route_binds_existing_typed_topology`

Expected: PASS. This is a characterization test for the already implemented generic admission and Caliptra beat policy; no production API change is expected.

- [x] **Step 3: Check that the test uses live D4 and Caliptra objects**

Keep all existing provider identity mutation tests intact. Confirm that the test uses the actual `bound` route matcher and Caliptra beat policy, not a fake topology or mock matcher.

- [x] **Step 4: Re-run the focused Caliptra D4 test after finalizing the assertions**

Run: `pytest -q tests/integration/test_p7b_p7c_dma_route_intent.py -k caliptra_ahb_d2_d3_route_binds_existing_typed_topology`

Expected: PASS; wrong key and `CTRL+4` do not reach or advance the Caliptra policy, while the two selected route keys complete in order.

---

### Task 3: Consume Caliptra routes in the native D4 gate

**Files:**
- Modify: `tests/integration/test_dma_caliptra_sha256_real.py`
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py` only if the existing D4 declaration needs a narrowly scoped test helper adjustment.
- Test: `tests/integration/test_dma_caliptra_sha256_real.py`

**Interfaces:**
- `_make_pair(cache_dir, d3_wiring)` returns the native DMA and Caliptra sessions, shared memory, prepared/compiled paths, generated Caliptra artifact, and a D4 evidence document.
- A test-only `_ObservedCaliptraSha256DmaBeatAdmission` subclass delegates `begin_case` and `completed` to the base Caliptra policy; it records successful completion keys and values only after the base callback accepts them.
- Each run generates `issued = generated_instance('dma')`; uses `issued.artifact` for `GeneratedWishboneDmaSession`; sets `artifact_links = {'dma': issued.endpoint_links_document()}`; creates generated Ibex owner `GeneratedLocalSession(_local_artifact(CPU_PROFILE, 'cpu'))`; and attaches the same memory object to the CPU owner and DMA session.
- Use `prepare_caliptra_sha256_dma_runtime_paths(...)`, `_caliptra_d4_declaration(d3_wiring, paths.prepared, artifact_links)`, and `bind_dma_intent_topology(...)`; spy on `PreparedRuntimePathContract.bind` to prove the exact prepared object is bound once.
- Construct `DmaMasterRouteAdmission(observed_policy, bound, path_id=paths.path_id, read_route=..., write_route=...)` from the exact prepared routes and install it with `dma.configure_dma_route_admission(admission)`. Since the pure prepare API deliberately returns `admission=None`, place the constructed observed policy and D4 compilation into the returned dataclass with `dataclasses.replace` before calling `paths.document()`.

- [x] **Step 1: Add the test-only completion-key observer and refactor the fixture to D4**

Add the observer subclass without changing `CaliptraSha256DmaBeatAdmission` production code. Replace the fake CPU `SimpleNamespace` and unlinked DMA artifact with the generated CPU session and linked DMA artifact. Generate D2/D3 with the native RAM base/size, create RAM once, give the same memory to CPU and DMA, and create the generated Caliptra AHB session/window. Prepare paths without binding, D4-bind that exact prepared object once, instantiate the observer with `paths.image_address` and `window`, place the bound compilation and observer into `paths` using `dataclasses.replace`, install the generic admission around the observed Caliptra policy, and retain the binding document plus bind-count proof.

- [x] **Step 2: Make positive execution join exact route matches, service events, provider effects, and native responses**

In `_run_one`, capture the generic admission's detached `route_matches` and the observed base-policy completion receipts. Require route keys `(0, 0)` and `(2, 0)`, exact source/destination address and operation, and matching typed transaction documents for each `dma.events` accepted row. Independently require the RAM read's `memory_read` and base-policy completion under its key plus successful native Wishbone response under that key. Require the CTRL write's AHB provider receipt/request-data response and base-policy completion under its key plus successful native Wishbone response under that key. Preserve final SHA status and `sha256(b'abc')` digest checks.

- [x] **Step 3: Remove the provider-method wrapper from the refusal run**

Keep observing the native `STEP_WB_DMA` pre-backend request by wrapping only `dma.command`; do not replace `sha.dma_master_target_access`. Run the actual `CTRL+4` write, capture the exact D4 matcher refusal, and require `expect_write`, one RAM-read route match only, one matching read-completion callback only, no write match, no AHB provider receipt, and unchanged AHB ticks. Exclude source preload and SHA input setup from the rejected-write no-effect assertion.

- [x] **Step 4: Exercise the native opt-in gate with isolated cache and evidence output**

Run:

```bash
PYTHONPATH=src \
MYFUZZ_DMA_CALIPTRA_REAL=1 \
MYFUZZ_DMA_CALIPTRA_CACHE=/tmp/myfuzz-caliptra-d4-cache-20261021 \
MYFUZZ_DMA_CALIPTRA_EVIDENCE=docs/reports/evidence/p7-d4-caliptra-generic-route-consumption-20261021 \
pytest -q tests/integration/test_dma_caliptra_sha256_real.py
```

Expected: PASS for positive, independent fresh replay, and in-window refusal. The gate writes `descriptor.json.gz`, `fresh.json.gz`, and `native-refusal.json.gz` into the new evidence directory.

- [x] **Step 5: Run focused policy, route-binding, and neighboring native regression gates**

Run:

```bash
PYTHONPATH=src pytest -q tests/scenario/test_caliptra_sha256_dma_paths.py tests/scenario/test_dma_route_admission.py tests/integration/test_p7b_p7c_dma_route_intent.py
```

Then rerun the opt-in Caliptra native command from Step 4 after any fixes. Expected: all focused software gates pass and the saved fresh normalized executions are equal.

---

### Task 4: Record D4 native evidence and update status indexes

**Files:**
- Create: `docs/reports/p7-d4-caliptra-protocol-neutral-dma-route-consumption-20261021.md`
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/reports/README.md`
- Modify: `docs/superpowers/plans/README.md`
- Modify: `docs/superpowers/plans/2026-10-21-protocol-neutral-dma-route-admission.md`
- Modify: this plan's task checkboxes after review.
- Evidence: `docs/reports/evidence/p7-d4-caliptra-generic-route-consumption-20261021/`

**Interfaces:**
- The report cites exact command output, gate counts and durations, D4 binding and bind-once evidence, route match key joins, native response key joins, fresh normalized equality, refusal details, evidence file names, and scope boundaries.
- Progress and indexes link the report and keep Caliptra attempt7 / earlier software-only D4 evidence separate.

- [x] **Step 1: Inspect the saved JSON evidence before drafting claims**

Read `descriptor.json.gz`, `fresh.json.gz`, and `native-refusal.json.gz`; verify the two route keys, same-key service and native response joins, SHA KAT, binding tier, exact prepared-object bind count, and refusal observations directly from the saved records.

- [x] **Step 2: Write the slice report and update progress/indexes**

State only observations present in saved evidence. Record exact test command/count/duration, same prepared-object bind-once proof, exact read/write route hashes and transaction keys, AHB provider/request-data evidence, separate native Wishbone response joins, fresh equality, exact refusal string and policy state, and the exclusions in Global Constraints.

- [x] **Step 3: Run documentation consistency checks**

Run: `git diff --check -- docs/CURRENT_PROGRESS.md docs/reports/README.md docs/superpowers/plans/README.md docs/superpowers/plans/2026-10-21-protocol-neutral-dma-route-admission.md docs/reports/p7-d4-caliptra-protocol-neutral-dma-route-consumption-20261021.md`

Expected: no whitespace errors, no evidence path points to attempt7, and every new status line preserves F6/P7-E/overall scope limits.

---

## Final Review Gate

- [x] Run `PYTHONPATH=src python3 -m py_compile tests/integration/test_dma_caliptra_sha256_real.py tests/integration/test_p7b_p7c_dma_route_intent.py` (exit 0).
- [x] Run `git diff --check` on touched tracked documentation and a scoped trailing-whitespace check across all nine source, test, report, plan, index, and progress files; no whitespace errors.
- [x] Review only this slice's implementation, evidence, and documentation; preserve unrelated dirty worktree files. Independent native implementation review approved with no findings.
- [x] Confirm report text limits its claim to bounded single-word process-level composition and explicitly excludes physical bridge, CPU consumption/retirement, F6, P7-E, and full-system completion.

