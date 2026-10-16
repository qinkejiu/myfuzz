# P7 D4 bounded artifact execution + strict semantic refusal

## Delivered boundary

The full D3-to-runtime semantic projection is NOT implemented. D3 consistency never grants execution. This slice delivers (1) actual D2 loaded-object consumption in an explicitly selected continuous runtime, including real CV32E40P/dual GPIO receipts and full fresh replay; (2) auto CLI now forwards its actual D2/D3 inputs rather than regenerating default artifacts; (3) exact semantic-gap inventory and fail-closed execution refusal. These three bounded deliverables address the missing compiled producers and unsupported obligations without granting full D3 execution.

## Production changes

- `local_harness/generated_execution_admission.py`: `select_execution_artifacts` requires explicit scope `loaded_artifacts` to execute exact supplied D2 objects in the already declared fixed runtime. It refuses ANY supplied compiled_inputs in that scope (`compiled-inputs-not-executed`), refuses missing D2 and unknown scopes. Default `compiled_paths` still calls the existing strict D3 gate. `runtime_projection_gaps` inventories each executable path's source, bound input, prerequisite, assertion, seed and constraint pointer as `execution_mapping_undeclared`; every row has runtime_admitted=false. It never upgrades consistency.
- `integration/{ibex,cv32e40p}_pulp_online.py`: explicit generated_execution_scope parameter; exact selected supplied objects go into existing factories. Default and compiled-input behavior remains fail-closed; other legacy callers remain unchanged.
- `local_harness/auto_harness_test.py`: D4 loads/reconstructs exact persisted D2 artifact bytes through the trusted loader, keeps typed D3 request, compiles once, derives actual ownership from the explicitly selected wiring declaration, and maps physical CPU IRQ by declared endpoint/role and other fields by exact physical input declaration. No profile-name semantic guess. It passes these objects to run_live_session, which always requires D3 execution projection BEFORE startup. Missing D2/D3 cannot silently run family defaults. CLI does not expose loaded-artifacts scope as a bypass.

No renderer/driver/template/header/build/session/source-lock modifications were made by this slice. generated_execution_admission.py was frozen when parent requested Vexii source stability.

## Concrete D3 refusals

Actual generated CV32E40P dual-GPIO composition gives:
- ownership-bound-producer-not-admitted at `/ownership/owners/0` (actual CPU IRQ producer)
- ownership-bound-producer-not-admitted at `/ownership/owners/2` (physical bound GPIO producer)
- ownership-source-uncompiled at `/ownership/owners/3` (actual external pin source absent from D3 wiring)

D2 compose/wiring currently carries windows/resources but does not declare the fixed factory's output-to-input and IRQ delivery/source graph. Those cannot be invented from profile names or from D3-compatible metadata. Full refusal plus four executable paths' precise obligation inventories: `/tmp/myfuzz-p7-d4-evidence/execution-refusal.json`.

Further blockers: F1 includes retirement-origin assertions, while CV32E40P has no authenticated retirement observation. F4 declares ip_register_version prerequisites and exact edge/chain assertion mappings that the fixed decoder/checker does not implement from D3. Source ranges/masks, seed mapping and compiled path identities also need real mapping; matching a familiar path name is insufficient. None was relaxed or treated as silently enforced.

## Real executable subset

Exact D2 artifacts generated and loaded from explicit CV32E40P/dual GPIO composition, with NONDEFAULT reset_assert_ticks=2 and reset_release_ticks=3 for all components. All three actual session.artifact references must be the supplied object, and `shared._artifact` is patched to RAISE throughout the real run AND fresh replay, so default artifact regeneration fails the test.

Eight online cases run continuously in the SAME three real RTL processes (PID equality checked after every case): four CPU instruction sources and four GPIO external-pin sources. No reset_barrier. Runtime template, whitelist, ownership and checker are the explicit existing declaration, NOT claimed as D3 semantics. Actual events include 14 MMIO deliveries, four external source injections, actual GPIO A PADOUT writes, and 690 dataflow deliveries. Final local ticks CPU=313, GPIO A=345, GPIO B=337. All eight actual receipts have status=running and no violations. These receipt statuses are not rewritten as complete path certificates.

Fresh replay constructs new actual RTL processes using the same exact loaded objects/factory; full existing replay framework comparison returns matches=true, verification_scope=full, over 4021 events. This does not create retirement evidence for CV32E40P, certify currently unknown source lineage, prove all F1..F6, or establish coverage-guided search. Saved-file replay with default family reconstruction is NOT newly admitted for loaded-artifact requests; verified replay here is in-process saved plan + exact supplied-object fresh factory.

## Real command and evidence

Final command:
```
MYFUZZ_GENERATED_RUNTIME_REAL=1 MYFUZZ_GENERATED_RUNTIME_CACHE=/tmp/myfuzz-p7-d4-real-cache MYFUZZ_GENERATED_RUNTIME_EVIDENCE=/tmp/myfuzz-p7-d4-evidence PYTHONPATH=/tmp/myfuzz-p7-d4-snapshot/src flock -n /tmp/myfuzz-p7-d4-snapshot/.superpowers/sdd/stage2-heavy-worker.lock python3 -m pytest -xq /tmp/myfuzz-p7-d4-snapshot/tests/integration/test_generated_dual_runtime_loaded_real.py
```
Result: **2 passed in62.84s** (strict D3 negative plus real persistent execution/fresh replay). Log `/tmp/myfuzz-p7-d4-real.log`.

Evidence `/tmp/myfuzz-p7-d4-evidence/`:
- summary.json: exact requests/artifact digests, eight raw inputs/receipts, tick counts, full actual build identities, full fresh verdict
- events.json: complete actual 4021-event prefix (~5.2MB)
- plan.json: complete saved execution plan
- compiled-paths.json: actual D3, explicitly not authorized
- execution-refusal.json: real D3 refusal and exact per-path semantic inventory
- artifact-hashes.json: SHA256 of retained evidence files

## Isolated source identity

All real builds/runs used `/tmp/myfuzz-p7-d4-snapshot`: git-archived repository plus the six owned changed/new files; pinned CV32E40P and GPIO source working files were copied. Independent local Git metadata (shared immutable objects, own worktree roots) permits normal filelist/revision verification; no source-path bypass. All source verification, artifact reconstruction, captured input hashing and post-build identity checks remain enabled. `flock` serializes the isolated real worker; no remote actions.

Snapshot SHA manifest `/tmp/myfuzz-p7-d4-snapshot-hashes.json`. Production admission, auto CLI, both runtime builders and real test bytes match successful snapshot exactly. summary.json records actual source/tool/build manifests for each compiled component. Current shared Vexii edits are not folded into this isolated evidence or claimed as tested.

## Verification

RED: new scope test import failed before select_execution_artifacts existed. GREEN scope tests include invalid scope, missing D2, refusing supplied D3 in loaded-only scope, exact object preservation, CLI missing-input refusal before subprocess, and located semantic gap inventory.

`PYTHONPATH=src python3 -m pytest -q tests/integration/test_generated_runtime_scope.py tests/integration/test_auto_harness_test.py tests/integration/test_generated_factory_consumption.py`
-> **36 passed,2 skipped in108.45s**; `/tmp/myfuzz-p7-d4-focused.log`. Skips are existing deliberately mismatched CPU/factory fixture combinations. Existing missing source/profile/kind/instance and changed D3 constraints retain refusal.

Initial isolated attempt exposed Git metadata worktree mismatch during filelist verification; independent worktree metadata fixed the snapshot, without changing production checks. Initial real test reached all eight cases/fresh matches then failed evidence enumeration on startup records without `kind`; test now uses get('kind'). Final reported run is fully passing. `git diff --check` passed.

Additional preserved semantic negative checks:
`PYTHONPATH=src python3 -m pytest -q tests/integration/test_compiled_artifact_admission.py -k 'modified_execution_semantic or reserved_mask'`
-> **16 passed,14 deselected in31.43s**. Changed source/constraint/seed/assertion/bound/prerequisite/runtime identity and reserved-mask edits still refuse with exact pointers. Log `/tmp/myfuzz-p7-d4-negative-checks.log`.

The real final gate was LOCAL isolated execution, not remote; no remote validation is claimed.

## Committed evidence copy

The full evidence files above are also preserved as deterministic gzip under `configs/scenarios/cv32e40p-pulp-dual-gpio/evidence/p7-d4-20261017/`. `index.json` records each original and compressed SHA256; the original `/tmp` files remain the direct gate outputs.
