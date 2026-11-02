# Task 2 — Stage2 r10 static package report

**Status:** Created exactly four new local Stage2 r10 JSON files. Static closure inspection passed. No remote access, upload, runtime execution, project-module execution or tests were performed. Two independent Stage2 ACCEPT reviews remain required.

**Stage2 package digest:** `2fb5f718368042fac5e665184f8966269badff7a17903036d86f8db9fb2f1646`
**Stage2 manifest file SHA-256:** `1e8242df2ede2d7a3be44472c453fa064ace2f7279bd86a27637fed7a477cc41`
**Accepted Stage1 package digest:** `ed7f53aa183e06a2341770805ddf1eecdc8d5a6e6ac22a7692096047e477f84b`
**Accepted Stage1 manifest SHA-256:** `ad44d0ab9a7116fbfdf09f50f93cb0a4001ff58116e36f89dbbeee9a3fb29c99`

Output directory: `/tmp/attempt10-v17-stage2-freeze-r10/`.
Generator: `/tmp/build-attempt10-stage2-r10.py`.
Read-only static inspection: `/tmp/inspect-attempt10-stage2-r10-static.py`.
Evidence: `/tmp/attempt10-stage2-r10-static-evidence.json`.
Preservation baseline: `/tmp/attempt10-stage2-r10-preservation-before.json`.

## Four r10 output files

| File | Mode | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `attempt10-freeze-seal-v17-r10.json` | `0600` | 3551 | `0db030bba36fb6f4ff3d648b30c142e71341546ad03463aaa6e9caf92c986cd8` |
| `attempt10-run-plan-intent-v17-r10.json` | `0600` | 21003 | `5e825f8547fa8d068b2f2c69e4d51ddd1dd4f39aba62c0bfcbfe252d96dfbe5a` |
| `attempt10-run-plan-v17-r10.json` | `0600` | 25085 | `5678c0060abaffbc5d65598a7aa6fe11fbdbe2947c3f5f44de927a6240db794c` |
| `attempt10-stage2-static-package-manifest-v17-r10.json` | `0600` | 90253 | `1e8242df2ede2d7a3be44472c453fa064ace2f7279bd86a27637fed7a477cc41` |

## Generator adaptation and trust boundary

- Started from the existing `/tmp/build-attempt10-stage2-r1.py`. Kept its r1 source receipts, source manifest, task5 snapshots, tools, Verilator and environment inputs unchanged.
- Stage1 r10 has not yet been uploaded. The generator therefore verifies the exact accepted local Stage1 manifest raw hash and canonical package digest, then verifies each of its six members against actual local bytes, size, mode and expected r10 remote target path. The seventh Stage1 file is the manifest itself, pinned by its raw hash. No r9 inventory row is renamed or treated as proof of remote r10 installation.
- Added all seven Stage1 r10 files to the Stage2 entries with exact path/hash/size/mode from the accepted local package. uid/gid `0` and nlink `1` describe required remote installation metadata; the generator does not claim local files are owned by root.
- Historical inventory r9 Stage1 rows are retained verbatim in identity and classified `existing_stage1_r9_artifact`. Existing r9 Stage2 seal/plan/intent/manifest bytes from `/tmp/attempt10-v17-stage2-freeze-r1/` are included as `existing_stage2_r9_artifact`. Parent provided a separate read-only confirmation that those four files match their remote copies; this task did not query the remote host.
- New seal, plan and intent paths use the three `-r10` basenames. Active Stage1 schema/controller/runner/auditor/bootstrap paths and hashes all use r10. The plan binds exact seal bytes; intent binds exact plan bytes. All launch contract values come directly from the accepted r10 schema and exact bootstrap bytes.
- The Stage2 manifest identifies revision `r10`, schema `attempt10_stage2_static_package_manifest.v17-r10`, and status `awaiting_independent_stage2_review`. Protocol statuses and version strings in seal/plan/intent remain the accepted schema values; no schema fields or runtime protocol were changed.
- Canonical entries digest covers 205 unique paths. The newly generated package manifest is excluded from its own entries to avoid self-reference and has a separately recorded raw SHA-256. Seven new r10 Stage1 entries and four existing r9 Stage2 entries account for the increase from the old package’s 194 entries.
- The stale `.superpowers/sdd/task-2-brief.md` describes an unrelated checker ABI implementation. The parent’s explicit Stage2 instructions supersede it; no action from that obsolete brief was performed.

## Stage1 r10 entries

| Remote basename | Mode | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `attempt10-external-launch-contract-v17-r10.json` | `0600` | 11468 | `3dbda8c6f6d431eac6c2ed7e2d0aedada4831dc7ff167b24b892d1b1589cbd5b` |
| `attempt10-plan-schema-v17-r10.json` | `0600` | 44258 | `3123c0784b6f9a45bf772d146634496fc9439a3fa1963afb269da1328e9eca88` |
| `attempt10-post-gate-audit-runner-v17-r10.py` | `0700` | 82814 | `b10d558cdfd3e2b10c3d1f9f6556a9bd19ca199141a1dceb4f7e513e0f43b1db` |
| `attempt10-source-byte-bootstrap-v1-r10.py` | `0600` | 4138 | `fdb33fcad0f57c1b09875a673b6590d0c2dcdf419f2e7f670515d70b0706cc35` |
| `independent_audit_task5.attempt10.v17-r10.py` | `0600` | 358211 | `b095d33b6d9f0c3fb5f4b1b8e0eaf58e02f604a1a79b59d46d621b4dc96d2007` |
| `static-code-manifest.v17-r10.json` | `0600` | 5639 | `ad44d0ab9a7116fbfdf09f50f93cb0a4001ff58116e36f89dbbeee9a3fb29c99` |
| `task5-attempt10-run-controller-v17-r10.py` | `0700` | 85525 | `1f899af051bb2129241392d1e93d6f5cbdb324d8392fca09305dfd8e35643fd9` |

## Static evidence

- exactly four r10 Stage2 JSON files.
- output directory 0700 and all four files 0600.
- r10 manifest revision/schema and pending-review status.
- manifest package digest independently recomputed from canonical entries.
- 205 manifest entries.
- manifest paths unique.
- canonical ordering and deduplicated roles.
- exact accepted Stage1 package digest closed.
- exact accepted local Stage1 manifest bytes closed.
- Stage1 r10 byte/metadata entry: attempt10-external-launch-contract-v17-r10.json.
- Stage1 r10 byte/metadata entry: attempt10-plan-schema-v17-r10.json.
- Stage1 r10 byte/metadata entry: attempt10-post-gate-audit-runner-v17-r10.py.
- Stage1 r10 byte/metadata entry: attempt10-source-byte-bootstrap-v1-r10.py.
- Stage1 r10 byte/metadata entry: independent_audit_task5.attempt10.v17-r10.py.
- Stage1 r10 byte/metadata entry: static-code-manifest.v17-r10.json.
- Stage1 r10 byte/metadata entry: task5-attempt10-run-controller-v17-r10.py.
- all seven Stage1 r10 entries have Stage1 roles.
- existing r9 Stage2 preserved identity: attempt10-freeze-seal-v17.json.
- existing r9 Stage2 preserved identity: attempt10-run-plan-v17.json.
- existing r9 Stage2 preserved identity: attempt10-run-plan-intent-v17.json.
- existing r9 Stage2 preserved identity: attempt10-stage2-static-package-manifest-v17-r9.json.
- seven historical r9 Stage1 files are existing-file roles only.
- Stage2 artifact and entry bytes agree: attempt10-freeze-seal-v17-r10.json.
- Stage2 artifact and entry bytes agree: attempt10-run-plan-v17-r10.json.
- Stage2 artifact and entry bytes agree: attempt10-run-plan-intent-v17-r10.json.
- new package manifest excluded from its own entries.
- seal/plan/intent exact top-level field sets match accepted schema.
- all intent nested field sets match accepted schema.
- run/source/post-audit field sets match accepted schema.
- plan binds exact r10 seal path and bytes.
- intent binds exact r10 plan path and bytes.
- plan binds exact r10 schema path and bytes.
- plan and seal static objects identical.
- static object binds correct entry: auditor.
- static object binds correct entry: bootstrap.
- static object binds correct entry: controller.
- static object binds correct entry: interpreter.
- static object binds correct entry: runner.
- static object binds correct entry: schema.
- all plan launch contracts match accepted schema.
- auditor argv expands exact r10 bootstrap and auditor hash.
- run and source joins close across plan/intent/manifest.
- all four documents record gate not started and not executed.
- all documents preserve exact four false claims.
- r10 active documents contain no old Stage1 or Stage2 filename references.
- source/environment/run are unchanged from frozen r9 Stage2.
- historical prelaunch observation retained with original observation time.
- acceptance matrix unchanged.
- all 56 existing Stage1 r9/r10, Stage2 r9/input, original generator and inventory files preserve bytes/modes/sizes.
- both static-only tooling scripts parse as Python AST.

## Source identity and limitations

- Source manifest remains `c50be8b660092914a709a3198e8aec998074451a9fe979a309d692e9f05c0dae` with 5513 source entries and parent head `e5d798a5f9f3d105b74af9375c267ea406563462`.
- Historical prelaunch observation remains `2026-10-18T23:22:13.377377Z`. The new intent creation timestamp is `2026-10-18T23:41:47.164397Z`. The old inventory is preserved as historical evidence; it is not presented as a new remote query. The parent separately confirmed the four r10 target filenames are absent.
- This package establishes local static closure only. Remote r10 installation, ownership/modes and current runtime absence are not established by this builder; they remain subsequent external checks.
- All four claims remain false and all four documents record `gate_started=false` and `gate_executed=false`. No gate/auditor result is implied.
- Stage1 and Stage2 r9 bytes/modes/sizes, Stage1 r10, r1 input receipts, original generator and inventory files were preserved. The old unrevisioned Stage2 remote filenames are represented only as existing-file identities. Four new r10 outputs are the only files in the new package directory.
- Both independent Stage2 reviews must ACCEPT the exact digest above before any upload or execution. No controller, gate, runner, auditor, project module or test was run. No protocol constraint conflict was found.

---

# F6 Task 2 — live runtime path compiler and Caliptra integration

**Status:** Implemented locally; focused verification below. This section is appended to preserve the pre-existing, unrelated Stage2 r10 report above.

## Scope and implementation

- Added `prepare_compiled_f6_runtime_path(compiled_paths, wiring, runner, *, source, transfer_pair, artifact_links)`. It checks the supplied D3 wiring identity, complete route and binding documents, F6 refusal, explicit route IDs and operation, then constructs one live graph and `PreparedRuntimePathContract`.
- Moved Caliptra live route-facts validation into `compiled_f6_runtime_path.py` and made the legacy `_route_declarations()` delegate to it. The shared validator retains exact shared memory service, ledger, RAM owner and readable region, unique DMA window, registered SHA endpoint, provider identity and callable access, AHB-Lite trace, and full-word CTRL policy checks.
- Moved the sole RAM-read → DMA-order → SHA-CTRL graph and runtime contract builder into `compiled_f6_runtime_path.py`. The legacy Caliptra prepare and compile functions use it.
- The compiler maps the explicit read route ID to edge `(0, 0)` and write route ID to `(2, 0)`, derives each endpoint link from the physical artifact-link record, and passes the exact prepared graph object through D4 declaration and handoff. The live path stores a process-local provenance marker tied to that object. Detached reader output is rejected before binding.
- Added `bind_compiled_f6_runtime_path()` and a bound wrapper that validates the handoff, graph, route links, and live topology on each route lookup. It invokes the D4 handoff binder once.
- Switched native Caliptra `_make_pair()` to the new compiler and binder. Its beat admission selects the two typed routes from the compiled route-link rows keyed by the explicit transfer pair IDs.
- Static D3 F6 remains unsupported with the live-topology refusal and no static DMA transfer edge. No CPU programming, IRQ, physical bridge, multiword DMA, or broad F6 completion is claimed.

## Test sequence and evidence

- TDD red: `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py -k live_compiler` exited 2 during collection with `ImportError: cannot import name 'prepare_compiled_f6_runtime_path'`; the new API was absent.
- TDD green: the same focused test later reported `1 passed, 43 deselected in 22.97s`.
- Legacy Caliptra regression: `PYTHONPATH=src pytest -q tests/scenario/test_caliptra_sha256_dma_paths.py` reported `11 passed in 0.25s`.
- Native integration seam smoke, using `_native_d3_wiring()` and `_make_pair()` with a temporary directory, printed `native-seam: one bind, same prepared graph, runtime artifact v1`.
- The opt-in native test command `PYTHONPATH=src pytest -q tests/integration/test_dma_caliptra_sha256_real.py` reported `1 skipped in 0.25s`; native RTL execution was not requested.
- `git diff --check` exited 0 with no output.
- The focused negative suite checks static identity/pair drift before graph creation, reversed normalized route tuple order, detached refusal before D4, exact prepared-object single bind, artifact-link and DMA endpoint identity drift, and Caliptra owner/region/window/provider/trace/CTRL refusals. Its final command and the required broad command results are recorded below.

## Limits

The process-local provenance marker protects the public bind API against detached/direct artifacts within normal use. It is not a Python memory-safety or adversarial in-process boundary. The live binder and beat admission remain the authorities for current owner identity and transaction policy. The opt-in native RTL test was not run in this local verification.

Final focused scenario command: `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py` reported `46 passed in 36.61s`.

Required broad command:
```text
PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_dma_route_admission.py tests/integration/test_p7b_p7c_dma_route_intent.py
```
Result: `181 passed in 294.38s (0:04:54)`, exit status 0. This broad run began before the final endpoint-identity-drift assertion was added; the final focused scenario rerun above includes that assertion.

Final `python3 -m py_compile` on all four modified Python files exited 0 with no output. Final `git diff --check` exited 0 with no output.

---

## F6 Task 2 follow-up — independent review findings

The review found that the live preflight checked only part of D3 before graph construction, and that the Caliptra refusal matrix called the internal graph builder. Both are addressed.

- Extracted `validate_compiled_f6_static(compiled, static_wiring)` from the existing handoff validator. It checks the complete D3 schema, wiring route and binding digests, F6 refusal including `reason.missing`, and both static graph and runtime contract readers. The handoff continues to check declaration route links against the validated static route IDs. `prepare_compiled_f6_runtime_path()` now uses the shared validator before calling the live graph builder.
- Added a failing preflight test first: malformed `compiled_paths.v0` reached a mocked graph builder and raised an unpack error. After the refactor, the same test rejects malformed schema, F6 missing rows, and invalid non-DMA static graph structure with zero graph-builder calls.
- Moved the live owner/region/window/provider/trace/CTRL refusal matrix to the public `prepare_compiled_f6_runtime_path()` API. The fixture uses actual D3 output with RAM `0x1000..0x2000` and a synthetic runner whose RAM region and source descriptor match it. Added public route-count, mover/target, operation, inside/outside source-address, artifact-link owner/provider/physical-link, and live DMA endpoint identity drift cases.
- Preserved the existing Caliptra compatibility API and the D3 static F6 refusal boundary.

Follow-up verification: `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py` reported `46 passed in 49.72s`; `PYTHONPATH=src pytest -q tests/scenario/test_caliptra_sha256_dma_paths.py` reported `11 passed in 0.25s`. The native `_make_pair()` smoke again printed `native-seam: one bind, same prepared graph, runtime artifact v1`.

The required broad suite result follows below.

Required broad command:
```text
PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_dma_route_admission.py tests/integration/test_p7b_p7c_dma_route_intent.py
```
Result: `181 passed in 317.54s (0:05:17)`, exit status 0.

### Second review follow-up: D3 graph/contract join

The shared static D3 validator already parsed the dependency graph and runtime contract independently. A contract with a wrong graph digest, or a graph changed together with its digest while retaining incompatible contract nodes/edges, could pass preflight. A failing test first showed the wrong-digest case reaching the mocked live graph builder.

The validator now requires the contract graph digest to equal the parsed graph document digest, the contract node IDs to equal the graph source/edge node IDs, and every declared runtime edge key to exist in the graph with a relation compatible with that rule kind. It uses the existing runtime relation map and allows graph edges without a runtime edge contract, as required by F5's first EVENT_ORDER edge. Tests include wrong digest, well-formed changed node mapping, and changed rule kind with incompatible relation. The synthetic handoff fixture now hashes its real empty graph; its v2 positive fixture supplies a matching contract.

Post-fix focused commands:
- `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py`: `47 passed in 65.10s (0:01:05)`.
- `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_dma_handoff.py`: `25 passed in 0.37s`.
- `PYTHONPATH=src pytest -q tests/scenario/test_caliptra_sha256_dma_paths.py`: `11 passed in 0.27s`.

The final required broad run against the frozen code is still running; its exact output will be appended.

Final frozen-code broad command:
```text
PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_dma_route_admission.py tests/integration/test_p7b_p7c_dma_route_intent.py
```
Result: `182 passed in 330.94s (0:05:30)`, exit status 0.

### Final review follow-up: complete D3 shape and bidirectional graph join

The final independent review found that a partial D3 document could reach the live graph builder, and that a graph could retain a DATA_BINDING or PERSISTENT_STATE_RULE edge after its runtime contract row was removed. Tests were added first; the F6-only and trace-schema mutations reached the public builder before their respective fixes.

`validate_compiled_f6_static()` now requires the full ordered F1–F6 path set with unique path IDs, the compiler's exact `FLOW_DEFINITIONS`, closed path rows with matching flow names and definitions, counts recomputed from statuses with integer values, typed top-level fields, and closed component identity rows matching the compiler's `_component_identity()` fields. The legacy handoff test fixture was expanded to a complete six-path D3 document. These checks run before `build_caliptra_runtime_graph()`.

The graph/contract join now requires every non-EVENT_ORDER graph edge to have a contract row, while retaining the compiler's F5 exception for an uncontracted EVENT_ORDER edge. Runtime node components must belong to D3 component identities. Graph source component/kind/physical-port metadata must agree with the corresponding runtime node. For an executable instruction-image source, graph source component/port/bit/width also agree with the corresponding D3 path source. Public preflight tests cover missing DATA_BINDING contract rows, graph-only source component drift, contract-only component drift, and coordinated drift of both to another valid D3 component. The F5 uncontracted EVENT_ORDER positive case remains accepted.

The public Caliptra facts preflight now checks the complete AHB trace schema, signals, and widths using D4's existing width map. The synthetic Caliptra fixture supplies the same trace shape. The unused Caliptra `RULES` constant was removed. Public tests cover omitted trace schema/signals/widths.

TDD and final verification:

- Red: `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py -k 'live_compiler_refuses_static or static_validator_allows_f5'` yielded `1 failed, 1 passed`; a F6-only D3 reached the mocked graph builder.
- Red: `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py -k public_compiler_refuses_owner` yielded `1 failed`; omitted trace schema reached public graph construction.
- Focused: `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_caliptra_sha256_dma_paths.py` yielded `84 passed in 68.65s (0:01:08)`, exit 0.
- Required broad: `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_dma_route_admission.py tests/integration/test_p7b_p7c_dma_route_intent.py` yielded `183 passed in 311.34s (0:05:11)`, exit 0.
- `python3 -m py_compile` on the six Task 2 source/test Python files exited 0 with no output. `git diff --check` exited 0 with no output.

The graph digest and source/edge joins cover graph fields and comparable D3 instruction-image metadata. They do not establish the graph's resource or MMIO aperture semantics, because those are not represented in the graph document. No extra source-to-effect reachability constraint was added without a confirmed compiler invariant. Static F6 remains unsupported and has no DMA transfer edge.

### Final review repair: F5 edge and nested compiler document closure

A further independent review found that the uncontracted EVENT_ORDER allowance was too broad, and that several compiler-emitted nested D3 records could retain unknown fields. These findings were repaired with tests added before each implementation change.

- The only graph edge allowed without a runtime edge contract is the compiler's unique `(EVENT_ORDER, F5.pin_event, F5.ip_irq)` edge at prerequisite index 0, with `F5.pin_event` declared as a `source`. All other EVENT_ORDER edges require a compatible contract row. A positive test compiles a real F5 graph from the repository's test-only declared-facts probe, with a one-bit CPU IRQ endpoint and the real static DMA route declarations; it retains the compiler-emitted missing first F5 edge. Negative tests reject the prior `F1.program_image -> F5.irq_event` shape, a missing F5 direct-binding row, and a duplicate same-endpoints edge.
- Graph sources of kind `source` now join the corresponding D3 path's single external-pin source on flow, component, physical port, bit offset, width, and direction. A test changes the graph source and runtime node together to another valid component while leaving the D3 source intact; validation refuses it.
- `input_constraints` now has exact emitted top-level keys, schema, typed layout/rule/closure/cycle/owned-input/gap rows, and rule ID consistency. Layout fields and their binding and normalized constraint rows have closed emitted shapes; constraint rule rows have the compiler's required and optional fields. Per-path constraints have exact keys, shared policy/layout hashes, rule IDs and declared rule rows, and source/register projections. Global register claim rows have the emitted required and optional fields, so changing both global and path copies together to add an unknown field is refused. Raw compiler tuple values and JSON round-trip lists remain accepted where the emitter uses them.
- Caliptra's trace width check now requires exact `int` values, rejecting `True` in a one-bit role. The trace is checked before invoking provider identity and before constructing the live dependency graph. A public-entry test installs a provider identity spy that would raise if invoked after the malformed trace.

TDD red evidence: the focused public preflight command with malformed layout, register claim, F5, and trace mutations reported `4 failed, 45 deselected in 48.15s` before the first validator repair; later nested-layout and dual-register-claim cases reported `2 failed, 48 deselected in 22.86s` before their closure. The exact commands and final results are:

- `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py -k 'live_compiler_refuses_static or closes_register_claim or static_validator_allows_only or compiled_f6_handoff' --tb=short`: `31 passed, 44 deselected in 34.21s`, exit 0.
- `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_caliptra_sha256_dma_paths.py`: `86 passed in 91.33s (0:01:31)`, exit 0.
- `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_dma_route_admission.py tests/integration/test_p7b_p7c_dma_route_intent.py`: `185 passed in 333.66s (0:05:33)`, exit 0 against the final code.
- `python3 -m py_compile` on the six Task 2 source/test Python files and `git diff --check` both exited 0 with no output.

The validator checks emitted record shape and cross-document joins. It does not recompute the input policy hash, solve constraints again, prove graph resource/MMIO aperture semantics, or add an unproven graph reachability invariant. Static F6 remains unsupported without a DMA transfer edge.

### Final review repair: canonical D3 graph source identities

The prior frozen package received `CHANGES_REQUIRED`: the memory-image join used the graph source ID prefix to find a path but silently skipped unknown prefixes, and accepted renamed or extra image IDs when their metadata matched. The review also found that layout-field provenance accepted unknown fields.

The validator now requires each memory-image graph source to have the exact compiler ID `<flow>.program_image`, a known executable F1–F5 path, and that path's unique `instruction_image` row. It joins component, port, bit offset, and width. It requires the compiler's fixed `CPU_TO_IP` direction for memory-image sources. F5 as a whole can have `IP_TO_CPU` direction while its program image remains CPU sourced, as confirmed by the compiler-emitted F5 probe. Graph sources of kind `source` are limited to the exact `F5.pin_event` ID and join the F5 external-pin row and F5 path direction. Layout provenance is closed to required `file` and positive integer `line`, plus optional positive integer `column`.

A test built from valid compiler-produced D3 mutates graph source/edge/runtime-node IDs and digest to `ghost.image` and `F1.ghost`, adds a duplicate unmatched image source and state node, and drifts the image direction. Public preflight refuses each before the live graph builder. The compiler-generated F5 positive remains accepted; a renamed F5 pin source with a matching extra contract edge is refused. The generic handoff v2 positive fixture now uses `F1.program_image` and a matching executable F1 instruction-image path row instead of an arbitrary `image` node.

TDD red: `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py -k live_compiler_refuses_static --tb=short` reported `1 failed, 49 deselected in 11.60s`; case 25 (`ghost.image`) reached the mocked live builder. The later combined ghost/provenance/F5 command reported `2 failed, 48 deselected in 23.06s` before those checks were completed.

Final verification against the repaired frozen code:

- `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py -k 'live_compiler_refuses_static or static_validator_allows_only or canonical_v2_dependency_graph' --tb=short`: `3 passed, 72 deselected in 22.98s`, exit 0.
- `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_caliptra_sha256_dma_paths.py`: `86 passed in 90.90s (0:01:30)`, exit 0.
- `PYTHONPATH=src pytest -q tests/scenario/test_compiled_f6_runtime_path.py tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_dma_route_admission.py tests/integration/test_p7b_p7c_dma_route_intent.py`: `185 passed in 334.45s (0:05:34)`, exit 0.
- `python3 -m py_compile` on the six Task 2 source/test Python files and `git diff --check` both exited 0 with no output.

The previous review verdict applies to its earlier snapshot. This repaired package is awaiting a new independent review. The structural validator still does not recompute input policy hashes or resource/MMIO semantics.

---

# BOOM Task 2 shared-memory service — 2026-10-22

**Status: DONE for the bounded software implementation and inline checks; independent review and native proof remain pending.** Earlier unrelated Task 2 reports above are preserved verbatim.

## Owned changes and stable interfaces

- Added `src/myfuzz/local_harness/boom_shared_memory.py`.
- Modified only `src/myfuzz/local_harness/boom_scenario_session.py` in production.
- Frozen `BoomSharedMemoryContract()` accepts only external `[0x4000,0x5000)`, source `[0x4100,0x4110)`, destination `[0x4200,0x4210)`, result `[0x4300,0x4318)`, and control `[0x4400,0x4410)`. Schema: `boom_shared_memory_contract.v1`.
- `BoomSharedMemoryService(memory: PersistentMemory, contract: BoomSharedMemoryContract)` exposes `.memory`, `.contract`, actual `.service: MemoryService`, `.records`, and actual issued objects in `.receipts`. Schema: `boom_shared_memory_service.v1`. Its native binding is once per fresh service; shared reset explicitly requires fresh sessions and fresh memory.
- `GeneratedBoomScenarioSession(..., shared_memory_service=None)` preserves the default constructor arguments, public method signatures and byte-equivalent default v1 identity. Opt-in schema: `boom_scenario_shared_memory_session.v1`; opt-in exposes `.service` and `.memory` for existing Runner event/state capture.
- CPU memory and Router control operations share the same actual service ledger and consecutive native `coherent-A-uncached` key sequence. DMA retains its own source ledger over the identical memory object. Router receives original data/mask with `beat_bytes=8` exactly once.
- Exact source/profile/port/native-driver/manager SHA-256 pins authenticate before native startup. The translated pinned legal/cacheable/write PMA predicates are checked over all selected bytes. No runtime PMP permission is synthesized.
- One common physical validator checks native opcode/param/size/source/address/mask/data/sequence/epoch. Page holes and malformed shapes fail before MemoryService or Router effects.
- Actual enabled physical bytes become exactly one width4/be15 MemoryService operation; Get results return to their physical low/high lane. Full physical request, typed key, actual write commit document/read snapshot, byte versions and writer keys are retained. The active key survives service commit and RESPOND until consumed native external D.
- Queue cancellation precedes transport close/reset refusal; stale/duplicate callbacks fail. Uncertain ledger entries remain unresolved and keep pending state nonzero. Cancelled committed writes retain their receipts. No invented denied/corrupt/CPU success response is emitted.

## Self-review and scope

Read Task 2 brief, accepted design, implementation plan and independent design review before editing. The TDD and verification skills were applied through transient inline exercises only. No persistent test file was created, no test suite was run, no native process was constructed or executed, no native build or RTL edit occurred, and no staging, commit, remote access or cleanup was performed.

The existing DeviceWindow enforces 4KiB base alignment. Root was informed and owns the Task 3 private exact 0x4400/16 subclass; this task did not alter generic Router.

Self-review checked common sequence continuity across memory/control, physical high-lane placement without double shifting, actual receipt retention, active-until-D lifecycle, callbacks after cancellation and duplicate callback delivery, changed object/configuration bindings, old identity/API, source drift refusal, and fresh-memory reset policy. A same-configuration replacement-memory gap and already-bound-service startup gap were each reproduced with an inline assertion before fixing. An absent Runner `.service/.memory` interface was likewise reproduced before adding opt-in-only bindings.

Native PMP-permitted access, actual CPU/DMA execution, source/D/control acceptance, quiesce no-partial-A precondition, deterministic replay, subprocess exits, and independent implementation review remain outside these software checks. The service is narrow observation/effect evidence and does not claim generic memory_commit_authority, cache coherence or retirement.

## Initial red checks

The first invocation used `python` and returned exit 127 (`python: command not found`). It was immediately corrected to `python3`.

```bash
PYTHONPATH=src python3 - <<'PY'
from pathlib import Path
assert Path('src/myfuzz/local_harness/boom_shared_memory.py').exists(), 'shared-memory contract/service is missing'
PY
```

Result before implementation: exit 1, `AssertionError: shared-memory contract/service is missing`.

```bash
PYTHONPATH=src python3 - <<'PY'
import inspect
from myfuzz.local_harness.boom_scenario_session import GeneratedBoomScenarioSession
assert 'shared_memory_service' in inspect.signature(GeneratedBoomScenarioSession).parameters, 'adapter lacks opt-in shared memory API'
PY
```

Result before adapter implementation: exit 1, `AssertionError: adapter lacks opt-in shared memory API`. The final full checks below confirm the new argument is optional and the original arguments are preserved.

## Exact commands and measured results

The commands below were all run inline; repeated identical commands are shown once with every observed result. Fakes are confined to the absent native transport/artifact and register target; the validator, contract authentication, PersistentMemory, MemoryService, ledgers, Router and coherent event stream are real software implementations. Git HEAD is read only for direct compatibility comparison.

### Check 1

```bash
PYTHONPATH=src python3 - <<'PY'
from myfuzz.local_harness.boom_shared_memory import BoomSharedMemoryContract, BoomSharedMemoryService
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory

def memory():
    return PersistentMemory(regions=tuple(MemoryRegion(n,a,z) for n,a,z in [('s',0x4100,16),('d',0x4200,16),('r',0x4300,24)]),initialization_seed=17,max_initialized_bytes=56)
s=BoomSharedMemoryService(memory(),BoomSharedMemoryContract())
s.memory=memory()
s.service.memory=s.memory
try:
    s.validate_binding()
except ValueError:
    pass
else:
    raise AssertionError('same-identity replacement memory object was accepted')
PY
```

Run 1: exit 1.

```text
Traceback (most recent call last):
  File "<stdin>", line 14, in <module>
AssertionError: same-identity replacement memory object was accepted
```

Run 2: exit 0.

```text
(no output)
```


### Check 2

```bash
PYTHONPATH=src python3 - <<'PY'
from copy import deepcopy
from dataclasses import dataclass, FrozenInstanceError
import hashlib, inspect, json
from pathlib import Path
from unittest.mock import patch
from myfuzz.local_harness.boom_shared_memory import BoomSharedMemoryContract, BoomSharedMemoryService
from myfuzz.local_harness.boom_scenario_session import GeneratedBoomScenarioSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

def refused(call, kinds=(ValueError, RuntimeError)):
    try: call()
    except kinds: return
    raise AssertionError('expected refusal')

def memory(regions=None):
    return PersistentMemory(regions=regions or tuple(MemoryRegion(n,a,z) for n,a,z in
        [('source',0x4100,16),('destination',0x4200,16),('result',0x4300,24)]),
        initialization_seed=17,max_initialized_bytes=56)

@dataclass(frozen=True)
class SubpageWindow(DeviceWindow):
    def __post_init__(self):
        assert self.device_id=='dma' and self.base==0x4400 and self.size==16

class Target:
    routed_register_access_enabled=True
    master_targets=()
    def __init__(self,m):
        self.memory_service=MemoryService(m,TransactionLedger())
        self.calls=[]
    def routed_register_access(self,key,**kw):
        self.calls.append((key,deepcopy(kw)))
        return {'rdata':0x12345678}
    def write_register(self,*a,**kw):
        raise AssertionError('host register helper called')
    def read_register(self,*a,**kw):
        raise AssertionError('host register helper called')

class Native:
    execution_id='native-execution'
    reset_epoch=1
    last_samples=()
    def __init__(self):
        self._process=object(); self.queue=[]; self.offers=[]; self.pending_responses=0
        self.close_calls=0; self.edges=0
    def respond_external(self,**kw):
        self.offers.append(deepcopy(kw))
    def step_local(self,inputs):
        self.edges+=1
        result=self.queue.pop(0)
        self.pending_responses=int(not result['drained'])
        return result
    def close(self):
        self.close_calls+=1; self._process=None
    def identity_document(self):
        return {'native':'fixture'}

def adapter(shared=True):
    m=memory(); service=BoomSharedMemoryService(m,BoomSharedMemoryContract())
    target=Target(m)
    window=SubpageWindow('dma',0x4400,16,target) if shared else DeviceWindow('gpio',0x4000,16,target)
    router=DataflowRouter((window,))
    with patch.object(Path,'read_text',return_value='{"fixture":true}'):
        cpu=GeneratedBoomScenarioSession(Path('/unused'),repo=Path('.'),router=router,
            program=b'\x13\0\0\0',shared_memory_service=service if shared else None)
    native=Native(); cpu._native=native; cpu._case_id='case'; cpu._started=True; cpu.reset_epoch=1
    if shared:
        service.bind(execution_id=native.execution_id,testcase_id='case',source_component='cpu',reset_epoch=1)
    return cpu,native,service,target

def request(seq,address,opcode=0,value=0):
    return dict(channel='A',opcode=opcode,param=0,size=2,source=1,address=address,
        mask=15<<(address&7),data=value<<(8*(address&7)),request_sequence=seq,reset_epoch=1)

def observation(events=(),external=None,drained=False):
    return dict(accepted_events=tuple(events),external_request=deepcopy(external),
        reset=False,drained=drained)

def submit(cpu,native,q):
    raw={k:v for k,v in q.items() if k not in ('request_sequence','reset_epoch')}
    native.queue.append(observation((raw,),q))
    cpu.step_local({})

def accept_d(cpu,native):
    active=cpu._active
    q=active['request']
    native.queue.append(observation((dict(channel='D',source=q['source'],size=2,
        opcode=1 if q['opcode']==4 else 0,param=0,sink=0,beat=0,
        data=active['data'],external=True),),drained=True))
    cpu.step_local({})
    assert cpu._active is None and cpu.pending_responses==0

c=BoomSharedMemoryContract()
refused(lambda:BoomSharedMemoryContract(source_range=(0x4100,0x4120)))
try: c.source_range=(0x4000,0x4010)
except FrozenInstanceError: pass
else: raise AssertionError('mutable contract')
for bad in [
    (MemoryRegion('a',0x4100,16,readable=False),MemoryRegion('b',0x4200,16),MemoryRegion('c',0x4300,24)),
    (MemoryRegion('a',0x4100,16,aliases=(0x5100,)),MemoryRegion('b',0x4200,16),MemoryRegion('c',0x4300,24)),
    (MemoryRegion('a',0x4100,16),MemoryRegion('b',0x4200,16),MemoryRegion('c',0x4300,28))]:
    refused(lambda bad=bad:BoomSharedMemoryService(memory(bad),c))
with patch.object(Path,'read_bytes',return_value=b'drift'):
    refused(lambda:c.authenticate_source(Path('.')))
assert c.authenticate_source(Path('.'))['pmp_permission']=='requires_actual_cpu_pmp'

cpu,native,s,target=adapter()
assert cpu.mmio_ledger is s.service.ledger
assert cpu.identity_document()['external_range']==(0x4000,0x5000)
assert cpu.identity_document()['memory_commit_authority'] is False
for seq,address,value in [(1,0x4100,0x12345678),(2,0x4104,0x89abcdef)]:
    q=request(seq,address,value=value)
    before=native.edges
    submit(cpu,native,q)
    assert native.edges==before+1 and not target.calls and cpu.pending_responses==1
    assert cpu._active['status']=='d_offered' and s.records[-1]['status']=='service_complete_d_pending'
    assert s.records[-1]['native_request']==q
    receipt=s.receipts[cpu._active['key']]
    assert receipt.commit_document()['width_bytes']==4
    assert all(cell['writer_event_id']==str(cpu._active['key']) for cell in receipt.commit_document()['enabled_byte_cells'])
    count=len(s.service.events); offers=len(native.offers)
    native.queue.append(observation((),q))
    cpu.step_local({})
    assert len(s.service.events)==count and len(native.offers)==offers
    accept_d(cpu,native)
    assert s.records[-1]['status']=='d_accepted'

# Native sequence 3 control high lane follows two memory operations on the same ledger.
q=request(3,0x4404,value=0x0fed0004)
submit(cpu,native,q)
assert not target.calls and cpu.router.pending_targets==('dma',)
callback=cpu.router._queued[0][-1]
assert cpu.router.drain_one('dma')
assert len(target.calls)==1 and target.calls[0][0].source_sequence==3
assert target.calls[0][1]['value']==0x0fed0004 and target.calls[0][1]['be']==15
assert cpu.router.acceptances[-1]['beat_bytes']==8
assert cpu.pending_responses==1 and cpu._active['status']=='d_offered'
refused(lambda:callback((0,0)))
accept_d(cpu,native)

# Return high-lane control data exactly once, then memory reads after the controls.
submit(cpu,native,request(4,0x440c,opcode=4))
assert cpu.router.drain_one('dma')
assert native.offers[-1]['data']==0x12345678<<32
accept_d(cpu,native)
for seq,address,value in [(5,0x4100,0x12345678),(6,0x4104,0x89abcdef)]:
    submit(cpu,native,request(seq,address,opcode=4))
    assert native.offers[-1]['data']==value<<(8*(address&7))
    snap=s.receipts[cpu._active['key']]
    assert len(snap.data)==len(snap.versions)==len(snap.writer_event_ids)==4
    assert all(writer==str(TransactionKey(native.execution_id,'case','cpu',1,'coherent-A-uncached',seq-4)) for writer in snap.writer_event_ids)
    accept_d(cpu,native)
assert len(s.records)==4 and len(s.receipts)==4 and s.memory.initialized_bytes==8

# Page holes, malformed shape, wrong sequence and epoch refuse before memory/provider.
before=s.memory.state_summary(); calls=len(target.calls); events=len(s.service.events)
for changed in [
    {'address':0x4000},{'address':0x4110},{'address':0x4210},{'address':0x4318},{'address':0x4410},
    {'size':3},{'opcode':6},{'param':1},{'mask':255},{'mask':True},
    {'source':8},{'reset_epoch':0},{'request_sequence':8}]:
    q=request(7,0x4108); q.update(changed)
    refused(lambda q=q:cpu._enqueue(q))
assert s.memory.state_summary()==before and len(target.calls)==calls and len(s.service.events)==events
q=request(7,0x4108)
for key in [
    TransactionKey('wrong','case','cpu',1,'coherent-A-uncached',7),
    TransactionKey(native.execution_id,'wrong','cpu',1,'coherent-A-uncached',7),
    TransactionKey(native.execution_id,'case','cpu',0,'coherent-A-uncached',7),
    TransactionKey(native.execution_id,'case','cpu',1,'other-channel',7)]:
    refused(lambda key=key:s.execute(key,q))
assert s.memory.state_summary()==before

# Closing revokes queued callbacks before native close; repeated close is safe.
queued,n,s2,t=adapter()
submit(queued,n,request(1,0x4400,value=1)); late=queued.router._queued[0][-1]
queued.end_case()
assert not queued.router.pending_targets and not t.calls and n._process is None
refused(lambda:late((0,0)))
queued.end_case()
assert queued.pending_responses==0

# In-place shared reset is explicitly refused after cancellation; fresh objects are required.
queued,n,s2,t=adapter()
submit(queued,n,request(1,0x4400,value=1)); late=queued.router._queued[0][-1]
refused(queued.reset_local)
assert not queued.router.pending_targets and n._process is None and not t.calls
refused(lambda:late((0,0)))
queued.end_case()

# A committed store remains recorded when its CPU D is cancelled.
pending,n,s3,t=adapter()
submit(pending,n,request(1,0x4100,value=55))
pending.end_case(); pending.end_case()
assert s3.records[0]['status']=='cancelled'
assert s3.records[0]['service_receipt']['performed_effect'] is True
assert s3.memory.initialized_bytes==4

# Default API and identity match the original v1 JSON byte for byte.
old,n,unused,t=adapter(False)
old._native=None
expected={'schema_version':'boom_scenario_session.v1','source_component':'cpu',
    'runtime_kind':'tilelink_coherent_cpu','native_artifact':{'fixture':True},'native_identity':None,
    'static_image':{'address':0x80000000,'bytes':4,'sha256':hashlib.sha256(b'\x13\0\0\0').hexdigest()},
    'native_ram_observation_addresses':(),'ram_model':'native_coherent_manager',
    'memory_commit_authority':False,'isa_retirement_authority':False,'runtime_verified':False,
    'generic_router_admitted':False,'defer_mmio':True}
assert json.dumps(old.identity_document(),separators=(',',':'))==json.dumps(expected,separators=(',',':'))
assert inspect.signature(GeneratedBoomScenarioSession).parameters['shared_memory_service'].default is None
assert old._validate_request(request(1,0x4000))=='control'
assert all(callable(getattr(old,name)) for name in ('begin_case','step_local','reset_local','end_case','close','begin_quiesce','coherent_report','coherent_coverage'))
print('PASS: exact layout/source/PMA, physical lanes and receipts, active-until-D, stable response, interleaved native keys, Router once, holes/shape/key/epoch refusal, cancellation/reset/idempotent close, byte-equivalent default identity/API')
PY
```

Run 1: exit 0.

```text
PASS: exact layout/source/PMA, physical lanes and receipts, active-until-D, stable response, interleaved native keys, Router once, holes/shape/key/epoch refusal, cancellation/reset/idempotent close, byte-equivalent default identity/API
```


### Check 3

```bash
PYTHONPATH=src python3 - <<'PY'
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from myfuzz.local_harness.boom_shared_memory import BoomSharedMemoryContract,BoomSharedMemoryService
from myfuzz.local_harness.boom_scenario_session import GeneratedBoomScenarioSession
from myfuzz.scenario.memory import MemoryRegion,PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.router import DeviceWindow,DataflowRouter
m=PersistentMemory(regions=tuple(MemoryRegion(n,a,z) for n,a,z in [('s',0x4100,16),('d',0x4200,16),('r',0x4300,24)]),initialization_seed=17,max_initialized_bytes=56)
s=BoomSharedMemoryService(m,BoomSharedMemoryContract())
s.bind(execution_id='previous',testcase_id='case',source_component='cpu',reset_epoch=1)
target=SimpleNamespace(memory_service=MemoryService(m,TransactionLedger()),routed_register_access_enabled=True,master_targets=())
class Window(DeviceWindow):
    def __post_init__(self): pass
r=DataflowRouter((Window('dma',0x4400,16,target),))
with patch.object(Path,'read_text',return_value='{}'):
    try: GeneratedBoomScenarioSession(Path('/unused'),repo=Path('.'),router=r,program=b'1234',shared_memory_service=s)
    except ValueError: pass
    else: raise AssertionError('already-bound shared service accepted before native startup')
PY
```

Run 1: exit 1.

```text
Traceback (most recent call last):
  File "<stdin>", line 20, in <module>
AssertionError: already-bound shared service accepted before native startup
```

Run 2: exit 0.

```text
(no output)
```


### Check 4

```bash
PYTHONPATH=src python3 - <<'PY'
from copy import deepcopy
from dataclasses import dataclass, FrozenInstanceError
import hashlib, inspect, json
from pathlib import Path
from unittest.mock import patch
from myfuzz.local_harness.boom_shared_memory import BoomSharedMemoryContract, BoomSharedMemoryService
from myfuzz.local_harness.boom_scenario_session import GeneratedBoomScenarioSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

def refused(call, kinds=(ValueError, RuntimeError)):
    try: call()
    except kinds: return
    raise AssertionError('expected refusal')

def memory(regions=None):
    return PersistentMemory(regions=regions or tuple(MemoryRegion(n,a,z) for n,a,z in
        [('source',0x4100,16),('destination',0x4200,16),('result',0x4300,24)]),
        initialization_seed=17,max_initialized_bytes=56)

@dataclass(frozen=True)
class SubpageWindow(DeviceWindow):
    def __post_init__(self):
        assert self.device_id=='dma' and self.base==0x4400 and self.size==16

class Target:
    routed_register_access_enabled=True
    master_targets=()
    def __init__(self,m):
        self.memory_service=MemoryService(m,TransactionLedger())
        self.calls=[]
    def routed_register_access(self,key,**kw):
        self.calls.append((key,deepcopy(kw)))
        return {'rdata':0x12345678}
    def write_register(self,*a,**kw):
        raise AssertionError('host register helper called')
    def read_register(self,*a,**kw):
        raise AssertionError('host register helper called')

class Native:
    execution_id='native-execution'
    reset_epoch=1
    last_samples=()
    def __init__(self):
        self._process=object(); self.queue=[]; self.offers=[]; self.pending_responses=0
        self.close_calls=0; self.edges=0
    def respond_external(self,**kw):
        self.offers.append(deepcopy(kw))
    def step_local(self,inputs):
        self.edges+=1
        result=self.queue.pop(0)
        self.pending_responses=int(not result['drained'])
        return result
    def close(self):
        self.close_calls+=1; self._process=None
    def identity_document(self):
        return {'native':'fixture'}

def adapter(shared=True):
    m=memory(); service=BoomSharedMemoryService(m,BoomSharedMemoryContract())
    target=Target(m)
    window=SubpageWindow('dma',0x4400,16,target) if shared else DeviceWindow('gpio',0x4000,16,target)
    router=DataflowRouter((window,))
    with patch.object(Path,'read_text',return_value='{"fixture":true}'):
        cpu=GeneratedBoomScenarioSession(Path('/unused'),repo=Path('.'),router=router,
            program=b'\x13\0\0\0',shared_memory_service=service if shared else None)
    native=Native(); cpu._native=native; cpu._case_id='case'; cpu._started=True; cpu.reset_epoch=1
    if shared:
        service.bind(execution_id=native.execution_id,testcase_id='case',source_component='cpu',reset_epoch=1)
    return cpu,native,service,target

def request(seq,address,opcode=0,value=0):
    return dict(channel='A',opcode=opcode,param=0,size=2,source=1,address=address,
        mask=15<<(address&7),data=value<<(8*(address&7)),request_sequence=seq,reset_epoch=1)

def observation(events=(),external=None,drained=False):
    return dict(accepted_events=tuple(events),external_request=deepcopy(external),
        reset=False,drained=drained)

def submit(cpu,native,q):
    raw={k:v for k,v in q.items() if k not in ('request_sequence','reset_epoch')}
    native.queue.append(observation((raw,),q))
    cpu.step_local({})

def accept_d(cpu,native):
    active=cpu._active
    q=active['request']
    native.queue.append(observation((dict(channel='D',source=q['source'],size=2,
        opcode=1 if q['opcode']==4 else 0,param=0,sink=0,beat=0,
        data=active['data'],external=True),),drained=True))
    cpu.step_local({})
    assert cpu._active is None and cpu.pending_responses==0

c=BoomSharedMemoryContract()
refused(lambda:BoomSharedMemoryContract(source_range=(0x4100,0x4120)))
try: c.source_range=(0x4000,0x4010)
except FrozenInstanceError: pass
else: raise AssertionError('mutable contract')
for bad in [
    (MemoryRegion('a',0x4100,16,readable=False),MemoryRegion('b',0x4200,16),MemoryRegion('c',0x4300,24)),
    (MemoryRegion('a',0x4100,16,aliases=(0x5100,)),MemoryRegion('b',0x4200,16),MemoryRegion('c',0x4300,24)),
    (MemoryRegion('a',0x4100,16),MemoryRegion('b',0x4200,16),MemoryRegion('c',0x4300,28))]:
    refused(lambda bad=bad:BoomSharedMemoryService(memory(bad),c))
with patch.object(Path,'read_bytes',return_value=b'drift'):
    refused(lambda:c.authenticate_source(Path('.')))
assert c.authenticate_source(Path('.'))['pmp_permission']=='requires_actual_cpu_pmp'

cpu,native,s,target=adapter()
assert cpu.mmio_ledger is s.service.ledger
assert getattr(cpu,'service',None) is s.service, 'Runner cannot drain actual CPU MemoryService events'
assert getattr(cpu,'memory',None) is s.memory, 'Runner cannot identify CPU shared memory object'
assert cpu.identity_document()['external_range']==(0x4000,0x5000)
assert cpu.identity_document()['memory_commit_authority'] is False
for seq,address,value in [(1,0x4100,0x12345678),(2,0x4104,0x89abcdef)]:
    q=request(seq,address,value=value)
    before=native.edges
    submit(cpu,native,q)
    assert native.edges==before+1 and not target.calls and cpu.pending_responses==1
    assert cpu._active['status']=='d_offered' and s.records[-1]['status']=='service_complete_d_pending'
    assert s.records[-1]['native_request']==q
    receipt=s.receipts[cpu._active['key']]
    assert receipt.commit_document()['width_bytes']==4
    assert all(cell['writer_event_id']==str(cpu._active['key']) for cell in receipt.commit_document()['enabled_byte_cells'])
    count=len(s.service.events); offers=len(native.offers)
    native.queue.append(observation((),q))
    cpu.step_local({})
    assert len(s.service.events)==count and len(native.offers)==offers
    accept_d(cpu,native)
    assert s.records[-1]['status']=='d_accepted'

# Native sequence 3 control high lane follows two memory operations on the same ledger.
q=request(3,0x4404,value=0x0fed0004)
submit(cpu,native,q)
assert not target.calls and cpu.router.pending_targets==('dma',)
callback=cpu.router._queued[0][-1]
assert cpu.router.drain_one('dma')
assert len(target.calls)==1 and target.calls[0][0].source_sequence==3
assert target.calls[0][1]['value']==0x0fed0004 and target.calls[0][1]['be']==15
assert cpu.router.acceptances[-1]['beat_bytes']==8
assert cpu.pending_responses==1 and cpu._active['status']=='d_offered'
refused(lambda:callback((0,0)))
accept_d(cpu,native)

# Return high-lane control data exactly once, then memory reads after the controls.
submit(cpu,native,request(4,0x440c,opcode=4))
assert cpu.router.drain_one('dma')
assert native.offers[-1]['data']==0x12345678<<32
accept_d(cpu,native)
for seq,address,value in [(5,0x4100,0x12345678),(6,0x4104,0x89abcdef)]:
    submit(cpu,native,request(seq,address,opcode=4))
    assert native.offers[-1]['data']==value<<(8*(address&7))
    snap=s.receipts[cpu._active['key']]
    assert len(snap.data)==len(snap.versions)==len(snap.writer_event_ids)==4
    assert all(writer==str(TransactionKey(native.execution_id,'case','cpu',1,'coherent-A-uncached',seq-4)) for writer in snap.writer_event_ids)
    accept_d(cpu,native)
assert len(s.records)==4 and len(s.receipts)==4 and s.memory.initialized_bytes==8

# Page holes, malformed shape, wrong sequence and epoch refuse before memory/provider.
before=s.memory.state_summary(); calls=len(target.calls); events=len(s.service.events)
for changed in [
    {'address':0x4000},{'address':0x4110},{'address':0x4210},{'address':0x4318},{'address':0x4410},
    {'size':3},{'opcode':6},{'param':1},{'mask':255},{'mask':True},
    {'source':8},{'reset_epoch':0},{'request_sequence':8}]:
    q=request(7,0x4108); q.update(changed)
    refused(lambda q=q:cpu._enqueue(q))
assert s.memory.state_summary()==before and len(target.calls)==calls and len(s.service.events)==events
q=request(7,0x4108)
for key in [
    TransactionKey('wrong','case','cpu',1,'coherent-A-uncached',7),
    TransactionKey(native.execution_id,'wrong','cpu',1,'coherent-A-uncached',7),
    TransactionKey(native.execution_id,'case','cpu',0,'coherent-A-uncached',7),
    TransactionKey(native.execution_id,'case','cpu',1,'other-channel',7)]:
    refused(lambda key=key:s.execute(key,q))
assert s.memory.state_summary()==before

# Closing revokes queued callbacks before native close; repeated close is safe.
queued,n,s2,t=adapter()
submit(queued,n,request(1,0x4400,value=1)); late=queued.router._queued[0][-1]
queued.end_case()
assert not queued.router.pending_targets and not t.calls and n._process is None
refused(lambda:late((0,0)))
queued.end_case()
assert queued.pending_responses==0

# In-place shared reset is explicitly refused after cancellation; fresh objects are required.
queued,n,s2,t=adapter()
submit(queued,n,request(1,0x4400,value=1)); late=queued.router._queued[0][-1]
refused(queued.reset_local)
assert not queued.router.pending_targets and n._process is None and not t.calls
refused(lambda:late((0,0)))
queued.end_case()

# A committed store remains recorded when its CPU D is cancelled.
pending,n,s3,t=adapter()
submit(pending,n,request(1,0x4100,value=55))
pending.end_case(); pending.end_case()
assert s3.records[0]['status']=='cancelled'
assert s3.records[0]['service_receipt']['performed_effect'] is True
assert s3.memory.initialized_bytes==4

# Default API and identity match the original v1 JSON byte for byte.
old,n,unused,t=adapter(False)
old._native=None
expected={'schema_version':'boom_scenario_session.v1','source_component':'cpu',
    'runtime_kind':'tilelink_coherent_cpu','native_artifact':{'fixture':True},'native_identity':None,
    'static_image':{'address':0x80000000,'bytes':4,'sha256':hashlib.sha256(b'\x13\0\0\0').hexdigest()},
    'native_ram_observation_addresses':(),'ram_model':'native_coherent_manager',
    'memory_commit_authority':False,'isa_retirement_authority':False,'runtime_verified':False,
    'generic_router_admitted':False,'defer_mmio':True}
assert json.dumps(old.identity_document(),separators=(',',':'))==json.dumps(expected,separators=(',',':'))
assert inspect.signature(GeneratedBoomScenarioSession).parameters['shared_memory_service'].default is None
assert old._validate_request(request(1,0x4000))=='control'
assert all(callable(getattr(old,name)) for name in ('begin_case','step_local','reset_local','end_case','close','begin_quiesce','coherent_report','coherent_coverage'))
print('PASS: exact layout/source/PMA, physical lanes and receipts, active-until-D, stable response, interleaved native keys, Router once, holes/shape/key/epoch refusal, cancellation/reset/idempotent close, byte-equivalent default identity/API')
PY
```

Run 1: exit 1.

```text
Traceback (most recent call last):
  File "<stdin>", line 112, in <module>
AssertionError: Runner cannot drain actual CPU MemoryService events
```

Run 2: exit 0.

```text
PASS: exact layout/source/PMA, physical lanes and receipts, active-until-D, stable response, interleaved native keys, Router once, holes/shape/key/epoch refusal, cancellation/reset/idempotent close, byte-equivalent default identity/API
```

Run 3 (final verification): exit 0.

```text
PASS: exact layout/source/PMA, physical lanes and receipts, active-until-D, stable response, interleaved native keys, Router once, holes/shape/key/epoch refusal, cancellation/reset/idempotent close, byte-equivalent default identity/API
```


### Check 5

```bash
PYTHONPATH=src python3 - <<'PY'
from copy import deepcopy
from dataclasses import dataclass, FrozenInstanceError
import hashlib, inspect, json
from pathlib import Path
from unittest.mock import patch
from myfuzz.local_harness.boom_shared_memory import BoomSharedMemoryContract, BoomSharedMemoryService
from myfuzz.local_harness.boom_scenario_session import GeneratedBoomScenarioSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

def refused(call, kinds=(ValueError, RuntimeError)):
    try: call()
    except kinds: return
    raise AssertionError('expected refusal')

def memory(regions=None):
    return PersistentMemory(regions=regions or tuple(MemoryRegion(n,a,z) for n,a,z in
        [('source',0x4100,16),('destination',0x4200,16),('result',0x4300,24)]),
        initialization_seed=17,max_initialized_bytes=56)

@dataclass(frozen=True)
class SubpageWindow(DeviceWindow):
    def __post_init__(self):
        assert self.device_id=='dma' and self.base==0x4400 and self.size==16

class Target:
    routed_register_access_enabled=True
    master_targets=()
    def __init__(self,m):
        self.memory_service=MemoryService(m,TransactionLedger())
        self.calls=[]
    def routed_register_access(self,key,**kw):
        self.calls.append((key,deepcopy(kw)))
        return {'rdata':0x12345678}
    def write_register(self,*a,**kw):
        raise AssertionError('host register helper called')
    def read_register(self,*a,**kw):
        raise AssertionError('host register helper called')

class Native:
    execution_id='native-execution'
    reset_epoch=1
    last_samples=()
    def __init__(self):
        self._process=object(); self.queue=[]; self.offers=[]; self.pending_responses=0
        self.close_calls=0; self.edges=0
    def respond_external(self,**kw):
        self.offers.append(deepcopy(kw))
    def step_local(self,inputs):
        self.edges+=1
        result=self.queue.pop(0)
        self.pending_responses=int(not result['drained'])
        return result
    def close(self):
        self.close_calls+=1; self._process=None
    def identity_document(self):
        return {'native':'fixture'}

def adapter(shared=True):
    m=memory(); service=BoomSharedMemoryService(m,BoomSharedMemoryContract())
    target=Target(m)
    window=SubpageWindow('dma',0x4400,16,target) if shared else DeviceWindow('gpio',0x4000,16,target)
    router=DataflowRouter((window,))
    with patch.object(Path,'read_text',return_value='{"fixture":true}'):
        cpu=GeneratedBoomScenarioSession(Path('/unused'),repo=Path('.'),router=router,
            program=b'\x13\0\0\0',shared_memory_service=service if shared else None)
    native=Native(); cpu._native=native; cpu._case_id='case'; cpu._started=True; cpu.reset_epoch=1
    if shared:
        service.bind(execution_id=native.execution_id,testcase_id='case',source_component='cpu',reset_epoch=1)
    return cpu,native,service,target

def request(seq,address,opcode=0,value=0):
    return dict(channel='A',opcode=opcode,param=0,size=2,source=1,address=address,
        mask=15<<(address&7),data=value<<(8*(address&7)),request_sequence=seq,reset_epoch=1)

def observation(events=(),external=None,drained=False):
    return dict(accepted_events=tuple(events),external_request=deepcopy(external),
        reset=False,drained=drained)

def submit(cpu,native,q):
    raw={k:v for k,v in q.items() if k not in ('request_sequence','reset_epoch')}
    native.queue.append(observation((raw,),q))
    cpu.step_local({})

def accept_d(cpu,native):
    active=cpu._active
    q=active['request']
    native.queue.append(observation((dict(channel='D',source=q['source'],size=2,
        opcode=1 if q['opcode']==4 else 0,param=0,sink=0,beat=0,
        data=active['data'],external=True),),drained=True))
    cpu.step_local({})
    assert cpu._active is None and cpu.pending_responses==0

# A provider failure may have acted; no forged D and unresolved ledger survives teardown.
cpu,n,s,t=adapter()
def uncertain(key,**kw):
    t.calls.append((key,kw))
    raise RuntimeError('provider effect uncertain')
t.routed_register_access=uncertain
submit(cpu,n,request(1,0x4400,value=7))
try: cpu.router.drain_one('dma')
except RuntimeError as e: assert str(e)=='provider effect uncertain'
else: raise AssertionError('provider failure hidden')
assert cpu.mmio_ledger.uncertain_keys and not n.offers
cpu.end_case()
assert cpu.pending_responses==1 and cpu.mmio_ledger.uncertain_keys
assert cpu.source_events[-1]['effect_may_have_occurred'] is True

# RESPOND failure preserves completed memory effects and the primary exception.
cpu,n,s,t=adapter()
def failed_response(**kw): raise RuntimeError('RESPOND transport failed')
n.respond_external=failed_response
try: submit(cpu,n,request(1,0x4100,value=77))
except RuntimeError as e: assert str(e)=='RESPOND transport failed'
else: raise AssertionError('RESPOND failure hidden')
assert s.records[0]['status']=='cancelled' and s.records[0]['service_receipt']['performed_effect']
assert s.memory.initialized_bytes==4 and n._process is None
cpu.end_case()

# Cleanup failure is chained without replacing the primary step failure.
cpu,n,s,t=adapter()
n.respond_external=failed_response
def failed_close():
    n._process=None
    raise RuntimeError('close failed')
n.close=failed_close
try: submit(cpu,n,request(1,0x4100,value=88))
except RuntimeError as e:
    assert str(e)=='RESPOND transport failed'
    assert str(e.__cause__)=='close failed'
else: raise AssertionError('primary/cleanup errors lost')

# Changing the router, exposed service, ledger, memory, target service or epoch refuses.
for change in ('router','service','ledger','memory','target_service','epoch'):
    cpu,n,s,t=adapter()
    state=s.memory.state_summary()
    if change=='router': cpu.router=DataflowRouter(cpu.router.windows)
    elif change=='service': cpu.service=MemoryService(s.memory,TransactionLedger())
    elif change=='ledger': cpu.mmio_ledger=TransactionLedger()
    elif change=='memory': cpu.memory=memory()
    elif change=='target_service': t.memory_service=MemoryService(s.memory,TransactionLedger())
    else: cpu.reset_epoch=2
    refused(lambda:cpu._enqueue(request(1,0x4100,value=99)))
    assert s.memory.state_summary()==state and not t.calls and not n.offers

# Unstarted factories pass full external page only in opt-in mode.
import myfuzz.local_harness.boom_scenario_session as module
for shared,want in [(True,(0x4000,0x5000)),(False,(0x4000,0x4010))]:
    cpu,old,s,t=adapter(shared)
    cpu._native=None; cpu._case_id=None; cpu._started=False
    if shared: s._binding=None
    created=[]
    class ConstructorNative(Native):
        def __init__(self,output,**kw):
            super().__init__(); created.append(kw)
        def begin_case(self,case): pass
        def load_program(self,program,**kw): self.program=program
    with patch.object(module,'GeneratedBoomCpuSession',ConstructorNative):
        cpu.begin_case('fresh-case')
    assert created[0]['external_range']==want
    cpu.end_case()
print('PASS: uncertain effect retention, no invented D, RESPOND/cleanup error preservation, runtime binding refusals, startup external ranges')
PY
```

Run 1: exit 0.

```text
PASS: uncertain effect retention, no invented D, RESPOND/cleanup error preservation, runtime binding refusals, startup external ranges
```

Run 2 (final verification): exit 0.

```text
PASS: uncertain effect retention, no invented D, RESPOND/cleanup error preservation, runtime binding refusals, startup external ranges
```


### Check 6

```bash
PYTHONPATH=src python3 - 3< <(git show HEAD:src/myfuzz/local_harness/boom_scenario_session.py) <<'PY'
import inspect, json, os, types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from myfuzz.local_harness.boom_scenario_session import GeneratedBoomScenarioSession
from myfuzz.scenario.router import DataflowRouter,DeviceWindow
original=types.ModuleType('myfuzz.local_harness._original_boom_adapter')
original.__package__='myfuzz.local_harness'
exec(compile(os.fdopen(3).read(),'<git HEAD boom adapter>','exec'),original.__dict__)
previous=original.GeneratedBoomScenarioSession
before=inspect.signature(previous)
after=inspect.signature(GeneratedBoomScenarioSession)
assert all(after.parameters[name]==parameter for name,parameter in before.parameters.items())
assert set(after.parameters)-set(before.parameters)=={'shared_memory_service'}
class Native:
    execution_id='native-run'
    reset_epoch=1
    pending_responses=0
    _process=object()
    def identity_document(self): return {'actual':'native fixture'}
for running in (False,True):
    for observations in ((),(0x80000100,0x80000200)):
        target=object()
        router=DataflowRouter((DeviceWindow('gpio',0x4000,16,target),))
        with patch.object(Path,'read_text',return_value='{"fixture":"identical-artifact"}'):
            old=previous(Path('/unused'),repo=Path('.'),router=router,program=b'1234',
                observed_ram_addresses=observations)
            new=GeneratedBoomScenarioSession(Path('/unused'),repo=Path('.'),router=router,
                program=b'1234',observed_ram_addresses=observations)
        if running:
            old._native=Native();new._native=Native()
        left=json.dumps(old.identity_document(),separators=(',',':')).encode()
        right=json.dumps(new.identity_document(),separators=(',',':')).encode()
        assert left==right
        assert not hasattr(new,'service') and not hasattr(new,'memory')
        for attr in ('artifact_kind','max_local_ticks_per_step','max_transaction_events_per_step',
                     'max_mmio_target_accesses_per_step','defer_mmio'):
            assert getattr(new,attr)==getattr(old,attr)
        for method in ('begin_case','step_local','reset_local','end_case','close','begin_quiesce',
                       'coherent_report','coherent_coverage','identity_document'):
            assert inspect.signature(getattr(new,method))==inspect.signature(getattr(old,method))
print('PASS: actual git HEAD default identity JSON byte-equivalent in four states; original constructor parameters/method signatures/constants preserved; default has no service/memory API')
PY
```

Run 1: exit 0.

```text
PASS: actual git HEAD default identity JSON byte-equivalent in four states; original constructor parameters/method signatures/constants preserved; default has no service/memory API
```

Run 2 (final verification): exit 0.

```text
PASS: actual git HEAD default identity JSON byte-equivalent in four states; original constructor parameters/method signatures/constants preserved; default has no service/memory API
```


### Check 7

```bash
python3 - <<'PY'
import ast
from pathlib import Path
for name in ('src/myfuzz/local_harness/boom_shared_memory.py','src/myfuzz/local_harness/boom_scenario_session.py'):
    ast.parse(Path(name).read_text(),filename=name)
print('PASS: both owned Python files parse')
PY
```

Run 1 (final verification): exit 0.

```text
PASS: both owned Python files parse
```


### Check 8

```bash
git diff --check -- src/myfuzz/local_harness/boom_scenario_session.py
```

Run 1 (final verification): exit 0.

```text
(no output)
```


### Check 9

```bash
sha256sum src/myfuzz/local_harness/boom_shared_memory.py src/myfuzz/local_harness/boom_scenario_session.py
```

Run 1 (final verification): exit 0.

```text
65e50934ed97ed4727a087908ccf560134dedf0fa2940e160adf848d3f2e6a44  src/myfuzz/local_harness/boom_shared_memory.py
fd92fb25549874d1a012182bdc20cd7677842db65bb3ddad373029f9f6de3f8f  src/myfuzz/local_harness/boom_scenario_session.py
```


## Final owned source hashes

- `boom_shared_memory.py`: `65e50934ed97ed4727a087908ccf560134dedf0fa2940e160adf848d3f2e6a44`.
- `boom_scenario_session.py`: `fd92fb25549874d1a012182bdc20cd7677842db65bb3ddad373029f9f6de3f8f`.

All six final verification commands exited 0. Production mutation stops at this report handoff; root will arrange independent review before Task 3 integration.

---

# BOOM Task 2 independent-review lifecycle fix — 2026-10-22

**Status: FIX IMPLEMENTED; ready for independent re-review.** This section supersedes the earlier source hash and mutation-stop point for the reviewed adapter. The shared-memory module has no change in this fix.

Read the final independent report `.superpowers/sdd/task-2-review.md` before mutation. Applied the receiving-code-review skill and verified both findings against the actual cleanup and Router source. The original cancellation-order and startup-primary failures were each reproduced inline before editing.

## Changes

- `_abort_pending` immediately detaches `self._active` and marks the captured active object cancelled, before any fallible cleanup. A late callback first tests active-object identity, so it refuses even if CPU close failed and the process remains reachable.
- Each control acceptance freezes its exact Router window, ledger, TransactionKey and the same payload fields that Router.enqueue uses. If Router cancellation fails, cleanup calls standard `ledger.cancel_accepted(key, payload)`, or recognizes a previously cancelled/complete terminal entry. This makes a retained queue undrainable before a future target effect; `target_ready` is explicitly checked. The queue is preserved and pending stays nonzero.
- If this exact-key ledger fallback also fails, cleanup attempts to close the frozen target object. Its Router/window reference remains reachable; queue and pending facts remain preserved. No generic Router code was changed.
- Queue cancellation/fallback, memory-service terminal update, diagnostic emission and CPU close each have separate error capture. Later cleanups are attempted after earlier failures. One failure propagates directly; multiple failures are retained in a `BaseExceptionGroup` on the current Python 3.12 runtime.
- `begin_case` chains cleanup failures beneath the original startup/load failure. The CPU handle is released only after close succeeds; failed-close handles remain reachable for another `end_case` cleanup attempt.
- `end_case` uses this cleanup once and removes the old unconditional second close. Shared-reset refusal likewise retains its policy error as primary and chains cleanup failures.
- Production change in this fix is limited to the originally owned `boom_scenario_session.py`; `boom_shared_memory.py` remains byte-identical.

## Focused inline evidence

All checks below are pure software and mocked lifecycle exercises. No persistent test file, test suite, native execution, native build, RTL change, staging, commit or remote action occurred. A tool-session store was unavailable on this follow-up, so the previously recorded inline fixture was read from this report in memory; no fixture/test file was created.


### Review-fix check 1

```bash
PYTHONPATH=src python3 - <<'PY'
from pathlib import Path
import re
report=Path('.superpowers/sdd/task-2-report.md').read_text()
baseline=next(c for c in re.findall(r"```bash\n(.*?)\n```",report,re.S) if 'def adapter(shared=True):' in c)
fixture=baseline.split("\nc=BoomSharedMemoryContract()")[0].split("<<'PY'\n",1)[1]
exec(fixture)

cpu,n,s,t=adapter()
submit(cpu,n,request(1,0x4404,value=7))
active=cpu._active
callback=cpu.router._queued[0][-1]
def failed_cancel(ledger): raise RuntimeError('router cancel failed')
cpu.router.cancel_for_ledger=failed_cancel
try: cpu._abort_pending('review_failure')
except RuntimeError: pass
assert cpu._active is None and active['status']=='cancelled', 'abort retained active callback authority'
assert cpu.mmio_ledger._entries[active['key']].status=='cancelled', 'retained queue remains drainable'
assert cpu.pending_responses==1 and cpu.router.pending_targets==('dma',)
assert cpu.router.drain_one('dma') is False and not t.calls and not n.offers
refused(lambda:callback((0,0)))
print('PASS: cancellation failure revokes active and makes retained queue undrainable before target effects')
PY
```

Run 1: exit 1.

```text
Traceback (most recent call last):
  File "<stdin>", line 16, in <module>
AssertionError: abort retained active callback authority
```

Run 2: exit 0.

```text
PASS: cancellation failure revokes active and makes retained queue undrainable before target effects
```


### Review-fix check 2

```bash
PYTHONPATH=src python3 - <<'PY'
from pathlib import Path
import re
report=Path('.superpowers/sdd/task-2-report.md').read_text()
baseline=next(c for c in re.findall(r"```bash\n(.*?)\n```",report,re.S) if 'def adapter(shared=True):' in c)
fixture=baseline.split("\nc=BoomSharedMemoryContract()")[0].split("<<'PY'\n",1)[1]
exec(fixture)

import myfuzz.local_harness.boom_scenario_session as module
cpu,old,s,t=adapter(False)
cpu._native=None;cpu._case_id=None;cpu._started=False
created=[]
class StartupNative(Native):
    def __init__(self,*a,**kw):
        super().__init__();created.append(self)
    def begin_case(self,case): raise RuntimeError('startup primary')
    def close(self): raise RuntimeError('startup close failure')
with patch.object(module,'GeneratedBoomCpuSession',StartupNative):
    try: cpu.begin_case('new-case')
    except RuntimeError as e:
        assert str(e)=='startup primary', 'cleanup replaced startup primary'
        assert str(e.__cause__)=='startup close failure'
    else: raise AssertionError('startup error was hidden')
assert cpu._native is created[0], 'native handle lost after failed close'
print('PASS: startup primary and cleanup both retained, failed-close handle remains reachable')
PY
```

Run 1: exit 1.

```text
Traceback (most recent call last):
  File "/home/qinkejiu/myfuzz/src/myfuzz/local_harness/boom_scenario_session.py", line 182, in begin_case
    self._native.begin_case(testcase_id)
  File "<stdin>", line 15, in begin_case
RuntimeError: startup primary

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "<stdin>", line 18, in <module>
  File "/home/qinkejiu/myfuzz/src/myfuzz/local_harness/boom_scenario_session.py", line 191, in begin_case
    self._native.close()
  File "<stdin>", line 16, in close
RuntimeError: startup close failure

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "<stdin>", line 20, in <module>
AssertionError: cleanup replaced startup primary
```

Run 2: exit 0.

```text
PASS: startup primary and cleanup both retained, failed-close handle remains reachable
```


### Review-fix check 3

```bash
PYTHONPATH=src python3 - <<'PY'
from pathlib import Path
import re
report=Path('.superpowers/sdd/task-2-report.md').read_text()
baseline=next(c for c in re.findall(r"```bash\n(.*?)\n```",report,re.S) if 'def adapter(shared=True):' in c)
fixture=baseline.split("\nc=BoomSharedMemoryContract()")[0].split("<<'PY'\n",1)[1]
exec(fixture)

def messages(error):
    if isinstance(error,BaseExceptionGroup):
        return [message for child in error.exceptions for message in messages(child)]
    return [str(error)]

# Both cancellation and CPU close fail: fallback ledger is terminal first,
# stale callback cannot respond even while the failed-close native stays alive.
cpu,n,s,t=adapter()
submit(cpu,n,request(1,0x440c,value=0x12345678))
active=cpu._active; late=cpu.router._queued[0][-1]
def cancel_failure(ledger):
    assert cpu._active is None and active['status']=='cancelled'
    raise RuntimeError('cancel failure')
def close_failure():
    assert cpu._active is None
    raise RuntimeError('native close failure')
cpu.router.cancel_for_ledger=cancel_failure
n.close=close_failure
try: cpu.end_case()
except BaseExceptionGroup as e:
    assert messages(e)==['cancel failure','native close failure']
else: raise AssertionError('cleanup errors lost')
assert cpu._native is n and n._process is not None
assert cpu._active is None and cpu.pending_responses==1
assert cpu.mmio_ledger._entries[active['key']].status=='cancelled'
assert cpu.router.drain_one('dma') is False and not t.calls
try: late((0,0))
except RuntimeError as e: assert str(e)=='stale/duplicate BOOM router callback'
else: raise AssertionError('late callback retained authority')

# If Router cancelled the ledger but failed before queue publication,
# fallback accepts its existing terminal status without closing the target.
cpu,n,s,t=adapter()
submit(cpu,n,request(1,0x4404,value=9))
ledger=cpu.mmio_ledger;key=cpu._active['key'];payload=deepcopy(cpu._active['control_payload'])
target_closes=[]
t.close=lambda:target_closes.append(True)
def partial_cancel(actual):
    actual.cancel_accepted(key,payload)
    raise RuntimeError('cancel publication failure')
cpu.router.cancel_for_ledger=partial_cancel
try: cpu.end_case()
except RuntimeError as e: assert str(e)=='cancel publication failure'
else: raise AssertionError('publication failure hidden')
assert ledger._entries[key].status=='cancelled' and cpu.router.drain_one('dma') is False
assert not target_closes and not t.calls and n._process is None

# If both ledger cancellation paths fail, the exact target is closed before
# diagnostics and native close. All errors and the residual queue remain.
cpu,n,s,t=adapter()
submit(cpu,n,request(1,0x4404,value=10))
active=cpu._active;order=[];target_alive=[True]
def cancel_failure(ledger):
    assert cpu._active is None
    order.append('router');raise RuntimeError('router blocked')
def ledger_failure(key,payload):
    assert key is active['key'] and payload==active['control_payload']
    order.append('ledger');raise RuntimeError('ledger blocked')
def target_close():
    order.append('target');target_alive[0]=False
def target_access(key,**kw):
    if not target_alive[0]: raise RuntimeError('target is closed')
    raise AssertionError('target effect after failed cancellation')
def diagnostic(*a,**kw):
    order.append('diagnostic');raise RuntimeError('diagnostic blocked')
real_close=n.close
def native_close():
    order.append('native');real_close()
cpu.router.cancel_for_ledger=cancel_failure
cpu.mmio_ledger.cancel_accepted=ledger_failure
t.close=target_close;t.routed_register_access=target_access
cpu._event=diagnostic;n.close=native_close
try: cpu.end_case()
except BaseExceptionGroup as e:
    assert messages(e)==['router blocked','ledger blocked','diagnostic blocked']
else: raise AssertionError('fallback failures hidden')
assert order==['router','ledger','target','diagnostic','native']
assert cpu._active is None and cpu.pending_responses==1 and cpu.router.pending_targets==('dma',)
assert n._process is None and not target_alive[0] and not t.calls
try: cpu.router.drain_one('dma')
except RuntimeError as e: assert str(e)=='target is closed'
else: raise AssertionError('closed target unexpectedly delivered')

# Every remaining cleanup still runs if target close also raises.
cpu,n,s,t=adapter()
submit(cpu,n,request(1,0x4400,value=11))
cpu.router.cancel_for_ledger=lambda ledger:(_ for _ in ()).throw(RuntimeError('router error'))
cpu.mmio_ledger.cancel_accepted=lambda *a:(_ for _ in ()).throw(RuntimeError('ledger error'))
t.close=lambda:(_ for _ in ()).throw(RuntimeError('target close error'))
n.close=lambda:(_ for _ in ()).throw(RuntimeError('cpu close error'))
try: cpu.end_case()
except BaseExceptionGroup as e:
    assert messages(e)==['router error','ledger error','target close error','cpu close error']
else: raise AssertionError('close failures hidden')
assert cpu._native is n and cpu._active is None and cpu.pending_responses==1
assert cpu.source_events[-1]['kind']=='boom_external_response_cancelled'

# A failing service terminal update and diagnostic cannot skip native close.
cpu,n,s,t=adapter()
submit(cpu,n,request(1,0x4100,value=99))
receipt=s.receipts[cpu._active['key']]
s.finish=lambda *a,**kw:(_ for _ in ()).throw(RuntimeError('finish error'))
cpu._event=lambda *a,**kw:(_ for _ in ()).throw(RuntimeError('diagnostic error'))
try: cpu.end_case()
except BaseExceptionGroup as e: assert messages(e)==['finish error','diagnostic error']
else: raise AssertionError('service/diagnostic errors hidden')
assert n._process is None and cpu._native is None and cpu._active is None
assert receipt.commit_document()['performed_effect'] is True
assert s.records[0]['status']=='service_complete_d_pending'

# Startup/load failures remain primary; each failed-close handle is retryable.
import myfuzz.local_harness.boom_scenario_session as module
for failed_phase in ('begin','load'):
    cpu,unused,s,t=adapter(False)
    cpu._native=None;cpu._case_id=None;cpu._started=False
    created=[]
    class StartupNative(Native):
        def __init__(self,*a,**kw):
            super().__init__();created.append(self)
        def begin_case(self,case):
            if failed_phase=='begin': raise RuntimeError('begin primary')
        def load_program(self,*a,**kw): raise RuntimeError('load primary')
        def close(self): raise RuntimeError('close cleanup')
    with patch.object(module,'GeneratedBoomCpuSession',StartupNative):
        try: cpu.begin_case('failed-case')
        except RuntimeError as e:
            assert str(e)==failed_phase+' primary' and str(e.__cause__)=='close cleanup'
        else: raise AssertionError('startup/load failure hidden')
    assert cpu._native is created[0] and cpu._case_id is None
    cpu._native.close=lambda: setattr(created[0],'_process',None)
    cpu.end_case()
    assert created[0]._process is None and cpu._native is None

print('PASS: cancellation/close failure matrix, undrainable residual queues, exact target fallback close, all cleanup attempts/errors retained, startup/load primary and retryable handles')
PY
```

Run 1: exit 0.

```text
PASS: cancellation/close failure matrix, undrainable residual queues, exact target fallback close, all cleanup attempts/errors retained, startup/load primary and retryable handles
```


### Review-fix check 4

Re-executed the exact previously recorded inline command above containing this unique marker:

`Runner cannot drain actual CPU MemoryService events`.

Run 1 (final post-fix verification): exit 0.

```text
PASS: exact layout/source/PMA, physical lanes and receipts, active-until-D, stable response, interleaved native keys, Router once, holes/shape/key/epoch refusal, cancellation/reset/idempotent close, byte-equivalent default identity/API
```


### Review-fix check 5

Re-executed the exact previously recorded inline command above containing this unique marker:

`provider effect uncertain`.

Run 1 (final post-fix verification): exit 0.

```text
PASS: uncertain effect retention, no invented D, RESPOND/cleanup error preservation, runtime binding refusals, startup external ranges
```


### Review-fix check 6

Re-executed the exact previously recorded inline command above containing this unique marker:

`actual git HEAD default identity`.

Run 1 (final post-fix verification): exit 0.

```text
PASS: actual git HEAD default identity JSON byte-equivalent in four states; original constructor parameters/method signatures/constants preserved; default has no service/memory API
```


### Review-fix check 7

```bash
python3 - <<'PY'
import ast
from pathlib import Path
for name in ('src/myfuzz/local_harness/boom_shared_memory.py','src/myfuzz/local_harness/boom_scenario_session.py'):
    ast.parse(Path(name).read_text(),filename=name)
print('PASS: both Task2 Python files parse after review fix')
PY
```

Run 1 (final post-fix verification): exit 0.

```text
PASS: both Task2 Python files parse after review fix
```


### Review-fix check 8

```bash
git diff --check -- src/myfuzz/local_harness/boom_scenario_session.py
```

Run 1 (final post-fix verification): exit 0.

```text
(no output)
```


### Review-fix check 9

```bash
sha256sum src/myfuzz/local_harness/boom_shared_memory.py src/myfuzz/local_harness/boom_scenario_session.py
```

Run 1 (final post-fix verification): exit 0.

```text
65e50934ed97ed4727a087908ccf560134dedf0fa2940e160adf848d3f2e6a44  src/myfuzz/local_harness/boom_shared_memory.py
6c11d17db2335610ebf442d70d55395b3e9ad25cdeaebe10f4a49835bca80768  src/myfuzz/local_harness/boom_scenario_session.py
```


## Post-fix source hashes and handoff

- `boom_shared_memory.py`: `65e50934ed97ed4727a087908ccf560134dedf0fa2940e160adf848d3f2e6a44` (unchanged).
- `boom_scenario_session.py`: `6c11d17db2335610ebf442d70d55395b3e9ad25cdeaebe10f4a49835bca80768`.

Both focused red assertions passed after the fix; the cancellation/close failure matrix and six final core/lifecycle/compatibility/AST/diff/hash commands exited 0. Residual queues are deliberately retained and pending stays nonzero when Router cancellation fails. If both ledger cancellation and target close fail, the error group preserves every error and the attempt must remain aborted; no subsequent target scheduling is authorized by this cleanup result.

Code mutation stops here for root re-review. Native execution/build remains unperformed.

## Second-review Important repair: failed shared terminal update stays pending

The independent follow-up in `task-2-review-b.md` found that a failing
shared `finish(cancelled)` could leave an actual service record pending after
active callback revocation and native close, while the old pending predicate
reported0. The preceding handoff hashes/approval describe the earlier source;
the frozen revision below supersedes that adapter hash and awaits independent
delta review.

Only `boom_scenario_session.py` changed. Callback authority is still revoked
before fallible cleanup. A separate pending-terminal registry retains the
original accepted active object, complete key/request, prior status, abort
reason and last cleanup error until the service record actually becomes
terminal. `pending_terminal_updates` exposes detached diagnostics. Truthful
`pending_responses` now counts both actual nonterminal shared records and this
registry, independently of native-handle or active-callback state.

End-case retries only the terminal metadata transition for retained entries;
it does not re-execute the MemoryService operation, Router target or native D.
Actual terminal record state is inspected before retry, so an already
terminal update is not duplicated. Missing/ambiguous records or unsuccessful
finish calls remain retained and raise cleanup errors.

Abort also makes the session terminal for future begin/step/quiesce and
direct internal enqueue work. This blocks new effects even if native close
itself fails and its handle remains available for cleanup retry. Earlier
control-ledger cancellation/fallback, primary exception preservation and
native-close retries remain in place. Default register-only identity is
unchanged; no shared service, Router or Task4 verifier was modified.

Inline software checks used real PersistentMemory, MemoryService and
BoomSharedMemoryService objects with a real accepted memory write/receipt,
an adapter allocated without constructing native resources, and a no-process
native stub. They injected failing terminal updates with native close success
and native close failure. Exact results:

```text
abort errors preserved: RuntimeError
old pending predicate RED:0 with actual unfinished service record
GREEN: unfinished key/request retained,pending1,new work refused; explicit cleanup retry resolves metadata,pending0,no RAM effect; close_failure= False
abort errors preserved: ExceptionGroup
GREEN: unfinished key/request retained,pending1,new work refused; explicit cleanup retry resolves metadata,pending0,no RAM effect; close_failure= True
```

Each case checked the retained full transaction/request/error diagnostics,
refused further running/enqueue operations, actual native-close attempt,
unchanged complete memory state_summary, and explicit subsequent cleanup retry
after restoring the terminal metadata operation. The retry resolved only the
service status to cancelled and cleared pending state; it created no RAM effect.
Syntax compilation exited0. No test suite/new test file, build, native,
remote operation or commit was performed.

Final frozen hashes for independent review:

```text
65e50934ed97ed4727a087908ccf560134dedf0fa2940e160adf848d3f2e6a44  src/myfuzz/local_harness/boom_shared_memory.py (unchanged)
d92c56fc9bc18640f6174a462ef506f857a1d41efcedea2b9ceeb624a2a81915  src/myfuzz/local_harness/boom_scenario_session.py
```

Implementation is frozen for r11 independent delta review. No native
acceptance or overall system status is upgraded by these inline checks.


