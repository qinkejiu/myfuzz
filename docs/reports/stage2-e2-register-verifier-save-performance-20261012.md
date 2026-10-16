# Verifier-enabled save: read-only performance evidence

2026-10-12. No production changes, no additional RTL execution. Offline calls below parse the already-produced14case JSON and validate comparison data; they do not install a Session, restore access authority or execute programs.

The failed actual run reached all14cases139.288881s, before encode142.831598s, after encode156.267697s, before finish159.231551s, after finish172.127849s and save entry172.127908s. Only about7.87seconds remained in the unchanged180-second generation budget. Thus save timeout does not itself establish that one new verifier validator caused the overrun.

On the actual outputs from `runs/stage2-e2-register-verifier-cli-20261012`:

| Offline component | Measured wall seconds | Evidence |
|---|---:|---|
| `validate_register_program_verifier_session_document` |0.0368|333830-byte wrapper,13 certificates,27 observed access validations;2300 `_json` calls consume0.026s |
| `_validate_register_manifest` over all14actual manifests |0.6897|One runtime configuration serializes to2361998bytes; canonical JSON consumes about0.493s; profiler includes initial imports |
| `validate_ordinary_apb_access_session_document` |0.5916|Actual complete28association state and its configuration |

These are software measurements on the current code snapshot, not a replacement resource receipt or a successful actual save. The live verifier `report()` path is separately being optimized by Root and was not restored from these files.

The writer calls `validate_register_program_plan` then `validate_register_program_state`, both of which must validate nested saved data. It then repeats the ordinary and verifier closed-channel validations to bind their configuration to the authenticated Session manifest. It canonicalizes the same large runtime configuration against state and Session config, regenerates each ordinary GPIO base artifact to verify its actual identity, writes plan/trace/state and hashes the run envelope. `_sources(assembly)` additionally computes code-owned AST transitive closure and file hashes. The selector repeats authenticated input reading and closed validation before constructing any actual factory. These boundaries must remain before mkdir/factory effects.

A safe optimization can retain one per-call validated register document and its detached state, pass those only through private internal helpers, and reuse canonical bytes of the expected startup configuration for exact comparison. Keep a strict traversal/type check on each candidate document so bool/int substitutions remain rejected. Cache expensive expected configuration canonical bytes or source path discovery only against actual immutable startup pins; compare current file hashes at every required command/export boundary. Do not accept saved `validated=True`, cached saved source paths, a saved digest without rehash, or a saved wrapper as authority. Preserve ordinary GPIO regeneration and same-alias/native-trace/causal-mode checks; consider deduplicating only already-computed results within the same writer invocation.

Meaningful TDD should count real validation/canonicalization invocations and bytes, then show reduction while existing tampered configuration/field metadata/receipt/RAM/source drift/default-off/schema17 tests remain green. Additional component profiling should separate full plan/state validation, GPIO regeneration, source-closure traversal and JSON output; aggregate wall timeout is insufficient to select a weaker validation path. Retain historical failed evidence and use a new actual directory after source freeze.

## Second actual timeout: exact pre-mkdir component profile

The verifier-v2 actual run again retained14 complete cases but exhausted the180-second generation budget before mkdir. Allcases137.065s; encode139.077→148.927s; finish151.976→162.191s. About17.8seconds remained for pre-save validation.

Offline comparison reconstruction used the historical identical bootstrap/template/state structural shell, replaced all14 manifests and runtime configuration with v2 actual case documents, and attached v2 actual startup/ordinary/verifier outputs. This is **not** a recovered live Session or authority; it is an input to pure saved-document validation, which passed. For GPIO checks the historical identical artifact identity shell was paired with the actual v2 cache build_identity; both strict generated-session checks passed. No command, build or RTL worker ran.

| Exact component | Profile wall seconds | Dominant evidence |
|---|---:|---|
| `_validate_saved_register_documents` |9.378|plan5.432/state3.781; `_register_plain_json` about14.8million calls/5.142s; JSON dumps2.423s; ordinary validator1.281s |
| `_sources(enabled)` |2.187|279 current code-owned paths; includes AST host closure discovery |
| `_verify_ordinary_gpio_identity(gpio_a)` |5.028|strict generated session regeneration; local_build_identity/_prepare3.651s; _host_sources2.641s; crawler2.028s |
| `_verify_ordinary_gpio_identity(gpio_b)` |5.588|same independent identity check; local_build_identity/_prepare3.671s; _host_sources2.658s; crawler2.649s |

The measured prechecks already total about22.18seconds, consistent with the17.8-second residual budget being insufficient. cProfile instrumentation overhead affects these wall figures; they are attribution evidence, not an exact prediction or a successful resource gate.

Safe next TDD units are: (1) remove repeated plain-JSON traversal/canonicalization of already validated *per-invocation* startup configuration while retaining strict traversal and exact bool/int comparison for each candidate; (2) reuse current code-owned host source discovery within a single writer/selector verification invocation, while still hashing current file bytes and validating each alias-specific generated artifact/build identity. Do not skip generic target validation, replace regeneration with saved digests, install a global unchecked cache or reuse a saved source-path list. Tests should count actual large-config traversals/host discovery, demonstrate identical pre-mkdir rejection for source drift/foreign alias/causal extension/trace hash mismatch, and preserve default-off identity layouts. Optimize before expanding the next actual alias gate; keep all timeout directories unchanged.

## v3 actual partial bundle: tail cost without a profiler

v3 also exhausted180seconds: allcases136.658s, encode138.600→147.296s, finish150.309→159.644s, save about160→180s. Unlike earlier runs, the actual partial bundle contains plan39129199bytes, trace19317945bytes and runtime state31410992bytes. Session manifest/identity/report/summary are absent; they must not be fabricated into successful evidence.

`/tmp/stage2-register-v3-tail-profile.py` measured those actual files (all byte SHAs recorded in `/tmp/stage2-register-v3-tail-profile.json`) without cProfile or a worker. Actual plan/state closed validation passed in4.795s. JSON re-encoding plan/state/trace took0.346/0.282/0.094s, temporary-file writes0.007/0.005/0.004s and hashes0.036s total. `_sources` took2.149s for279paths. Therefore JSON output and SHA hashing are not the20-second save bottleneck. Missing manifest encoding was measured only with an explicitly separate historical comparison shell:11.79MB/.103s; that is not the actual v3 manifest or authenticated identity and was never written into the run directory.

The integration writer independently discovers code-owned host closure in ordinary-channel validation, verifier-channel validation, each of two strict GPIO build identity regenerations and the ordinary/verifier union inside `_sources`. These equivalent discoveries must be counted in a complete software writer fixture before changing behavior. A minimal optimization design is a private bounded invocation-scoped source-discovery context, entered by writer/selector and discarded on return/exception. It may reuse only paths/material computed from current code-owned roots, never saved paths, flags or hashes. Every required current-content SHA check and each alias-specific full artifact/driver/build identity regeneration remains. Cache keys must include current actual profile/lock/source context; mutations of these during a verification invocation cause rejection. No global unchecked cache or alias-name shortcut.

Meaningful RED is repeated actual `_host_sources`/source crawler invocation count under a full nonempty software authenticated writer/selector, then GREEN reduced discovery with all existing foreign alias/trace/config/causal/source drift pre-mkdir/pre-factory failures. Source/config drift between two alias checks must reject even when discovery paths are cached. This optimization is not implemented or approved as successful by this report; no extra actual gate ran.

## Invocation-scoped discovery implementation: software checkpoint

The minimal scoped implementation is now a frozen candidate in `local_harness/build.py` (`726fa1bfb76f87550debe3c8d323359cf426f8b9cc31f3573657ddb2031fb5c6`) and register integration (`7fe28b291fd2f2164db5edcaffd6ad7b8c0a5a6a52d43d82f87cc974c8583774`). `host_source_discovery_scope()` discovers from current code-owned roots once, snapshots actual bytes and every seed/import candidate existence probe, and rereads/checks them on each reuse. Nested scopes isolate their cache and restore the outer scope; exceptional exit only resets context. Discovery methods, parser/import resolution, root and both context/access aliases are pinned. Default no-scope behavior retains independent discovery. Scoped `_prepare` rechecks before an existing prepared-cache hit.

The writer owns a scope for its invocation. Selector preflight owns a separate scope that exits before constructing fresh runtime/factory or executing commands. No scope/cache spans fresh execution. Each alias still undergoes full strict generated-session identity regeneration; every current-content/probe check remains. The public writer description is retained and old CLI output is unchanged.

TDD checkpoint: four missing-API REDs were observed; public writer/selector dispatch missing-scope RED was also observed. Final relevant software command ran the four scope tests, one dispatch discovery call-count fixture, cached scalar identity tests and six non-compilation build identity checks:13passed/3subtests/4excluded actual-build tests in45.52s. Dispatch fixtures prove scope boundaries and real discovery counts, not a complete authenticated writer. Full nonempty saved-file/verifier pipeline and independent method/context-alias boundary tests are being run by Root/reviewer; no final actual-success or performance claim is granted at this checkpoint.

## v4 complete artifacts and process-terminal distinction

v4 saved its authenticated bundle at178.245092s and printed final summary, but resource supervision ended `wall_timeout` at180.092762s. `check.py` has already called `finish`; its final branch only checks `_finished` and therefore does not call finish again. The supervisor checks wall expiry before process.poll; this is a boundary-ordering risk but the available evidence does not prove the child had already exited. Interpreter/global-object release and process polling are plausible remaining costs, not measured attribution. Retain resource status124 rather than promoting generation to resource-complete.

Using the **actual v4** manifest/plan/state/trace, `/tmp/stage2-register-v4-writer-profile.py` ran the complete production writer offline in a temporary directory:14.641192s, successful exact identity `d79623d4c8b606941823f349ee9a8b4f015d1ee16c6ce457650e15a37d6994da`, identical to the saved original. No historical shell, Session, factory, command replay or live authority was restored; temporary comparison bundle was deleted afterward. Input byte SHAs/source SHA/provenance are saved in `/tmp/stage2-register-v4-actual-writer-profile.json`. This validates actual writer comparison behavior and cost, not a new native resource gate.

To measure the remaining exit tail in a future separately recorded script, place monotonic markers after summary write/print and at a bounded cleanup/atexit boundary, retain actual child poll/termination timing and make cleanup release large comparison copies before the last marker. Do not use os._exit to conceal cleanup, skip authenticating facts, enlarge180seconds or rewrite the existing timeout receipt. A prepared-cache host-closure blindspot has meanwhile been reproduced as a next-package issue and is separately designed; current frozen scope success cannot be extended to that case without its RED/GREEN.
