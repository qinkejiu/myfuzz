# Next generic APB storage integration brief

2026-10-17; design/source inspection only. Basis bd1c3b8, source contract2dbcc2d reviewed d5a7f5f, and existing F4 new-IP design. No frozen module or shared core changed; no frontend/model/build/native/remote or new test run. Below are proposed RED controls, not executed results.

## Observed seams that must remain closed

- `runtime_renderer.py` adds current GPIO probes through a named profile branch; generic APB already has actual ABI-derived APB trace and canonical whole-wrapper/runtime re-projection. A new source-owned probe path must use registered source selection, never a second named timer factory.
- `NativeResetObservation.__init__` requires exact GeneratedPulpGpioSession. `session._native_reset_check_producers` additionally pins exact class, inherited methods, GPIO method table, base session/build/wire/Popen functions and actual build issuance. Generic APB legitimately overrides begin_case/reset_local and needs its own exact resolved method table, not relaxed base-method equality.
- `NativeResetObservation._actual_producer_frame` and `GpioRegisterVersionAuthority._actual_command` check the real `_command_impl` frame/receipt identity. An extra callback wrapper would change the frame chain. Keep direct callbacks from the real base producer; a registry may select a pinned consumer but must not impersonate the producer frame.
- `_command_impl` currently directly dispatches the GPIO weak-key authority registry after parsed reset-command observation and before committing sequence/ticks. Source/process/epoch/command uncertainty revokes issuance. GPIO behavior/order and existing method pin maps must remain regression invariants.
- Runner `NativeResetEvidence` separately requires GPIO targets and exact CPU/router/ledger bindings. It is not automatically generalized by session support and grants no storage/version rights itself.

## Recommended first atomic increment: opt-in generation/probe only

Add a v2 optional `apb_storage_observations` record with exact endpoint_id/contract_id/register; at most one per APB target endpoint. Absence must preserve old v2 document bytes (no unconditional empty key). Reject foreign endpoint/protocol, duplicates, unknown fields/expression/evidence callbacks and nonregistered source before generating the selected probe. Selection reuses the already reviewed source contract.

Use a dedicated `storage_probes` raw snapshot group and `storage_probe_ports` metadata, rather than pretending internal storage is an ordinary external physical pin or CPU protocol tap. Probe set: selected32-bit storage, actual normalized harness reset, and APB address/control/data/error wires derived from exact structural ABI. Port names/widths/expressions are code-owned. Input ownership and bus/DUT connections remain unchanged; every new output is read-only.

This increment may state generated_expression/source_mapped only. `hierarchy_verified`, native/reset/version/source authority stayfalse. Full prospective `u_component.u_dut.TIMER_GEN[0].timer_i.regs_q[1]` remains unverified until the later actual generated elaboration/build plus native sample gate; no declaration, string match, saved ABI fixture or successful codegen supplies that missing fact.

### Exact proposed owned files for immediate authorization

| File | Change |
|---|---|
| new `local_harness/apb_storage_probe_contract.py` | Closed request selector, source-contract revalidation, probe document, exact canonical generated wiring checks; no tokens |
| `local_harness/tuning.py` | One optional bounded selector record; default document identities unchanged |
| `local_harness/apb3_register_template.py` | Allow that selector only for the exact existing full-word APB policy/endpoint; no setup/producer fallback |
| `local_harness/runtime_renderer.py` | Generic APB opt-in read-only output assignments/metadata and source-contract/probe-module implementation pins |
| `local_harness/driver_renderer.py` | Optional storage_probes snapshot/maxima/reply reservation; absent selection CPP/READY/tick bytes unchanged |
| `local_harness/native_physical_observation.py` | Canonical projection includes storage metadata/probe ports, catches rewiring/fake drivers just as full runtime comparison does |
| new `tests/local_harness/test_apb_storage_probe_generation.py` | Pure RED controls described below; saved frontend facts explicitly fixture-only |
| owned report/receipts | Exact RED/GREEN/source pins and prospective hierarchy/native boundary |

No session/build/reset/version/F4 admission edit in this first increment. Generic session already retains unknown nested measured groups in raw samples; it must not export storage values as a granted prerequisite. Build runtime/driver exact regeneration and host source discovery should capture these new code bytes without changing closed driver-only keys. If an existing historical AST extraction test compares the entire current body, update only that historical assertion explicitly to distinguish the previously proven extraction from this new opt-in feature; do not broaden payload normalization or skip unrelated regressions. Coordinate renderer ownership with root/CPU agent before editing.

### Concrete source-only RED sequence

1. Exact selector parsing and JSON roundtrip; missing selector leaves old APB/OBI/AHB requests/CPP unchanged. Wrong source, GPIO name spoof, wrong register/expr, endpoint, duplicate and bool width reject.
2. Actual timer profile + saved physical facts render selected storage group with exact source/contract digests, storage32/reset1/APB role widths and canonical expressions. These facts are software generation evidence only.
3. Compare old/new non-opt-in wrapper/runtime/CPP/tick/reset/READY bytes. Verify no new protocol input or tick call and no hidden setup/probe read or expected-value producer.
4. Canonical re-projection rejects caller-rehashed comment/procedural tap, detached DUT connection, wrong hierarchy/index, alias decode, source params, reset polarity, duplicate driver/port and metadata digest.
5. Real canonical RESULT parsing retains pre/post storage group and declared conservative payload bounds; malformed widths/missing group reject in the dedicated consumer, without treating generic nested JSON as trusted hardware.
6. All subprocess/frontend/model/build constructors guarded; only actual saved fact/source inspection permitted. End this atomic increment at source/codegen review, not native or live-version acceptance.

## Later increments, separately authorized

**B: closed producer/reset eligibility.** Add one code-owned class-spec registry (exact class + resolved base/subclass method/code pins + module/build/wire/Popen pins + admitted contract digest). Preserve the GPIO row byte/behavior contract; add only exact GeneratedApb3RegisterSession with a registered generated probe artifact, empty setup_writes/probe_offsets and no dynamic fake producer. Refactor session/native-reset observers/evidence to consume that immutable spec, preserving actual build issuance and Popen/nonce/epoch/READY/command/close private facts. Direct `_command_impl` frame checks remain. No native eligibility from a mock process/build report, source descriptor or JSON registry.

**C: live generic storage version authority.** New process-local single-use issuer consumes every real command sample, binds actual storage/reset/APB probes, validates contiguous ticks and selected reset→write→hold equation, counts every mask0x1c/value4 alias (including raw ignored low/high bits) with exact routed context. Revoke on every command/reset/process/source change or uncertain receipt. Bind source/probe/build/artifact/epoch/process/sequence/tick/register in private witnesses. No source, reset, readback-only or serialized token can substitute. GPIO issuer remains separately registered and unchanged until equivalent regression proof.

**D: F4 selection and actual gates.** Only after B/C review expose a protocol/template + registered producer-contract factory to compiled F4; preserve exact source/ownership/candidate layout and all required assertions/prerequisite joins. Then new independent generated timer storage gate (including alias writes/controlled refusal), CPU→timer3cases+2fullfresh with actual plan/events/PID/nonce/close/source pins, and old GPIO/both CPU ABI regressions. No fullP7 or arbitrary-IP claim from this one registered source dialect.

Essential B/C RED controls: subclass/instance method monkeypatch, forged build/command/frame/receipt/Popen, registry replacement, fake/no-reset READY, stale or serialized/foreign tokens, skipped tick, untracked alias write, source/probe/layout/ownership mutation, changed process/epoch, lost reply, bounds and teardown errors. Pure fixtures must stay explicitly noneligible; actual live eligibility remains native-gated.
