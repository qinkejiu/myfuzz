# E2 ordinary-access file replay boundary review

2026-10-12; independent design/code-review checkpoint by `review_d1_c7`. No RTL execution, no production edits. The proposed optional channel persists command/protocol-boundary associations, with all verified/storage/functional grants false. It cannot change the register runtime's capability level or prerequisite policy.

## Closed optional identity

The register assembly must omit the ordinary option by default. An enabled option is exactly `ordinary_apb_access_evidence = {"max_records": N}` with exact non-boolean integer N in 1..65536. Reject null, booleans, strings, floats, lists, unknown keys, alternate providers and invalid capacities before constructing a factory or beginning a Session. Presence must agree across assembly, plan, manifest and saved state. The capability-preflight switch remains independent; its absence/default source closure must remain 38 files, and its explicit enabled closure 40 files, before ordinary-only source additions. Do not add optional fields or change default plan schemas/bytes merely because the new APIs exist.

The live configuration should include the actual pinned provider configuration and its canonical digest, not a saved caller-selected provider object. Source closure must cover the ordinary helper/collector, the actual callback source and router/ledger/normalizer/checker rules. Saved paths select no code. File bytes must be authenticated again at use; a rehashed artifact envelope only attests bytes, not actual authority or successful execution.

## Startup and atomicity

Session configuration must be explicit and before begin. It must bind the Session's actual Runner, actual attached register runtime, current native GPIO targets, actual CPU/router/service/ledger/memory and the validated endpoint/window configuration. A foreign Runner's observer or a same-profile target with another instance cannot be installed as the current provider.

Complete preflight and all fallible source/configuration capture before publishing Session optional-channel state. If target-helper installation is part of startup, prevalidate every target and collector budget first: failure on the second target must not leave the first target configured or silently alter its identity. Failure must preserve slots, source actions, materialized RAM, command sequences, journal events and runtime identity. Existing configured helpers/providers must either match exactly and follow an explicit idempotent policy or be refused; do not silently overwrite them.

The live collector must still check pinned identities/source/configuration before each command. Beginning a Session does not make cached metadata permanent truth. Capacity must reject before native target ticks or ACCESS. Queries/exports should return detached documents; restoring an exported snapshot must not heal a permanently incomplete collector.

## Fresh replay sequence

1. Authenticate and strictly parse assembly, Session schema16/17 plan, ordinary configuration/state and manifest before factory construction. Check the optional channel's presence agreement, closed types, canonical hashes, source closure, capacity/count bounds, record/ref shapes and no-grants flags.
2. Construct the code-owned known assembly factory and register runtime against fresh actual objects. Install the optional provider through the same before-begin API used by production. Compare the complete actual current configuration with the saved configuration before commands. A valid saved configuration cannot override actual targets, capacities, memory identity or source files.
3. Execute bootstrap/reset and each original register request through the existing current-context compiler/admission path. Actual callbacks and parsed target commands alone produce receipts, phase digests, raw/base refs and association records. Do not call observer ingest with saved rows, import saved private tokens, restore scoring or reconstruct a ledger from saved state.
4. Compare complete actual terminal configuration/state, plan and trace. Every record's status/reason, source key, target/endpoint, target epoch, memory generation and receipt/acceptance/delivery/raw/base refs must match; selected counts or a saved SHA alone are insufficient. APB transaction keys remain null with an explicit native identity gap.
5. Failed registration/command/reconstruction must clean up all components and preserve the original rejection exception when cleanup also fails. Schema17 incomplete/terminal attempts must follow existing registration-versus-execution phases; a command that never appended a case cannot be invented by restoring an ordinary record.

## Required independent tests

- Four switch combinations: ordinary off/on × capability preflight absent/present. Default fields, schemas, source closures and original plan bytes stay unchanged; enabled ordinary config is detached and participates in identity.
- Exact closed option shape/capacity, including bool-int substitutions; malformed saved config/state fails before factory/startup.
- Valid configuration then rehash saved state with fabricated confirmed records, status/count changes, changed refs or renamed target instance. Fresh reconstruction rejects or compares unequal; no saved row enters a live authority registry.
- Same profile across GPIO A/B, wrong actual window target, replaced helper/ledger/memory/provider or normalizer configuration. Reject before commands and do not regain qualification by restoring saved snapshots.
- Session after-begin install, duplicate changed install and failure while capturing source closure/configuration. Verify no partial publication, target opt-in identity change, slot/RAM mutation or event/command effect.
- Actual CPU queued read/write plus parsed software target transport as positive control; synchronous router flag forgery and callback failure as negative controls. Successful private confirmations and original phase digests are rebuilt, not copied from saved objects.
- Missing/duplicated/conflicting raw/base/delivery refs, reset/process/generation mismatch, and bounded exhaustion. Terminal state and history remain bounded and detached, with no verified/storage/functional grants.
- Schema16 complete and schema17 terminal failures; legacy schemas/default ordinary-off remain accepted under their existing contract. Source/API mismatch rejects before begin; runtime failure cleans up while preserving the primary exception.

Use the existing actual-rendered factory and strict parsed software transport fixtures rather than shape-only SimpleNamespace providers. A recording Session may isolate execution/cleanup for orchestration tests, but it cannot establish positive command authority; pair it with actual helper/router/collector software tests.

Implementation review and independent test results will be appended after the exact API and frozen code are available. No full replay/RTL acceptance is claimed at this checkpoint.

## Current implementation checkpoint

The implementation now defines `ScenarioSession.configure_ordinary_apb_access_evidence(*, max_records=256)`. Target helpers are constructed locally before installation; source capture precedes publication; failure rolls back helper/collector installation and restores protocol-projector caches. The optional plan field is `register_programs.ordinary_apb_access_evidence = {schema_version: "ordinary_apb_access_session.v1", configuration, state}`. Manifest fields hold only startup configuration and enabled source closure. Enabled source identity uses the current code-owned host-source closure; default 38/40 selector closure counts are preserved.

Static review confirms closed channel validation and presence agreement, actual fresh startup configuration comparison, and full terminal state comparison in the file API. Saved state is not ingested into a live provider. For generic Session replay, a self-consistent saved terminal state change may produce `matches=False` after actual execution rather than a pre-factory exception; the independent test accepts either explicit rejection or unequal fresh comparison and verifies the fresh registry was not restored from the saved claim. This distinction does not authorize the changed state.

Independent tests are in `tests/integration/test_ordinary_apb_register_replay_boundaries.py`: 11 pure closed-assembly/default-closure cases passed (0.31 seconds); eight actual-object startup/replay checks await the final source freeze. No full-suite, file replay or RTL success is claimed from this draft checkpoint.

## Frozen independent software verification

`PYTHONPATH=.:src python3 -m pytest -q tests/integration/test_ordinary_apb_register_replay_boundaries.py` completed with **19 passed in 21.63 seconds**. This includes exact option/capacity validation, default 38/40 closure compatibility, actual second-target preflight atomicity, detached startup configuration, changed reinstall refusal, and self-consistent rehashed terminal state remaining comparison data rather than restored authority. The test run used source rendering and software execution stubs; it started no RTL process.

The following SHA-256 values were identical before and after this run:

- `src/myfuzz/scenario/session_runtime.py`: `3eebb6c82ebc9ed209b39c9bbd6f169318303f6815d70ae17f37d6357d7a82e4`
- `src/myfuzz/scenario/ordinary_apb_access_evidence.py`: `131304413d2abb2ffcdd4790522cbc52025bc4f85324a0ac2847ea6c4866f2bf`
- `src/myfuzz/integration/ibex_pulp_register_replay.py`: `bfc33d3c554f3401291bd57d40690f9ec16365e840add2900a691bb9aaf6ee8d`

No remaining concrete P1/P2 defect was found in this reviewed optional-channel startup, saved-document and fresh replay boundary. This is a software review result, not a claim of actual file/RTL replay acceptance, internal storage certification, active prerequisites or functional completion. The only files written by this review are the owned independent tests and this review note; production files remain unchanged.

## Actual v2 partial artifact audit

Read-only examination of `runs/stage2-e2-ordinary-access-file-cli-20261012-v2` confirmed 281 current source pins, ten case outputs, 18 CPU deliveries and command-boundary associations, 54 base protocol refs, 144 command-span raw phase refs and two RAM commit events. Exact source/acceptance/receipt/delivery linkage and native APB phase/data/ref checks passed. Every association retains false verified/storage/functional grants.

The worker terminated with `command_failed` at a fixed total-record-count assertion after those cases: bootstrap ordinary accesses also belong to the full-session collector state. No bundle, summary or fresh CLI replay result was written, so this run establishes only the saved per-case evidence. The resource receipt records one worker, 96.250152396 seconds and peak RSS 1,647,923,200 bytes below the 3,244,351,488-byte limit. The independent audit JSON records these limits; no RTL or test was started by the audit. A subsequent gate must compare startup-prefix plus case associations against the complete terminal state and preserve full-state fresh replay comparison.

## Actual v3 saved run and separate fresh CLI audit

Independent read-only verification accepted the production identity verifier and trusted selector preflight for nine authenticated artifacts, 281 current external source pins and the 278-file enabled source closure. The complete trace contains **22,387 events**, semantic SHA-256 `7eab0303fdf4c4116174a032ee33651ebc977fb3dab4577299595ca31705da5d`; identity SHA-256 is `99f608b5243fdb8f4a9ea46f86196e0d9d79742eed16bd1c189add4dbba5c47c`.

The six actual bootstrap associations plus 18 case associations equal all 24 terminal records, with zero pending records. Full records equal the actual journal after stripping journal metadata. All 24 exact source/acceptance/target-receipt/delivery chains and their 192 raw phase refs and 72 APB base refs passed independent checks. Case-only counts remain 18 associations, 144 raw refs and 54 base refs; two read-result RAM commit documents have valid canonical hashes and full transaction matches. Three cache binaries and all frozen input bytes matched their manifests (281/281/350 input counts).

The separately supervised production CLI fresh replay reports `matches=true`, identical event count/semantic digest, and complete canonical equality of all 24 ordinary records and the saved capability preflight. Capability remains requested/effective L1 with no verified level. The CLI output, saved plan and terminal snapshot agree; no saved evidence was loaded as permission by this audit.

The original combined run retains **wall_timeout at 180.074088845 seconds**, peak RSS 2,628,591,616 below 3,247,824,896 bytes. The separate fresh CLI phase completed in **103.455045 seconds**, peak RSS 2,116,165,632 below 2,558,029,824 bytes, with one worker. This is a saved-run plus separate-fresh-phase success, not a combined-budget success. No fresh trace was persisted separately; fresh equality is evidenced by the frozen worker path and production CLI output. The audit started no RTL/replay and grants no storage, functional completion, active prerequisites, verified L2, RFuzz or BFM acceptance. Full audit is `runs/stage2-e2-ordinary-access-file-cli-20261012-v3/independent-audit.json`; v2 failure remains unchanged.
