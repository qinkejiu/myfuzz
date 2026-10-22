# Compiled F4 Built Identity Implementation Plan

> **For agentic workers:** Use subagent-driven-development, independent task and final reviews. Preserve the shared feature workspace; no stage/commit/reset/clean.

**Goal:** Join admitted D2 artifacts to validated executable outputs and original/fresh native processes.

**Architecture:** A receipt-capable builder shares the existing build implementation. Opted sessions pin stable receipts before manifest capture, validate outputs before launch and observe the live executable before READY. The compiled runtime includes only stable identities in prefixes and writes per-invocation diagnostics/process joins separately.

**Tech Stack:** Python frozen dataclasses/canonical JSON, existing generated Verilator sessions, Linux proc executable references, current compiled RFuzz CLI.

## Global constraints

- Approved design: `../specs/2026-10-22-compiled-f4-built-identity-design.md`; user continued after written-spec review.
- Stable receipt schema `local_harness_built_receipt.v1`; observation schema `local_harness_build_preparation.v1`; run-level schema `compiled_F4_build_join.v1`, filename `compiled_f4_build_join.v1.json`.
- Stable fields: artifact_digest, build_digest, complete build_identity, binary_sha256. Exclude duration/cache outcome/raw manifest/stage path/PID/nonce from stable receipt.
- Keep ordinary Path build API/session identity behavior; new session mode opt-in, actual compiled-F4 mode mandatory. Preserve native-reset checks.
- Cache corruption refuses. Repeat preparation validates pinned result without replacing its receipt or first observation. Raw manifest bytes are pinned per session separately.
- After Popen, capture lifecycle immediately; hash /proc/PID/exe before accepting READY. Failure aborts/reaps, preserving lifecycle diagnostics.
- Fresh validates independently, compares expected stable receipts before any fresh process launch, then compares complete prefixes with no binary-hash normalization.
- Structural D2 generation remains truthful. Do not grant general P7-E/P6/P8, other execution paths, retirement, DMA or clean-room provenance.
- Save development/frozen/native evidence under `.superpowers/sdd/compiled-f4-built-identity/` and `docs/reports/evidence/compiled-f4-built-identity-20261022/`. Freeze all production edits before final native gates.

## Task 1: Receipt-capable builder

Files: modify `src/myfuzz/local_harness/build.py`; create `tests/local_harness/test_built_executable_receipt.py`.

Public interface: frozen `LocalHarnessBuildResult` with `binary_path: Path`, `receipt_document() -> dict`, `receipt_sha256: str`, `observation_document() -> dict`, and `validate_current(artifact, *, base_dir, cache_dir) -> Path`. `build_local_harness_with_receipt(artifact, *, base_dir, cache_dir) -> LocalHarnessBuildResult`; old `build_local_harness(...) -> Path` remains compatible. Result methods return detached copies. LocalHarnessBuildError exposes optional detached preparation_observation on failed receipt calls.

- [x] Add RED tests for stable receipt issuance, detached views, cache_hit/compiled_published/compiled_race_reused, malformed schemas, manifest-byte drift, changed binary/input/artifact and exact path. Use real source-backed fixture and fake compile only where testing branch classification.
- [x] Run `PYTHONPATH=src:. python3 -m pytest -q tests/local_harness/test_built_executable_receipt.py` and save meaningful RED.
- [x] Refactor only the common build execution into a helper; old Path API delegates without new receipt semantics. New API captures branches/timing at source, validates selected cache identity and bytes, pins raw manifest and stable canonical bytes.
- [x] Add result validation against current artifact/identity/cache path/materialized inputs/raw manifest/binary and structured failure observations. Cache-hit compile_seconds is null with explicit reason.
- [x] Run focused new tests plus `tests/local_harness/test_build_identity.py` and `tests/local_harness/test_build_cache_scalar_identity.py`; save GREEN and scoped diff. Independent Spec/Quality review before acceptance.

## Task 2: Opt-in session receipt and launch lifecycle

Files: modify `src/myfuzz/local_harness/session.py`; create `tests/local_harness/test_session_built_identity.py`.

Consumes Task1 API. Methods: `configure_built_executable_receipt()`, `built_executable_receipt_document()`, `build_preparation_observation_document()`, `built_executable_launch_observations() -> tuple[dict,...]`, `validate_built_executable_receipt() -> dict`. Before preparation, receipt document/validation methods refuse. Available failed-build preparation observations and retained launch/cleanup diagnostics may be exported after refusal or damaged pins; diagnostics grant no authority. Detached views only.

- [x] Add RED tests showing ordinary identity unchanged, irreversible early opt-in, prepare-attempted tracking after failure, repeated prepare preserving first observation, missing/replaced pin refusal, prelaunch input/manifest/binary drift refusal.
- [x] Test live executable check before READY acceptance with native executable fixtures; scripts/interpreter mismatch and failed READY preserve PID/nonce/argv, failure stage and exit/reap records.
- [x] Run `PYTHONPATH=src:. python3 -m pytest -q tests/local_harness/test_session_built_identity.py`; save RED before behavior edits.
- [x] Implement opt-in state. First prepare stores Task1 result; subsequent prepare and validate reuse it after current validation. Identity adds stable `built_executable_receipt` only when opted/prepared.
- [x] Capture live /proc executable digest before reading/accepting READY. Populate launch row with receipt/artifact/build/binary digests, executable digest, READY digest and PID/nonce/argv. Retain failures and updates through abort/end_case. Existing native-reset observation keeps its checks.
- [x] Run focused new and existing `tests/local_harness/test_session.py`, native-reset session tests as applicable. Save scoped diff and independent review.

## Task 3: Compiled binding and saved build join

Files: modify `src/myfuzz/integration/compiled_f4.py`, `src/myfuzz/integration/compiled_rfuzz.py`, `src/myfuzz/local_harness/auto_harness_test.py`; create `src/myfuzz/integration/compiled_f4_build_join.py`, `tests/integration/test_compiled_f4_build_join.py`.

Join helper interface: `build_compiled_f4_build_join(*, artifacts, execution_binding, compiled_document_sha256, runtime_path_id, logical_path_id, original, fresh, error=None) -> dict`; strict verifier `verify_compiled_f4_build_join(document, *, artifacts, execution_binding, original, fresh) -> None`. `original` and `fresh` contain receipts, preparation observations, process identities and exits; complete join requires successful closed/reaped exits and exact component associations. Error joins retain only material actually observed and status refused.

- [x] Add RED controls for wrong D2 artifact/component/process/receipt mapping, rehashed swaps, missing exits, diagnostics-only differences and stable binary mismatch; use real admitted artifact material from existing F4 fixtures.
- [x] Extend execution binding optionally with built receipt map; prebuild derive API remains structural. Actual runtime constructs sessions, opts/prepares all, then binds. `_stable` revalidates component-keyed live receipts. Expected fresh receipts are identity constraints, never issuance authority; compare before begin.
- [x] Extend runtime process audit using validated session launch records; enforce artifact/receipt/build/binary/live executable/READY mapping. Keep timing and lifecycle outside prefixes.
- [x] Create external audit sink before original/fresh construction. Export available partial observations on constructor/start/cleanup failure before reraising. Orchestration always attempts refused/complete build-join writing, preserving primary errors.
- [x] Write run-level join after cleanup and register byte digest in CLI run summary. At CLI boundary verify it against same-call harness-set artifact digests, runtime binding, manifest, prefix and execution audits. Leave generated structural D2 files unchanged.
- [x] Run `PYTHONPATH=src:. python3 -m pytest -q tests/integration/test_compiled_f4_build_join.py tests/integration/test_compiled_f4_runtime_path_wiring.py tests/integration/test_compiled_f4_execution_binding.py tests/integration/test_compiled_online_decoder.py`; independent review exact slice.

## Task 4: Frozen acceptance and docs

- [x] After all scoped reviews/fixes, freeze production Python/config and run software regression including Tasks1–3, session/native-reset, compiled decoder/runtime-path and CLI regressions. Archive exact inputs and terminal receipts; no edits while gates execute.
- [x] Run existing Timer and SPI sibling CLI with same max-tests2/budget30/rounds32 parameters as predecessor. Preserve every attempt. Confirm full prefix equality,2certified each, process/build/D2 joins, all native exits, live executable hashes, preparation mode/time, and source snapshots.
- [x] Independent raw-evidence audit of both runs and archive members. Record real cache/compile outcomes; cache hits do not meet cold-build cost gate.
- [x] Update scoped report, CURRENT_PROGRESS, LOCAL_HARNESS_RUNTIME, report index, P7 plan, component/code organization and spec/plan status. Only mark passed bounded requirements complete; P7-E/P6/P8/system remain open.

## Bounded acceptance result

Tasks1–4 completed against saved scoped RED/GREEN, independent reviews and
frozen evidence; see [report](../../reports/compiled-f4-built-identity-20261022.md).
Final focused software:611passed/30skipped/53subtests; all30 skips retain the
timer-only source reason and do not grant omitted capability. Timer/SPI native
gates each2/2certified with complete538/2806-event fresh matches. Production
inputs are unchanged; final software differs by one test-only fixture correction
(and SPI's own wrapper). No P6/P7-E/P8 or full-system completion is awarded.
