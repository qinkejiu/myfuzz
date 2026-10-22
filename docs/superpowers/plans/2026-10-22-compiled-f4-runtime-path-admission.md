# Compiled F4 Runtime Path Admission Implementation Plan

> **For agentic workers:** Use subagent-driven-development with independent task and integration reviews. Preserve the current shared feature branch and unrelated edits; do not stage, commit, reset, or clean.

**Goal:** Configure the same-call selected D3 F4 path on the actual online session and reconstruct it in fresh replay.

**Architecture:** A pure admission helper restores the D3 graph/contract and issues a selected-path/source binding. A generic opt-in session adapter admits explicitly bound instruction inputs against the graph source and actual RAM region. The compiled runtime, decoder and RFuzz identity share that binding and retain both logical and runtime path IDs.

**Tech Stack:** Python dataclasses, existing RuntimePathContract/ScenarioSession, generated OBI/APB3 sessions, pytest, native first/fresh evidence.

## Global constraints

- Spec: `../specs/2026-10-22-compiled-f4-runtime-path-admission-design.md`; user selected A and continued after written-spec review.
- Selected F4 only. P6/P7-E/P8 and general F1-F6 admission remain open.
- Keep the original D3 graph/contract unchanged. No CPU/IP name dispatch or action-ID parsing for source authority.
- Existing plain OnlineInstruction serialization remains unchanged. New source identity uses a versioned bound form.
- Bind image source ID/component/resource/range/width/permissions to one actual RAM region; reject before native case effects.
- Keep exact native originals, failed attempts, process exits, source inputs, and first/fresh comparison evidence.

## Task 1: Opt-in session instruction-image binding

Files: create `src/myfuzz/scenario/instruction_image_binding.py`, `tests/scenario/test_instruction_image_binding.py`; modify `src/myfuzz/scenario/session_runtime.py`; create `tests/scenario/test_bound_instruction_session.py`.

Interface: frozen `InstructionImageSourceBinding(path_id, direction, source_id, logical_source_id, component, memory_id, base, size, readable, writable)`, strict `document()/from_document()`, and `validate(prepared, runner)`. Add frozen `BoundOnlineInstruction(OnlineInstruction)` with required `source_id`. Extend `configure_runtime_paths(..., instruction_image_bindings=())` and expose detached `instruction_image_binding_documents`.

- [x] Write meaningful failing tests for strict types, selected graph source/edge/resource identity, exact region base/size/permissions, range boundaries, missing/wrong explicit source ID, and unchanged plain instruction plan form.
- [x] Verify the tests fail before implementation; save RED output in `.superpowers/sdd/compiled-f4-runtime-path/`.
- [x] Implement binding and source resolution. Persist optional bindings in manifest and version24/25 online plans; validate saved provenance and reconstruct binding before replay begins. Versions24/25 require runtime paths/provenance and distinguish terminal failure.
- [x] Run focused adapter/session/preflight/provenance/replay tests; independently review the exact diff.

## Task 2: Strict same-call selected-F4 admission

Files: create `src/myfuzz/integration/compiled_f4_runtime_path.py`, `tests/integration/test_compiled_f4_runtime_path.py`.

Interface: `admit_compiled_f4_runtime_path(*, request, compiled, path=None)` returns immutable `CompiledF4RuntimePathAdmission` with `prepared`, `instruction_binding`, `logical_path_id`, `runtime_path_id`, `document()`, `digest`, and `validate_cached_identity()`.

- [x] Write failing tests using real generated Timer D2/D3 fixtures. Change compiled graph/contract/path/source/range/layout independently and require refusal; reject selected external-pin or other unmapped sources.
- [x] Recompile request and compare canonical full D3 content; strictly restore graph/contract and the selected DependencyPath, verifying the complete runtime_path_identity.
- [x] Join image source to graph memory_image and request resource. Produce inspectable graph/contract/path/source/layout digests and the Task1 instruction binding; preserve the D3 graph bytes.
- [x] Run pure focused tests without native construction, then independent review.

## Task 3: Wire the compiled runtime and decoder

Files: modify `src/myfuzz/integration/compiled_f4.py`, `src/myfuzz/scenario/compiled_online_decoder.py`, `src/myfuzz/integration/compiled_rfuzz.py`, and focused compiled decoder/runtime tests.

- [x] Add failing integration tests proving `configure_runtime_paths` precedes begin, cases use the selected runtime path/source ID, and decoder/session declarations match.
- [x] Add explicit runtime-path admission into the F4 execution binding. Configure the actual session with Task2 prepared paths and Task1 image binding before begin. Use BoundOnlineInstruction and the runtime path ID for each case; retain logical IDs for compiled receipt joins.
- [x] Include graph/contract/path_mapping/source binding in decoder manifest. Derive executor runtime status from matching configured session material. Include path/source mapping in certificates and first/fresh prefix.
- [x] Run compiled decoder, execution binding, runtime preflight, provenance and generic replay regressions. Fix identified regressions and independently review.

## Task 4: Real evidence and documentation

Files: add scoped report/evidence; update `docs/CURRENT_PROGRESS.md`, `docs/LOCAL_HARNESS_RUNTIME.md`, `docs/reports/README.md`, P7 plan and this plan.

- [x] Freeze inputs and run the existing Timer compiled F4 CLI with first/fresh; retain process receipts and all failures. Follow agent.md for any remote work.
- [x] Independently reconstruct saved runtime path/source mapping and session/decoder/topology identities; verify full typed-prefix replay and process exit receipts.
- [x] Record exact software/native commands and bounded outcome; mark only genuinely passed tasks complete and retain aggregate open gates.

Acceptance: [bounded report](../../reports/compiled-f4-runtime-path-admission-20261022.md). Frozen software 399 passed / 48 subtests; Timer and SPI sibling native gates each 2/2 certified, full prefixes 538 and 2806 events respectively. Both independent saved-evidence audits pass. Task4 complete for this selected-F4 slice; general P7-E/P6/P8 and system completion remain open.
