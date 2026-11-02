# Compiled F2 Read Response Implementation Plan

2026-10-24 reconciliation: bounded F2 delivery accepted. Tasks4–6 are now reconciled with the original directed file-entry cohort and the separately completed unified RFuzz supplement. The final unified cohort uses 21,916 archived inputs: software498 passed/5 exact native skips/22 subtests, five native controls, three normal pairings, rename/two refusals and both same-source F4 compatibility gates; all ten have independent acceptance. See the [final report](../../reports/compiled-f2-rfuzz-entry-20261023.md) and [frozen acceptance audit](../../reports/evidence/compiled-f2-rfuzz-entry-20261023/audits/final-frozen-slice-acceptance.md). Below, older live checkpoints retain their historical scope. No P6/P7-E/P8/general F6/system completion is granted.

> **For agentic workers:** Use subagent-driven-development with task Spec/Quality review and final broad review. User approved the written design by “继续”. Preserve the shared feature branch and its uncommitted predecessor implementation; no stage/commit/reset/clean.

**Goal:** Execute admitted F2 CPU loads against real source-registered APB storage and join native CPU consumption, current versions, assertions and fresh replay.

**Architecture:** Correct the compiler's F2-only versioned contract and graph; install separate read layout/program/consumer modules using existing session/native authority mechanisms. Integrate a dedicated runtime and CLI executor with strict builder/process identities, typed assertion results and saved-file validation.

**Tech Stack:** Python, current D3 typed compiler, RV32I instruction encoder, OBI CPU sessions, source-registered APB3 storage sessions, ScenarioSession/Runner/Router, Verilator, existing RFuzz CLI.

## Global constraints

- Approved spec: `../specs/2026-10-23-compiled-f2-read-response-design.md`.
- Keep `compiled_paths.v1`; F2 adds `execution_contract.schema_version=compiled_F2_read_contract.v1`. Old F2 marker/shape refuses, never upgraded or disguised as F4.
- Read-owned address source only; PRDATA/storage remain bound. Full32-bit side-effect-free source-registered storage only; no hidden setup writes, diagnostic accesses or invented entropy.
- Current native register version after actual startup+idle step; no RAM alias, reset proof or prior CPU-write claim. Dynamic epoch and exact observation/version resolve the static selector.
- CPU LW then XORI with constant `0x5a5`, followed by dependent SW to a separate declared result RAM word; no architectural retirement grant.
- Exact D2/source/build/live executable/READY/session/case/transaction/epoch/byte-version identity; full first/fresh comparison, no binary/value normalization.
- Two D3 expectations: receipt violations and declared edge hops. Each admitted case has exactly one passed/failed/missing row per expectation. Observed contradictions fail; missing observations stay missing. Findings remain bug classifications.
- Work in existing branch `codex/system-completion-20261016`: predecessors are uncommitted and required by integration, so a HEAD-only worktree would omit them. Do not stage/commit/reset/clean.
- User explicitly requested parallel agents. Parallel edits have disjoint assigned files. Serialize edits to shared runtime/report modules and freeze all source/tests during final acceptance.
- Development logs/reviews/baselines: `.superpowers/sdd/compiled-f2/`; final evidence `docs/reports/evidence/compiled-f2-read-response-20261023/`.
- No P6/P7-E/P8, unrestricted onboarding, useful mutation diversity or full-system completion is implied.

## Interface agreement

`compiled_F2_read_contract.v1` exact keys:
`schema_version,instruction_source_id,load_source_id,source_component,source_endpoint,target_component,target_endpoint,device_id,window,address,register,field,response_mask,width_bytes,allowed_byte_enables,version_selector,nodes,consumption_mode,expectation_ids`.
`window={base,size}`; `version_selector={kind:ip_register_version,component,register,epoch_policy:current_live_epoch}`; `nodes={image,request,response,consumed}`; consumption mode `native_read_then_dependent_ram_store`; expectation_ids sorted. Address source is width32/bit_offset0/mask0xffffffff, independent of `response_mask`.

## Task 1: Compiler contract and pure selected-path admission

Files: modify `src/myfuzz/scenario/compiled_paths.py`; create `src/myfuzz/scenario/f2_read_contract.py`, `src/myfuzz/integration/compiled_f2_runtime_path.py`; create `tests/scenario/test_f2_read_contract.py`, `tests/integration/test_compiled_f2_runtime_path.py`; adjust only existing compiler expectations affected by the deliberate new F2 output.

APIs: `build_f2_read_contract(path)->dict`, `validate_f2_read_contract(path)->dict` in scenario module; builder runs on complete executable F2 row and validator compares exact fields to rebuilt contract. `admit_compiled_f2_runtime_path(*,request,compiled,path=None)` returns immutable admission exposing `prepared,instruction_binding,logical_path_id,runtime_path_id,document(),digest,validate_cached_identity()`.

- [x] RED on fresh Timer/SPI compiler output: marker present, IP version selector, address vs response metadata, three graph edges with real CPU/IP pairs, final CPU consumption. Legacy/mutated/extra contract refuses. Save baseline and RED log.
- [x] Correct `_evaluate_f2`, graph construction and row output. Static prerequisite kind ip_register_version with target component/register selector; epoch is resolved at runtime via marker. Do not broaden F4 or assign register names to RAM resources.
- [x] Implement canonical contract builder/validator and complete original-request recompile/path/resource/source/contract admission. Pin exact three-edge graph and two MMIO declarations; reject old or swapped identity before startup.
- [x] Run focused new tests and compiler/F4 runtime-path regressions; save GREEN and scoped diff. Independent Spec/Quality review.

Command: `PYTHONPATH=src:. python3 -m pytest -q -ra tests/scenario/test_f2_read_contract.py tests/integration/test_compiled_f2_runtime_path.py tests/scenario/test_compiled_paths.py tests/integration/test_compiled_f4_runtime_path.py`.

## Task 2: Read candidate layout and dependent reader program

Files: create `src/myfuzz/integration/compiled_f2_layout.py`, `src/myfuzz/integration/generated_register_reader.py`; create `tests/integration/test_compiled_f2_layout.py`, `tests/integration/test_generated_register_reader.py`. No edits to F4 layout/writer in this task.

APIs: `compile_f2_candidate_layout(path)` immutable layout with `document(),digest,classify(raw),source_slices`; classification exposes accepted/address/reason. Raw input is exactly four little-endian address bytes, checked against address/range/alignment/domain, not a PRDATA value. `declare_reader(request,compiled,*,source_id,address,result_address)->dict` revalidates original D3 read candidate; declaration schema `generated_register_reader.v1` retains candidate/program/result/XOR/source/compiled identity and functional instruction offsets.

- [x] RED address-domain tests (singleton remains singleton), PRDATA/read-value ownership refusal, wrong lane/operation/source, mirrored-constraint drift, legacy marker and partial readmask rejection.
- [x] Implement separate read layout, strict full request/compiled candidate validation, RV32I address setup/LW/XORI0x5a5/result-address setup/SW/trailing NOPs. Validate separate writable result memory, source range and instruction/result nonoverlap at decoder integration boundary.
- [x] Tests decode functional instruction bytes and dependency registers, compare recomputed declaration hashes and refuse mutated/coherently rehashed inputs. Save GREEN and scoped diff; independent Spec/Quality review.

Command: `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f2_layout.py tests/integration/test_generated_register_reader.py tests/integration/test_compiled_candidate_layout.py`.

## Task 3: Typed assertion results

Files: create `src/myfuzz/scenario/compiled_assertion_results.py`, `tests/scenario/test_compiled_assertion_results.py`. Capability report/CLI integration owned by Task5.

APIs: `build_assertion_results(*,compiled_document_sha256,binding_sha256,path,run_id,cases)->dict`; `validate_assertion_results(document,*,compiled_document_sha256,binding_sha256,path,run_id,cases)->None`. Each case has `case_id`, `observations` keyed by expected expectation_id with status/reason/evidence_refs, and an independent `evidence_inventory` map. Missing observation gets explicit missing row; contradictory observations must be failed; unknown/duplicate expectations/cases, invalid status, passed without refs or refs absent from inventory refuse. Pre-admission refusal is separate runtime envelope, not a forged case.

- [x] RED controls for complete inventory, missing observations, checker violation failed, contradictory edge failed, unexpected/duplicate cases/assertions, swapped compiled/binding/run/path/case identities and forged/missing refs.
- [x] Implement deterministic canonical document and strict rebuilding validator; no file IO/native authority or bug-finding relabeling.
- [x] Save GREEN/report/diff; independent Spec/Quality review.

Command: `PYTHONPATH=src:. python3 -m pytest -q -ra tests/scenario/test_compiled_assertion_results.py`.

## Task 4: Native read-specific consumer and provenance

Files: create `src/myfuzz/integration/compiled_f2_consumer.py`, narrow `src/myfuzz/integration/native_obi_hops.py` if needed; modify `src/myfuzz/scenario/edge_provenance.py` and runtime contract relation-role handling only as required; tests `tests/integration/test_compiled_f2_consumer.py` and read-specific provenance tests.

APIs: `select_f2_read_producer(*,artifacts,compiled_inputs,base_dir=None)` returns immutable source/ABI/register/session/native-authority binding; `check_f2_read_observation(...)` consumes actual receipt/events, before/after native-authority documents and immutable memory snapshots. Input keys must explicitly include admitted path/declaration, target source contract, native CPU taps, exact routed context/transaction and native APB command/sample evidence.

- [x] RED with a complete source-backed read fixture and each missing/cross-scope/native-data/version/history/order/result negative. No serialized witness grants live authority.
- [x] Reuse exact existing native issuer and startup+empty idle handoff; resolve typed live prerequisite before CPU candidate. Select generic APB storage source registrations by capability identity, not names. Do not use F4's write selector with edited inputs.
- [x] Verify request acceptance→APB PRE response→return delivery→native OBI completion→dependent RAM store and functional fetch/version proofs. Read-request and read-return provenance have distinct roles and same transaction; no write matcher broadening by merely removing write=True guard.
- [x] Re-run focused existing write provenance/F4 consumer tests; independent Spec/Quality review exact diff.

## Task 5: Dedicated runtime, CLI and saved report integration

Files: create `src/myfuzz/integration/compiled_f2.py`, `src/myfuzz/scenario/compiled_f2_decoder.py`, `src/myfuzz/integration/compiled_f2_rfuzz.py`; modify shared builder-join primitives only via explicit F2 schemas; modify `src/myfuzz/local_harness/auto_harness_test.py`, `compiled_execution_projection.py`, `src/myfuzz/scenario/capability_report.py`; add focused runtime/decoder/CLI/saved-material tests.

- [x] RED actual selected D3 instruction binding before begin, decoder source identity and all-sequence validation; both components prepared before final F2 execution binding; old F4 schema is not accepted as F2.
- [x] Compose existing sessions/Runner/Router with current-version resolution and read handler, preserving pending-slot/materialization/persistence rules and actual native completion requirements. Extract only small shared exact invariants, no inheritance from giant F4 runtime.
- [x] Integrate original/fresh snapshots, strict binary-prefix identity, partial error/cleanup diagnostics, new build join and saved-byte verification. Preserve first primary error through exporter failures.
- [x] Register explicit F2 executor/projection and unsupported reasons for every other flow. Feed typed assertion results with actual event inventory into capability report, keeping findings separate. Final summary pins actual saved artifact bytes.
- [x] Save focused GREEN and independent review, then whole-slice independent review; fix important findings through meaningful RED/GREEN and rereview without further permission prompts.

## Task 6: Frozen software/native acceptance and docs

- [x] Freeze all source/test/config/wrapper inputs and archive exact byte map; run focused new F2 plus affected compiler/provenance/CLI/session/build/F4 regressions. Save every attempt, skip reasons, terminal PID/exit/reap/timeout/RSS and before/after maps.
- [x] Run real Timer/CV32E20 and SPI/CV32E40P F2 original/fresh CLI gates, renamed-instance control and refusal controls; verify full prefixes, versions, assertions, all native build/process joins and cleanup. Run current-source F4 compatibility gates after D3 compiler changes.
- [x] Independent audit exact archive members/source maps, native commands/builds/live executable/READY/process records, receipts/assertions and full fresh data. No borrowed current-source acceptance from historical F4 runs.
- [x] Update spec/plan/report, CURRENT_PROGRESS/runtime/component/code references, report index and P7 status. Distinguish observed zero/singleton cases from search diversity/useful throughput. Keep P6/P7-E/P8/system open.

## 2026-10-23 reconciliation checkpoint

Task1 final source-backed Timer/SPI software gate83passed/3subtests, independent
Spec/QualityPASS; Task2 final44passed, independentSpec/QualityPASS; Task3 final
21passed, independentSpec/QualityPASS. These checkboxes record scoped deliverables,
not native/system acceptance. Current committed F2 has historical Timer/SPI
cleanHEAD native evidence, but current-source proof review identified failed-case
assertion omissions, functional-fetch ordering and replay-export failure defects.
Those fixes and remaining typed capability-report/per-path refusal integration
are active. Task4–6 are not fully accepted; final frozen software/native,
renamed-instance and independent audits still required. See
[reconciliation report](../../reports/f2-f4-current-acceptance-20261023.md).


## Current-source follow-up after independent whole-slice review

The previously reported proof/accounting and typed-report integration defects are
now fixed and independently reviewed. Shared audit31pass; failure/order/selected
read absence45pass; typed capability90pass; original file-output scope41pass.
Whole-slice review additionally rejected fresh document and initial byte-pin
handling. Meaningful REDs reproduced10semantic substitution failures and5later
formatting-only failures; final24controls passed, including two successful
replays with verified saved-file hashes. Final whole-slice Spec/Quality PASS in
`.superpowers/sdd/compiled-f2/whole-slice-review-20261023.md`.

These are development results, not a final frozen gate. Software attempts1/2
were intentionally interrupted and retained as nonpassing; supervisor preflight
now accepts a self-contained53module scope. Software attempt3 is live with2098
frozen inputs. Task6 and broad system gates remain open; do not infer completion
from in-flight status. See the reconciliation report for exact evidence paths.
