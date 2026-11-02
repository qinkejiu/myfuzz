# Compiled F2 RFuzz Entry Implementation Plan

2026-10-24 reconciliation: Tasks1–6 completed for the selected registered F2 contract. All ten final freeze3 gates have independent acceptance; exact commands/counts/attempts and retained failures are in the [final report](../../reports/compiled-f2-rfuzz-entry-20261023.md) and [frozen acceptance audit](../../reports/evidence/compiled-f2-rfuzz-entry-20261023/audits/final-frozen-slice-acceptance.md). Actual software scope expanded to28 relevant modules:498 passed/5 exact native skips/22 subtests. The five skipped native nodes separately passed in native-suite2. This status/checklist/link-only revision occurs after every gate and final frozen audit; archived plan bytes remain unchanged in freeze3. It does not reinterpret earlier failures, combine development totals or grant useful search/retirement/general onboarding/P6/P7-E/P8/system completion.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This supplements the already authorized F2 implementation Task5; do not request renewed approval. Respect the active source freeze before starting edits.

**Goal:** Complete the original F2 Task5 delivery by running the admitted address-only F2 source through the unified `auto_harness_test` RFuzz entry, actual runtime assertions, fresh execution, and final saved-byte validation.

**Architecture:** Keep `CompiledF2Runtime` and `CompiledF2Decoder` independent of F4 semantics. Share only the bounded RFuzz wire/shared-memory transport operations; add a separate F2 transport executor, explicit driver dispatch, strict receipt-to-case joins, and F2 saved-output verification. Reuse the existing live transport and F2 report collector; preserve same-call D2/D3 identities and original/fresh native evidence.

**Tech Stack:** Python, existing RFuzz FIFO/shared-memory transport and client, ScenarioSession/Runner/Router, RV32I OBI, source-registered APB3 storage, typed assertion documents, Verilator.

## Global Constraints

- Authority: [approved F2 design](../specs/2026-10-23-compiled-f2-read-response-design.md), [original implementation Task5](2026-10-23-compiled-f2-read-response.md#task-5-dedicated-runtime-cli-and-saved-report-integration), and [next-system-gap route1](../../../.superpowers/sdd/next-system-gap-20261023.md). This is completion of an existing delivery, not a reduction of its acceptance conditions.
- At plan preparation, current F2/F4 source/tests/configs/wrappers are frozen. `software5` subsequently reached terminal exit0/reaped with1001 passed,31 skipped and53 subtests; its independent saved-material audit is separate from this plan. F2 CV32E20 Timer2 was still live at the latest status supplied to the planner. Do not edit any active gate input closure or reuse output directories. Obtain the remaining actual terminal states before opening the next implementation freeze; this is sequencing, not a request for user approval.
- Current branch and required uncommitted predecessor work are retained. No stage/commit/reset/clean. Replace the skill's commit step with an archived scoped diff, source hash map, RED/GREEN log, and Spec/Quality review. Do not create a HEAD-only worktree that omits predecessors.
- F2 has one admitted address, stable full32-bit source-registered APB storage, and reset-zero PRDATA. Candidate bytes never supply PRDATA, target state, IRQ, XOR constant, or a setup write. No new F6, FIFO, priming, architectural-retirement, or protocol adapter feature is part of this plan.
- Wire record is **8 bytes**; candidate is its exact first **4 little-endian address bytes**. Last4 bytes are unbound transport evidence and never affect instructions or RTL inputs. Preserve raw8 and projected4 identities separately.
- Common wire parser accepts1..200 records per test for existing F4 compatibility. **F2 admits1..8 records per test, all prechecked;9..200 explicitly refuses before any submit.** Do not silently take the first8. A malformed frame above200 fails transport parsing before execution.
- Atomic preflight applies to one RFuzz test/slot, not to every test in a buffer: an invalid later record cannot execute an earlier record of that same test. Already completed other slots remain recorded. Once execution starts, a later runtime failure retains partial effects and typed failed/missing rows; no rollback claim.
- Exactly two D3 expectations remain: `protocol_checker.receipt_violations` and `cross_component.declared_edge_hops`. Dependent RAM and individual edge feedback are executor observations, not extra D3 expectations or bug classifications.
- This gate proves the unified transport seam. A working client, repeated singleton address, or stable reset-zero result does not demonstrate useful mutation diversity, feedback benefit, P6/P7-E/P8, or system completion.
- Development evidence: `.superpowers/sdd/compiled-f2-rfuzz-entry-20261023/`. Final evidence: `docs/reports/evidence/compiled-f2-rfuzz-entry-20261023/`, new attempt directories only. Native work uses one existing heavy-worker lock and isolated cache; any remote work follows `agent.md` and stays under `/root/fanzehui/`.

## Current interfaces and boundaries

| Existing interface | Actual behavior | Required adaptation |
| --- | --- | --- |
| `CompiledF2Decoder.decode_sequence(records, *, cursor, case_index)` | Takes tuple, returns tuple of `CompiledF2Candidate`; validates all records and planned slots; ordinary `ValueError` refusals | Expose read-only `path_id/source_id/direction/max_input_bytes`; add a typed candidate-refusal subtype without catching arbitrary executor errors |
| F2 candidate | `candidate.case.case_id`, `.case.direction`, `.case.source.address`, `.candidate_bytes`, `.document()` | Do not read F4-only `.value/.register/.case_id/.direction` fields; F2 receipt/decision construction uses its actual shape |
| `run_scenario_rfuzz_live` | Requires `isinstance(executor, ScenarioRfuzzExecutor)`; reads `online_decoder.max_input_bytes`, `.document()`, shared executor state and `_finish_online_session` | Independent `CompiledF2RfuzzExecutor(ScenarioRfuzzExecutor)` owns the explicit live surface; do not invoke the genome initializer or subclass `CompiledRfuzzExecutor` |
| `process_owned_pair` | Returns `(coverage_id, input_id)` | Preserve exact tuple order, ownership, capacity check, and segment closing |
| `execute_batch` | Returns `tuple[bytes, ...]`, one vector per input test | Preserve vector count/width and duplicate-slot semantics |
| `_finish_online_session` | Live finalizer unpacks `(trace, plan_hex)` | Return the pair, cache idempotently, preserve partial trace/plan on failure |
| `ScenarioLiveResult` | Dataclass, not tuple/dict | Wrapper outcome is a dict with `outcome['live'].client_returncode`, `.tests`, `.statuses`; do not unpack live as a pair |
| F4 `join_compiled_receipts` | Checks F4 source/path, not an F2 wire/case ledger | Add F2 join with raw, projected candidate, case, assertion and fresh-record bijections; preserve F4 API |
| `auto_harness_test` | Registry, input loader, support assessment, wrapper, output verifier and artifact names are F4-specific | Dispatch each by a closed executor entry; never infer a family or fall back to F4 |

Files are split as follows. `compiled_rfuzz_transport.py` owns only wire parsing and shared-memory exchange; `compiled_f2_rfuzz.py` owns F2 transport execution and orchestration; `compiled_f2_feedback.py` owns pure validated F2 observation projection; `compiled_f2_receipts.py` owns strict saved wire/case joining; `compiled_f2_saved_outputs.py` owns F2 initial/final byte checks and build-material joins. No new general execution framework is required.

## Task1: Expose F2 wire contract and share only transport primitives

**Files:** create `src/myfuzz/integration/compiled_rfuzz_transport.py`; modify `src/myfuzz/integration/compiled_rfuzz.py` only to delegate the two wire operations while preserving its exported constants/functions; modify `src/myfuzz/scenario/compiled_f2_decoder.py`; add `tests/integration/test_compiled_f2_rfuzz_wire.py`; extend `tests/integration/test_compiled_f2_decoder.py`.

**Interfaces:**

- `parse_compiled_input_buffer(data) -> InputBatch`: common8-byte/200-record parser.
- `process_compiled_owned_pair(executor, input_id, coverage_id, *, creator_pid, on_receipt=None) -> tuple[int, int]`.
- F2 decoder read-only properties: `path_id=self.path['path_id']`, `source_id=self.contract['load_source_id']`, `direction=self.path['direction']`, `max_input_bytes=8`. Keep `.layout.byte_length=4`; `max_input_bytes` is one transport record, not candidate width or the sequence budget.
- `CompiledF2CandidateRefused(ValueError)` exposes `code`, `pointer`, `detail`. Only `_require` candidate/preflight refusal sites produce it. Existing callers catching `ValueError` remain compatible. Its initializer is `__init__(self, code, pointer='', detail=None)` and stores the three values before `super().__init__('compiled-F2-decoder-'+code)`.
- `f2_seed_record(path) -> bytes`: rebuild/validate the existing F2 layout and classify the exact contract address; `path['seed']` stays `None` as required by current admission. This transport seed is derived from the admitted source, not a new D3 seed declaration.

- [x] **Step1 RED:** decoder tests assert the live-facing properties, immutable semantic identity, refusal subtype, tuple result and actual candidate attributes. Add seed checks on real Timer/SPI D3 rows; zero seed must fail candidate classification when address is nonzero.

```python
def test_f2_wire_seed_is_the_admitted_address(inputs):
    from myfuzz.integration.compiled_f2_rfuzz import f2_seed_record
    from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
    path = next(p for p in inputs['compiled']['paths']
                if p['flow_id'] == 'F2' and p['status'] == 'executable')
    raw = f2_seed_record(path)
    assert len(raw) == 8
    assert raw[:4] == path['execution_contract']['address'].to_bytes(4, 'little')
    assert raw[4:] == bytes(4)
    assert compile_f2_candidate_layout(path).classify(raw[:4]).accepted
    assert path['seed'] is None
```

- [x] **Step2 Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f2_rfuzz_wire.py tests/integration/test_compiled_f2_decoder.py`. Save missing-module/property failures before implementation. Existing `inputs` fixture in `test_compiled_f2_decoder.py` supplies the real generated Timer D3; import it into the new wire test module.
- [x] **Step3 Implement the exact wire operations and legal seed:**

```python
# compiled_rfuzz_transport.py
from .rfuzz_shmem import OwnedSegment
from .rfuzz_wire import parse_input_buffer, encode_coverage_buffer

WIRE_RECORD_BYTES = 8
WIRE_MAX_CYCLES = 200

def parse_compiled_input_buffer(data):
    return parse_input_buffer(data, input_bytes=WIRE_RECORD_BYTES,
                              max_cycles=WIRE_MAX_CYCLES)

def process_compiled_owned_pair(executor, input_id, coverage_id, *, creator_pid,
                                on_receipt=None):
    if input_id == coverage_id:
        raise ValueError('input and coverage shared-memory IDs alias')
    with OwnedSegment(input_id, creator_pid=creator_pid) as inputs, \
            OwnedSegment(coverage_id, creator_pid=creator_pid, writable=True) as outputs:
        batch = parse_compiled_input_buffer(inputs.read())
        stride = ((executor.counter_count + 2 + 7) // 8) * 8
        if 16 + stride * len(batch.tests) > outputs.size:
            raise ValueError('RFuzz coverage capacity is insufficient')
        coverages = executor.execute_batch(batch, on_receipt=on_receipt)
        outputs.write(encode_coverage_buffer(batch, coverages,
            counter_count=executor.counter_count, capacity=outputs.size))
    return coverage_id, input_id

# compiled_f2_rfuzz.py
from .compiled_f2_layout import compile_f2_candidate_layout

def f2_seed_record(path):
    layout = compile_f2_candidate_layout(path)
    raw = path['execution_contract']['address'].to_bytes(4, 'little') + bytes(4)
    if not layout.classify(raw[:4]).accepted:
        raise ValueError('compiled-F2-rfuzz-seed-refused')
    return raw
```

Add the four read-only decoder properties and the refusal class; `_require` raises that subtype with its existing reason code and useful source pointer. F4 `parse_compiled_input_buffer` remains importable at the old path; its constants remain200/8 and its `process_owned_pair` delegates without changing cap/tail behavior.

- [x] **Step4 GREEN:** run the Task1 command plus `tests/integration/test_compiled_online_decoder.py tests/integration/test_rfuzz_wire.py tests/integration/test_rfuzz_shmem.py`; prove1/8/9/64/200 frames parse and201 fails, segment alias/capacity errors close both handles, and tuple order is unchanged. Archive source diff/hash map and scoped review.

## Task2: Add independent F2 executor with whole-test preflight

**Files:** implement `src/myfuzz/integration/compiled_f2_rfuzz.py`; create `tests/integration/test_compiled_f2_rfuzz_executor.py` and `tests/integration/f2_rfuzz_support.py`.

**Interfaces:** `CompiledF2RfuzzExecutor(ScenarioRfuzzExecutor)` and `build_compiled_f2_rfuzz_executor(runtime, *, run_id, evidence_dir=None, feedback_interval=16)`. Builder accepts an actual `CompiledF2Runtime`, validates decoder/session runtime-path admission equality and full compiled digest, and never constructs native authority from saved JSON. `execute_batch` consumes `InputBatch`; actual submissions call `runtime.submit(candidate.candidate_bytes)` only.

- [x] **Step1 RED:** new software support module builds real source-backed Timer inputs using existing `timer_loaded`, and an explicitly marked runtime spy around `CompiledF2Runtime.__new__` with real admission/declaration/layout and synthetic receipts. It must never launch/build or claim native evidence. Test `(valid, invalid)` and `(valid, valid)` with insufficient case/slot budget: no submits, no ticks, cursor/records/attempts unchanged. Also test9/64/200 records, duplicate raw slot, changed raw under same slot, and runtime failure on second planned candidate retaining the first effect plus second failed attempt.

Define fixture `transport_case` in `tests/integration/f2_rfuzz_support.py` and import it explicitly into executor/feedback/receipt tests. It yields `(executor,runtime,valid_wire)`; `runtime.submits` is the spy's actual submission log, `runtime.runner.local_ticks` is its mutable tick map, `valid_wire=f2_seed_record(runtime.path)`. The spy uses source-backed admission and emits synthetic F2 certificates solely for transport tests; Task3 adds actual checker-fixture validation rather than promoting those synthetic dictionaries to native authority.

```python
def test_invalid_second_record_submits_neither_candidate(transport_case):
    from copy import deepcopy
    from myfuzz.integration.rfuzz_wire import InputBatch
    executor, runtime, valid = transport_case
    before = (runtime.cursor, deepcopy(runtime.runner.local_ticks),
              len(runtime.records), len(runtime.attempts))
    vectors = executor.execute_batch(InputBatch(1, 8, ((valid, bytes(8)),)))
    assert vectors == (bytes(executor.counter_count),)
    assert runtime.submits == []
    assert before == (runtime.cursor, runtime.runner.local_ticks,
                      len(runtime.records), len(runtime.attempts))
    assert executor.receipts[-1].status == 'input_invalid'
```
- [x] **Step2 Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f2_rfuzz_executor.py`; expect absent executor, then observable preflight/tuple/state failures until implemented.
- [x] **Step3 Implement preflight as a pure phase:**

```python
def preflight_f2_test(runtime, decoder, records):
    from myfuzz.scenario.compiled_f2_decoder import CompiledF2CandidateRefused
    if type(records) is not tuple or not 1 <= len(records) <= 8:
        raise CompiledF2CandidateRefused('sequence-count', '/wire/records',
                                       {'observed': len(records)})
    if runtime._failed_attempt is not None:
        raise ValueError('compiled-F2-rfuzz-runtime-already-failed')
    requested = len(records)
    admitted = len(runtime.attempts)
    if admitted + requested > runtime.max_cases:
        raise CompiledF2CandidateRefused('case-budget-exhausted', '/cases',
            {'admitted': admitted, 'requested': requested,
             'max_cases': runtime.max_cases})
    # Decoder plans every instruction slot before any native submit.
    return decoder.decode_sequence(records, cursor=runtime.cursor,
                                   case_index=admitted)
```

Normalize each `InputBatch` test to tuple before this call, preserve the complete raw8 record list, and do not slice it. No preflight helper advances cursor, reserves a session case or issues a version. `_require` errors inside decoding are input-invalid; unknown exceptions are environment errors, never recast as candidate refusal.

Implement these F2-owned methods: `__init__`, `execute_batch`, `_build_receipt`, `_new_decision`, `_check_case_budget`, `_duration_reached`, `_local_ticks`, `_tick_delta`, `_receipts_append`, `_save_failure`, `mutation_hint`, `note_published_hint`, `applied_source_uses`, `_finish_online_session`, `execution_audit`, `candidate_exploration_state`, `classified_feedback_state`. Common `process_owned_pair` delegates to Task1. Do not copy F4 commit targets, F4 certificate parsing, F4 `.value/register` candidate fields, genome decoder state, or base online case-reservation methods.

Explicitly initialize every live/report-read field from the existing F4 `_SHARED_SURFACE`; add a F2 `_SHARED_SURFACE` equality/test guard. `decoder=None`, `online_decoder=CompiledF2Decoder.from_runtime(runtime)`, `session=runtime.session`, `factory=lambda:runtime.runner`; configured checker remains the runtime session checker, while transport `checker/checker_config/checker_identity_target` stay `None` because the transport does not collect a second checker. Set runtime-path fields from the decoder's validated admission and require actual session contract/prepared document/instruction binding equality. `runtime_path_status='contract_preflight'`; replay_only/closed_loop_energy/path_switch/classified_feedback/candidate_exploration are false and their report methods return no unsupported feature state. Initialize receipt/decision/dedup/hint/stop/finalization counters explicitly; do not rely on base initializer side effects.

For each preflighted candidate, require current runtime cursor to equal `candidate.case.source.address`, submit4, then require returned F2 certificate case/path/source/binding/runtime-path identities match the planned candidate and admitted binding. Decisions retain `case_ids`, per-candidate documents and ordered raw8/projected4 hashes. Use `ScenarioRfuzzReceipt` keyword arguments, including `online_case={'source': sequence_document}`, `path_id`, `applied_sources`, `applied_source_ids`, `coverage_hex`; do not edit its positional field order. Refused test: status=`input_invalid`, committed=false, zero vector, no invented admitted case IDs/assertions. Post-submit exception: status=`environment_error`, stop session, retain actual attempted case IDs and partial runtime evidence; do not continue to later tests/candidates as though execution was clean.

Duplicate `(buffer_id,slot)` with identical raw hash returns cached coverage/receipt, without new submissions; changed raw is terminal refusal. Callback persistence remains idempotent in the live writer. Finalization calls `runtime.finish()` once, caches `runtime.trace` and `runtime.session.encode_plan().hex()`, returns `(trace,plan_hex)` on repeat, and preserves actual partial trace/plan if finish raises. Mutation hint lists the actual address source with constant weight1, no F4 write-bit energy heuristic.

- [x] **Step4 GREEN:** Task2 command plus Task1 tests; include explicit tuple assertions for `decode_sequence`, `execute_batch`, shared-memory reply and `_finish_online_session`. Scope review must inspect whole-test preflight before first submit and partial-failure inventory, not only a mocked successful submit count.

## Task3: Project actual F2 observation feedback and join receipts strictly

**Files:** create `src/myfuzz/integration/compiled_f2_feedback.py`, `src/myfuzz/integration/compiled_f2_receipts.py`, `tests/integration/test_compiled_f2_rfuzz_feedback.py`, `tests/integration/test_compiled_f2_rfuzz_receipts.py`; wire Task2 executor to the projection.

**Interfaces:**

- `f2_observation_targets(path) -> tuple[CoverageTarget, ...]`: six explicit executor observation predicates under `compiled_f2.<path_id>`, component=contract source component, port=`compiled_F2_case_facts`, masks1/2/4/8/16/32, expected mask value. This port is a named code projection of validated live case facts, not an invented DUT pin.
- `f2_observation_hits(*, runtime, candidates, certificates) -> tuple[frozenset[str], dict]`: validate runtime typed results against independently collected `assertion_case_evidence()` using `validate_assertion_results`; join only the submitted case IDs; return target hits plus detached evidence references for receipts.
- `join_compiled_f2_receipts(receipts_path, *, compiled_inputs, runtime, executor, plan, replay) -> dict`: strict byte/identity/ordered-record join; crosschecks original live executor decisions/receipts before comparing runtime projections; no native authority returned.

- [x] **Step1 RED:** use real synthetic exact-hop fixtures from `test_compiled_f2_consumer.py`/`test_compiled_f2_read_response.py` and source-backed runtime inventory. Reject a fabricated certified dict, missing typed row/ref, wrong binding/case/transaction, unknown edge and missing RAM store. A valid case produces only actual witnessed hits; invalid/preflight-refused cases produce zero. Mutating suffix4 changes raw hash and leaves candidate/declaration/feedback equal. Receipt join rejects F4 rows, wrong source/path/run/binding, altered raw8/projected4, omitted/duplicate case or assertion, reordered candidate sequence, wrong instruction address/code hash, and coherent rehash of any such substitution.

```python
def test_feedback_target_names_cannot_be_f4_commit_bits(inputs):
    from myfuzz.integration.compiled_f2_feedback import f2_observation_targets
    path = next(p for p in inputs['compiled']['paths']
                if p['flow_id'] == 'F2' and p['status'] == 'executable')
    targets = f2_observation_targets(path)
    assert len(targets) == 6
    assert {t.mask for t in targets} == {1, 2, 4, 8, 16, 32}
    assert all(t.port == 'compiled_F2_case_facts' for t in targets)
    assert all(t.target_id.startswith('compiled_f2.') for t in targets)
```

This shape test supplements, rather than replaces, the evidence-substitution/hit tests above. Import the real source-backed `inputs` fixture from `test_compiled_f2_decoder.py`.
- [x] **Step2 Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f2_rfuzz_feedback.py tests/integration/test_compiled_f2_rfuzz_receipts.py`.
- [x] **Step3 Implement six predicates from exact existing fields:**

| Bit | Hit condition after the typed case join | Evidence retained |
| --- | --- | --- |
| 0 | protocol expectation passed with actual final receipt | case assertion evidence ref and actual violations observation |
| 1 | declared-edge expectation passed | case assertion evidence ref |
| 2 | exact edge0 relation persistent_state certified, nonempty functional instruction hops | actual fetch/image/version refs |
| 3 | exact edge1 CPU→IP mmio read_request certified with actual hops | same transaction's CPU acceptance/APB refs |
| 4 | exact edge2 IP→CPU mmio read_return certified with actual hops | APB producer/native OBI response refs |
| 5 | exact dependent RAM hop present and consistent with the validated certificate | `exact_hops.ram_write_hop.memory_write_event` plus writer/version/result |

Check edge identity/endpoints/ordering against `runtime.declared_edges`, not role string alone: existing edge roles are `[read_request,read_request,read_return]`, so “find any read_request” would confuse edge0 with edge1. Typed validation success alone does not invent a protocol hit; missing/failed stays unset. If a submitted test partially fails, preserve per-attempt diagnostics and return a conservative zero test vector; never credit unauthenticated late settlement. The resulting vector is six bytes, one0/1 per target; it is observation feedback, not six D3 assertions or architectural coverage. `runtime.feedback()['dependent_result_stores']` and `certified` aggregates cannot stand in for per-case proofs.

The receipt join first compares persisted rows against the same-call `executor.receipts` and `executor.online_decisions`, keyed uniquely by run/buffer/slot/raw hash, so a coherently rehashed raw8 suffix replacement cannot substitute for the actual transported bytes. It reads the persisted `online_raw_records_hex` and `online_source` document, recomputes SHA256 of concatenated raw8 records and SHA256 of concatenated projected4 candidates, constructs a fresh independent decoder with `CompiledF2Decoder.from_request(request=compiled_inputs['request'],compiled=compiled_inputs['compiled'],run_id=runtime.run_id,schedule=tuple(runtime.runner.sessions),rounds=runtime.rounds,result_address=runtime.result)` and calls `decode_sequence` at each saved cursor/case index. Record every attempted case and source/source-instruction/runtime path mapping. Certified receipts must biject to original `plan['records']` and typed assertion cases; projected records and instruction addresses/code must also match `replay['actual_prefix']['records']`. Preflight input-invalid rows independently reproduce the same typed rejection and correspond to no runtime attempt. Match runtime original/fresh compiled/binding identities under the existing allowed process-local normalization. On failure exports, typed attempt inventory remains available even if a complete plan does not exist; do not run the success join and emit `status=ok` on an incomplete run.

- [x] **Step4 GREEN:** Task3 command plus Task2 tests. Save a receipt example with multiple candidates; ensure JSON row uses source=`cpu_load_stream`, no F4 `.commit.after`, and the full raw8 list remains independently hashable. Archive review/diff.

## Task4: Orchestrate actual F2 live/fresh execution and pin all outputs

**Files:** finish `src/myfuzz/integration/compiled_f2_rfuzz.py`; create `src/myfuzz/integration/compiled_f2_saved_outputs.py`, `tests/integration/test_compiled_f2_rfuzz_saved_outputs.py`; reuse `compiled_runtime_report.py` and `compiled_f2_build_join.py` without changing their authority model.

**Interfaces:**

```python
def run_compiled_f2_rfuzz_session(*, artifacts, compiled_inputs, base_dir,
        cache_dir, run_id, session_dir, output_dir, client_binary, budget_seconds,
        max_tests, search_seed, max_runs_per_batch, rounds_per_case=128):
    # Return the same driver outcome keys as the existing F4 wrapper.
    # live: ScenarioLiveResult; plan/replay/verification/join: dict;
    # executor/runtime: actual objects; build_join: dict;
    # assertion_material: captured independent F2 material;
    # saved_output_hashes: filename -> initial SHA256.
    return _run_f2_live_and_fresh(artifacts=artifacts, compiled_inputs=compiled_inputs,
        base_dir=base_dir, cache_dir=cache_dir, run_id=run_id,
        session_dir=session_dir, output_dir=output_dir, client_binary=client_binary,
        budget_seconds=budget_seconds, max_tests=max_tests, search_seed=search_seed,
        max_runs_per_batch=max_runs_per_batch, rounds_per_case=rounds_per_case)

def verify_saved_compiled_f2_build_outputs(output_dir, *, outcome,
                                          harness_set, manifest):
    return _verify_f2_same_call_outputs(output_dir, outcome=outcome,
                                       harness_set=harness_set, manifest=manifest)
```

Implement `_run_f2_live_and_fresh` and `_verify_f2_same_call_outputs` in their respective files with the following fixed sequence; the public signatures above are the integration contract, not permission to return an unfinished stub.

- [x] **Step1 RED:** exercise actual wrapper with software runtime/live doubles (pattern in `test_compiled_f4_saved_build_outputs.py`) to prove legal seed forwarding, actual fresh flags, mandatory raw materials, constructor audit sink retention, and primary-error preservation. Swap each saved document semantically; separately reformat it without changing semantics; both must refuse initial pins. Make one replay export fail and verify other raw/audit exports are still attempted, with the primary error preserved.

Add helper `saved_f2_outcome(tmp_path)` to the new saved-output test file: construct the same-call F2 document set listed below, write it once using the production writer, and return `(outcome,documents)` with actual initial `saved_output_hashes`; use source-backed F2 binding/admission fixtures. The verifier's material-join function may be patched only after testing that semantic/byte comparisons happen before that call.

```python
def test_format_change_is_not_allowed_to_reset_initial_pin(tmp_path):
    import json
    import pytest
    from myfuzz.integration.compiled_f2_saved_outputs import verify_saved_compiled_f2_build_outputs
    outcome, documents = saved_f2_outcome(tmp_path)
    name = 'compiled_f2_fresh_events.json'
    (tmp_path / name).write_text(json.dumps(documents[name], indent=4) + '\n')
    with pytest.raises(ValueError, match='bytes-changed|initial-bytes'):
        verify_saved_compiled_f2_build_outputs(tmp_path, outcome=outcome,
            harness_set=outcome['harness_set'], manifest=outcome['manifest'])
```
- [x] **Step2 Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f2_rfuzz_saved_outputs.py`.
- [x] **Step3 Implement construction/live/fresh in this order:**

```python
# Core execution inside _run_f2_live_and_fresh's guarded lifecycle:
runtime = CompiledF2Runtime(artifacts=artifacts, compiled_inputs=compiled_inputs,
    base_dir=base_dir, cache_dir=cache_dir, run_id=run_id,
    rounds_per_case=rounds_per_case, max_cases=min(max_tests * 8 + 8, 65536),
    build_audit_sink=save_original_build)
executor = build_compiled_f2_rfuzz_executor(runtime, run_id=run_id)
live = run_scenario_rfuzz_live(executor=executor, client_binary=client_binary,
    output_dir=session_dir, duration_seconds=budget_seconds,
    seed_records=(f2_seed_record(runtime.path),), max_tests=max_tests,
    search_seed=search_seed, max_runs_per_batch=max_runs_per_batch)
plan = runtime.finish()
replay = runtime.replay(plan, audit_sink=save_fresh_material)
```

The nested `save_original_build(snapshot)` retains an independent copy. `save_fresh_material(envelope)` writes every available actual_prefix/actual_events/execution_audit and the replay summary, retaining original_build/fresh_build; attempts all exports before raising the first exporter error and appends later errors as notes. Construct the full verification only from replay's actual `matches`, `first_difference`, `verification_scope`, semantic hashes and raw material; reject absent scope, non-full scope, non-true match, non-null difference, missing actual prefix/events/closed audit or nonzero client returncode before claiming success. Do not hardcode `verification_scope='full'` or derive a match by rereading saved JSON.

Use actual F2 build snapshots to construct and verify `compiled_F2_build_join.v1`. `verify_compiled_f2_build_material` joins harness_set, actual session manifest, original plan and replay; retain raw distinct processes/UUIDs, receipts, binary/executable/READY hashes. Capture original typed inventory with `capture_f2_report_material` **after** actual full replay; keep it independent of saved typed result JSON. Export required filenames:

```text
compiled_f2_prefix.json
compiled_f2_replay.json
compiled_f2_fresh_prefix.json
compiled_f2_fresh_events.json
compiled_f2_fresh_execution_audit.json
compiled_f2_fresh_verification.json
compiled_f2_build_join.v1.json
compiled_f2_receipt_join.v1.json
compiled_assertion_results.v1.json
compiled_assertion_evidence.v1.json
```

The wrapper outcome includes `assertion_material` (assertions/evidence/report), not a different artificial case inventory. Its preliminary generic report is not published as the final auto-harness capability report. Native original events/manifests/online plan/raw seed/raw receipt rows remain in `session/` under the existing live writer. Verification describes projected admitted cases as the RTL replay source and complete raw8 as pinned transport evidence; independent redecoding plus matching fresh prefix proves which raw bytes reached RTL. Do not claim suffix bytes were executed.

Implement atomic initial JSON export: compute exact bytes with a single explicit serializer, write through a temporary file/replacement, immediately compare bytes with the prepared value, and retain SHA256 before any later export. Final verifier compares same-call semantic objects **and** original byte digests; it also pins raw seed/receipts and the session manifest/online plan/original trace bytes. Missing required files refuse. Final auto-harness finalization rechecks all returned hashes after capability/bundle export; coherent rehash and formatting-only drift both refuse.

Construction failure preserves available sink diagnostics in refused F2 build join with binding=None, no fabricated cases/trace. Later submit/finish/replay failure independently tries partial_events, typed assertions, independent case evidence, process audit and build join; missing observations stay missing, observed contradictions failed. Cleanup/export errors add notes and never replace the first primary error. A failure cannot return an outcome that the driver reads as completed; `.incomplete` remains.

- [x] **Step4 GREEN:** Task4 command plus existing `test_compiled_f2_runtime_report.py`, `test_compiled_f2_report_outputs.py`, `test_compiled_f2_failure_audit.py`, `test_compiled_f4_saved_build_outputs.py`. Require a successful software outcome with actual saved raw material, first/fresh semantic substitution failures, and byte-only substitution failures. Review exact code before moving to driver wiring.

## Task5: Dispatch same-call D2/D3 into F2 and publish validated capability report

**Files:** modify `src/myfuzz/local_harness/auto_harness_test.py`, `scripts/auto_harness_test.py`; extend `tests/integration/test_auto_harness_test.py`; create `tests/integration/test_compiled_f2_rfuzz_entry.py`. No changes to family defaults or guessed component selection.

**Interfaces:** `load_compiled_session_inputs(..., flow='F4')` keeps existing F4 callers; add `run_compiled_f2_session` with the same keyword signature as existing `run_compiled_session`. Preserve existing `run_compiled_session` as F4 wrapper. Closed registry adds metadata `flow`, support assessor, runner wrapper, output verifier and required filenames, selected only by the explicit executor string.

- [x] **Step1 RED:** CLI `--executor compiled-f2-rfuzz --skip-session` produces D1/D2/D3/support without native start; full software-double call sends **the exact just-loaded artifact objects** and typed request/compiled/ownership into the F2 wrapper, never `run_compiled_session` or a family. SPI fixed physical inputs must still have exact owners; F2 CPU-owned address source is not an environment pin source. Missing client, runtime/executor conflict, unknown executor, stale F2 marker, wrong shape and modified same-call D3 refuse with code/pointer. Tuple/live/outcome handling must reach final report without attribute/unpacking errors.

```python
def test_f2_entry_is_registered_without_a_family_fallback():
    from myfuzz.local_harness.auto_harness_test import COMPILED_EXECUTORS
    row = COMPILED_EXECUTORS['compiled-f2-rfuzz']
    assert row['flow'] == 'F2'
    assert row['entry'] == 'myfuzz.integration.compiled_f2_rfuzz:run_compiled_f2_rfuzz_session'
    assert row['family_fallback'] is False
```

The principal integration test patches only the runtime wrapper/client/bundle layer, records object identities at `load_compiled_session_inputs` and at `run_compiled_f2_session`, and checks the final generic report's joined typed rows. It must fail if driver F2 dispatch is changed to F4 or if assertion_evidence is rebuilt from the result document.
- [x] **Step2 Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f2_rfuzz_entry.py tests/integration/test_auto_harness_test.py`.
- [x] **Step3 Implement closed flow dispatch:**

```python
# Values are code-owned functions; no caller-supplied entry or factory.
COMPILED_EXECUTORS['compiled-f2-rfuzz'] = {
    'entry': 'myfuzz.integration.compiled_f2_rfuzz:run_compiled_f2_rfuzz_session',
    'flow': 'F2',
    'requires': ['one executable admitted D3 F2 read target',
                 'the RFuzz client binary', 'an existing shared build cache'],
    'family_fallback': False,
}
```

Make loader selection use `flow`, retain original F4 default/rejection behavior, and keep existing fixed-artifact ownership reconstruction/refusal logic. F2 side effects or unsupported source still refuse via actual F2 support assessment before constructor. Add explicit driver branches for `assess_compiled_f2_support`, `run_compiled_f2_session`, `verify_saved_compiled_f2_build_outputs`; avoid dynamic imports supplied by inputs. Preserve current F4 registry public values where existing compatibility tests assert them, or update only expected metadata changes with explicit regression evidence.

At final capability call, F2 supplies the independently captured pair, without rebuilding evidence from the saved result:

```python
typed_kwargs = {}
if executor == 'compiled-f2-rfuzz' and outcome is not None:
    typed_kwargs = {
        'assertion_results': outcome['assertion_material']['assertions'],
        'assertion_evidence': outcome['assertion_material']['assertion_evidence'],
    }
report_document = build_capability_report(compiled_path, harness_set=harness_path,
    session=session_dir, fresh_verification=fresh_path, checker_findings=None,
    unavailable=None, label=summary['label'], base_dir=base, **typed_kwargs)
```

Initialize `outcome=None` before dispatch so a refusal cannot reuse a prior outcome. Pre-session projection is saved separately (`execution_projection.v1.json` / `execution_support.json`) and cannot impersonate final typed outcomes. Record F2 required artifact names, raw hashes and join in run summary. Pin final `capability-report.json`, `fresh-verification.json`, session/build material and typed documents at their initial export, then recheck them in `finish()` after all writes. Report typed assertion outcomes with no additional tier grant; finding classifications stay separate. Explicitly add run limits `candidate_domain_size=1`, observed distinct projected candidates, real observed response values, feedback targets/hits, build cost, useful cases/s/chains/s when measurable, and `useful_search_benefit_claimed=False`. Existing generic grading may grant other tiers only under its independent existing gates.

Update CLI help to list both explicit executors, shared rounds/budget options, actual F2 output names, and no fallback. Default invocation remains unchanged. F2 early refusal emits explicit selected-flow reason and per-other-path unsupported entries; `.incomplete` removal still requires all requested stages and final saved-pin checks.

- [x] **Step4 GREEN:** Task5 command plus `test_compiled_f4_spi_source_real.py`, `test_compiled_execution_projection.py`, Task1–4 modules. Include final report typed rows and no implicit tier promotion, saved-byte drift immediately before `finish()`, late raw8/receipt swap, first-error retention, and old F4 command compatibility. Archive independent Spec/Quality review.

## Task6: Freeze and execute software, real RFuzz, rename and refusal gates

**Files:** create `tests/integration/test_compiled_f2_rfuzz_native.py` (opt-in only), `scripts/verify_compiled_f2_rfuzz.py` (saved-material auditor), and `docs/reports/compiled-f2-rfuzz-entry-20261023.md`; existing scenarios are inputs, not rewritten historical evidence. Gate wrapper/refusal/rename fixture declarations are generated and archived **before** freeze, then treated as read-only inputs.

**Interfaces:** native tests run only with `MYFUZZ_RUN_NATIVE_F2_RFUZZ=1`; auditor CLI `python3 scripts/verify_compiled_f2_rfuzz.py --output <run-directory>` verifies saved bytes against the frozen supervisor's external input/output map, independently redecodes every raw8 receipt into projected4 and checks assertion/case/fresh/build joins. It never issues live authority from saved documents.

- [x] **Step1 RED/GREEN gate wrapper:** prove auditor rejects altered raw receipt, typed result, binding, original/fresh prefix, actual events, process audit, receipt join, binary association, missing file, stale marker and formatting-only byte drift. Assert native tests skip with the exact named opt-in reason when the environment variable is absent. Use saved software outcomes for wrapper development; do not run native during source edits.
- [x] **Step2 Freeze:** archive exact production/tests/configs/generated-control/wrapper input bytes, commands, Python/client executable hashes, existing tool provenance scope, source/dir maps and skip policy; record all prior RED/failed attempts. No concurrent edits inside this closure. Use the same working-tree snapshot for F2 and affected F4 regressions; broad source changes invalidate current-byte attribution of old native evidence.
- [x] **Step3 Frozen software command:**

```bash
PYTHONPATH=src:. python3 -m pytest -q -ra \
  tests/integration/test_compiled_f2_rfuzz_wire.py \
  tests/integration/test_compiled_f2_decoder.py \
  tests/integration/test_compiled_f2_rfuzz_executor.py \
  tests/integration/test_compiled_f2_rfuzz_feedback.py \
  tests/integration/test_compiled_f2_rfuzz_receipts.py \
  tests/integration/test_compiled_f2_rfuzz_saved_outputs.py \
  tests/integration/test_compiled_f2_rfuzz_entry.py \
  tests/integration/test_compiled_f2_runtime_report.py \
  tests/integration/test_compiled_f2_report_outputs.py \
  tests/integration/test_compiled_f2_failure_audit.py \
  tests/integration/test_compiled_online_decoder.py \
  tests/integration/test_compiled_f4_saved_build_outputs.py \
  tests/integration/test_compiled_f4_build_orchestration.py \
  tests/integration/test_compiled_f4_runtime_path_wiring.py \
  tests/integration/test_compiled_f4_spi_source_real.py \
  tests/integration/test_auto_harness_test.py \
  tests/integration/test_scenario_rfuzz_live_client.py \
  tests/integration/test_scenario_rfuzz_terminal_identity.py \
  tests/integration/test_rfuzz_wire.py \
  tests/integration/test_rfuzz_shmem.py
```

Expected: exit0, no unexpected skips, native skips explicitly named. Save actual count; no planned count is an acceptance fact. Supervisor records PID/reaped/exit/timeout/RSS and before/after byte maps. Broaden regression only if changed dependencies or failures justify it.

- [x] **Step4 Actual real-client gates:** under the existing heavy-worker lock, invoke the unified CLI with existing Timer and SPI scenarios and the real RFuzz client. The Timer command is:

```bash
PYTHONPATH=src:. python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/ibex_obi_local/component_profile.json \
  --ip configs/peripherals/pulp_timer/component_profile.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-timer/test_capability.json \
  --compose configs/scenarios/compiled-f4-obi-apb-timer/compose.json \
  --executor compiled-f2-rfuzz \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir .superpowers/cache/compiled-f2-rfuzz-entry-20261023 \
  --output docs/reports/evidence/compiled-f2-rfuzz-entry-20261023/timer-attempt1 \
  --budget-seconds 30 --max-tests 4 --max-runs-per-batch 1 \
  --search-seed 1 --rounds-per-case 128
```

The Timer profiles above were read from its current request JSON. Use these literal SPI and extra CV32E20 Timer commands; archive all three commands and their request bytes in the freeze. Create the isolated cache directory before running; native test module owns serialization and asserts gate selection count.

```bash
PYTHONPATH=src:. python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/cv32e40p/component_profile.json \
  --ip configs/peripherals/pulp_spi/local_component_profile.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/test_capability.json \
  --compose configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/compose.json \
  --executor compiled-f2-rfuzz \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir .superpowers/cache/compiled-f2-rfuzz-entry-20261023 \
  --output docs/reports/evidence/compiled-f2-rfuzz-entry-20261023/spi-attempt1 \
  --budget-seconds 30 --max-tests 4 --max-runs-per-batch 1 \
  --search-seed 1 --rounds-per-case 128

PYTHONPATH=src:. python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/cv32e20/component_profile.json \
  --ip configs/peripherals/pulp_timer/component_profile.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-timer-cve2/test_capability.json \
  --compose configs/scenarios/compiled-f4-obi-apb-timer-cve2/compose.json \
  --executor compiled-f2-rfuzz \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir .superpowers/cache/compiled-f2-rfuzz-entry-20261023 \
  --output docs/reports/evidence/compiled-f2-rfuzz-entry-20261023/cve2-timer-attempt1 \
  --budget-seconds 30 --max-tests 4 --max-runs-per-batch 1 \
  --search-seed 1 --rounds-per-case 128
```

Each real-client positive must show at least one actual seed-projected F2 case, real client receipt/feedback exchange, zero false coverage, current IP version, native OBI/APB/return/dependent RAM proof, exact typed expectation rows, full original/fresh match, complete F2 build join, distinct original/fresh PID/nonces and reaped exit0. Report actual rejected mutations and singleton candidate count; multiple accepted mutations are not required when the legal domain is one. Add a separate real-runtime two-record `InputBatch` control with the same legal seed twice, proving continuous same-process execution and whole-test cursor planning; do not relabel that directed control as client search diversity.

- [x] **Step5 Renamed/refusal controls:** native tests materialize pre-frozen copied scenario declarations with renamed CPU/IP instance IDs, memory owner and routing references while retaining unchanged registered profile/source/template semantics. Run that renamed fixture through the **same unified F2 CLI** with the real client and require exact regenerated identities/full fresh; no component-name selector edits. Include these controls:

  1. invalid second address in a two-record real-runtime test: no load/APB/version/slot/tick activity for either candidate; repeat using an independent fresh runtime and raw8 sequence;
  2. test count9: complete raw retained, explicit input-invalid and no submitted candidate; no clipping to8;
  3. same legal address with distinct suffix4: distinct raw identities, same program/projection/observation vector, actual native result unchanged;
  4. wrong source registration or incompatible same-name protocol shape: refuse before construction/native startup; saved diagnostics and marker retained;
  5. separately declared controlled execution fault/missing dependent-store observation: real attempted case has failed/missing typed outcomes, zero unproved feedback, incomplete status; preserve primary and actual cleanup. Any injector belongs to the frozen gate wrapper and is labeled controlled, never attributed to natural RTL behavior;
  6. actual F4 unified CLI Timer/SPI compatibility gates under the same final production snapshot, because Task1/5 touch shared transport/driver. Old frozen F4 runs do not substitute.

Run the opt-in suite through the supervisor:

```bash
MYFUZZ_RUN_NATIVE_F2_RFUZZ=1 PYTHONPATH=src:. python3 -m pytest -q -ra \
  tests/integration/test_compiled_f2_rfuzz_native.py
```

For every attempt save exact command, selected cases, actual client/DUT exit/reap receipts, complete raw streams, all output initial/final hashes, frozen input map, supervisor terminal receipt and skip reasons. No repeated native run merely to improve a headline; repeat only for a documented failure/change or unresolved gate.

- [x] **Step6 Independent saved-material audit and docs:** run the auditor on each successful/expected-refused result, then obtain independent source/evidence review scoped to the frozen bytes. Update original Task5 status with explicit unified-entry completion evidence and Task6 with actual gates; update CURRENT_PROGRESS, runtime/component/code references and report index. Keep prior directed F2 acceptance as its own bounded record. Report generated/executed/certified/input-invalid/failed counts separately and mark useful search benefit unclaimed. Do not mark P6/P7-E/P8/system complete.

## Plan self-review and execution handoff

- [x] Before implementation, verify the active freeze has ended and archive this plan with the next development baseline; continue the already authorized Task5 work without a new approval question.
- [x] At each task boundary run its specified RED/GREEN and scoped review; resolve actual defects before dependent work. Reviews do not replace the next implementation deliverable.
- [x] Before final acceptance, check spec coverage: read-owned source/seed (Task1); whole-test ownership and tuple contracts (Task2); real assertion/edge feedback and strict raw/case joins (Task3); independent actual fresh/build/raw and byte pins (Task4); same-call auto-harness/capability integration (Task5); software/native/rename/refusal and F4 compatibility (Task6).
- [x] Historical preparation boundary: writing this plan itself granted no implementation/test/native acceptance. Actual later acceptance is documented in the reconciliation above; the original approved acceptance bar remained in effect.
