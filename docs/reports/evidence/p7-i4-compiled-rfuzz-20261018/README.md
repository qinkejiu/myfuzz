# P7 I4 compiled candidate → RFuzz continuous search — pure-software handoff

Commit lineage: started at `00dd54d`; concurrent `P8 S3` commits landed during
the turn. The I4 work is `2a9e84b` (bridge), the digest fix (`4b66185`, amended
to `2b713f2`) and this wire follow-up; the follow-up's parent is the then-current
`P8 S3` HEAD, and every I4 commit adds only the I4 files.

Status: **PURE SOFTWARE + a cited root-session native attempt.** This
implementation turn did not run a real RTL/RFuzz gate. The root session's native
attempt (`runs/p7-i4-real-2b713f2c`) is summarized from its own artifacts and is
**not a pass**: one seed receipt was certified, then the inherited wire parse
refused the real eight-cycle test. The wire fix awaits the root rerun; no gate
result is claimed here.

## What landed

- `src/myfuzz/scenario/compiled_online_decoder.py` (new)
  - `CompiledOnlineDecoder.from_request(...)` recompiles D3 from the typed
    compile request (`compile_paths(request) == compiled`) and binds the layout
    issued by `compile_candidate_layout(path)`; `from_runtime(...)` binds the
    runtime's own already-issued layout object and checks the cursor.
  - `decode_sequence(records, cursor=...)` plans 1..8 records of one real
    RFuzz test as an ordered candidate sequence (all values, masks and slot
    budgets checked before any native command); `decode_candidate(raw, ...)`
    is the one-record form. Each record projects the exact declared byte prefix
    of the eight-byte RFuzz wire record onto the `CandidateLayout`, calls
    `declare_writer(request, compiled, source_id=<D3 cpu_mmio_stream id>,
    value=..., result_address=<runtime result word>)` and carries the exact
    `source_id`, `path_id`, register contract, value, compiled digest, layout
    digest and candidate digest into `compiled_online_candidate.v1`.
  - Refuses (before any native command) an edited compiled document, a layout
    not issued for the path, a forged path table, a record not sized by the
    wire, a layout wider than the wire, values outside mask/range/alignment,
    a cursor that is not the runtime's declared cursor, and a slot-budget
    overrun.
  - No component/family/register name branch; a test parses the module and
    rejects `component == "<literal>"` comparisons.
- `src/myfuzz/integration/compiled_rfuzz.py` (new)
  - `CompiledRfuzzExecutor` owns one `CompiledF4Runtime` for the whole session
    and enters the shipped `run_scenario_rfuzz_live` transport (it subclasses
    `ScenarioRfuzzExecutor` only to pass the transport's executor gate; it
    initializes the shared executor surface explicitly, checks that surface,
    and overrides every genome/online operation it does not use).
  - Overrides `process_owned_pair` to parse with the legacy 200-record bound
    (`COMPILED_WIRE_MAX_CYCLES=200`; 1..200 accepted, 201 refused, never
    clipped), takes the **first 8** records as candidates
    (`COMPILED_CANDIDATE_CYCLES=8`; the rest are unreferenced lanes), decodes
    and executes that ordered candidate sequence in the same runtime, then
    emits one aggregate coverage vector/receipt/`receipts.jsonl` row for the
    wire test. The receipt/decision records `wire_cycle_count`,
    `candidate_count`, `unreferenced_wire_cycle_count` and
    `unreferenced_wire_records_hex`; the compiled receipt row carries the two
    top-level count fields.
  - Maps each returned certificate to one `ScenarioRfuzzReceipt` with the real
    path/source/status,
    real per-component local ticks, the certificate digest and one
    `session/receipts.jsonl` row per slot (the transport persists it).
  - Exposes 8 real coverage targets: `compiled_f4.<target>.<register>
    .commit_word_bit_24..31`, each a predicate on the actual observed commit
    word (`certificate["commit"]["after"]`) of the certificate the runtime
    returned. A refused candidate has the zero coverage vector.
  - Refuses a candidate before the native command when `runtime.records >=
    runtime.max_cases` or the declared candidate does not fit the remaining
    instruction image; a post-submit failure is an `environment_error` receipt
    and stops the search, never a pass.
  - `mutation_hint()` keeps the shipped `scenario_mutation_hint.v1` contract
    (`run_id`, increasing sequence, nonempty completed-batch feedback,
    template/path/source, energy).
  - `run_compiled_f4_rfuzz_session(...)` runs the live transport, then
    `CompiledF4Runtime.finish()` and `CompiledF4Runtime.replay(plan)`: the
    replay constructs fresh native processes, re-admits the private source
    documents and re-executes every saved candidate before comparing the saved
    compiled prefix. It writes `compiled_f4_prefix.json`,
    `compiled_f4_replay.json`, `compiled_f4_fresh_prefix.json`,
    `compiled_f4_fresh_execution_audit.json`,
    `compiled_f4_fresh_verification.json` and
    `compiled_receipt_join.v1.json`.
  - `join_compiled_receipts(...)` re-checks every saved receipt's `path_id` /
    `source_id` / `flow_id` against the one executable F4 path.
  - `fresh_verification_document(...)` sets `verification_scope=full` only from
    the replay's own `matches`/`first_difference`/`semantic_hash` values and
    records both process identity sets.
- `src/myfuzz/local_harness/auto_harness_test.py`
  - `run_auto_harness_test(..., executor=None)`; a closed `COMPILED_EXECUTORS`
    set (`compiled-f4-rfuzz`), refusal of an unknown name and of
    `--executor` + `--runtime`, and a family-free
    `load_compiled_session_inputs(...)` that derives ownership only from D3's
    `external_pin` sources (a fixed/literal wiring input is refused).
  - The compiled session runs under the existing heavy-worker lock, includes
    the full fresh replay, writes/records `fresh-verification.json`,
    `compiled_receipt_join.v1.json`, the compiled prefix/replay artifacts and
    the authenticated bundle copy, and refuses a nonzero client return code.
  - `scripts/auto_harness_test.py --executor` passes the selection through,
    and `--rounds-per-case` (default 128, 1..4096) is threaded through
    `run_compiled_session` into the compiled runtime; out-of-range values and a
    non-default value without a compiled executor are named refusals before any
    stage.

## Design deviation the root session must review

The RFuzz decision wire in this tree is **one eight-byte record per decision**
(`RECORD_BYTES=8`; scenario-mode input fields are 8 × 8 bits), and one real
scenario **test** may carry a longer sequence of such records (the legacy
`GenomeRecordDecoder.max_records` bound is 200; the root's native wire shows
eight fields that may span 64 records). The compiled route parses the legacy
bound but uses at most the **first eight** records as candidates; every further
record is an unreferenced transport lane. The PULP timer F4 candidate is
**four bytes** (`configs/scenarios/compiled-f4-obi-apb-timer*` README: "Each
candidate is 4 bytes: the CPU MMIO word alone"). An exact four-byte layout
therefore cannot be a whole RFuzz wire record.

The bridge consumes the **declared byte prefix** of the wire record
(`raw[:layout.byte_length]`) and records the remaining bytes as *unreferenced
transport lanes* in the decoder manifest and in the candidate document. Those
bytes never reach the RTL; the exact original wire record is retained verbatim
in the receipt's `raw_records_hex`, and the runtime's fresh replay re-executes
the exact candidate bytes that did reach the RTL. A layout wider than the wire
is refused at decoder construction; a record that is not eight bytes is
refused at decode. For the eight-byte GPIO layout the projection is the whole
record and this caveat does not apply. A test's first eight records are
projected independently and retained as an ordered candidate sequence in the
receipt's `online_case.source`; the remaining records are recorded as
`unreferenced_wire_records_hex` lanes and never reach the RTL or count as
coverage.

This is the one place where the brief's "one raw record → exact layout" and
the shipped wire width cannot both be literal. It was **not** turned into a
fabricated pass: the extra lanes are named, never used as candidate bits, and
the gate can inspect the projection in `decoder_manifest.json` /
`compiled_f4_prefix.json`.

## Pure-software commands and actual results

All commands: `cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest -q`.

| command | result |
|---|---|
| `pytest -q tests/integration/test_compiled_online_decoder.py` | **25 passed, 0 failed** in 28.66 s |
| `pytest -q tests/integration/test_auto_harness_test.py` | **33 passed, 0 failed** in 136.24 s |
| `pytest -q tests/integration/test_scenario_rfuzz_live_client.py tests/integration/test_scenario_rfuzz_terminal_identity.py tests/integration/test_scenario_rfuzz_transport.py tests/integration/test_scenario_rfuzz_acceptance.py` | **39 passed, 4 skipped, 4 subtests passed** in 0.76 s |
| `pytest -q tests/integration/test_compiled_online_decoder.py tests/integration/test_auto_harness_test.py` | **58 passed, 0 failed** in 162.42 s |
| `pytest -q tests/integration/test_compiled_f4.py tests/integration/test_compiled_f4_storage_producer.py tests/integration/test_compiled_candidate_layout.py` | **104 passed, 1 skipped** in 176.22 s (rerun after the wire change) (the skip is the existing `MYFUZZ_COMPILED_F4_REAL=1` native gate, intentionally not run) |
| `pytest -q tests/integration/test_compiled_execution_files.py tests/integration/test_compiled_execution_projection.py tests/integration/test_compiled_artifact_admission.py tests/integration/test_compiled_f4_layout_replay_audit.py` | **77 passed, 0 failed** in 116.58 s (rerun after the digest fix) |
| `python3 scripts/auto_harness_test.py --cpu configs/cpus/ibex_obi_local/component_profile.json --ip configs/peripherals/pulp_timer/component_profile.json --ip-capability configs/scenarios/compiled-f4-obi-apb-timer/test_capability.json --compose configs/scenarios/compiled-f4-obi-apb-timer/compose.json --output <new> --executor compiled-f4-rfuzz --skip-session` | exit 0; `status=complete`; `executor.status=ok`, name `compiled-f4-rfuzz`, `family_fallback=false`; session/fresh `not_requested` |

The new test file covers: a real non-ASCII compiled document binding from the
runtime's own canonical digest (with the tamper refusals below), forged/edited
compiled document and forged layout,
value outside mask/range/alignment, a record not sized by the wire, decoder
metadata naming the exact D3 path/source/register/digests, receipt source/path
join with tampered rows detected, `max_cases` and slot budget refused **before**
any submit (the runtime double records zero/one submit), the receipt mapping
with real ticks and nonzero coverage, a full-scope fresh-verification document
control, two different execution UUIDs producing the same normalized replay
hash while the raw event hash differs, and the no-component-name-branch parse
guard, that one/eight/nine/64/200-cycle tests parse while 201 is refused, that
a 64-cycle (and a 9-cycle) test uses exactly the first eight candidates with the
rest recorded as unreferenced lanes, that a ninth candidate is refused by the
candidate API, that an eight-cycle test over `max_cases` refuses before any
submit, that the compiled receipt rows declare `wire_cycle_count`/
`candidate_count` (and the conditional row helper is empty for family rows),
and that `--rounds-per-case` reaches the compiled session while 0/4097/bool/
non-int values refuse and a non-default value without a compiled executor
refuses. The CLI tests cover: no client ⇒ named absence (no family fallback),
unknown executor ⇒ named refusal, executor + runtime ⇒ named refusal,
`--executor … --skip-session` ⇒ exit 0 with the selection visible, and
`--rounds-per-case 32` accepted on the compiled route.


## Follow-up after the first real-gate attempt (`2a9e84b`, before RTL)

The root session's first real-gate attempt on `2a9e84b` refused before RTL with
`CompiledCandidateRefused: compiled-digest-mismatch`. Root cause: the decoder
hashed the compiled document with `ensure_ascii=False`, while
`compiled_f4._digest` (the runtime's `compiled_digest`) uses the default
`ensure_ascii=True`. The compiled documents contain non-ASCII declaration text,
so the same document produced two digests (`4c0a…` vs `c0b5…` in that run).

Fix (this follow-up commit): one shared
`myfuzz.scenario.compiled_paths.compiled_document_sha256` canonical form
(sorted-key compact JSON, default ASCII escaping) is now used by
`CompiledF4Runtime.compiled_digest`, `CompiledOnlineDecoder`, and
`join_compiled_receipts`; `compiled_rfuzz`'s own canonical encoder no longer
uses `ensure_ascii=False`. The runtime's digest value is unchanged (its form
was already ASCII-escaped); only the consumers now match it.

Regression tests added:
`test_a_real_non_ascii_compiled_document_binds_from_the_runtime` asserts the
real compiled document contains non-ASCII text, that
`compiled_document_sha256(...) == compiled_f4._digest(...)`, binds that document
through `from_runtime`, and proves a tampered document still refuses both at
construction (`compiled-document-mismatch`) and after construction
(`compiled-digest-identity-changed`). The join test now also asserts
`compiled_receipt_join.v1.json`'s `compiled_sha256` equals the runtime's
digest.

The real gate must be rerun by the root session on the new commit; no gate
result is claimed here.


## Native client and the real eight-cycle scenario test

The gate uses the **native** client (`runs/rfuzz_client_native_build/target/debug/kfuzz`).
The bounded client (`runs/rfuzz_client_bounded_build/...`) enforces a minimum
256 runs per batch in its build, while the shipped transport accepts only
`--max-runs-per-batch 1..8`; the bounded client is therefore not usable for
this route and was not used.

The native client's real scenario test can carry more than eight decision
records (the root's wire inspection indicates the eight declared fields may
span 64 records; the legacy `max_records` bound is 200). The first native run
proved the runtime path itself: one seed test executed and was persisted as a
certified receipt (`value=0`, `local_ticks` 136/128, correct `path_id` /
`source_id`), and the next buffer then failed at
`ValueError: test cycle count outside bound` because the inherited
`process_owned_pair` derived its cycle bound from
`online_decoder.max_input_bytes // RECORD_BYTES` = 1.

Fix (this follow-up commit): `CompiledRfuzzExecutor.process_owned_pair` is
overridden to parse with `parse_compiled_input_buffer`, whose bound is the
legacy **200** records (`COMPILED_WIRE_MAX_CYCLES=200`; 1..200 parse, 201 is
refused, never clipped). The executor then takes the **first eight** records as
candidates (`COMPILED_CANDIDATE_CYCLES=8`) and records every further record as
an unreferenced transport lane; the candidate API itself refuses a ninth
candidate. A test's candidate records are decoded as an ordered sequence (all
values, masks and slot budgets checked **before any native command**), executed
in order in the same runtime, and represented by one aggregate coverage vector
/ receipt / `receipts.jsonl` row for the test (the wire test is one slot). The
receipt/decision records `wire_cycle_count`, `candidate_count`,
`unreferenced_wire_cycle_count` and `unreferenced_wire_records_hex`; the
compiled receipt row carries the two top-level count fields. The runtime case
budget is sized `max_tests * 8 + 8` so a test can carry its full candidate
sequence; `max_tests` still counts wire tests. Coverage is the union of the
actual commit predicates of every executed candidate certificate.


## Per-case rounds budget (`--rounds-per-case`)

The compiled route accepts an explicit `--rounds-per-case` (default 128,
allowed 1..4096). It is threaded through `run_compiled_session` into
`run_compiled_f4_rfuzz_session` and `CompiledF4Runtime(rounds_per_case=...)`;
the decoder/executor read the runtime's `rounds`, so every candidate case in a
test uses the declared value. Validation happens before any stage:
out-of-range (including `bool` and non-int) refuses `rounds-per-case-invalid`
at `/rounds-per-case`, and a non-default value without a compiled executor
refuses `rounds-per-case-requires-a-compiled-executor`. The value is never
inferred from timing.

The real gate uses `--rounds-per-case 32`: the native client's eight-record
test then drives 8 candidate cases at 32 rounds each, which fits the wall
budget; if 32 rounds is too short for the case to commit, 48/64 remain inside
the declared 1..4096 range. A too-short value is not a pass: it fails the real
gate's own receipt/verification artifacts.

## Real gate (NOT run here; for the root session)

```
PYTHONPATH=src python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/cv32e20/component_profile.json \
  --ip configs/peripherals/pulp_timer/component_profile.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-timer-cve2/test_capability.json \
  --compose configs/scenarios/compiled-f4-obi-apb-timer-cve2/compose.json \
  --executor compiled-f4-rfuzz \
  --client-binary runs/rfuzz_client_native_build/target/debug/kfuzz \
  --budget-seconds 60 --max-tests 200 --rounds-per-case 32 \
  --output runs/p7-i4-<utc>/ \
  --cache-dir .superpowers/cache-p7-i4-<utc>
```

The cache directory must already exist (the driver refuses a missing cache
before starting RTL, same as the family session). The client is the native
build because the bounded build's minimum batch (256) is outside the transport's
1..8 bound; the native client's eight-cycle scenario tests are the wire this
route now parses and executes. Acceptance fields from the
brief: client return code 0; at least one real coverage-guided batch; each
`session/receipts.jsonl` row's `source_id`/`path_id` joins
`compiled_paths.v1.json` (also summarized in
`compiled_receipt_join.v1.json`); `fresh-verification.json` has `matches=true`
and `verification_scope=full`; no fabricated `Bug confirmed` (no checker
findings are supplied).

Pure probes on both timer target configs (ibex and cv32e20) pass
`assess_compiled_f4_support` with `status=supported_requires_actual_startup`
and `execution_supported=1`, bind path `F4:ram.image`, source
`peripheral.TIMER0_CTRL.value.mmio`, and produce 8 coverage targets. No native
startup, model, build, certificate or replay positive was produced.

## Not claimed

- No real RTL, RFuzz client run, coverage-guided search execution, fresh
  replay, certificate, receipt join over real rows, or P7 acceptance.
- The real gate's client/budget/cache behavior is unverified here; a failure
  must be reported from the gate's own artifacts, never inferred from this
  file.
