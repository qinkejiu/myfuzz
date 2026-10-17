# P7 I4 compiled candidate → RFuzz continuous search — pure-software handoff

Commit lineage: started at `00dd54d`; concurrent `P8 S3` commits landed during
the turn, so the source commit's parent is `0eff9a7` (the I4 files are the only
ones that commit adds).

Status: **PURE SOFTWARE ONLY. No real RTL/RFuzz gate was run by this
implementation turn.** The source is committed for the root session to freeze
and run the real gate; nothing here is gate evidence.

## What landed

- `src/myfuzz/scenario/compiled_online_decoder.py` (new)
  - `CompiledOnlineDecoder.from_request(...)` recompiles D3 from the typed
    compile request (`compile_paths(request) == compiled`) and binds the layout
    issued by `compile_candidate_layout(path)`; `from_runtime(...)` binds the
    runtime's own already-issued layout object and checks the cursor.
  - `decode_candidate(raw, cursor=...)` projects the exact declared byte prefix
    of one eight-byte RFuzz wire record onto the `CandidateLayout`, calls
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
  - Feeds each decoded raw record to `runtime.submit(...)`; maps each returned
    certificate to one `ScenarioRfuzzReceipt` with the real path/source/status,
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
  - `scripts/auto_harness_test.py --executor` passes the selection through.

## Design deviation the root session must review

The RFuzz decision wire in this tree is **one eight-byte record per test**
(`RECORD_BYTES=8`; scenario-mode input fields are 8 × 8 bits). The PULP timer
F4 candidate is **four bytes** (`configs/scenarios/compiled-f4-obi-apb-timer*`
README: "Each candidate is 4 bytes: the CPU MMIO word alone"). An exact
four-byte layout therefore cannot be a whole RFuzz wire record.

The bridge consumes the **declared byte prefix** of the wire record
(`raw[:layout.byte_length]`) and records the remaining bytes as *unreferenced
transport lanes* in the decoder manifest and in the candidate document. Those
bytes never reach the RTL; the exact original wire record is retained verbatim
in the receipt's `raw_records_hex`, and the runtime's fresh replay re-executes
the exact candidate bytes that did reach the RTL. A layout wider than the wire
is refused at decoder construction; a record that is not eight bytes is
refused at decode. For the eight-byte GPIO layout the projection is the whole
record and this caveat does not apply.

This is the one place where the brief's "one raw record → exact layout" and
the shipped wire width cannot both be literal. It was **not** turned into a
fabricated pass: the extra lanes are named, never used as candidate bits, and
the gate can inspect the projection in `decoder_manifest.json` /
`compiled_f4_prefix.json`.

## Pure-software commands and actual results

All commands: `cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest -q`.

| command | result |
|---|---|
| `pytest -q tests/integration/test_compiled_online_decoder.py` | **15 passed, 0 failed** in 29.58 s |
| `pytest -q tests/integration/test_compiled_online_decoder.py tests/integration/test_auto_harness_test.py` | **39 passed, 0 failed** in 138.37 s |
| `pytest -q tests/integration/test_compiled_f4.py tests/integration/test_compiled_f4_storage_producer.py tests/integration/test_compiled_candidate_layout.py` | **104 passed, 1 skipped** in 210.07 s (the skip is the existing `MYFUZZ_COMPILED_F4_REAL=1` native gate, intentionally not run) |
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
guard. The four CLI tests cover: no client ⇒ named absence (no family
fallback), unknown executor ⇒ named refusal, executor + runtime ⇒ named
refusal, and `--executor … --skip-session` ⇒ exit 0 with the selection visible.


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

## Real gate (NOT run here; for the root session)

```
PYTHONPATH=src python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/cv32e20/component_profile.json \
  --ip configs/peripherals/pulp_timer/component_profile.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-timer-cve2/test_capability.json \
  --compose configs/scenarios/compiled-f4-obi-apb-timer-cve2/compose.json \
  --executor compiled-f4-rfuzz \
  --client-binary runs/rfuzz_client_bounded_build/target/debug/kfuzz \
  --budget-seconds 60 --max-tests 200 --output runs/p7-i4-<utc>/ \
  --cache-dir .superpowers/cache-p7-i4-<utc>
```

The cache directory must already exist (the driver refuses a missing cache
before starting RTL, same as the family session). Acceptance fields from the
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
