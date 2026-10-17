# P7 I3 generic APB storage consumer — timer F4 evidence

Status: **Final real timer F4 artifact gate completed at `ade3fe6`.**

The historical source/software notes below predate the final run. Current evidence is in `outputs/timer-ade3fe6/`: `report.json` records 3/3 certified cases and `replays.json` records a full fresh match. See [the consolidated report](../../../p7-p8-real-gates-20261018.md). This is artifact-level acceptance; a raw process exit receipt is absent, as recorded by the independent audit.

This directory retains the historical pure-software RED/GREEN evidence for the P7 I3
generic APB storage consumer and the queued (not run) real timer F4 gate
declaration.  The real gate is serialized by the root session on a frozen
source tree; its current result must be read from the final outputs, not from these historical notes.

## Implemented source (commit reported in the handoff message)

- `src/myfuzz/integration/generated_storage_consumer.py` (new):
  `check_storage_observation(...)` consumes one actual chain
  CPU data acceptance → Router delivery → native APB pre/post `storage_probes`
  → `ApbStorageRegisterVersionAuthority.consume(token)` → CPU readback/RAM.
  It also exposes `stable_storage_version(...)` for fresh-prefix certificates
  and `storage_consumer_support(...)` for the four receipt-join completeness
  report.  No caller JSON, readback or serialized write record is a token.
- `src/myfuzz/integration/compiled_storage_producer.py`: the generic row now
  names the in-row consumer, pins it (source digest + four receipt elements)
  and refuses an incomplete row before constructing a session.
- `src/myfuzz/integration/compiled_f4.py`: row-selected consumer and
  construction; GPIO keeps its original session/issuer/consumer and
  certificate semantics, generic uses a stable witness projection.
- `src/myfuzz/local_harness/compiled_execution_projection.py`: the generic row
  enters `supported_requires_actual_startup` only when all four receipt joins
  are installed; `runtime_admitted` stays false.
- `tests/integration/test_compiled_f4_storage_producer.py`: rewritten D1
  generic-support control plus consumer tamper negatives.
- `tests/integration/test_compiled_execution_files.py`: the minimal GPIO
  `_check_chain` fixture gained the new `row` attribute (behavior unchanged).
- `configs/scenarios/compiled-f4-obi-apb-timer/README.md`: runtime paragraph
  describes the implemented consumer and the still-open real gate.

## Pure-software commands and results

All runs use `PYTHONPATH=src python3 -m pytest -q` from the repository root.

| id | command | result | artifact |
|---|---|---|---|
| red | `pytest -q tests/integration/test_compiled_f4_storage_producer.py -k "storage_consumer or generic_producer_is_supported or generic_support or stable_storage"` with the four I3 source files stashed at base `f9fc9b0` | **38 failed, 28 deselected** in 18.26s | `pure-software/red.log` |
| green (pre-tuple-fix, first commit) | `pytest -q tests/integration/test_compiled_f4_storage_producer.py tests/integration/test_compiled_f4.py tests/integration/test_compiled_execution_files.py` | **106 passed, 1 skipped** in 170.42s | superseded |
| tuple red | `pytest -q tests/integration/test_compiled_f4_storage_producer.py -k tuple_receipt` before accepting tuple receipts | **1 failed** in 16.50s (`compiled-F4-storage-receipt-required`, same failure as the real gate) | `pure-software/tuple-red.log` |
| tuple green | same focused command after the tuple fix | **1 passed** in 16.08s | `pure-software/tuple-green.log` |
| green (final, tuple fix) | `pytest -q tests/integration/test_compiled_f4_storage_producer.py tests/integration/test_compiled_f4.py tests/integration/test_compiled_execution_files.py` | **107 passed, 1 skipped** in 168.99s | `pure-software/green.log` |
| adjacent (final) | `pytest -q tests/integration -k "compiled_f4 or compiled_storage"` | **98 passed, 1 skipped, 3136 deselected** in 197.84s | `pure-software/adjacent-compiled-f4.log` |
| real-events dry run | pure-software replay of the preserved real gate `outputs/timer/partial_events.json` through the consumer with a forged token | refused only at **`storage-version-actual-native-build-required`** | `pure-software/real-events-dry-run.log` |

The single skip is the existing `MYFUZZ_COMPILED_F4_REAL=1` native gate.  It
was intentionally **not** run and is not claimed.

RED method: the four I3 source files were temporarily saved with
`git stash push -u` so the new tests executed against the pre-I3 tree at
`f9fc9b0`; the stash was popped immediately after the RED run and the source
hashes below were re-recorded.  No test was skipped or relaxed.

## First real timer gate attempt (frozen snapshot 53a9b7b)

The root session's first frozen-snapshot run reached the compiled checker and
failed with:

```
compiled-dataflow-refused: compiled-F4-protocol-checker-failed:('compiled-F4-storage-receipt-required',)
```

Root cause: `OnlineCaseReceipt.events` is a `tuple[dict, ...]`, while the
consumer accepted only `list`.  The fix accepts `list`/`tuple` and additionally
requires every member to be a `dict`; no content check was relaxed.  The
non-native dry run then fed the preserved real `partial_events.json` through
the consumer (real accepted write pre sample index 6 at tick 15, real value
0 → 85, real read at tick 22) and it refused only at the genuine-native token
boundary, not at a shape/join check.  The real gate itself must be rerun by
the root session on a frozen source tree and is not claimed here.

## Second real timer gate attempt (tuple fix): 3 certified, fresh hash mismatch

After the tuple fix the same frozen-source gate executed all three records
continuously and **certified** them (`0x55`/`0xaa`/`0x12345678`, commit
before/after `0 → 85 → 170 → 305419896`, the three compiled assertions
passed).  The fresh replay then refused:

```
compiled-files-fresh-prefix-mismatch
```

`fresh-1/comparison.json` reported `first_difference=/semantic_hash`
(expected `71216b07…`, actual `edc1e2a6…`).  Both event streams are 1956
events long and byte-identical except exactly six `target_access_id` values:
`apb-storage:<execution-uuid>:<n>` with the same suffixes
(13/17/143/147/273/277) but the primary process UUID `42765f21…` vs the fresh
`d9470689…`.

Root cause: `ScenarioTrace.semantic_sha256` covers the process-local receipt
id; a fresh process always has a different UUID, so an honest replay can never
match.  Fix: `compiled_f4.normalized_semantic_sha256(...)` hashes the real
event chain with only the `target_access_id` execution segment replaced by a
stable placeholder (sequence suffix preserved, nested occurrences included).
Receipts, events and certificates are not rewritten; the GPIO row keeps its
exact previous raw hash.  `test_generic_finish_normalizes_hash_but_keeps_real_records`
and `test_normalized_semantic_hash_ignores_only_the_process_execution_nonce`
lock it; `test_consumer_keeps_real_process_local_access_ids_untouched` proves
the consumer still joins on the real ids.

Non-native validation on the **preserved real events**: the six real ids are
present in the files, the normalized hashes of `events.json` and
`fresh-1/events.json` are equal (with and without local ticks), and the raw
canonical event hashes still differ — see
`pure-software/semantic-normalization-real-events.log`.  This is a software
cross-check, not a gate pass; the real timer gate is rerun by the root session.

## Historical real timer F4 declaration (superseded by final outputs)

See `gate-pending.json` for the exact command, records and acceptance criteria.
At this earlier checkpoint there were no native output documents. The final `outputs/timer-ade3fe6/` now contains the actual report, prefix, events, certificates and fresh comparison; the earlier pending declaration is retained as history.  The design-requested literal F4 `path_id`
`F4:timer.TIMER0_CTRL.value.mmio` is **not** what the current compiler emits:
D3 derives `path_id` from the first F4 source (`ram.image`) and this compose's
device instance is `peripheral`.  The actual target source id is
`peripheral.TIMER0_CTRL.value.mmio` and the actual `path_id` is `F4:ram.image`.
This discrepancy is recorded rather than patched by renaming a config or
forging a path id.
