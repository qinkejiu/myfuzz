# P7 I3 — generic APB storage consumer (source + pure software) report

- Date: 2026-10-17. Role: P7 I3 implementation agent.
- Base tree at handoff: `f9fc9b0` (P8 S1c). Coordinator instruction: commit I3
  source/tests first; run the real timer F4 RTL gate later on a **frozen**
  source tree, serialized by the root session. This report therefore claims
  **no native gate**.
- P7 overall is **not** passed: I4 (compiled candidate search) and I5 (new CPU)
  are not done.

## 1. What is implemented

### `src/myfuzz/integration/generated_storage_consumer.py` (new)

`check_storage_observation(declaration, receipt, *, target_artifact, authority,
token, register, reset_epoch, before, prior_writes)` consumes exactly one
actual generic APB storage F4 chain:

1. **Shape/identity**: the authority must be the exact
   `ApbStorageRegisterVersionAuthority` (not a subclass/twin), its artifact must
   be the passed artifact, the token must be an opaque `object` (a dict/
   serialized witness/readback is refused as `token-required`), and the
   `before` witness must be the exact 20-field live witness from the C issuer.
2. **Native APB observation**: `verify_apb_register_trace` and the
   `base_protocol_trace` (`apb3`, exact 8 roles/widths) plus the exact 10
   `storage_probe_ports`; the `storage_observation`/`source_contract` must be
   the reviewed probe/contract (selection, digest, hierarchy/native/authority
   flags all false).
3. **Declaration geometry**: address = window base + offset, offset aligned,
   `PADDR[4:2] == 3'b001` (mask `0x1c`, value `0x4`), full write mask, be=15,
   write/cpu-transaction-wdata/bound-register-commit/heap alignment; the
   register must equal the reviewed `TIMER0_CTRL` contract.
4. **Event chain**: exactly one CPU `mmio_acceptance` per delivery, exactly one
   write delivery and one later read delivery at the declared address/device/
   offset/be, consecutive data-channel `source_sequence`, then the exact
   accepted native APB pre sample (psel/penable/pready, pwrite, raw paddr
   alias, pwdata/prdata) and its post sample of the same tick.  The
   `storage_probes` group must agree with the native backend taps
   (`storage_*` == `trace_*`), reset levels must be stable, and the source-owned
   `storage_value` transition must be before → value → persisted value.  The
   CPU readback value must reach the declared RAM result address.
5. **C version journal** (`authority.writes()`): exactly one new CTRL-alias
   write (never filtered by routed context); the before-history digest must
   equal the journal prefix; the commit tick/before/after/raw_address/
   command_sequence/context/raw_reference must join the accepted pre/post
   sample and the Router delivery; context `execution`/`reset_epoch`/
   `command_sequence` must match the same live process.
6. **Opaque token**: `authority.consume(token)` only after all of the above.
   The witness must match register/epoch/value, `write_count ==
   field_version == prior+1` (even when old == new), the full-journal digest,
   pid/execution/local_tick/command_sequence, artifact/source/probe digests,
   the actual C issuer source hash, `grants_reset_prerequisite=false`,
   `routed_context_authenticated=false` and the unobserved-startup history
   scope.  Any missing fact refuses; no fallback to value/readback.

`stable_storage_version(witness)` builds the certificate prerequisite/
postcondition projection from deterministic fields only (register, value,
tick, command sequence, version counts, artifact/source/probe digests, basis
and non-claims). PID, driver execution nonce, build identity and the journal
digest stay validated against the live witness but are excluded from the
fresh-prefix comparison.

`storage_consumer_support(binding, artifacts)` reports the four receipt joins
(`cpu_acceptance`, `router_delivery`, `native_apb_pre_sample`,
`version_token`) from code/source identity and the binding-owned digests.  It
never grants runtime admission.

### `src/myfuzz/integration/compiled_storage_producer.py`

- `_APB_COMMIT_CONSUMER` now names
  `myfuzz.integration.generated_storage_consumer.check_storage_observation`.
- The generic producer document carries `commit_consumer_source_sha256` and
  `commit_consumer_receipt_elements` (the four joins); the consumer and the
  support function are import-time pins.
- `build_storage_producer` refuses an incomplete generic row **before**
  constructing the session (`compiled-F4-producer-receipt-join-incomplete`),
  then constructs the exact `GeneratedApb3RegisterSession(setup_writes=(),
  probe_offsets=())` + `ApbStorageRegisterVersionAuthority`.  The GPIO row is
  byte-for-byte unchanged (same classes, construction and consumer).

### `src/myfuzz/integration/compiled_f4.py`

- The constructor no longer rejects the generic row; it selects the row from
  `producer_binding.row`, requires `storage_consumer_support` complete for
  generic (fail closed before any native tick), and records the row in the
  checker identity.
- `_check_chain` dispatches: GPIO keeps the existing
  `check_writer_observation` + commit/epoch/command_scope logic and
  `consume(issue(...))`; generic calls the new consumer with a live
  `authority.issue(...)` token.  The certificate prerequisite/postcondition for
  generic use the stable projection, which keeps fresh-prefix comparison from
  depending on PIDs/nonces.
- CPU/target/route/layout/prerequisite/assertion/constraint checks are
  untouched.

### `src/myfuzz/local_harness/compiled_execution_projection.py`

The generic row now reports
`execution_supported=1, status='supported_requires_actual_startup',
runtime_admitted=False` **only** when all four receipt joins are installed;
otherwise `status='unsupported'` with
`reason='compiled-F4-generic-receipt-join-incomplete:<element>'`.  The GPIO
report is unchanged.  The report is source/code identity only; it is not a
token or native claim.

### Tests and config

- `tests/integration/test_compiled_f4_storage_producer.py`:
  - the old `test_generic_producer_is_not_reported_as_executable` is
    **rewritten**, not deleted:
    `test_generic_producer_is_supported_only_with_complete_in_row_receipts`
    asserts the positive report/row/consumer/receipt elements, that a missing
    element still yields `unsupported`, that construction fails before startup
    when incomplete, and that the old generic hard refusal is gone;
  - `test_generic_support_requires_each_of_the_four_receipt_joins` mutates
    consumer/bound/artifact/issuer one at a time and requires the matching
    element to be absent; `build_storage_producer` must refuse the tampered
    row before Popen;
  - new consumer negatives use real declarations, real generated artifacts
    and a real `GeneratedApb3RegisterSession` + `ApbStorageRegisterVersionAuthority`
    (pure construction, no process): valid chain reaches
    `storage-version-actual-native-build-required` (the C issuer refuses a
    fake token without native eligibility); tampering with delivery
    address/offset/device/be/value/sequence/acceptance/native pre/prdata/
    storage transition/RAM, the C journal tick/epoch/sequence/context/value/
    alias, the before witness history/register/digest/flags/extra key, and the
    declaration alias/mask/be/address/result/operation refuses by name; forged
    authority/token forms (dict witness, SimpleNamespace, string, bytes, int,
    None, foreign authority) are refused and never substituted;
  - `stable_storage_version` is checked to exclude pid/nonce/build/history
    digests and to refuse extra witness keys.
- `tests/integration/test_compiled_execution_files.py`: the minimal GPIO
  `_check_chain` fixture gained the new row attribute; no assertion changed.
- `configs/scenarios/compiled-f4-obi-apb-timer/README.md`: runtime paragraph
  updated to the implemented consumer and the still-open native gate.  No
  compose/request/sidecar/records/gate was relaxed or changed.

## 2. RED / GREEN (pure software only)

All commands run from the repository root with `PYTHONPATH=src python3 -m pytest -q`.

| id | command | result |
|---|---|---|
| RED | `pytest -q tests/integration/test_compiled_f4_storage_producer.py -k "storage_consumer or generic_producer_is_supported or generic_support or stable_storage"` with the four I3 source files stashed at `f9fc9b0` | **38 failed, 28 deselected** in 18.26s |
| GREEN | `pytest -q tests/integration/test_compiled_f4_storage_producer.py tests/integration/test_compiled_f4.py tests/integration/test_compiled_execution_files.py` | **106 passed, 1 skipped** in 170.42s |
| adjacent | `pytest -q tests/integration -k "compiled_f4 or compiled_storage"` | **97 passed, 1 skipped, 3133 deselected** in 198.89s |

The single skip is the existing `MYFUZZ_COMPILED_F4_REAL=1` native test; it
was intentionally not run.  The RED stash was popped immediately and the
source hashes were re-recorded; no test was removed, skipped or weakened.
Evidence: `docs/reports/evidence/p7-i3-timer-f4-20261017/` (`pure-software/`
logs + `commands.json` + source pins + `gate-pending.json`).

## 3. Real timer F4 gate (deferred, not executed)

The coordinator deferred the real gate to the root session's frozen-source
window (P8 S2 source edit and P6 row2/3 campaigns first).  This commit contains
**no** native build, model, Verilator run, token, certificate or fresh prefix
for the timer target.

Queued command (also in `gate-pending.json`):

```
flock -w 14400 /home/qinkejiu/myfuzz/.superpowers/heavy-worker.lock \
  env PYTHONPATH=src python3 scripts/run_compiled_dataflow.py \
  --compose configs/scenarios/compiled-f4-obi-apb-timer/compose.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-timer/test_capability.json \
  --supplement configs/scenarios/compiled-f4-obi-apb-timer/execution_supplement.json \
  --records configs/scenarios/compiled-f4-obi-apb-timer/example_records.json \
  --executor compiled_f4_obi_apb \
  --output docs/reports/evidence/p7-i3-timer-f4-20261017/outputs/timer \
  --cache-dir .superpowers/cache/p7-i3-timer \
  --run-id p7-i3-timer-f4 --replays 1
```

Acceptance for that run: three records (0x55/0xaa/0x12345678) continuously in
one runtime, each certificate certified (or honest candidate status) with
before → value commit and version token, the three compiled F4 assertions
present/passed, at least one fresh replay `matches=true` with full scope, and
summary/prefix/events/audit/source-pins retained.  Any failure must be kept
raw; no gate relaxation.

**path_id discrepancy recorded, not patched:** the brief asks for
`F4:timer.TIMER0_CTRL.value.mmio`, but the current compiler derives F4
`path_id` from the first F4 source (`ram.image`) and this compose's device
instance is `peripheral`.  The actual target source id is
`peripheral.TIMER0_CTRL.value.mmio` and the actual `path_id` is
`F4:ram.image` (historical GPIO compiled-F4 evidence is `F4:ram.image` too).
No config rename or forged path id was introduced.

## 4. Boundaries and not-claimed

- No native eligibility, live token, live certificate, hierarchy verification
  or fresh replay is claimed by this commit.
- The timer artifact has no A2 startup selection and
  `driver_schema_version=local_driver_generation.v1`, so no startup pages are
  required for this row; `grants_reset_prerequisite=false` remains.  Reset
  prerequisite support is still not granted.
- The generic consumer is registered-source-specific (`TIMER0_CTRL`, mask
  `0x1c`, value `4`); it is not arbitrary same-protocol IP inference.
- F2/F3 retirement/version execution, F5 IRQ, F6 DMA, compiled candidate
  search (I4) and a new CPU (I5) are out of scope.  P7 overall is not passed.
- The consumer's real `sample_index` is not required to be 0 (a real APB wait
  state may put the accepted transfer later in the command); it is joined to
  the C journal reference instead.
- Stable certificate projection excludes PID/driver nonce/build identity/
  history digest; those are validated live and cannot be used to weaken the
  chain.

## 5. Files changed by this increment

- `src/myfuzz/integration/generated_storage_consumer.py` (new)
- `src/myfuzz/integration/compiled_storage_producer.py`
- `src/myfuzz/integration/compiled_f4.py`
- `src/myfuzz/local_harness/compiled_execution_projection.py`
- `tests/integration/test_compiled_f4_storage_producer.py`
- `tests/integration/test_compiled_execution_files.py`
- `configs/scenarios/compiled-f4-obi-apb-timer/README.md`
- `docs/reports/evidence/p7-i3-timer-f4-20261017/` (pending-gate evidence + pure-software logs)
- this report

Untouched: `agent.md`, `third_party/`, other agents' DMA/UART sources and
untracked DMA evidence, P6/P8 files, C issuer/session/startup/version modules.

## 6. Concurrency note

P8 S2 was editing `src/myfuzz/integration/dma_uart_descriptor_runtime.py` and
`tests/integration/test_dma_uart_descriptor.py` while this work ran.  Neither
was staged or committed here.  The RED run temporarily stashed only the four
I3 source files; the stash was popped and the resulting hashes are in
`commands.json`.  The GREEN/adjacent runs recorded here were executed on the
final I3 bytes above.

## 7. Commit

Commit message starts with `P7 I3`; SHA is reported in the handoff message.

## Addendum: first frozen-snapshot real gate attempt (snapshot `53a9b7b`)

The root session ran the queued timer gate on frozen snapshot `53a9b7b`.  The
run started the native processes and reached the compiled checker, then
failed:

```
compiled-dataflow-refused: compiled-F4-protocol-checker-failed:('compiled-F4-storage-receipt-required',)
```

**Root cause**: `OnlineCaseReceipt.events` is a `tuple[dict, ...]`; the
consumer's receipt guard accepted only `list`, so the real receipt was
misclassified as missing before any chain join ran.

**Fix (this follow-up commit)**: the guard now accepts `list`/`tuple`,
requires the sequence to be non-empty, and additionally requires every member
to be a `dict`.  No content check (delivery/acceptance/native sample/probe/
journal/token) was relaxed.  New pure control
`test_storage_consumer_accepts_an_actual_tuple_receipt_without_relaxing` locks
the tuple case, a tampered tuple still refuses
`native-transfer-missing`, and a non-dict member is refused as an invalid
receipt.

**Validation**:

- tuple control RED before the fix: 1 failed
  (`compiled-F4-storage-receipt-required`) in 16.50s; GREEN after: 1 passed
  in 16.08s;
- focused file `test_compiled_f4_storage_producer.py`: 67 passed;
- three-file gate: 107 passed, 1 skipped in 168.99s;
- adjacent `-k "compiled_f4 or compiled_storage"`: 98 passed, 1 skipped,
  3136 deselected in 197.84s;
- **non-native dry run on the preserved real `partial_events.json`**: the
  consumer passed the whole event chain (real accepted write pre sample index
  6 at tick 15, value 0→85; read pre at tick 22 with prdata 85; RAM write at
  `0x3fffc`) and the shaped C journal join, and refused only at
  `storage-version-actual-native-build-required`.  This is a software
  cross-check, **not** a gate pass.

The real timer gate must be rerun by the root session on a frozen tree; no
native build/token/certificate/fresh result is claimed by this fix.  P7
overall remains unpassed (I4/I5 open).  Root-run evidence stays under
`docs/reports/evidence/p7-i3-timer-f4-20261017/outputs/` (not committed by
this agent).
