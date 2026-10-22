# Independent audit — local Task 5 three-branch native source-completion gate (2026-10-23)

Repository `/home/qinkejiu/myfuzz`, HEAD `800b04a`; audited commit `d8d88c7`
(parent `06ee952`). Evidence:
`docs/reports/evidence/native-completion-task5-local-20261023/` (23 files, tracked at
`d01e952`, clean). Report under audit: `docs/reports/native-completion-task5-local-20261023.md`
(tracked at `d01e952`, clean).

Read-only audit. No source, test, config or evidence file was modified; the only file written is
this report. Recomputation used `hashlib`/`json`/`gzip`, the shipped verifier functions
(`check_host_source_bindings`, `check_native_completion`, `check_native_source_completion`,
`check_native_source_completion_refusal_events`) and `_trace_semantic_sha256`, all imported with
`PYTHONDONTWRITEBYTECODE=1`. No RTL run, rebuild or pytest run was performed. The original run
directory `/home/qinkejiu/.native-gate/agent-refusal-1/run2` was also read (read-only) for a
byte comparison; the archive is byte-identical to it.

## Verdict

The archived package is **internally consistent and reproduces**: the three branch statuses, the
process capture, the full-scope fresh replays, the refusal terminal state, the script hash and the
archive hashes all recompute exactly, and the report's "what this does not prove" section is
accurate and conservative. Two framing problems remain (F-1, F-2), both material to how the
evidence may be cited: the run was **not** produced by commit `d8d88c7` alone (the executed
`myfuzz`/verifier code is uncommitted, including one untracked module), and the "narrow fix /
nothing weakened" claim has **no committed baseline to diff against**. Neither problem changes the
branch results, but both forbid treating this package as source-closed or as r11 Stage 2.

## 1. `summary.json.gz`

SHA-256 `15a089d7c1efb8c353ae9fce175a79701a094ca7463865834ba60085debd3543` — recomputed and
equal to the report. The file is tracked at `d01e952` and unmodified. The archived copy is
byte-identical to `/home/qinkejiu/.native-gate/agent-refusal-1/run2/summary.json.gz`.

| Field | Value | Recompute |
|---|---|---|
| `schema_version` | `native_online_directed_gate.v1` | matches script |
| `gate_run_id` | `fdeab0ce868540f0d429df29ec71f2fce7c2ee4eaffcde416065f5d53d7285ca` | 64 lowercase hex ✓; identical in all three `result.json.gz` ✓ |
| `gate_pid` | `90770` | identical in all three results ✓ (self-consistent; no process log) |
| `positive_status` | `bounded_directed_gate_passed` | equals `positive/result.json.gz:status` ✓ |
| `controlled_status` | `bounded_directed_gate_passed` | equals `controlled-response/result.json.gz:status` ✓ |
| `native_source_refusal_status` | `native_source_completion_refusal_gate_passed` | equals `native-source-refusal/result.json.gz:status` ✓ |
| `native_completion_observation` / `_binding` / `_completion` | `true` / `true` / `true` | CLI-flag echoes, not independently re-derived |
| `script_sha256` | `1422dc3f595eb97f181a6a875d271af238031d7fbd7d5f9a2914c54ab4cc7124` | equals `sha256(scripts/verify_picorv32_native_online.py)` and the frozen r11 script ✓ |
| `coverage_guided_search` | `false` | false flag; no coverage claim anywhere ✓ |
| `formal_p6_complete` | `false` | false flag ✓ |
| `retirement_authority` | `false` | false flag ✓ |
| `source_authority` | `false` | false flag ✓ |

There are **no true/false claims in the summary that the archive contradicts**. The four false
flags are hard-coded constants in `main()` (not derived), but they are conservative, and the report
does not overstate them.

Limits of the summary: it records no argv, cwd, start/end time, gate exit code, or digest of any
branch result. It therefore does not *bind* the branch bundles; the linkage is the identical
`gate_run_id`/`gate_pid` plus the directory layout (see F-5). `gate_run_id` is an operator-supplied
`--gate-run-id` argument (only validated as 64 lowercase hex), not a content hash; the r11 launch
contract says the controller creates one fresh value before plan freeze, but no controller or claim
document exists in this package, so freshness/single-use is not evidenced (F-3). The report shows
the value in its command block and does not claim controller provenance for the local run.

## 2. Branch recomputation

All three `result.json.gz` are tracked, unmodified, and byte-identical to the original run
directory. All three carry the same `gate_run_id` and `gate_pid`, `capture_errors: []`, and no
`error` field.

### 2.1 `positive/result.json.gz` — SHA-256 `e48e69c5ea731d3fd8eb3f8e5d6024050f3e9ab393139eccafaa94ff788c3528`

- `status=bounded_directed_gate_passed` (matches summary). Recomputed from the archived evidence:
  3 cases, every independently re-derived relation has `findings=[]`; the script raises on any
  finding (`positive-relation-check-failed`), so the pass condition holds.
- Cases (recomputed from `first.json.gz` events, not copied from the stored relation):
  - case 1 `cpu.instructions` (`1305e003`), joint `62`, RAM `62`, final GPIO `62`;
  - case 2 `gpio0.pin_byte`, joint `153`, a=`62`, b=`167`;
  - case 3 `cpu.instructions`, joint `153`.
  All delivery shapes `[(W,12),(R,12),(R,8),(W,12)]`, one `0x100` RAM write per case, CPU
  consumption found for both reads, stored `relation` equal to the re-derivation (delivery ids
  `[622,713,804,1025]`, `[1546,1637,1728,1953]`, `[2474,2565,2656,2881]`).
- Fresh replay: `matches=true`, `first_difference=null`, `verification_scope=full`,
  `difference_context=null`; 3,251 events in both `first.json.gz` and `fresh-comparison.json.gz`.
  Independently: the two event streams are **identical after replacing only the two execution
  nonces** (all differing leaves are `execution`/`native_driver_scope`/`accepted_scope`/
  `response_scope`/`binding`/`completion_scope` values). Recomputed `semantic_sha256` equals the
  stored value for both traces (`6d096f75…` original, `27507493…` fresh — the fresh digest differs
  only because it embeds the fresh nonce; the replay's own comparison is the nonce-normalized
  projection).
- Checks: `native-source-binding-checks.json.gz`, `native-observation-checks.json.gz`,
  `native-source-completion-checks.json.gz` all have `status=…_passed`/`raw_checks_passed` and
  `errors=[]`. Re-ran the three verifier functions over the archived events + plan + archived
  `artifact_document` + archived nonces: results are **exactly equal** to the stored check
  documents (original and fresh). `plan.json` SHA-256 equals `genome_sha256` in both traces and
  `manifest_sha256` is identical between original and fresh.
- Bundle hashes: `first` (`eb38e8c2…`/`299251b1…`), `fresh` (`afd6df73…`/`bd3bb7f0…`) and the
  three check bundles all match both `gzip_sha256` and canonical `json_sha256`; `case-{1,2,3}`
  files are exactly `result.cases[0..2]`.

### 2.2 `controlled-response/result.json.gz` — SHA-256 `cd352010fd84b593283bcd231181880d468eeee48f6e8f637ccad091907ef136`

- `status=bounded_directed_gate_passed` (matches summary), `controlled_fault=true`,
  `controlled_response_records` has 2 records (one per run: original + fresh), identical
  (`address=1073741836`, `delivered_response=[63,0]` vs `actual_target_response=[62,0]`).
- 1 case; the independent re-derivation yields exactly
  `['routed_read_response_mismatch','joint_ram_mismatch','joint_gpio_mismatch']`, which is the
  exact set the script requires for the corruption branch; stored `relation` equals the
  re-derivation.
- Fresh replay: `matches=true`, `first_difference=null`, `scope=full`, 1,395 events both sides,
  equal after nonce normalization; both semantic digests recompute.
- No `native-source-completion-checks.json.gz` for this branch — correct by construction: the
  script skips completion checks when `corrupt` (`if native_source_completion and not corrupt`).
  The result's `native_source_completion=true` is the configuration echo, not a completion claim;
  the report does not claim completion checks for this branch.
- Re-ran `check_host_source_bindings` and `check_native_completion` (with the split fault records,
  `fault_records[:1]`/`[1:]`, as the gate does): exactly equal to the archived check documents.
- Bundle hashes and `case-1.json.gz` verify.

### 2.3 `native-source-refusal/result.json.gz` — SHA-256 `4ee8c3b128034644dad251708cdaecdc860687a9b9f62413f3a0dd7192e58a99`

- `status=native_source_completion_refusal_gate_passed` (matches summary); `source_authority=false`,
  `retirement_authority=false`, `controlled_response_negative_preserved=true`, no `error`.
- Terminal failure (in `plan.json`, re-read): `{phase: step, command_index: 2, case_index: 0,
  case_id: online-0-6e1ec30dca4987858e3e64c0, error_type: ValueError,
  error_message: native_source_candidate_refused}` — exactly the refusal the report names.
- The exact selected-source contradiction is present: bound instruction `1305e003` at address 512
  vs actual read `13000000`, i.e. the poisoned store of `0x00000013` overwrote the instruction word
  (RAM/instruction source `online-0-6e1ec30dca4987858e3e64c0:cpu.instructions`).
- Refused raw sample: `refused_raw_event_id=500`, which in the trace is
  `local_tick_sample/cpu/pre`, scope `command_sequence=49, local_tick=49`, `producer_event_id=499`
  (the `harness_failure` event with `status=uncertain_effect`); its `protocol_taps` carry
  `cpu_native_trace_rdata=19`, `addr=512`, `valid=ready=1` — i.e. the real pin state at the
  completion edge that contradicted the bound bytes. The accepted request is event 487 (tick 47),
  the consumed response event 494 (tick 48, sequence 9), so the refused completion is exactly the
  next tick (`response tick T`, `completion T+1`), as the fix description says.
- Poisoned write journal: event 476 is `memory_write`, `address=512`, `value=19`,
  `width_bytes=4`, `byte_enable=15`, `version=[0,2]`, transaction
  `channel_id=native-source-poison, source_sequence=1, testcase_id=native-pulp-online`; it is
  listed in `raw_checks.excluded_injected_writes`. The refusal checker re-derives and verifies the
  write receipt, commit document, byte cells, commit id, service event and journal producer — all
  present.
- Retained-response accounting (recomputed from events): 9 `native_backend_request_accepted`,
  9 `native_backend_response_consumed`, 8 `native_bus_completed`; the single uncompleted
  transaction is `source_sequence=9`, identical to `refusal_record.native_transaction`; the
  archived `raw_checks` counts are `accepted=responses=raw_completed=9`, `completed=8`,
  `terminal_refusals=1`; `terminal_refusal.no_completion=true`. This is the one retained response.
  Ownership ("retained by the observer, host holds no duplicate") is asserted in-process by
  `_validate_native_source_completion_terminal_cleanup`
  (`observer.pending.state='response'`, `completion_issued=None`, `cpu.pending_responses=1`,
  `cpu._pending=None`, `runner.finalize`d, `failure_status=uncertain_effect`) for **both** the
  original reference session and the fresh session, but that state object is **not serialized**
  into the archive (F-4).
- Fresh replay: `matches=true`, `first_difference=null`, `scope=full`, 501 events on both sides,
  equal after replacing the two execution nonces; `refusal_record` identical original vs fresh;
  the original and fresh `refusal_checks` documents are identical after nonce normalization, and
  both are `native_source_completion_refusal_checks_passed` with `errors=[]`.
- Original and fresh checks are both present in `native-source-refusal-checks.json.gz`
  (`original`, `fresh`). Recomputed `check_host_source_bindings` and
  `check_native_source_completion_refusal_events` (against the archived `raw_checks`) equal the
  archived documents for both runs. The archived `raw_checks`/`terminal_refusal` themselves depend
  on the CPU `runtime_document`, which is **not archived** for this branch, so they are verified
  for internal consistency and event-join correctness but not re-executed (F-4).
- Not SIGKILLed: all four `terminal_returncode=0`, no `-9`/signal entry, `capture_errors=[]`, and
  the CPU cleanup path used is the graceful `finalize()` (END) path, not `_abort()`. Corroboration
  that the prior attempt *was* killed exists only outside the package
  (`/home/qinkejiu/.native-gate/run-attempt2/native-source-refusal/result.json.gz`: status
  `failed`, `native source completion terminal cleanup state mismatch`, cpu `terminal_returncode=-9`,
  2 processes) (F-6).
- Bundle hashes: `original-terminal`, `fresh-terminal-replay`, `native-source-refusal-checks` all
  match both embedded hashes; `plan.json` SHA-256 `278088ea…` equals `genome_sha256` in both traces.

### 2.4 Process capture (all branches)

| Branch | component | pid | nonce | ns | epoch | rc |
|---|---|---|---|---|---|---|
| positive | cpu | 93251 | `1d7d5a37…` | runner-0 | 0 | 0 |
| positive | gpio0 | 93283 | `4d7a1fce…` | runner-0 | 0 | 0 |
| positive | cpu | 93403 | `88534ee0…` | runner-1 | 0 | 0 |
| positive | gpio0 | 93435 | `a04feb54…` | runner-1 | 0 | 0 |
| controlled-response | cpu | 93743 | `4b6914a7…` | runner-0 | 0 | 0 |
| controlled-response | gpio0 | 93775 | `64d4bcda…` | runner-0 | 0 | 0 |
| controlled-response | cpu | 93919 | `61fcb3c3…` | runner-1 | 0 | 0 |
| controlled-response | gpio0 | 93951 | `c150c5f8…` | runner-1 | 0 | 0 |
| native-source-refusal | cpu | 94310 | `e968e8d1…` | runner-0 | 0 | 0 |
| native-source-refusal | gpio0 | 94342 | `8c023be7…` | runner-0 | 0 | 0 |
| native-source-refusal | cpu | 94440 | `39ec68f5…` | runner-1 | 0 | 0 |
| native-source-refusal | gpio0 | 94472 | `0ad7b097…` | runner-1 | 0 | 0 |

Four rows per branch; PIDs globally distinct (12/12); nonces globally distinct; per component the
two runs share `artifact_digest` (cpu `0bca86c3…`, gpio0 `608dd251…`) but differ in pid/nonce;
`reset_epoch=0`; `initial_process_identities` equal the runner-0 rows and equal every case's
`process_identities`. These are metadata assertions only: no argv, executable path, launch log or
`/proc` capture is archived, so "four real processes" is consistent and cross-checked in-branch but
not independently observable (F-3). The artifact digest recomputes as the canonical SHA-256 of the
artifact document without `artifact_digest`, and is identical in both positive/controlled
`native-observation-checks` documents (original and fresh).

### 2.5 Archive integrity

Every one of the 23 archived files is byte-identical to
`/home/qinkejiu/.native-gate/agent-refusal-1/run2/…` (including `summary.json.gz` and all three
`result.json.gz`). The evidence directory and the report are tracked at `d01e952` and
`git status --porcelain` is empty for both, so the archived bytes are the committed bytes. The
worktree as a whole is a live shared tree (111 modified files and 302 untracked at audit start,
including the gate-path modules discussed in §2.5/F-1; another untracked test appeared at 04:42).
That does not touch the evidence, but it means the executed modules cannot be recovered from the
current tree with certainty either.

## 3. Gate script identity

| Check | Result |
|---|---|
| `sha256(scripts/verify_picorv32_native_online.py)` | `1422dc3f595eb97f181a6a875d271af238031d7fbd7d5f9a2914c54ab4cc7124` |
| `sha256(scripts/task5_native_completion_r11/r11-gate-script.v1.py)` | `1422dc3f595eb97f181a6a875d271af238031d7fbd7d5f9a2914c54ab4cc7124` |
| `cmp -l` bytes | identical (exit 0, no output) |
| summary `script_sha256` | equal |
| `r11-static-code-manifest.v1.json` entry for `r11-gate-script.v1.py` | equal (`1422dc3f…`) |
| `git show d8d88c7:scripts/verify_picorv32_native_online.py` | equal (`1422dc3f…`) |
| worktree vs HEAD for the script | clean (no diff) |
| earlier independent snapshot (`compiled-f4-built-identity-20261022/.../source-after.json`) | also `1422dc3f…`, so the script bytes predate the run |

The frozen r11 script directory is **untracked** (`?? scripts/task5_native_completion_r11/`), but its
content is pinned by the manifest, which itself is untracked; the two records agree with each other
and with the summary. The script was last modified 03:54:21, before the run's first artifact
(04:08:42) and last (04:09:47), and is unchanged since. Scope of this proof: **only the entry script**. The `myfuzz.*` and
`verifier.*` modules it imports are not hashed in the archive (F-1), and `summary.script_sha256`
is self-computed by the running script at its end.

## 4. The `d8d88c7` "narrow fix" and retained-response evidence

### 4.1 What the commit actually contains

`git show --numstat d8d88c7`:

```
339 24 scripts/verify_picorv32_native_online.py
 43 10 src/myfuzz/local_harness/native_session.py
688 35 src/myfuzz/scenario/session_runtime.py
```

The patch adds the **entire** native source-completion feature (the planner/refusal gate in the
script, `_validate_native_source_completion_terminal_failure`,
`_validate_native_source_completion_reference`,
`_validate_native_source_completion_terminal_cleanup`, the refusal trace/marker projection, etc.).
The parent `06ee952` contains none of it: `session_runtime.py` grows 2,926 → 3,579 lines and has no
`_validate_native_source_completion_terminal_cleanup`. There is no committed pre-fix version
anywhere (`git log --all -- src/myfuzz/scenario/session_runtime.py`; the `codex/native-exact-source-completion-20261018`
branch's `e5d798a` also lacks it; the stash does not touch the file). The commit message itself
says the change is "a delta on the shared uncommitted task-5 worktree".

### 4.2 Does the final state weaken retained-response evidence?

Inspected in the final worktree (= `d8d88c7` for these files):

- `native_session._record_native_bus_receipt` still sets `observer.failed = True` for every
  `observe()` exception, then re-raises; the observer's `pending` (state `response`, snapshot,
  read handle, scopes) is untouched.
- The only behaviour change is `_terminal_source_refusal`: it skips `_abort()` **only** for
  `type(primary) is ValueError`, `str(primary) == 'native_source_candidate_refused'`, and only
  while `_native_source_completion_session is not None`. Every other error still aborts; a refusal
  outside a completion session still aborts. Skipping `_abort()` hands the close to
  `abort_packet_submission` → `_revoke_native_source_completion` → `runner.finalize()` (END) →
  `end_case()`, which reaps rc 0; `revoke_source_completion` clears only `_source_completions` and
  read/completion authority, **not** `observer.pending`.
- `_validate_native_source_completion_terminal_cleanup` (new) asserts, for original and fresh:
  observer failed; `pending.state='response'`; `completion_issued=None`; no samples/source
  completions; session finished=False/halted=True, packet terminal + cleanup attempted, accepted
  count and cursor exact; completion session cleared and CPU process reaped; `pending_responses==1`
  with `cpu._pending is None` (no host duplicate); runner finalized with
  `failure_status='uncertain_effect'`; the pending `TransactionKey` / `ReadSnapshot` / read handle /
  native tuple / response value / accepted-response scopes / tick ordering / source binding
  canonical equality. Transaction identity uses `reference.template.testcase_id`
  (`native-pulp-online`), which is immutable in the plan (`template.testcase_id` present), because
  terminal cleanup clears the short-lived `_case_id` — consistent with the evidence, where the
  refusal keys all carry `testcase_id=native-pulp-online`.
- The replay path additionally requires `observer.failed is terminal_native_refusal` and, for the
  terminal case, `observer.pending.state='response'`; in the final code the non-terminal paths
  still require `observer.pending is None` and `failed=False`, so the positive/controlled replay
  invariant is present unchanged in shape.
- The independent refusal checker remains exhaustive: terminal-failure shape, exactly one selected
  instruction source, full transaction keys, accepted/response/refused raw ids, raw prefix counts
  (`accepted==responses==raw_completed==completed+terminal_refusals`, one terminal refusal),
  injected-write raw audit, write receipt/commit document/byte cells/commit id/service event/
  journal producer, binding, and the refused PRE. Recomputed from the archived events, all of it
  matches.

**Assessment:** the final code contains every retained-response, transaction, writer, PRE/POST,
journal and process check named in the report, and the changed host assertion (`_pending is None`)
is a different, tighter ownership constraint rather than a removed check; the retained response,
snapshot, handle and scopes are still asserted, and the poisoning journal is still audited cell by
cell. But because the pre-fix version is not committed, "the fix is narrow" and "unchanged" are
**not verifiable as deltas** (F-2). The
observed failure it repairs (`-9` and `terminal cleanup state mismatch`) is corroborated only by
the out-of-package `run-attempt2`/`diag-*` runs (F-6).

## 5. What this evidence does NOT prove

1. **No remote Stage 2.** Nothing here is `/root/fanzehui/myfuzz`: no upload, no claim, no
   controller lifecycle, no independent post-gate auditor, no controller-created plan/intent. The
   local run directory has only the three branch directories plus `summary.json.gz` — it does not
   even have the r11 controller's required `argv`/`cwd`/`output`/`requested_gates` run identity
   (`r11-one-shot-controller.v1.py` plan), so it cannot be substituted for Stage 2.
   `docs/reports/README.md` still states Stage 2 admission, remote upload and the native gate are
   unexecuted and Task 5/source completion remains open.
2. **No source-tree or tool closure, no executable identity.** The executed code is not the named
   commit: 7 gate-path modules are modified-uncommitted (`picorv32_native_online.py`,
   `native_packet_session.py`, `native_cpu_events.py`, `memory_service.py`,
   `native_instruction_source_binding.py`, `local_harness/session.py`,
   `scripts/verifier/native_completion_gate_checks.py`) and one is untracked
   (`native_instruction_bus_completion.py`, 8,447 B, sha256 `92b1a708…`). HEAD's verifier has
   **no** refusal-check code at all; the refusal checks were produced by the uncommitted verifier
   (+884 lines). No hashes of these modules were archived. The artifact document self-reports
   `cpp_sha256=a91d0494…`, `runtime_sv_sha256=64d5843c…`, Verilator
   `5.051 devel rev vUNKNOWN-built20260806-e413e67`, one closure file under
   `third_party/picorv32_upstream_reference`, and those hashes are corroborated only by the
   mutable cache manifests outside the archive; there is no archived toolchain/closure manifest and
   no gate executable identity.
3. **Proof scope is only `native_instruction_bus_transfer_completed`.** The completion object's
   `proof_scope` is exactly that, with `grants_source_authority=false`; it does not prove decode,
   architectural retirement, CPU semantic consumption, peripheral payload consumption or feedback
   (checks keep `retirement=false`, `feedback_authority=false`).
4. **No P6/P7/P8 completion** and no six-CPU/four-IP objective closure; `formal_p6_complete=false`.
5. Local gate identity beyond self-consistency: `gate_run_id` freshness/single-use and `gate_pid`
   are operator-supplied/copied; no argv, process log, exit code or timestamp is archived.
6. The retained pending response *state* (observer ownership, no host duplicate) is asserted
   in-process for both runs but not serialized; the archive proves it indirectly
   (9 responses, 8 completions, one terminal refusal at sequence 9, `no_completion=true`).
7. The refusal `raw_checks`/`terminal_refusal` depend on the CPU `runtime_document`, which is not
   archived for this branch; only their internal consistency and event joins were recomputable.
8. Test-count claims in the commit message ("242 passed, 3 skipped, 81 subtests") are not in the
   package and were not re-run.

## 6. Verdict table

| # | Claim / field | Recomputed / checked value | Verdict |
|---|---|---|---|
| S-1 | summary SHA-256 | `15a089d7c1efb8c353ae9fce175a79701a094ca7463865834ba60085debd3543` | PASS |
| S-2 | three branch statuses | `bounded_directed_gate_passed`, `bounded_directed_gate_passed`, `native_source_completion_refusal_gate_passed`; equal to each branch result and to the summary fields | PASS |
| S-3 | `gate_run_id` | `fdeab0ce…d7285ca`, 64 hex, identical everywhere | PASS (self-consistency only; provenance UNVERIFIABLE, F-3) |
| S-4 | `script_sha256` | `1422dc3f…cc7124` = entry script = r11 manifest = frozen copy | PASS |
| S-5 | false flags (coverage/P6/retirement/source authority) | all `false`, no contradicting claim in the archive | PASS |
| P-1 | positive status, 3 cases, empty findings | re-derived findings `[]` for all 3; joint 62/153/153 | PASS |
| P-2 | positive fresh replay | matches `true`, first_difference `null`, scope `full`, 3,251 = 3,251 events, equal modulo nonce | PASS |
| P-3 | positive binding/observation/completion checks | re-executed checkers equal the archived documents; `errors=[]` | PASS |
| C-1 | controlled negative preserved | exact 3 findings; 2 identical fault records (63 delivered vs 62 actual) | PASS |
| C-2 | controlled fresh replay | matches `true`, `null`, `full`, 1,395 events, equal modulo nonce | PASS |
| C-3 | controlled checks | re-executed binding/raw checkers equal archived; completion checks intentionally skipped for corrupt branch | PASS |
| R-1 | exact terminal refusal | `ValueError: native_source_candidate_refused`, phase step, case index 0, command 2, case id exact | PASS |
| R-2 | contradiction, refused PRE, poison journal | bound `1305e003` vs actual `13000000`; refused PRE event 500 (tick 49, rdata 19); journal event 476 (`value=19`, version `[0,2]`) | PASS |
| R-3 | response accounting | 9 accepted = 9 responses; 8 completions; 1 terminal refusal at sequence 9; `no_completion=true` | PASS |
| R-4 | one retained pending response | inferred from R-3 + terminal record; state asserted in-process, not serialized | PASS WITH CAVEAT (F-4) |
| R-5 | refusal full fresh replay | matches `true`, `null`, `full`, 501 = 501 events, equal modulo nonce; refusal_record identical | PASS |
| R-6 | original and fresh refusal checks present | both `native_source_completion_refusal_checks_passed`, `errors=[]`; event-level checks recomputed equal | PASS |
| R-7 | refusal not SIGKILLed | 4/4 `terminal_returncode=0`; graceful END path; prior `-9` only out of package | PASS (baseline F-6) |
| X-1 | four real processes per branch, distinct pids/nonces | 12 rows, all rc 0, pids/nonces globally distinct, artifact digests equal per component | PASS (metadata only) |
| X-2 | archive integrity | 23/23 files byte-identical to `run2`; tracked at `d01e952`, clean | PASS |
| X-3 | gate script identity | byte-equal frozen r11 script; hash in manifest/summary | PASS |
| X-4 | run produced by commit `d8d88c7` | three named files match `d8d88c7`, but 7 modified + 1 untracked gate-path modules and an uncommitted verifier were executed | FAIL AS STATED (F-1) |
| X-5 | "narrow fix", "no weakening" | final code strict; no committed baseline to diff | UNVERIFIABLE (F-2) |
| X-6 | remote Stage 2 / claim / controller / independent auditor | absent by design | NOT ATTEMPTED (report says so) ✓ |
| X-7 | P6/P7/P8 completion | not claimed; summary `formal_p6_complete=false` | NOT CLAIMED ✓ |

## Findings

**F-1 (material) — the executed source is not commit `d8d88c7`.** The report opens with
"Commit: `d8d88c7`" as though the run used that tree. It did not: the gate imports
`myfuzz.integration.picorv32_native_online`, `myfuzz.scenario.native_packet_session`,
`native_cpu_events`, `memory_service`, `native_instruction_source_binding`,
`myfuzz.local_harness.session` and `verifier.native_completion_gate_checks`, all modified-uncommitted
at run time, plus the untracked `native_instruction_bus_completion.py`. HEAD's verifier contains no
refusal-check code. Consequence: the evidence is reproducible only from a worktree snapshot that
was never recorded (no source manifest or module hashes in the archive); the commit message itself
admits the scope but the report drops it. Remedy (not applied): archive a hash manifest of every
imported module, or commit the worktree and re-run.

**F-2 (material) — "narrow fix / nothing weakened" cannot be verified as a delta.** `d8d88c7`
introduces the whole completion feature (1,070 insertions across three files); the pre-fix version
exists in no commit, branch or stash. The final code keeps every cited check and adds the terminal
cleanup validator, but "remains"/"not weakened" is an assertion about an unrecorded baseline. The
report should say "the final state still asserts X, Y, Z", not that the checks were unchanged.

**F-3 (moderate) — gate identity is self-declared.** `gate_run_id` is an operator-supplied CLI
value validated only as 64 lowercase hex; the r11 contract expects a controller-created fresh id.
`gate_pid` is `os.getpid()` copied into three results and the summary. There is no argv, cwd,
start/end time, gate exit code or process log in the package, so freshness, single-use, and the
gate process's own exit are unproven. (The branch statuses do imply a successful `main()` return,
because the script returns non-zero otherwise, but that is inference.)

**F-4 (minor, scope) — the retained response and the refusal raw checks are asserted, not
serialized.** The ownership state (`observer.pending`, `cpu._pending is None`,
`pending_responses=1`, handle/snapshot/scopes) is validated in-process for the original and fresh
sessions, but the archive only carries the counts (9/8/1), the terminal refusal record and the
refused PRE. Likewise the refusal `raw_checks`/`terminal_refusal` depend on the CPU
`runtime_document`, which is not archived for that branch. An external auditor cannot re-run those
python-state/artifact assertions; it can only recompute the event accounting (which it does
exactly) and the event-level refusal checks (which reproduce).

**F-5 (minor) — the summary does not bind the branch bundles.** It records no per-branch hashes or
file manifest, so a future edit to a branch result would not be detected by the summary. The
linkage is by identical `gate_run_id`/`gate_pid` and directory convention; the report's table of
result hashes is correct today (all three recomputed) but is not itself covered by the summary.

**F-6 (informational) — the "no longer SIGKILLed" baseline is outside the package.** The current
run is clean (rc 0). The prior failure it repairs is only visible in
`/home/qinkejiu/.native-gate/run-attempt2/native-source-refusal/result.json.gz` (status failed,
"native source completion terminal cleanup state mismatch", cpu rc `-9`, 2 processes) and the
`diag-*` state snapshots — none archived or committed. This is corroboration, not evidence in the
package.

**F-7 (informational) — controlled branch carries `native_source_completion=true` without
completion checks.** Correct by construction (`and not corrupt`), and the report does not claim
otherwise, but a reader skimming `result.json.gz` could misread the flag as a completion claim.

## Positives worth recording

- All branch statuses, process lists, replay fields and check documents reproduce from the archived
  bytes; the six trace `semantic_sha256` digests all recompute.
- The fresh runs are exact replays modulo the declared execution nonce, including the refusal run's
  501-event prefix and both refusal-check documents.
- The archive is byte-identical to the original run directory and is committed/unmodified.
- The report's boundaries (local only; Stage 2 open; no source-tree/tool closure or executable
  identity; proof scope `native_instruction_bus_transfer_completed`; no P6/P7/P8) are accurate and
  conservative; the summary's authority flags are all false.

## Exact paths

- Evidence: `docs/reports/evidence/native-completion-task5-local-20261023/` (`summary.json.gz`,
  `positive/{result,first,fresh-comparison,case-1..3,native-observation-checks,native-source-binding-checks,native-source-completion-checks}.json.gz`,
  `positive/plan.json`, `controlled-response/{result,first,fresh-comparison,case-1,native-observation-checks,native-source-binding-checks}.json.gz`,
  `controlled-response/plan.json`, `native-source-refusal/{result,original-terminal,fresh-terminal-replay,native-source-refusal-checks}.json.gz`,
  `native-source-refusal/plan.json`).
- Report audited: `docs/reports/native-completion-task5-local-20261023.md`.
- Gate script: `scripts/verify_picorv32_native_online.py`; frozen copy and manifest:
  `scripts/task5_native_completion_r11/r11-gate-script.v1.py`,
  `scripts/task5_native_completion_r11/r11-static-code-manifest.v1.json`.
- Commit: `d8d88c7` (`scripts/verify_picorv32_native_online.py` `1422dc3f…`,
  `session_runtime.py` `f1cae068…`, `native_session.py` `1eb4bfec…`).
- Original run directory (outside repo, read-only): `/home/qinkejiu/.native-gate/agent-refusal-1/run2`.

## Reproduction (all read-only)

```sh
sha256sum docs/reports/evidence/native-completion-task5-local-20261023/summary.json.gz \
          docs/reports/evidence/native-completion-task5-local-20261023/*/result.json.gz
cmp scripts/verify_picorv32_native_online.py scripts/task5_native_completion_r11/r11-gate-script.v1.py
# for each branch: gunzip, recompute the relation/response/replay invariants above,
# canonical json_sha256 = sha256(json.dumps(doc, sort_keys=True, allow_nan=False)),
# gzip_sha256 = sha256(file bytes), _trace_semantic_sha256 over the archived events,
# and re-run the shipped verifier functions with the archived plans/artifact documents.
# Fresh/original equality was checked after replacing the two execution nonces with a token.
git show --numstat d8d88c7
git status --porcelain   # 7 modified + 1 untracked on the gate import path
```
