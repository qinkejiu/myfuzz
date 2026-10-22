# Independent audit — CVW directed-session and Vexii fixed-instance IRQ evidence

Date: 2026-10-23. Repository: `/home/qinkejiu/myfuzz`, HEAD `3a6c4766f711c58694b9d08328c172f864a272d9`.
Audited commits (all confirmed ancestors of HEAD): CVW `3d86c19`, `5051054`; Vexii
`f454962`, `ad4eb9e`, `69556d3`, `9287e47`, `2c99a00`.

Read-only audit. No source, test, config or evidence file was modified. The only file written is
this report. Recomputation used only `hashlib`/`json`/`gzip` and read-only imports of the shipped
modules (`verify_local_source_lock`, `make_cvw_boot_image`, `review_component_declarations.py`).
No RTL run, rebuild or test execution was performed; test counts were verified by `--collect-only`.

Evidence directories are at HEAD, unmodified and touched only by the named commits
(`git status --porcelain` empty for both; `git log -- <dir>` = `3d86c19` for CVW and
`2c99a00`/`69556d3` for Vexii).

## Verdict table

| # | Check | Evidence path | Recomputed / observed | Verdict |
|---|---|---|---|---|
| CVW-1 | Gate verdict `status: complete`, `exit_code: 0`, no refusals, `.incomplete` absent | `docs/reports/evidence/cvw-session-20261018/run/run-summary.json`, `gate-exit.txt`, `run/` | `status=complete`, `exit_code=0`, `refusals=[]`, `absences=[]`; `started 2026-10-17T18:25:33Z` / `finished …18:26:42Z` = 69 s = `wall_seconds=69`; `run/.incomplete` absent | **PASS** |
| CVW-2 | D1/D2/D3/projection/session/fresh/capability all `ok` | same file, `stages` | 9/9 stages `ok`; `runtime_family=ok`, `driver=ok` | **PASS** |
| CVW-3 | Fresh verification `matches:true`, `first_difference:null`, `verification_scope:full`, 98 events | `run/fresh-verification.json`, `run/session/directed-session.json` | `matches=true`, diff `null`, scope `full`; 98 = 43 beats + 7 deliveries + 4 RAM writes + 43 source beats + 1; recomputed projection SHA-256 `93e76e05…` equals the reported `semantic_sha256` **and** `manifest_sha256`; first/fresh projections identical | **PASS** (scope label caveat, F-2) |
| CVW-4 | Report claim: first and fresh are “two independent processes” | `docs/reports/cvw-directed-session-20261018.md:52`; `src/myfuzz/integration/cvw_directed_session.py:467,473` | Both runs are `_run_once(...)` calls in one Python process; saved first/fresh evidence documents are equal except `elapsed_seconds`; no PID/UUID/exit of either run is recorded | **UNVERIFIABLE / overclaim** |
| CVW-5 | Capability tiers: `F4:ram.image` = Catalog + Generated + RTL operational + Cross-component accepted | `run/capability-report.json`, `run/session/receipts.jsonl` | F4 `awarded=[Catalog,Generated,RTL operational,Cross-component accepted]`; receipt `flow_id=F4`, `candidate_disposition_reason=rtl_case_committed`, `total_local_ticks=373` (172+201), 5 `cpu:gpio:apb*` features | **PASS** |
| CVW-6 | F1–F3 Catalog+Generated; F5/F6 Catalog only; Coverage-guided and Bug confirmed 0 | same file | `F1..F3.awarded=[Catalog,Generated]`, `F5/F6=[Catalog]`, unsupported `interrupt-consumer-missing` / `dma-master-not-declared`; `tier_awards`: `Bug confirmed 0`, `Coverage-guided searched 0`, `Catalog 8`, `Generated 6`, `RTL operational 3`, `Cross-component accepted 3` | **PASS** |
| CVW-7 | 7 CPU→GPIO APB deliveries with the reported sequence | `run/session/directed-session.json:first.deliveries`, `run/session/report.json:evidence` | 7 rows: `(0,W,0xFFFFFFFF) (4,W,0xFFFFFFFF) (12,W,0x35) (12,R,0x35) (12,W,0x6A) (12,R,0x6A) (8,R,0xA5)`; `delivery_count=7`, `accepted_beat_count=43`, `cpu_steps=172` | **PASS** |
| CVW-8 | RAM result `[0x35,0x6a,1,0xa5]` and final GPIO state | `run/session/report.json:evidence`, `run/session/directed-session.json:first.final_target_state` | `result_words=[53,106,1,165]`, `result_state=success`; `gpio_out=106`, `gpio_dir=4294967295`, `gpio_in_sync=165` | **PASS** |
| CVW-9 | First measured fetch `0xC0000000`, boot word held 1 tick | same files, `instruction_source` | `first_measured_fetch_address=3221225472`, `hold_ticks_before_delivery=1`, `instruction_hold_ticks=1`, `instruction_hold_addresses=[0xC0000000]`, `first_presented_step=1`, `delivered_step=2`; CPU boot contract `configured_boot_base=0xC0000000` | **PASS** |
| CVW-10 | Boot image: 256 B / 64 words, sha `8444b6ab…`, base `0xC0000000`, result `0xC0000400` | `run/session/report.json`, `source-identity.json` | Rebuilt with `make_cvw_boot_image(gpio_base=0xCFFF0000)`: 256 B, 64 words, sha256 `8444b6abf745055806f8fe0c7243d330cd0d62600889547def03aed72fef84b9`, base `0xC0000000`, result `0xC0000400`, reset word `0xCFFF00B7` (LUI, aligned page) — exact match | **PASS** |
| CVW-11 | Artifact digests CPU `37038890…`, GPIO `1331b597…` | `run/generated/{cpu,gpio}/artifact.json` | sha256(canonical artifact document without its `artifact_digest` field) = `370388904ee6b149ab961060e99c82a413eec31e6e4196b9c53e602f40797282` / `1331b597185e3b0915d0c946fe5ef2607482d003a299683cd276bd79d2576c41` | **PASS** |
| CVW-12 | Bundle is a second view of the directed documents, not an authenticated online prefix | `run/bundle/bundle-manifest.json`, `run/bundle/*` | bundle copies are byte-identical to `run/session/*`; manifest hashes match; `authenticated_online_prefix=false` | **PASS** |
| CVW-13 | Negative control: RFuzz client binary refused by name, no session started | `client-binary-refusal/run-summary.json`, `.incomplete`, `client-binary-refusal.stdout.log` | `status=refused`, `exit_code=1`, refusal `stage=session`, `code=directed-session-does-not-consume-client-binary`, `pointer=/client-binary`; `fresh_verification` absent with `fresh-replay-requires-a-session`; no `session/` directory; refusal capability report awards 0 `RTL operational` / 0 `Cross-component accepted`; stdout records `client_binary_refusal_exit=1` | **PASS WITH GAPS** (argv only in `run-tests.sh`; stderr file absent; docs say D1–D3, D4 also ran — F-5) |
| CVW-14 | Boundary honesty: directed fixed image, no RFuzz/online decoder, no F5/F6, no P6 claim | `run/execution_projection.v1.json`, `run/session/report.json:not_claimed`, `run/capability-report.json`, report §5/§7 | `execution_status=directed_fixed_image`, `runtime_admitted=false`, `compiled_semantics_executed=false`; `not_claimed` lists no OnlineCaseDecoder / no F5 / no DMA / no retirement / no persistent multi-case; F5/F6 unsupported with named codes; report and checklist keep the P6 row open | **PASS** |
| CVW-15 | Pinned hashes recompute | `run/run-summary.json:documents`, `source-identity.json`, `.superpowers/cache/cvw-session-gate` | 12/12 document byte hashes; 72/72 `evidence_files_sha256`; 7/7 cache `manifest.json` hashes and 7/7 manifest `binary_sha256` ↔ `harness`; 4/4 canonical capability inputs (`f287050e…`, `6f50890d…`, `7ca67043…`, `888ae9cf…`); assembly `65273f0f…` (3 copies agree) | **PASS** |
| CVW-16 | Gate-time source identity | `source-identity.json:our_files_sha256` | 14/15 recorded hashes equal the `3d86c19` blob; `src/myfuzz/integration/cvw_pulp_online.py` recorded `38839219…` matches **no** preserved blob (HEAD/`3d86c19`/`5051054` = `8873a83e…`) | **PASS WITH GAPS** (F-3) |
| CVW-17 | Test-count claims | `pure-tests.log`, `pytest-gate.log`, `ahb-session-tests.log`, `static-chain-tests.log`, `ahb-runtime-generation-tests.log` | Logs state 69 passed/1 skipped 48.01 s, 1 passed 69.43 s, 8 passed 144.98 s, 2 passed 112.72 s, 4 passed 62.22 s; collection now yields 70 (=69+1), 8, 2, 4 tests respectively; `test_cvw_session_assembly.py` 29 collected | **PASS** |
| CVW-18 | D4 throughput / p5 aggregation | `run/capability-report.json:session`, `run/run-summary.json` | `metrics_available=false`, reason “invalid coverage_hex on line 1 of receipts.jsonl”, `throughput_status=not_measured`; report §4 does not mention this limitation | **PASS WITH GAPS** (F-8) |
| VEX-1 | First/fresh compressed evidence bytes/hashes | `docs/reports/evidence/vexi-irq-fixed-20261018/{first,fresh}.json.gz` | 170,177 B `05363adb…`; 170,172 B `71aca53a…` — match README and `summary.json` | **PASS** |
| VEX-2 | Uncompressed documents | same, gunzip | 6,598,806 B `ff6b49ce…`; 6,598,805 B `0eaffe7c…` — match `summary.json` | **PASS** |
| VEX-3 | Summary/gate-log bytes | `summary.json`, `gate.log` | 22,059 B `83ec540e…`; 922 B `ea8539be…` — match README | **PASS** |
| VEX-4 | 8-case fixed row, per-case pattern | `first.json`/`fresh.json`: `cases`, `driven_values`, `rounds` | cases `[17,34,51,90,165,291,1023,127]`, driven `[17,35,51,91,165,291,1023,127]`, 8 rounds; every round = `(16,W,driven) (12,R,driven) (36,R,bit0=1) (20,W,0xffffffff)` exactly | **PASS** |
| VEX-5 | 1,567 CPU / 1,711 GPIO ticks | `counts`, `cpu_samples`, `gpio_samples` | lengths 1,567 / 1,711 in both runs; `host_rounds=1567`, `trace_events=2928` | **PASS** |
| VEX-6 | 8 IRQ rises / 8 falls, 8 mtvec fetches | `host_events`, `cpu_irq_edges`, `fetch_addresses` | 8 `irq_rise` + 8 `irq_fall` + 8 `isr_vector_fetch` (24 events); `cpu_irq_edges` = 16 levels `[1,0]*8`; 8 of 471 fetches at `0x80000200` | **PASS** |
| VEX-7 | 36 APB deliveries (4 config + 8×4) | `deliveries`, `acceptances` | 36 rows = 4 one-time writes (offsets 4/24/28/20) + 32 round deliveries; 36 acceptances | **PASS** |
| VEX-8 | RAM result/status/check/done | `ram` | `result=[17,35,51,91,165,291,1023,127]`, `status=[1]*8`, `check=[0]*8`, `done=0x600d` in both runs | **PASS** |
| VEX-9 | 77/77 row checks in each run | `checks` (both docs), `summary.row_checks` | 77 checks, all `ok`, identical in both runs; checks compare RAM words to expected driven values, INTSTATUS bit 0, PADOUTCLR, per-case vector fetch | **PASS** |
| VEX-10 | Two fresh OS processes, distinct native execution IDs | `summary.children`, `execution`/`fresh_execution`, `measurement.child_pid` | child PIDs 534 / 779, child `exit_code=0`, empty stderr; CPU `5b849cb6…`/`1be5e0d7…`, GPIO `75464baf…`/`e095531b…` (all distinct); `compare_fresh_runs` `distinct-native-executions=true` | **PASS** (per-native PID/exit not recorded, F-10) |
| VEX-11 | Fresh replay equality | `summary.replay`, `compare_fresh_runs` | stable-evidence digest `c1661efd…` recomputed for both runs; raw CPU `d0d32b63…`, GPIO `5c0ca3c8…` recomputed and equal; nested diffs are only `execution_id`/`testcase_id`, plus `measurement.wall_seconds` (13.929/13.36) and `child_pid` (534/779); `matches=true` | **PASS WITH GAPS** (wording F-2) |
| VEX-12 | Program image 4,384 B, sha `e4fb014d…`, 52 main/21 ISR words | `program` | Rebuilt from `main_words`/`isr_words`/`cases` with the documented layout: 4,384 B, sha256 `e4fb014dbfcae1920261bec4ffb078b4340c8a33d3d0cc6274fc784632a69c86` | **PASS** |
| VEX-13 | Runtime artifact / harness identities | `artifacts`, `binaries` | artifact digests recompute from canonical runtime documents minus `artifact_digest` (`ee91caef…`, `ac5c4224…`); harness files still in `.superpowers/vexi-irq-cache/…` hash to `d9a986e6…` / `1fb4696c…` | **PASS** |
| VEX-14 | Implementation hashes | `summary.implementation` | all 5 (scenario module `04621b74…`, gate script `122556d1…`, derived profile `eb7aecd1…`, derived contract `7277c026…`, driver header `1e72a2d2…`) equal both the `ad4eb9e` and HEAD blobs | **PASS** |
| VEX-15 | Derived-profile/source-lock claims (same RTL bytes, exact delta) | `first.json:identities.*.source_verification` | Re-verified: `profile_union_revision=sha256:5e73d052…` identical for baseline and derived; derived `eb7aecd1…`, baseline `426e8ff0…`, closure `8ad3e471…`, lock `4caf0ae6…`; delta names `int_m_external`, `processor.interrupts`, `machine_external`, `active_high` and keeps timer/software constant; PULP submodule at `f82caeb7…`, `rtl/apb_gpio.sv` = `1e271914…` | **PASS** |
| VEX-16 | Declaration review 9/9 for both profiles | `scripts/review_component_declarations.py` | Re-run now: `ok vexiiriscv (9/9)`, `ok vexiiriscv_irq (9/9)`, exit 0 | **PASS** |
| VEX-17 | Gate exit code | `gate.log`, `summary.children` | child exit codes 0/0 recorded; the publication command’s own exit is **not** recorded anywhere; `gate.log` has no command, selection or exit marker | **UNVERIFIABLE** |
| VEX-18 | Test-count prose (36 passed/2 skipped; 98 passed/3 skipped/64 subtests) | `gate.log`, report, README | 36+2 = 38 equals 12+14+12 collected for the three Vexii files (2 tests skip without `MYFUZZ_VEXII_REAL`/`_MMIO_REAL`); 98+3 = 101 equals the eight-file pure selection’s collection; no log preserved for the 98/3/64 run | **PASS WITH GAPS** (F-11) |
| VEX-19 | Declared host boundaries, no P6 claim | `first.json:wiring`, `summary.boundaries`, report, `docs/reports/README.md`, `docs/COMPONENT_REFERENCE.md`, `docs/LOCAL_HARNESS_RUNTIME.md` | `pulse_to_level` and `gpio_in <- previous GPIO edge gpio_out` declared; `injects_trap=false`, `injects_cause=false`; boundaries list fixed row/no mutation/no coverage; every doc keeps P6, interrupt-controller RTL, online mutation and authenticated prefix replay open | **PASS** |

## Exact paths

CVW: `docs/reports/evidence/cvw-session-20261018/` (`run/run-summary.json`,
`run/fresh-verification.json`, `run/execution_projection.v1.json`, `run/capability-report.json`,
`run/session/report.json`, `run/session/receipts.jsonl`, `run/session/directed-session.json`,
`run/bundle/*`, `run/generated/{cpu,gpio}/artifact.json`, `source-identity.json`,
`gate-exit.txt`, `client-binary-refusal/*`, test logs); report
`docs/reports/cvw-directed-session-20261018.md`.

Vexii: `docs/reports/evidence/vexi-irq-fixed-20261018/` (`first.json.gz`, `fresh.json.gz`,
`summary.json`, `gate.log`); reports `docs/reports/vexiiriscv-cpu-ip-irq-20261018.md`,
`docs/LOCAL_HARNESS_RUNTIME.md` (Vexii row and 2026-10-18 increment), `docs/reports/README.md`,
`docs/COMPONENT_REFERENCE.md`.

## Findings

### Overclaims

- **F-1 (CVW, material).** `docs/reports/cvw-directed-session-20261018.md:52` presents the fresh
  replay as “真实 first 与 fresh 两次独立进程” (two independent processes). The implementation calls
  `_run_once` twice inside one Python process (`src/myfuzz/integration/cvw_directed_session.py:467`
  and `:473`); `make_cvw_gpio_session_factory` does create fresh sessions, and each `begin_test`
  starts new simulator subprocesses, so the RTL runs are process-fresh — but the saved evidence
  records no PID, native execution UUID, child exit or `reaped` status for either run (the delivery
  `execution_id` is the constant `local-execution`), and `first`/`fresh` are byte-equal apart from
  `elapsed_seconds`. Process independence is therefore an implementation claim, not a recorded fact.
  By contrast the older static-chain evidence in the same directory does record distinct execution
  UUIDs (`static-chain/first.json` `10403169…/98dba7ca…` vs `fresh.json` `7309fa19…/e2f806eb…`).
- **F-2 (both, minor wording).** CVW `verification_scope: "full"` is a literal constant at
  `src/myfuzz/integration/cvw_directed_session.py:494`, not a derived verdict. The comparison itself
  is a full-field projection comparison (excluding nine volatile identity keys), so the label is
  defensible, but it carries no computed information. Vexii says the replay is “whole-document
  equality modulo native run identity”, while `compare_fresh_runs`
  (`src/myfuzz/scenario/vexii_pulp_gpio_fixed.py:706-740`) compares a declared 16-key stable subset
  plus raw samples and identities; `measurement` (wall time/PID), `implementation`, `error`,
  `profile_paths` and `schema_version` are not compared. The Vexii evidence README’s “differ by one
  measurement byte … not in any evidence field” is also loose: the documents additionally differ in
  `testcase_id` and in every nested `execution_id`/`testcase_id`; the one-byte size delta is
  `wall_seconds` (`13.929` vs `13.36`).
- **F-4 (CVW, corrected).** The report as gated (`acff5529…`, hash pinned in `source-identity.json`)
  stamped the gate HEAD as `ade3fe6`; `5051054` corrected it to “gate HEAD `2c99a00` + task changes;
  final commit `3d86c19`”, which matches `source-identity.json:head`. This was a fixed documentation
  error, not a live overclaim.
- **F-5 (CVW, understatement).** README/report §5 say the negative control “completes D1–D3 and
  refuses the session stage”. The saved `client-binary-refusal/capability-report.json` shows D4 also
  ran and is `ok` (correctly with 0 `RTL operational` / 0 `Cross-component accepted`, no session).
  This understates, not overstates, the run.

### Missing process / exit records

- **CVW:** no process identity or exit record for either of the two session runs, and no record of
  the heavy-worker lock despite the README’s `flock` claim. The gate’s exit is self-declared in
  `run-summary.json` (`exit_code: 0`) plus `gate-exit.txt` (`exit_code=0 wall_seconds=69`) and is
  consistent with `started_utc`/`finished_utc` and the absence of `run/.incomplete`.
- **CVW negative control:** its own evidence records the refusal, `exit_code: 1`, the marker
  `.incomplete` and the appended `client_binary_refusal_exit=1`, but not the CLI argv or the RFuzz
  client path. Those appear only in `run-tests.sh`; that script also redirects stderr to
  `client-binary-refusal.stderr.log`, which is absent from the preserved evidence.
- **CVW source identity:** 14/15 gate-time source hashes equal the `3d86c19` blobs; the
  `src/myfuzz/integration/cvw_pulp_online.py` bytes recorded at gate time (`38839219…`) are not
  preserved in any commit (`3d86c19`/`5051054`/HEAD = `8873a83e…`). Additionally the run’s worktree
  contained another agent’s uncommitted Vexii changes plus modified `third_party` entries; they are
  listed by path (`foreign_worktree_changes_preserved`) but not hashed, so the exact software identity
  of that run is only partially reconstructible.
- **Vexii:** the two Python children are recorded (PIDs 534/779, `exit_code=0`, empty stderr,
  wall 14.332/13.736 s), but the publication script’s own exit code is not recorded, `gate.log` has no
  command/selection/exit marker, and there is no per-native CPU/GPIO PID or exit record (only the
  native execution UUIDs). The `flock` acquisition claimed by the README is also unrecorded.

### Unverifiable fields

- CVW “two independent processes” (F-1).
- CVW gate-time bytes of `src/myfuzz/integration/cvw_pulp_online.py`.
- CVW negative-control argv/client path from the run itself.
- Vexii overall gate `exit 0`.
- Vexii “36 passed, 2 skipped” selection (counts are consistent with a 12+14+12 collection, but the
  command is not recorded) and “98 passed, 3 skipped, 64 subtests” (no log preserved).
- Vexii `flock` usage and per-native-process exit status.

## Residual gaps

1. No run-level process identity/exit evidence for the CVW directed session; the report’s
   “two independent processes” should be restated as “two fresh RTL process starts driven from one
   host process, with no preserved per-run identity”.
2. `verification_scope: "full"` (CVW) is a constant; either derive it or label it as a fixed schema
   field.
3. One gate-time CVW source file’s bytes are unrecoverable; the run’s foreign worktree changes are
   recorded only by path, not hash.
4. CVW negative-control run has no self-recorded argv; its reproduction script’s stderr target is
   missing from the archive.
5. CVW capability report’s p5 arm-metrics aggregation failed on the directed receipt
   (`coverage_hex: null`); the report does not mention that limitation, only that throughput is
   `not_measured`.
6. CVW capability `tier_awards` counts (RTL operational 3, Cross-component 3) include both component
   subjects plus F4, while the report table lists only paths; the numbers are correct but easy to
   misread.
7. Vexii’s overall publication exit is unrecorded, and its `gate.log` omits the pytest selection and
   command.
8. Vexii’s replay wording should name the compared stable projection and the separately compared raw
   samples rather than “whole document”; measurement/PID differences are not “native run identity”
   only.
9. Vexii has no per-native-process PID/exit record; the “one native CPU process and one native GPIO
   process per run” statement is a design property of the sessions.
10. Vexii’s GPIO loopback is the *previous* GPIO edge’s `gpio_out` (one-edge delay, as stated in the
    evidence `wiring`); the report’s shorthand “loopback of its own real `gpio_out` output” omits
    that qualifier.
11. Vexii’s pure test selection and subtest counts have no preserved log; only the combined
    `gate.log` line exists.
12. The Vexii snapshot directory (`.superpowers/vexi-irq-snapshot`) no longer exists and the
    harness binaries live only in `.superpowers/vexi-irq-cache/`; re-verification depends on those
    caches (they are present and match today), while the evidence identity itself verifies against
    `ad4eb9e`.

## What the evidence does support

Within the declared boundaries, the saved evidence supports: a real CVW AHB-Lite directed fixed-image
run with 172 CPU steps, 43 accepted beats, 7 real routed APB deliveries, RAM `[0x35,0x6a,1,0xa5]`,
first fetch and boot-word hold at `0xC0000000`, an F4 grade of RTL operational + Cross-component
accepted (and nothing above), an honest directed-only boundary, and a named refusal of an RFuzz client
binary; and a real VexiiRiscv + PULP GPIO IRQ row with 8 cases, 1,567/1,711 ticks, 8 IRQ rises/falls,
8 `mtvec` fetches, 36 APB deliveries, correct RAM `result`/`status`/`check`/`done`, 77/77 checks in
each of two genuinely separate child processes with distinct native execution UUIDs, matching
stable-evidence digests, and no P6 claim.

No numeric contradiction between the reports and the saved evidence was found. Every pinned hash that
was recomputed (12/12 CVW run-summary documents, 72/72 CVW evidence files, 7/7 CVW cache manifests and
binary bindings, 4/4 CVW canonical capability inputs, CVW boot image/artifact/assembly digests, all
four Vexii file hashes plus uncompressed hashes, Vexii program image, artifact digests, harness
binaries, implementation hashes and source locks, Vexii stable/raw replay digests) matches exactly.
