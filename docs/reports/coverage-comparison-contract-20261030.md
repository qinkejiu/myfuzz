# Coverage comparison contract — declared-IRQ F5 incl. the wb-timer CPU side, 2026-10-30

Scope: the three declared-IRQ F5 runs under
`research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030/`
(`wb-timer`, `apb-spi`, `ahb-sha`) **and** the previously unmeasurable CPU side
of `wb-timer`.  Coverage is Verilator line/block instrumentation replayed
offline from the recorded command prefix.  One instrumented build was made
(`-j 4`, exit 0, 7.95 s wall) together with its replay; no fuzz campaign, no
native harness session and no DUT search was started.  `research/` and `runs/`
recorded artifacts were not modified; every new output is in a new directory.

The machine-readable twin is
[`coverage-comparison-contract-20261030.json`](coverage-comparison-contract-20261030.json);
it records the SHA256 of each of the 65 input files it read, the per-scope
contracts, the pairwise contract checks and the exact reproduction commands.
`docs/reports/new-path-coverage-20261030.md`/`.json` are unchanged and still
reproduce byte-identically.

## 1. What is now measured

| Run | Scope | Component | DUT line/block | Verilator line | Verilator branch | Commands | Local ticks | Status |
|---|---|---|---|---|---|---|---|---|
| `wb-timer` | `coverage-cpu-replay-20261030` | `cpu` (Ibex) | **616 / 1782** | 245 / 812 | 371 / 970 | 105 | 105 | **measured (new)** |
| `wb-timer` | `coverage-target` | `wb_timer_active` | 37 / 39 | 23 / 23 | 14 / 16 | 110 | 116 | measured (unchanged) |
| `apb-spi` | `coverage-target` | `spi_active` | 85 / 271 | 38 / 77 | 47 / 194 | 106 | 112 | measured (unchanged) |
| `ahb-sha` | `coverage-target` | `sha_active` | 359 / 614 | 178 / 286 | 181 / 328 | 134 | 146 | measured (unchanged) |

`wb-timer` CPU, exact command (stdout `status=measured`, exit code 0):

```sh
PYTHONPATH=src:. python3 scripts/measure_local_coverage.py \
  --trace research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030/wb-timer/original/original/local-command-trace.json \
  --component cpu \
  --cache runs/config-driven-20261028/cache/a06ff3b42591ca1097f9b8c3a471080d4346199501245baeb66edd0fe718c8fc \
  --output research/input-strategy-audit-20261027/runs/declared-irq-f5-cpu-20261030/wb-timer/coverage-cpu \
  --max-commands 2048 --build-jobs 4
```

The command is saved verbatim in
`research/input-strategy-audit-20261027/runs/declared-irq-f5-cpu-20261030/command.txt`
with its stdout/stderr/timing in `measure.out`/`measure.err` (`EXIT:0`).
The build is one fresh instrumented copy of the **pinned** cache entry; its
`coverage.json` records `build_jobs: 4` and `build_executed_argv` with `-j 4`,
while `build_argv` stays the instrumentation command derived from the pinned
identity (the saved `-j 8`).  The job cap changes only the compile schedule,
never the pinned inputs or `--coverage-line`; the executed argv is recorded next
to the derived one instead of being silently substituted.

Why the earlier offline attempt was refused, and what changed: the saved CPU
artifact's `structural_build.source_files` renders 45 entries as
`./third_party/.../*.sv`, while the content-addressed cache input paths are the
same files without the `./` prefix.  The replay verifier required an exact
cache-input path and refused with `coverage-dut-source-list-invalid` even though
45/45 entries resolved to a known, hash-verified cache input.  The verifier now
normalises that leading prefix (absolute or `.`/`..`/empty components still
refuse) in both the measurement and the saved-measurement loader.  Everything
else already matched: the current toolchain equals the pinned toolchain, the
cache validates, the cache `harness` SHA256 equals the trace's
`binary_sha256` (`588359f8…`), the artifact digest equals the trace's
(`e243a26e…`), and the `cpu` session is `complete` with 105 sequential records.
The same `build_digest` (`a06ff3b4…`) and `binary_sha256` are the values in the
run's saved `original/summary.json` process row, and the run's own
`coverage-cpu/inputs/generated/artifact.json` carries the same
`artifact_digest` (`e243a26e…`), so the cache entry is the run's own CPU build,
not a look-alike.
No number is parsed from the old raw `coverage.dat`.

Independent corroboration: the run's own saved
`coverage-cpu/coverage.dat` (SHA256 `1cbc3ba6…`) and the fresh replay's
`coverage.dat` (SHA256 `eb75992b…`) decode to the **same 1826 point identities
and the same 650 hit points** after normalising each absolute source path
relative to its `inputs/` directory; per-point counts are identical.  The bytes
differ only because the build directory is embedded in each point.  Evidence:
`research/input-strategy-audit-20261027/runs/declared-irq-f5-cpu-20261030/wb-timer/corroboration.json`.
This is replay corroboration, not authentication of the original process.

## 2. The fixed comparison contract

Contract id: **`dut-line-block/offline-recorded-prefix.v1`**.  A covered/total
may only be compared when **all** of the following hold on both sides:

1. same DUT: identical declared structural-build source files
   (`dut.source_files_sha256`) and the same component;
2. same point set: identical saved point map (`dut.point_set_sha256`) and
   canonical denominator (`dut.denominator_sha256`);
3. same workload: identical recorded command sequence with the 32-hex execution
   nonce normalised (`workload.commands_sha256`), same command count and local
   ticks (recorded replies are compared too);
4. same budget: identical `replay_budget` and executed command count; a search
   budget is never inferred and remains `unknown`;
5. same explicit coverage mode: `offline` recorded-prefix replay on both sides
   (`online` and `fixed_time_coverage` are `false`);
6. both sides instrumented: a prefix without its own instrumented replay has no
   covered/total and is **never** compared.

Identity of the four measured scopes (all values also in the JSON):

| Run/scope | DUT source-set SHA256 | Point-set SHA256 | Denominator SHA256 | `coverage.dat` SHA256 | Build digest |
|---|---|---|---|---|---|
| `wb-timer/coverage-cpu-replay-20261030` (`cpu`, 45 files) | `c1478824…` | `568adb35…` | `3611450e…` | `eb75992b…` | `a06ff3b4…` |
| `wb-timer/coverage-target` (`wb_timer_active`, 1 file) | `4cb33052…` | `e221d9ac…` | `2df82e53…` | `1491e394…` | `f526592a…` |
| `apb-spi/coverage-target` (`spi_active`, 7 files) | `3758308a…` | `009ab3fb…` | `c8dc6081…` | `8b92abc2…` | `1e26eb15…` |
| `ahb-sha/coverage-target` (`sha_active`, 11 files) | `f40f8dce…` | `87f0c9c4…` | `6849c90f…` | `461c4caf…` | `7c80b436…` |

Workload and budget per scope:
| Run/scope | Workload SHA256 (nonce-normalised commands) | Commands | Local ticks | Replay budget |
|---|---|---|---|---|
| `cpu` | `0a7a4e94…` | 105 | 105 | 2048 commands / 64 MiB in / 64 MiB out / 60 s |
| `wb_timer_active` | `3f6847b0…` | 110 | 116 | same |
| `spi_active` | `e6c0077b…` | 106 | 112 | same |
| `sha_active` | `8d63048d…` | 134 | 146 | same |

The CPU denominator (1782) is the number of points that actually exist in the 45
declared source files (packages and primitives without line/branch bodies add
files but no points); it is not a file count and not `45 × something`.  The
whole-harness point universe is 1826, of which 44 points belong to generated
runtime/driver code and are therefore excluded from the DUT denominator.

All six pairs of measured scopes are checked by
`compare_under_contract`: **0 comparable pairs**.  Every pair is
`not_comparable` with `component-mismatch`, `metric-mismatch`,
`dut-source-set-mismatch`, `point-set-mismatch`, `denominator-mismatch`,
`workload-mismatch`, `workload-length-mismatch`, `workload-tick-mismatch` and
`replies-mismatch`.
No cross-component or cross-workload covered/total is formed, and the package
publishes no aggregate (`aggregate: null`, `aggregate_reason` given), because the
per-component denominators are not additive.

Metric: `verilator-line-block:<component>:dut`, i.e. Verilator's line/branch
point kinds over the declared structural-build source files, all retained
hierarchy instances, **including startup/reset and any budget-overrun tail**.
It is not source-branch coverage, not a semantic/SoC/native metric, not online
coverage, not fixed-time coverage and not coverage AUC.

## 3. Own original/fresh-prefix comparability (kept unchanged)

All four measured scopes keep `status = comparable_prefix`,
`mode = own-original-fresh-prefix`, with `comparison = null`:
same config and admission, same artifacts/case/group, same component build
digest and binary SHA256 on both sides, identical recorded commands and replies
modulo the execution nonce, identical per-command `tick_after` sequence and the
same final tick, both invocations' processes exit 0, and the original side still
equals the verified measurement.  Condition values: `seed`, `time_budget`,
`execution_budget`, `fairness` remain `unknown`; `process_independence` is
`separate-invocations` (distinct nonces and pids).

`coverage_comparison_available` is `false` with reason
`fresh-prefix-not-instrumented` for every scope: the fresh prefix reproduces the
same commands on the same build but was not built with `--coverage-line`, so it
contributes no covered/total and none is derived.  Reproducing a prefix is not
evidence of tool superiority.

## 4. What stays unavailable and the exact reason

- `wb-timer/coverage-cpu` (the original directory): `status = unavailable`,
  reason `incomplete-saved-measurement`, missing `coverage.json`,
  `commands.txt`, `replies.txt`.  It remains a historical artifact; the
  measured CPU number comes from the new `coverage-cpu-replay-20261030`
  directory, not from that one.
- `cv32e40p-irq-20261030/shared-six-v6` (six-flow acceptance, 8 cases, F1–F6):
  `status = unavailable`, reason `missing-per-component-command-trace`, missing
  `original/local-command-trace.json`, `original/local-commands.json`,
  `original/local_commands.json` and the same three names under `fresh/`; no
  `coverage-*` directory exists either.  Cause: `scripts/run_shared_all_flows.py`
  and `scripts/run_shared_slot_subset.py` called `run_descriptor` without a
  `command_trace`, so `run_shared_slot_descriptor` took its
  `if command_trace is not None` branch as false.  The
  `run_descriptor` → `run_shared_slot_descriptor` forwarding already existed;
  only the entry scripts were missing it.  Both entry scripts now accept
  `--record-local-commands`, wrap the run in `record_local_commands()` and pass
  the trace through; the shared-slot kernel already writes
  `local_commands.json` (original invocation) and `fresh_local_commands.json`
  (within-invocation replay) from `recorded_command_documents(..., audited=True)`.
  `src/myfuzz/runtime/flows/shared_slots.py` was not modified.
  Existing saved session proof: feeding the saved `wb-timer` sessions and the
  saved process identities through the same export join reproduces the saved
  records exactly, and the resulting document is accepted by
  `select_recorded_session(..., 'wb_timer_active', build_digest)` and equals the
  saved `coverage-target` `commands.txt`/`replies.txt`
  (`tests/integration/test_shared_flow_command_trace.py`).
  No RTL session was started to demonstrate this.

## 5. What is still missing before a same-budget comparison with another tool

No external tool has produced a measurement under this contract, so the
comparison is `status = unavailable`,
`reason = no-second-tool-measurement-under-this-contract`.  A legal comparison
needs, for at least one component:

1. the other tool's **offline** line/block measurement of the same DUT source
   files (same `dut.source_files_sha256`) and the same point set
   (`dut.point_set_sha256`/`denominator_sha256`);
2. that tool's replay of the **identical recorded command sequence**
   (`workload.commands_sha256`) with a recorded command count and local ticks;
3. evidence of the **identical replay budget** and executed command count — the
   current budget is the replay bound (2048 commands, 64 MiB in/out, 60 s), not a
   fuzzing budget; **no search/time/seed budget is recorded anywhere and it
   stays `unknown`**;
4. an explicit mode declaration.  Only `offline` coverage exists here
   (`online: false`, `fixed_time_coverage: false`), so an online-only tool
   number is not comparable by construction;
5. for the fresh-prefix question, a second **instrumented** replay of the fresh
   commands; the saved fresh prefixes reproduce the commands but carry no
   coverage, and they are never compared with the instrumented original.

Until all five exist, the honest output is the four individual measured
fractions above and `unavailable` for any comparison.

## 6. Reproduction commands and results

```sh
# 1. one CPU instrumented build + replay (exit 0, 7.95 s, -j 4)
PYTHONPATH=src:. python3 scripts/measure_local_coverage.py \
  --trace research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030/wb-timer/original/original/local-command-trace.json \
  --component cpu \
  --cache runs/config-driven-20261028/cache/a06ff3b42591ca1097f9b8c3a471080d4346199501245baeb66edd0fe718c8fc \
  --output research/input-strategy-audit-20261027/runs/declared-irq-f5-cpu-20261030/wb-timer/coverage-cpu \
  --max-commands 2048 --build-jobs 4

# 2. re-verify the new measurement offline and derive its contract (exit 0)
R=research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030
M=research/input-strategy-audit-20261027/runs/declared-irq-f5-cpu-20261030/wb-timer/coverage-cpu
PYTHONPATH=src:. python3 scripts/measure_new_path_coverage.py \
  --run $R/wb-timer/original --measurement $M \
  --cache runs/config-driven-20261028/cache/a06ff3b42591ca1097f9b8c3a471080d4346199501245baeb66edd0fe718c8fc \
  --component cpu --original-prefix $R/wb-timer/original \
  --fresh-prefix $R/wb-timer/fresh --contract \
  --output research/input-strategy-audit-20261027/runs/declared-irq-f5-cpu-20261030/wb-timer/contract

# 3. build this package (exit 0)
PYTHONPATH=src:. python3 scripts/report_coverage_comparison_contract.py \
  --runs-root research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030 \
  --cpu-measurement research/input-strategy-audit-20261027/runs/declared-irq-f5-cpu-20261030/wb-timer/coverage-cpu \
  --output docs/reports/coverage-comparison-contract-20261030.json

# 4. the existing report still reproduces byte-identically (exit 0, cmp identical)
PYTHONPATH=src:. python3 scripts/report_declared_f5_coverage.py \
  --runs-root research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030 \
  --output /tmp/new-path-recheck.json && cmp docs/reports/new-path-coverage-20261030.json /tmp/new-path-recheck.json

# 5. tests
PYTHONPATH=src:. python3 -m pytest tests/integration/test_coverage_comparison_contract.py \
  tests/integration/test_shared_flow_command_trace.py \
  tests/integration/test_new_path_coverage_measurement.py \
  tests/integration/test_compare_local_harness_coverage.py \
  tests/local_harness/test_coverage.py -q
```

The package is deterministic (no timestamps, sorted keys, repo-relative paths);
rerunning step 3 over the same saved files reproduces the same bytes.

## 7. Changes a rerun of the old commands would notice

- `src/myfuzz/local_harness/coverage.py`: `coverage_argv(..., build_jobs=None)`
  opt-in schedule cap; new `dut_source_paths()` normaliser; the measurement now
  records `build_executed_argv`/`build_jobs` only when a cap is requested.  A
  measurement without `--build-jobs` records exactly the same fields as before.
- `scripts/compare_local_harness_coverage.py`: `load_run` normalises the saved
  DUT source list (same rejection for absolute/`.`/`..` paths).  Existing
  measurements are unaffected because their lists carry no `./` prefix.
- `scripts/measure_local_coverage.py`: new optional `--build-jobs` (default:
  none, i.e. the pinned command verbatim).
- `scripts/measure_new_path_coverage.py`: new opt-in `--contract` and the
  `comparison_contract` block; the default document is byte-identical, so the
  old `measure_new_path_coverage.py` invocations and
  `new-path-coverage-20261030.json` still reproduce.
- `scripts/run_shared_all_flows.py` and `scripts/run_shared_slot_subset.py`:
  new `--record-local-commands` flag (off by default; no behaviour change
  without it).  `src/myfuzz/runtime/flows/shared_slots.py` is untouched.
- New: `scripts/report_coverage_comparison_contract.py`,
  `tests/integration/test_coverage_comparison_contract.py`,
  `tests/integration/test_shared_flow_command_trace.py`, this report and its
  JSON twin, and the new CPU measurement directory
  `research/input-strategy-audit-20261027/runs/declared-irq-f5-cpu-20261030/`.
  No existing recorded artifact under `research/` or `runs/` was modified.
