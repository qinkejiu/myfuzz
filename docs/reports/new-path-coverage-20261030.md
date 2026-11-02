# Declared-IRQ F5 new-path coverage and own-prefix comparability — 2026-10-30

Scope: the three declared-IRQ F5 runs under
`research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030/`
(`wb-timer`, `apb-spi`, `ahb-sha`), read **offline** from already saved
artifacts. No RTL campaign, no Verilator build, no DUT simulation and no native
replay was started for this record; `research/` and `runs/` were not modified.

Every figure is re-derived by `scripts/measure_new_path_coverage.py` (which
reuses `scripts.compare_local_harness_coverage.load_run` for the saved-file
hashes, the original cache identity, the instrumentation check and the
Verilator point decoding) and assembled by
`scripts/report_declared_f5_coverage.py`. The machine-readable twin is
[`new-path-coverage-20261030.json`](new-path-coverage-20261030.json); it records
the SHA256 of each of the 56 input files it read, the per-run documents, and the
exact reproduction commands.

## Measured versus unavailable

| Run | Component | Saved measurement | DUT line/block | local ticks | result replies | Status |
|---|---|---|---|---|---|---|
| `wb-timer` | `wb_timer_active` | `coverage-target` | **37 / 39** (`ziptimer.v`) | 116 | 110 | measured |
| `apb-spi` | `spi_active` | `coverage-target` | **85 / 271** | 112 | 106 | measured |
| `ahb-sha` | `sha_active` | `coverage-target` | **359 / 614** | 146 | 134 | measured |
| `wb-timer` | `cpu` (Ibex) | `coverage-cpu` | — | — | — | **unavailable** |

- `wb-timer/coverage-cpu` holds `coverage.dat`, `build.log`, `obj/harness` and
  `inputs/generated/{driver.cpp,artifact.json}`, but it has no `coverage.json`,
  no `commands.txt`, no `replies.txt` and **no point map**
  (`coverage-points.json`). Without those there is no verified DUT source
  selection, no denominator identity and no replay identity, so the raw
  `coverage.dat` is *not* converted into a covered/total: the scope is
  unavailable with reason `incomplete-saved-measurement` and missing inputs
  `coverage.json`, `commands.txt`, `replies.txt`. A point count parsed from that
  file would be a number without a denominator, so none is reported.
- `wb-timer/coverage-cpu` is the CPU side of the same run; the measured row of
  `wb-timer` is the Wishbone ZipTimer target only. The three `coverage-target`
  directories are the only complete saved measurements in these run
  directories.

Identity of the measured rows (all values are in the JSON, re-verified against
the saved files):

| Run | denominator SHA256 | point-set SHA256 | `coverage.dat` SHA256 | build digest |
|---|---|---|---|---|
| `wb-timer` | `2df82e5397fa2c42c37083bcad1635d220169179dfd4f7bdfa5d89015b944160` | `e221d9ac6b2d5992193307c160220663353f2120ee164eb1259a20197a16b429` | `1491e39428e20d3bfc1bc5a6662dc3a5ba5500e81b1c5d95108bab27d019de3e` | `f526592ac533fdfd499289646df2156ad58139099f7565b14b0ade7c5c1dcc6a` |
| `apb-spi` | `c8dc60812118edd53b3113f51bd6cc33a3c59ed7ed12c74133d5e2eb861a96b7` | `009ab3fba69473efb641a4690c93fa8461bdec3a55f09391bed22c968693e518` | `8b92abc2a93c1124572c03b4c3cc99f9762cbd09e5f5a46e48fe0ef5a3cd3764` | `1e26eb155dfb6e8ca7d150a7d3bef59e032836b7a8fe2cf0490bd2ab77981d46` |
| `ahb-sha` | `6849c90f1bf5aaa1dd39587b574d3f0595ed168916292f86ea4075e07f2919db` | `87f0c9c4eeab1928e574ff16d50f159108dcb93a20ee2a91ee443c6930853c72` | `461c4cafe2e1b30a230019c427064d44e0a5302402622fdf46d8c68fda40a97f` | `7c80b436b4d4f0a9b1ad8c4b0ed8f226ff2263884f8c4b4fee8ec995a0ba44fa` |

The denominator is the canonicalised DUT point-identity set; the point-set hash
is the saved `coverage-points.json` hash that the verifier re-checks, together
with `coverage.json`, `coverage.dat`, `obj/harness`, the instrumented
`driver.cpp` and the original content-addressed cache. The per-file breakdown
sums to the total (39, 271, 614) and the per-kind breakdown to the same
denominator. The denominators are per component and are **not additive**; the
report publishes no aggregate.

## Comparability: the run's own `original` vs `fresh` prefix

`scripts/measure_new_path_coverage.py` now derives the comparability document
from a run's own saved prefixes (`--original-prefix`, `--fresh-prefix`) instead
of a foreign baseline. For all three runs the result is
`status = comparable_prefix`, `mode = own-original-fresh-prefix`, with
`comparison = null`:

- same config: `prefix.config_sha256` equal and `config.json` byte-identical
  (`74906255…`, `2e339543…`, `db29bb77…`);
- same admission (`368a53ae…`, `7248d41c…`, `ccb9d2c6…`), same artifact
  digests, same case and group document;
- same component build digest and binary SHA256 on both sides
  (`9f10add5…`, `eb9c0824…`, `0d1282a8…`);
- identical recorded commands and replies modulo the 32-hex execution nonce
  (110, 106 and 134 records respectively), identical per-command `tick_after`
  sequences, and the same final tick (116, 112, 146);
- every recorded process of both invocations exited 0 (three processes each,
  distinct nonces and pids) and both `summary.json` files are `verified`;
- the original side still equals the verified measurement (command count and
  tick count), so the 37/39, 85/271 and 359/614 numbers are bound to the prefix
  that was compared.

What this does **not** say: only the original prefix was instrumented, so the
fresh prefix has no coverage number. The comparability document sets
`coverage_comparison_available = false` with reason
`fresh-prefix-not-instrumented` and never compares covered/total between the two
invocations. Seed, time budget, execution budget and fairness remain `unknown`;
process independence is recorded as `separate-invocations` because the nonces and
pids differ. Reproducing a prefix is not evidence of tool superiority.

The old `apb-spi/comparability/summary.json` (and the equivalent reason in the
audit trail) compared this run against the **foreign** baseline
`reverse-pairs-20261028/spi-ibex-v1/seed-7-state-none/coverage-measurement`,
whose recorded trace layout this harness does not produce, and therefore
reported `status = unavailable`,
`reason = recorded-prefix-unverified:invalid-local-command-trace` with no
number. That artifact is superseded by this report; rewriting it in place is
lead work below because `research/` is read-only here.

## What the number is

Verilator line/block instrumentation (`--coverage-line`) of the full recorded
component command prefix, replayed offline: **startup/reset is included**
(`includes_startup_reset: true`) and every executed command is included, with
any budget overrun tail (`includes_budget_overrun: true`). The DUT point
universe is the structural-build source files of the component with hierarchy
retained. Verilator's own point kinds are reported as saved, e.g. `wb-timer`
23/23 line and 14/16 branch, `apb-spi` 38/77 line and 47/194 branch, `ahb-sha`
178/286 line and 181/328 branch; this is line/block coverage, **not**
source-branch, semantic, SoC or native-authority coverage.

It is **offline saved-prefix coverage**: not online coverage, not fixed-time
coverage, not coverage AUC (`online`, `fixed_time_coverage` and
`coverage_auc_available` are all `false`), and it does not measure a search
budget. A missing input never becomes a number: an incomplete or inconsistent
measurement yields `status = unavailable` with an exact reason and
`coverage = null`.

## Reproduction (offline, from the repo root)

```sh
PYTHONPATH=src:. python3 scripts/report_declared_f5_coverage.py \
  --runs-root research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030 \
  --output docs/reports/new-path-coverage-20261030.json

R=research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030
C=runs/config-driven-20261028/cache
PYTHONPATH=src:. python3 scripts/measure_new_path_coverage.py \
  --run $R/wb-timer/original --measurement $R/wb-timer/coverage-target \
  --cache $C/f526592ac533fdfd499289646df2156ad58139099f7565b14b0ade7c5c1dcc6a \
  --component wb_timer_active \
  --original-prefix $R/wb-timer/original --fresh-prefix $R/wb-timer/fresh
PYTHONPATH=src:. python3 scripts/measure_new_path_coverage.py \
  --run $R/apb-spi/original --measurement $R/apb-spi/coverage-target \
  --cache $C/1e26eb155dfb6e8ca7d150a7d3bef59e032836b7a8fe2cf0490bd2ab77981d46 \
  --component spi_active \
  --original-prefix $R/apb-spi/original --fresh-prefix $R/apb-spi/fresh
PYTHONPATH=src:. python3 scripts/measure_new_path_coverage.py \
  --run $R/ahb-sha/original --measurement $R/ahb-sha/coverage-target \
  --cache $C/7c80b436b4d4f0a9b1ad8c4b0ed8f226ff2263884f8c4b4fee8ec995a0ba44fa \
  --component sha_active \
  --original-prefix $R/ahb-sha/original --fresh-prefix $R/ahb-sha/fresh

PYTHONPATH=src:. python3 -m pytest tests/integration/test_new_path_coverage_measurement.py -q
```

The report is deterministic (no timestamps, sorted keys); rerunning it over the
same saved files reproduces the same bytes. All three measured numbers describe
a prefix that a second, separate invocation actually reproduced record for
record, so the coverage is not a one-off artifact of the original process.

## Lead work remaining

1. **The stale `apb-spi/comparability/summary.json` is superseded (done by the
   lead).** It still carries `status=unavailable`,
   `reason=recorded-prefix-unverified:invalid-local-command-trace`,
   `coverage=null` from the foreign-baseline call, and it is left in place as a
   historical artifact. The same run now measures 85/271 with
   `comparable_prefix`; the regenerated documents are in
   `research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030/apb-spi/comparability/own-prefix/`
   (`summary.json`, `coverage.json`, `comparability.json`).
2. **Measure `wb-timer/coverage-cpu`** if the CPU side is wanted. That needs an
   instrumented build plus a real replay, which was refused offline. After
   permission, the exact command is
   `PYTHONPATH=src:. python3 scripts/measure_local_coverage.py --trace $R/wb-timer/original/original/local-command-trace.json --component cpu --cache $C/a06ff3b42591ca1097f9b8c3a471080d4346199501245baeb66edd0fe718c8fc --output NEW_DIR`
   (`measure_cached_harness` builds a new instrumented copy and rejects an
   existing output directory; `NEW_DIR` must be new and writable).
3. **A fresh-prefix coverage number** would require the same instrumented build
   and a replay of the fresh commands; the fresh trace is saved only in the
   raw per-component list form, so the lead must pass a normalised
   `local_command_trace.v1` document. Without that second measurement no
   original-vs-fresh coverage comparison can exist, and none is claimed here.
